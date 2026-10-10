;;; tls.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Every TLS test runs once per backend: OpenSSL (cl+ssl) and pure-tls. The
;;; mock server always uses OpenSSL, so the pure-tls runs also check interop.

(in-package #:smtp/test)

(def-suite :smtp/tls :in :smtp :description "STARTTLS, implicit TLS and certificate checks.")
(in-suite :smtp/tls)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *backends* '(:openssl :pure-tls)))

(defmacro def-tls-test (name &body body)
  `(progn
     ,@(loop for backend in *backends*
             collect `(test ,(intern (format nil "~a/~a" name backend))
                        (let ((*tls-backend* ,backend))
                          ,@body)))))

(defun tls-options (&rest more)
  (append more (list :ca-file (fixture "ca.pem") :tls-hostname "localhost"
                     :local-name "client.test" :timeout 5)))

(defun tls-failure (&rest open-args)
  "The SMTP-ERROR signalled by OPEN-CONNECTION, or NIL if it succeeded."
  (handler-case (progn (close-connection (apply #'open-connection open-args)) nil)
    (smtp-error (e) e)))

(def-tls-test starttls-upgrades-and-re-ehlos
  (with-mock-server (port s (standard-server :pre-tls-extensions '("STARTTLS")
                                             :extensions '("AUTH PLAIN" "PIPELINING")))
    (let ((c (apply #'open-connection "127.0.0.1" :port port
                    (tls-options :credentials '(:username "alice" :password "secret")))))
      (is (connection-tls-p c))
      (is (eq *tls-backend* (connection-tls-backend c)))
      (is (connection-authenticated-p c))
      ;; Extensions come from the EHLO sent after the handshake.
      (is-true (nth-value 1 (connection-extension c "AUTH")))
      (is-false (nth-value 1 (connection-extension c "STARTTLS")))
      (send-message c (simple-message :text (format nil "over TLS~%.~%end")))
      (close-connection c))
    (is-true (session-tls s))
    (is (= 2 (length (sent-commands s "EHLO"))))
    (is (search (crlf "over TLS" "." "end") (message-text-of s)))))

(def-tls-test implicit-tls-with-large-message
  (let ((data (make-array 300000 :element-type '(unsigned-byte 8))))
    (dotimes (i (length data)) (setf (aref data i) (mod (* i 31) 256)))
    (with-mock-server (port s (standard-server) :implicit-tls t)
      (let ((c (apply #'open-connection "127.0.0.1" :port port :tls :implicit (tls-options))))
        (is (connection-tls-p c))
        (send-message c (simple-message :attachments (list (make-attachment data :filename "big.bin"))))
        (close-connection c))
      (is (= 1 (length (session-messages s))))
      (is (search (base64-encode (subseq data 0 57)) (message-text-of s))))))

(def-tls-test hostname-mismatch-is-fatal
  (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
    (let ((e (tls-failure "127.0.0.1" :port port :ca-file (fixture "ca.pem")
                                      :tls-hostname "mail.example.org" :local-name "client.test"
                                      :timeout 5)))
      (is (typep e 'smtp-tls-error))
      (is (search "does not match mail.example.org" (princ-to-string e))))
    (is (null (sent-commands s "MAIL")))))

(def-tls-test untrusted-certificate-is-fatal
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((e (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file (fixture "other-ca.pem")
                                      :tls-hostname "localhost" :local-name "client.test" :timeout 5)))
      (is (typep e 'smtp-tls-error))
      (is (search "could not be verified" (princ-to-string e))))))

(def-tls-test system-trust-store-rejects-test-ca
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (is (typep (tls-failure "127.0.0.1" :port port :tls :implicit :tls-hostname "localhost"
                                        :local-name "client.test" :timeout 5)
               'smtp-tls-error))))

(def-tls-test verification-can-be-disabled-for-testing
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((c (open-connection "127.0.0.1" :port port :tls :implicit :verify nil
                                          :ca-file (fixture "other-ca.pem")
                                          :local-name "client.test" :timeout 5)))
      (is (connection-tls-p c))
      (close-connection c))))

(def-tls-test ip-addresses-are-verified
  ;; The server certificate has an IP SAN for 127.0.0.1.
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((c (open-connection "127.0.0.1" :port port :tls :implicit :ca-file (fixture "ca.pem")
                                          :local-name "client.test" :timeout 5)))
      (is (connection-tls-p c))
      (close-connection c)))
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((e (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file (fixture "ca.pem")
                                      :tls-hostname "192.0.2.1" :local-name "client.test" :timeout 5)))
      (is (typep e 'smtp-tls-error))
      (is (search "does not match 192.0.2.1" (princ-to-string e))))))

(def-tls-test missing-ca-file
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (is (typep (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file "/nonexistent/ca.pem"
                                        :tls-hostname "localhost" :local-name "client.test" :timeout 5)
               'smtp-tls-error))))

(def-tls-test stalled-handshake-times-out
  ;; The server accepts the connection but never answers the ClientHello.
  (with-mock-server (port s (lambda (s) (declare (ignore s)) (sleep 3)))
    (let* ((start (get-internal-real-time))
           (e (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file (fixture "ca.pem")
                                       :tls-hostname "localhost" :local-name "client.test" :timeout 1)))
      (is (typep e 'smtp-timeout))
      (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 2.5)))))

(def-tls-test stalled-server-after-handshake-times-out
  (with-mock-server (port s (lambda (s)
                              (srv-start-tls s)
                              (srv-send s "220 hi")
                              (srv-read-line s)
                              (srv-send s "250 hello")
                              (srv-read-line s)
                              (sleep 3)))
    (let ((c (open-connection "127.0.0.1" :port port :tls :implicit :ca-file (fixture "ca.pem")
                                          :tls-hostname "localhost" :local-name "client.test"
                                          :timeout 1)))
      (signals smtp-timeout (send-message c (simple-message)))
      (close-connection c))))

(def-tls-test trust-settings-apply-to-every-connection
  ;; A session established with the right CA must not let a later connection
  ;; with the wrong CA (or with verification required after it was off)
  ;; skip verification, for example by TLS session resumption.
  (dotimes (i 2)
    (with-mock-server (port s (standard-server) :implicit-tls t)
      (close-connection (apply #'open-connection "127.0.0.1" :port port :tls :implicit (tls-options)))))
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (is (typep (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file (fixture "other-ca.pem")
                                        :tls-hostname "localhost" :local-name "client.test" :timeout 5)
               'smtp-tls-error)))
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (close-connection (open-connection "127.0.0.1" :port port :tls :implicit :verify nil
                                                   :tls-hostname "mail.test" :local-name "client.test")))
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (is (typep (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file (fixture "other-ca.pem")
                                        :tls-hostname "mail.test" :local-name "client.test" :timeout 5)
               'smtp-tls-error))))

(test pure-tls-leaves-no-session-tickets
  ;; Control: the mock server does send NewSessionTickets after the handshake.
  (let ((cache (make-hash-table :test 'equal)))
    (with-mock-server (port s (standard-server) :implicit-tls t)
      (let* ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)))
             (pure-tls:*session-ticket-cache* cache)
             (tls (pure-tls:make-tls-client-stream (usocket:socket-stream socket)
                                                   :hostname "localhost"
                                                   :context (pure-tls:make-tls-context
                                                             :ca-file (namestring (fixture "ca.pem"))))))
        (loop for b = (read-byte tls nil) until (or (null b) (= b 10)))
        (write-sequence (octets (crlf "QUIT" "")) tls)
        (force-output tls)
        (ignore-errors (loop while (read-byte tls nil)))
        (ignore-errors (close tls))
        (usocket:socket-close socket)))
    (is-true (gethash "localhost" cache) "the server should have issued a ticket"))
  ;; Through smtp, no ticket reaches pure-tls's shared cache.
  (pure-tls:session-ticket-cache-clear "localhost")
  (let ((*tls-backend* :pure-tls))
    (with-mock-server (port s (standard-server) :implicit-tls t)
      (let ((c (apply #'open-connection "127.0.0.1" :port port :tls :implicit (tls-options))))
        (send-message c (simple-message))
        (close-connection c))))
  (is (null (gethash "localhost" pure-tls:*session-ticket-cache*))))

(def-tls-test bracketed-addresses
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((c (open-connection "[127.0.0.1]" :port port :tls :implicit :ca-file (fixture "ca.pem")
                                            :tls-hostname "[IPv6:127.0.0.1]" :local-name "client.test"
                                            :timeout 5)))
      (is (connection-tls-p c))
      (close-connection c))))

(def-tls-test unusable-ca-file
  (uiop:with-temporary-file (:pathname path :type "pem" :stream out :direction :output)
    (write-string "not a certificate" out)
    (finish-output out)
    (with-mock-server (port s (standard-server) :implicit-tls t)
      (let ((e (tls-failure "127.0.0.1" :port port :tls :implicit :ca-file path
                                        :tls-hostname "localhost" :local-name "client.test" :timeout 5)))
        (is (typep e 'smtp-tls-error))
        (is (null (search "server's certificate" (princ-to-string e))))))))

(test unknown-backend-fails-before-connecting
  ;; Port 1 is never contacted: the backend is checked first.
  (signals smtp-tls-error (open-connection "127.0.0.1" :port 1 :tls-backend :bogus))
  (finishes (handler-case (open-connection "127.0.0.1" :port 1 :tls :none :tls-backend :bogus)
              (smtp-connection-error () t))))
