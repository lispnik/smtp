;;; tls.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/tls :in :smtp :description "STARTTLS, implicit TLS and certificate checks.")
(in-suite :smtp/tls)

(defun tls-options (&rest more)
  (append more (list :ca-file (fixture "ca.pem") :tls-hostname "localhost"
                     :local-name "client.test" :timeout 5)))

(test starttls-upgrades-and-re-ehlos
  (with-mock-server (port s (standard-server :pre-tls-extensions '("STARTTLS")
                                             :extensions '("AUTH PLAIN" "PIPELINING")))
    (let ((c (apply #'open-connection "127.0.0.1" :port port
                    (tls-options :credentials '(:username "alice" :password "secret")))))
      (is (connection-tls-p c))
      (is (connection-authenticated-p c))
      ;; Extensions come from the EHLO sent after the handshake.
      (is-true (nth-value 1 (connection-extension c "AUTH")))
      (is-false (nth-value 1 (connection-extension c "STARTTLS")))
      (send-message c (simple-message))
      (close-connection c))
    (is-true (session-tls s))
    (is (= 2 (length (sent-commands s "EHLO"))))
    (is (= 1 (length (session-messages s))))))

(test implicit-tls
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((c (apply #'open-connection "127.0.0.1" :port port :tls :implicit (tls-options))))
      (is (connection-tls-p c))
      (send-message c (simple-message))
      (close-connection c))
    (is (= 1 (length (session-messages s))))))

(test hostname-mismatch-is-fatal
  (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
    (let ((e (handler-case
                 (open-connection "127.0.0.1" :port port :ca-file (fixture "ca.pem")
                                              :tls-hostname "mail.example.org" :local-name "client.test"
                                              :timeout 5)
               (smtp-tls-error (e) e))))
      (is (typep e 'smtp-tls-error))
      (is (search "does not match mail.example.org" (princ-to-string e))))
    (is (null (sent-commands s "MAIL")))))

(test untrusted-certificate-is-fatal
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((e (handler-case
                 (open-connection "127.0.0.1" :port port :tls :implicit :ca-file (fixture "other-ca.pem")
                                              :tls-hostname "localhost" :local-name "client.test" :timeout 5)
               (smtp-tls-error (e) e))))
      (is (typep e 'smtp-tls-error))
      (is (search "could not be verified" (princ-to-string e))))))

(test system-trust-store-rejects-test-ca
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (signals smtp-tls-error
      (open-connection "127.0.0.1" :port port :tls :implicit :tls-hostname "localhost"
                                   :local-name "client.test" :timeout 5))))

(test verification-can-be-disabled-for-testing
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((c (open-connection "127.0.0.1" :port port :tls :implicit :verify nil
                                          :local-name "client.test" :timeout 5)))
      (is (connection-tls-p c))
      (close-connection c))))

(test ip-addresses-need-a-tls-hostname
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (let ((e (handler-case (open-connection "127.0.0.1" :port port :tls :implicit
                                                        :ca-file (fixture "ca.pem")
                                                        :local-name "client.test" :timeout 5)
               (smtp-tls-error (e) e))))
      (is (typep e 'smtp-tls-error))
      (is (search ":tls-hostname" (princ-to-string e))))))

(test missing-ca-file
  (with-mock-server (port s (standard-server) :implicit-tls t)
    (signals smtp-tls-error
      (open-connection "127.0.0.1" :port port :tls :implicit :ca-file "/nonexistent/ca.pem"
                                   :tls-hostname "localhost" :local-name "client.test" :timeout 5))))
