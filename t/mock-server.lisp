;;; mock-server.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; An in-process SMTP server for tests. A handler function drives each
;;; session, either a hand-written script or the configurable STANDARD-SERVER.
;;; The session records what the client sent and any protocol violations.

(in-package #:smtp/test)

(defclass session ()
  ((socket :initform nil :accessor session-socket)
   (stream :initform nil :accessor session-stream)
   (tls :initform nil :accessor session-tls)
   (commands :initform '() :accessor session-commands
             :documentation "Lines received outside DATA, oldest first.")
   (messages :initform '() :accessor session-messages
             :documentation "Received messages as (from recipients octets).")
   (violations :initform '() :accessor session-violations)
   (pipelined :initform nil :accessor session-pipelined
              :documentation "True if RCPT arrived before MAIL was answered.")
   (error :initform nil :accessor session-error)))

(defun %violation (session fmt &rest args)
  (push (apply #'format nil fmt args) (session-violations session)))

(defun srv-read-line (session &key (record t))
  "The next line from the client without CRLF, or NIL at end of file."
  (let ((stream (session-stream session))
        (bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (handler-case (read-byte stream nil nil) (error () nil))
          do (cond ((null b) (return-from srv-read-line nil))
                   ((= b 10)
                    (if (and (plusp (length bytes)) (= (aref bytes (1- (length bytes))) 13))
                        (decf (fill-pointer bytes))
                        (%violation session "bare LF after ~s" (text bytes)))
                    (return))
                   (t (vector-push-extend b bytes))))
    (let ((line (text (coerce bytes '(simple-array (unsigned-byte 8) (*))))))
      (when record
        (setf (session-commands session) (append (session-commands session) (list line))))
      line)))

(defun srv-send (session &rest lines)
  (let ((stream (session-stream session)))
    (dolist (line lines)
      (write-sequence (octets line) stream)
      (write-sequence #(13 10) stream))
    (force-output stream)))

(defun srv-send-raw (session string)
  (write-sequence (octets string) (session-stream session))
  (force-output (session-stream session)))

(defun srv-read-data (session)
  "Read DATA content up to the terminating dot line, undoing dot-stuffing, as
the receiving MTA would. Returns octets with CRLF line endings."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for line = (srv-read-line session :record nil)
          do (cond ((null line) (return))
                   ((string= line ".") (return))
                   (t (let ((content (if (and (plusp (length line)) (char= (char line 0) #\.))
                                         (subseq line 1)
                                         line)))
                        (loop for b across (octets content) do (vector-push-extend b out))
                        (vector-push-extend 13 out)
                        (vector-push-extend 10 out)))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun srv-read-octets (session n)
  (let ((data (make-array n :element-type '(unsigned-byte 8))))
    (read-sequence data (session-stream session))
    data))

(defvar *server-certificate* "server.pem"
  "The fixture the mock server presents: a certificate, or with
*SERVER-CHAIN* true a file holding the certificate and its issuers.")
(defvar *server-key* "server-key.pem")
(defvar *server-chain* nil)

(defun srv-start-tls (session)
  (setf (session-stream session)
        (if *server-chain*
            (cl+ssl:with-global-context
                ((cl+ssl:make-context :certificate-chain-file (namestring (fixture *server-certificate*))
                                      :private-key-file (namestring (fixture *server-key*))
                                      :verify-mode cl+ssl:+ssl-verify-none+)
                 :auto-free-p t)
              (cl+ssl:make-ssl-server-stream (session-stream session)))
            (cl+ssl:make-ssl-server-stream (session-stream session)
                                           :certificate (namestring (fixture *server-certificate*))
                                           :key (namestring (fixture *server-key*))))
        (session-tls session) t))

(defun srv-input-pending-p (session)
  (handler-case (listen (session-stream session)) (error () nil)))

(defun call-with-mock-server (handler function &key implicit-tls (timeout 15))
  "Run HANDLER on a session for one client connection while FUNCTION is called
with the port and the session."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                                        :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (session (make-instance 'session))
         (certificate *server-certificate*) (key *server-key*) (chain *server-chain*)
         (thread
           (bt:make-thread
            (lambda ()
              (let ((*server-certificate* certificate) (*server-key* key) (*server-chain* chain))
              (handler-case
                  (sb-sys:with-deadline (:seconds timeout)
                    (when (usocket:wait-for-input listener :timeout timeout :ready-only t)
                      (let ((socket (usocket:socket-accept listener)))
                        (setf (session-socket session) socket
                              (session-stream session) (usocket:socket-stream socket))
                        (unwind-protect
                             (progn
                               (when implicit-tls (srv-start-tls session))
                               (funcall handler session))
                          (ignore-errors (close (session-stream session)))
                          (ignore-errors (usocket:socket-close socket))))))
                (serious-condition (e) (setf (session-error session) e)))))
            :name "mock smtp server")))
    (unwind-protect (funcall function port session)
      (bt:join-thread thread)
      (usocket:socket-close listener))))

(defmacro with-mock-server ((port session handler &rest options) &body body)
  `(call-with-mock-server ,handler (lambda (,port ,session)
                                     (declare (ignorable ,port ,session))
                                     ,@body)
                          ,@options))

;;; A configurable, mostly RFC-conforming server

(defun %verb (line)
  (string-upcase (subseq line 0 (or (position #\Space line) (length line)))))

(defun %arg (line)
  (let ((sp (position #\Space line)))
    (if sp (subseq line (1+ sp)) "")))

(defun %path (arg)
  ;; "FROM:<a@b> SIZE=1" -> "a@b"
  (let ((open (position #\< arg)) (close (position #\> arg)))
    (and open close (subseq arg (1+ open) close))))

(defun %b64 (string) (text (base64-decode string)))

(defun standard-server (&key (greeting "220 mock.test ESMTP ready")
                          (extensions '("PIPELINING" "8BITMIME" "ENHANCEDSTATUSCODES"))
                          (pre-tls-extensions nil pre-tls-p)
                          (users '(("alice" . "secret")))
                          (tokens '(("alice" . "good-token")))
                          (reject-recipients '())
                          (defer-recipients '())
                          (mail-reply "250 2.1.0 OK")
                          (data-reply "250 2.0.0 OK queued as 12345")
                          (ehlo-reply nil))
  "A handler for a well-behaved ESMTP server. EXTENSIONS are announced with
EHLO; PRE-TLS-EXTENSIONS, if given, replace them before TLS. Users
authenticate with USERS (passwords) or TOKENS (OAuth)."
  (lambda (s)
    (let ((from nil) (rcpts '()) (chunks '()))
      (labels ((ext () (if (and pre-tls-p (not (session-tls s))) pre-tls-extensions extensions))
               (offered (name) (find-if (lambda (e) (string-prefix-p name (string-upcase e)))
                                        (ext)))
               (reset () (setf from nil rcpts '() chunks '()))
               (store (octets)
                 (setf (session-messages s)
                       (append (session-messages s) (list (list from (reverse rcpts) octets))))
                 (reset))
               (auth-ok (user secret table)
                 (equal (cdr (assoc user table :test #'string=)) secret))
               (auth (arg)
                 (let* ((mech (string-upcase (subseq arg 0 (or (position #\Space arg) (length arg)))))
                        (initial (let ((sp (position #\Space arg))) (and sp (subseq arg (1+ sp))))))
                   (cond
                     ((string= mech "PLAIN")
                      (let* ((resp (or initial (progn (srv-send s "334 ") (srv-read-line s))))
                             (parts (let ((d (%b64 resp)))
                                      (loop with start = 0
                                            for pos = (position (code-char 0) d :start start)
                                            collect (subseq d start pos)
                                            while pos do (setf start (1+ pos))))))
                        (if (and (= (length parts) 3) (auth-ok (second parts) (third parts) users))
                            (srv-send s "235 2.7.0 Authentication successful")
                            (srv-send s "535 5.7.8 Authentication credentials invalid"))))
                     ((string= mech "LOGIN")
                      (srv-send s "334 VXNlcm5hbWU6")
                      (let ((user (%b64 (srv-read-line s))))
                        (srv-send s "334 UGFzc3dvcmQ6")
                        (let ((password (%b64 (srv-read-line s))))
                          (if (auth-ok user password users)
                              (srv-send s "235 2.7.0 Authentication successful")
                              (srv-send s "535 5.7.8 Authentication credentials invalid")))))
                     ((member mech '("XOAUTH2" "OAUTHBEARER") :test #'string=)
                      (let* ((d (%b64 initial))
                             (fields (loop with start = 0
                                           for pos = (position (code-char 1) d :start start)
                                           collect (subseq d start pos)
                                           while pos do (setf start (1+ pos))))
                             (user (if (string= mech "XOAUTH2")
                                       (let ((f (find "user=" fields :test #'string-prefix-p)))
                                         (and f (subseq f 5)))
                                       (let* ((gs2 (first fields))
                                              (a (search ",a=" gs2)))
                                         (and (string-prefix-p "n," gs2) a
                                              (subseq gs2 (+ a 3) (position #\, gs2 :start (+ a 3)))))))
                             (bearer (let ((f (find "auth=Bearer " fields :test #'string-prefix-p)))
                                       (and f (subseq f 12)))))
                        (if (auth-ok user bearer tokens)
                            (srv-send s "235 2.7.0 Accepted")
                            (progn
                              (srv-send s (format nil "334 ~a"
                                                  (base64-encode "{\"status\":\"invalid_token\",\"scope\":\"mail\"}")))
                              (srv-read-line s)
                              (srv-send s "535 5.7.8 Invalid token")))))
                     (t (srv-send s "504 5.5.4 Unrecognized authentication type"))))))
        (srv-send s greeting)
        (loop
          (let ((line (srv-read-line s)))
            (when (null line) (return))
            (let ((verb (%verb line)) (arg (%arg line)))
              (cond
                ((string= verb "EHLO")
                 (if ehlo-reply
                     (srv-send s ehlo-reply)
                     (let ((exts (remove-if (lambda (e) (and (session-tls s)
                                                             (string-equal e "STARTTLS")))
                                            (ext))))
                       (apply #'srv-send s
                              (append (list (format nil "250~:[ ~;-~]mock.test greets ~a" exts arg))
                                      (loop for (e . more) on exts
                                            collect (format nil "250~:[ ~;-~]~a" more e)))))))
                ((string= verb "HELO") (srv-send s "250 mock.test"))
                ((string= verb "STARTTLS")
                 (if (and (offered "STARTTLS") (not (session-tls s)))
                     (progn (srv-send s "220 2.0.0 Ready to start TLS")
                            (srv-start-tls s)
                            (reset))
                     (srv-send s "502 5.5.1 Not supported")))
                ((string= verb "AUTH") (auth arg))
                ((string= verb "MAIL")
                 (when (srv-input-pending-p s) (setf (session-pipelined s) t))
                 (if (string-prefix-p "250" mail-reply)
                     (setf from (%path arg)))
                 (srv-send s mail-reply))
                ((string= verb "RCPT")
                 (cond ((null from) (srv-send s "503 5.5.1 Need MAIL first"))
                       ((member (%path arg) reject-recipients :test #'string-equal)
                        (srv-send s "550 5.1.1 No such user"))
                       ((member (%path arg) defer-recipients :test #'string-equal)
                        (srv-send s "450 4.2.1 Try again later"))
                       (t (push (%path arg) rcpts)
                          (srv-send s "250 2.1.5 OK"))))
                ((string= verb "DATA")
                 (if (null rcpts)
                     (srv-send s "554 5.5.1 No valid recipients")
                     (progn (srv-send s "354 Go ahead")
                            (let ((data (srv-read-data s)))
                              (if (string-prefix-p "250" data-reply)
                                  (store data)
                                  (reset))
                              (srv-send s data-reply)))))
                ((string= verb "BDAT")
                 (let* ((parts (loop with start = 0
                                     for pos = (position #\Space arg :start start)
                                     collect (subseq arg start pos)
                                     while pos do (setf start (1+ pos))))
                        (n (parse-integer (first parts)))
                        (last (equalp (second parts) "LAST")))
                   (push (srv-read-octets s n) chunks)
                   (if (and last rcpts)
                       (progn (store (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                                            (reverse chunks)))
                              (srv-send s data-reply))
                       (srv-send s (if rcpts "250 2.0.0 Chunk OK" "554 5.5.1 No valid recipients")))))
                ((string= verb "RSET") (reset) (srv-send s "250 2.0.0 OK"))
                ((string= verb "NOOP") (srv-send s "250 2.0.0 OK"))
                ((string= verb "QUIT") (srv-send s "221 2.0.0 Bye") (return))
                (t (srv-send s "500 5.5.2 Command unrecognized"))))))))))

(defun sent-commands (session verb)
  "The commands SESSION received whose verb is VERB."
  (remove-if-not (lambda (l) (string-equal (%verb l) verb)) (session-commands session)))

(defun simple-message (&rest keys)
  (apply #'make-message
         (append keys
                 (list :from "Alice <alice@example.com>"
                       :to "bob@example.net"
                       :subject "Hello"
                       :text "Hi Bob."))))

(defun connect (port &rest options)
  "Open a plaintext connection to the mock server on PORT."
  (apply #'open-connection "127.0.0.1" :port port
         (append options (list :tls :none :local-name "client.test" :timeout 5))))
