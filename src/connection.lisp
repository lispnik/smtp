;;; connection.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Connections: sockets, TLS, timeouts, commands and replies, EHLO and
;;; STARTTLS.

(in-package #:smtp)

(defvar *trace* nil
  "Where new connections log the SMTP conversation: NIL, T for
*TRACE-OUTPUT*, a stream, or a function of a direction (:CLIENT or :SERVER)
and a line. Credentials are always redacted and message content is never
logged.")

(defconstant +max-line-length+ 4096
  "The longest reply line accepted. RFC 5321 allows 512 octets; servers exceed
that in practice, but an unbounded line is a memory-exhaustion vector.")

(defclass connection ()
  ((host :initarg :host :reader connection-host)
   (port :initarg :port :reader connection-port)
   (socket :initform nil :accessor %socket)
   (stream :initform nil :accessor %stream)
   (state :initform :new :accessor connection-state
          :documentation ":NEW, :OPEN, :BROKEN (unusable after an I/O or
protocol error) or :CLOSED.")
   (tls :initform nil :accessor connection-tls-p)
   (tls-backend :initarg :tls-backend :initform nil :accessor connection-tls-backend)
   (greeting :initform nil :accessor connection-greeting)
   (extensions :initform '() :accessor %extensions)
   (esmtp :initform nil :accessor connection-esmtp-p)
   (authenticated :initform nil :accessor connection-authenticated-p)
   (in-transaction :initform nil :accessor %in-transaction)
   (local-name :initarg :local-name :initform nil :accessor connection-local-name)
   (timeout :initarg :timeout :reader connection-timeout)
   (data-timeout :initarg :data-timeout :reader connection-data-timeout)
   (tls-hostname :initarg :tls-hostname :reader %tls-hostname)
   (verify :initarg :verify :reader %verify)
   (ca-file :initarg :ca-file :reader %ca-file)
   (client-certificate :initarg :client-certificate :reader %client-certificate)
   (client-key :initarg :client-key :reader %client-key)
   (client-key-password :initarg :client-key-password :reader %client-key-password)
   (allow-insecure-auth :initarg :allow-insecure-auth :reader %allow-insecure-auth)
   (trace :initarg :trace :reader connection-trace))
  (:documentation "An SMTP session with one server. Not safe for concurrent use
from several threads."))

(defmethod print-object ((c connection) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~a:~a ~(~a~)~:[~; TLS~]" (connection-host c) (connection-port c)
            (connection-state c) (connection-tls-p c))))

(defun connection-extensions (connection)
  "The ESMTP extensions the server announced, an alist of (keyword . params)
with upcased keywords."
  (copy-alist (%extensions connection)))

(defun connection-extension (connection name)
  "If the server announced extension NAME, its parameters (a list of strings)
and T."
  (let ((entry (assoc name (%extensions connection) :test #'string-equal)))
    (values (cdr entry) (and entry t))))

;;; Tracing

(defun %trace (connection direction line)
  (let ((dest (connection-trace connection)))
    (cond ((null dest))
          ((functionp dest) (funcall dest direction line))
          (t (let ((s (if (eq dest t) *trace-output* dest)))
               (format s "~&~:[S~;C~]: ~a~%" (eq direction :client) line)
               (force-output s))))))

;;; I/O with timeouts and error translation

(defun %call-with-deadline (seconds fn)
  ;; On SBCL every blocking wait, including cl+ssl's on its non-blocking
  ;; sockets, honours the current deadline.
  #+sbcl (if seconds
             (sb-sys:with-deadline (:seconds seconds) (funcall fn))
             (funcall fn))
  #-sbcl (progn seconds (funcall fn)))

(defun %ensure-open (connection)
  (unless (eq (connection-state connection) :open)
    (error 'smtp-connection-error
           :message (format nil "The connection to ~a is ~(~a~)"
                            (connection-host connection) (connection-state connection)))))

(defun call-with-io (connection operation timeout fn)
  "Call FN, translating timeouts and transport errors into SMTP-CONNECTION-ERRORs.
Transport and protocol errors leave CONNECTION :BROKEN, since its state is no
longer known."
  (%ensure-open connection)
  (handler-bind (((or smtp-connection-error smtp-protocol-error)
                   (lambda (c)
                     (declare (ignore c))
                     (setf (connection-state connection) :broken))))
    (handler-case (%call-with-deadline
                   timeout
                   (lambda ()
                     (handler-bind ((error (lambda (e)
                                             (when (and (not (typep e 'smtp-error))
                                                        (tls-condition-p e))
                                               (error 'smtp-connection-error
                                                      :message (format nil "TLS error while ~a" operation)
                                                      :cause e)))))
                       (funcall fn))))
      #+sbcl
      (sb-sys:deadline-timeout ()
        (error 'smtp-timeout :operation operation :seconds timeout))
      #+sbcl
      (sb-sys:io-timeout ()
        (error 'smtp-timeout :operation operation :seconds timeout))
      (end-of-file ()
        (error 'smtp-connection-closed))
      (stream-error (e)
        (error 'smtp-connection-error :message (format nil "I/O error while ~a" operation)
                                      :cause e))
      (usocket:socket-condition (e)
        (error 'smtp-connection-error :message (format nil "Socket error while ~a" operation)
                                      :cause e)))))

(defmacro with-io ((connection operation &optional timeout) &body body)
  (alexandria:once-only (connection)
    `(call-with-io ,connection ,operation
                   ,(or timeout `(connection-timeout ,connection))
                   (lambda () ,@body))))

(defun %read-line (connection)
  "Read one line from the server, without its line ending."
  (let ((stream (%stream connection))
        (buffer (make-octet-buffer 128)))
    (loop for octet = (read-byte stream nil nil)
          do (cond ((null octet) (error 'smtp-connection-closed))
                   ((= octet 10) (return))
                   ((>= (length buffer) +max-line-length+)
                    (error 'smtp-protocol-error
                           :message (format nil "Reply line longer than ~d octets"
                                            +max-line-length+)))
                   (t (buffer-push octet buffer))))
    (let ((n (length buffer)))
      (when (and (plusp n) (= (aref buffer (1- n)) 13))
        (decf (fill-pointer buffer))))
    ;; Server text ends up in conditions and traces; keep it inert.
    (substitute-if #\? (lambda (c) (and (control-char-p c) (char/= c #\Tab)))
                   (utf8-string buffer))))

(defun read-reply (connection &key (timeout (connection-timeout connection)))
  "Read one complete, possibly multi-line, reply."
  (with-io (connection "waiting for the server's reply" timeout)
    (let ((lines '()) (count 0))
      (loop
        (let ((line (%read-line connection)))
          (%trace connection :server line)
          (multiple-value-bind (code more text) (parse-reply-line line)
            (push (cons code text) lines)
            (when (> (incf count) +max-reply-lines+)
              (error 'smtp-protocol-error
                     :message (format nil "Reply longer than ~d lines" +max-reply-lines+)))
            (unless more (return)))))
      (assemble-reply (nreverse lines)))))

(defun %write-octets (connection octets &key (start 0) (end (length octets)) timeout)
  "Write OCTETS in pieces, each within the timeout, so that a slow but live
link can carry a large message while a stalled one is still detected."
  (loop for from from start below end by 65536
        for to = (min end (+ from 65536))
        do (with-io (connection "sending data" (or timeout (connection-timeout connection)))
             (write-sequence octets (%stream connection) :start from :end to)
             (when (= to end) (force-output (%stream connection)))))
  (when (= start end)
    (with-io (connection "sending data") (force-output (%stream connection)))))

(defun %command-octets (line max-length)
  (when (find-if (lambda (c) (or (line-break-char-p c) (char= c (code-char 0)))) line)
    (error 'mail-format-error
           :message "Refusing to send an SMTP command containing a line break or NUL"))
  (let ((octets (utf8-octets line)))
    (when (> (length octets) max-length)
      (error 'mail-format-error
             :message (format nil "SMTP command longer than ~d octets" max-length)))
    (let ((buffer (make-octet-buffer (+ 2 (length octets)))))
      (buffer-append buffer octets)
      (buffer-crlf buffer))))

(defconstant +max-command-length+ 2048
  "The longest command sent, in octets. RFC 5321 allows 512, raised by each
extension that adds MAIL or RCPT parameters.")

(defun send-command (connection line &key (max-length +max-command-length+) trace-as)
  "Send LINE, which must not contain a line break, followed by CRLF.
TRACE-AS replaces LINE in the trace."
  (let ((octets (%command-octets line max-length)))
    (%trace connection :client (or trace-as line))
    (%write-octets connection octets)))

(defun %send-commands (connection lines)
  "Send LINES in a single write, for PIPELINING (RFC 2920)."
  (let ((buffer (make-octet-buffer)))
    (dolist (line lines)
      (buffer-append buffer (%command-octets line +max-command-length+))
      (%trace connection :client line))
    (%write-octets connection buffer)))

(defun %expected-p (reply expect)
  (some (lambda (e)
          (if (< e 10)
              (= e (reply-class reply))
              (= e (reply-code reply))))
        expect))

(defun check-reply (connection reply command expect &key message)
  "Signal an SMTP-REPLY-ERROR unless REPLY matches EXPECT, a list of codes or
of reply classes (2 for any 2xx)."
  (when (= (reply-code reply) 421)
    ;; The server is closing the transmission channel.
    (setf (connection-state connection) :broken))
  (unless (%expected-p reply expect)
    (error (case (reply-class reply)
             (4 'smtp-transient-error)
             (5 'smtp-permanent-error)
             (t (setf (connection-state connection) :broken)
                'smtp-reply-error))
           :reply reply :command command :message message))
  reply)

(defun command (connection line &key (expect '(2)) trace-as timeout)
  "Send LINE and read the reply, which must match EXPECT (NIL accepts any
reply)."
  (send-command connection line :trace-as trace-as)
  (let ((reply (read-reply connection :timeout (or timeout (connection-timeout connection)))))
    (when expect
      (check-reply connection reply (or trace-as line) expect))
    reply))

;;; Opening and closing

(defun %ip-literal-p (host)
  (or (find #\: host)
      (and (every (lambda (c) (or (ascii-digit-p c) (char= c #\.))) host)
           (= 3 (count #\. host)))))

(defun %normalize-host (host)
  "HOST without the brackets or IPv6: prefix of URL and SMTP address
literals, so \"[::1]\" and \"[IPv6:::1]\" mean the address ::1."
  (let* ((h (string-trim " " host))
         (h (if (and (> (length h) 1) (char= (char h 0) #\[) (char= (char h (1- (length h))) #\]))
                (subseq h 1 (1- (length h)))
                h)))
    (if (string-prefix-p "IPv6:" h) (subseq h 5) h)))

(defun %connect (connection host port timeout)
  (handler-case
      (%call-with-deadline
       timeout
       (lambda ()
         (let ((socket (usocket:socket-connect host port :element-type 'octet
                                                         :timeout timeout
                                                         :nodelay :if-supported)))
           (setf (%socket connection) socket
                 (%stream connection) (usocket:socket-stream socket)
                 (connection-state connection) :open))))
    #+sbcl
    (sb-sys:deadline-timeout ()
      (error 'smtp-timeout :operation (format nil "connecting to ~a:~d" host port)
                           :seconds timeout))
    (usocket:timeout-error ()
      (error 'smtp-timeout :operation (format nil "connecting to ~a:~d" host port)
                           :seconds timeout))
    (usocket:ns-condition (e)
      (error 'smtp-connection-error :message (format nil "Cannot resolve ~a" host) :cause e))
    (usocket:socket-condition (e)
      (error 'smtp-connection-error :message (format nil "Cannot connect to ~a:~d" host port)
                                    :cause e))
    (stream-error (e)
      (error 'smtp-connection-error :message (format nil "Cannot connect to ~a:~d" host port)
                                    :cause e))))

(defun %start-tls-session (connection)
  "Replace the connection's stream with a TLS stream from its backend. The
server's certificate chain and name are verified unless verification was
turned off. Timeouts and transport errors are translated here for every
backend; each backend translates its own TLS conditions."
  (handler-bind ((smtp-connection-error
                   (lambda (c)
                     (declare (ignore c))
                     (setf (connection-state connection) :broken))))
    (let ((backend (resolve-tls-backend (connection-tls-backend connection)))
          (timeout (connection-timeout connection)))
      (setf (%stream connection)
            (handler-case
                (%call-with-deadline
                 timeout
                 (lambda ()
                   (handler-bind ((error (lambda (e)
                                           (when (and (not (typep e 'smtp-error)) (tls-condition-p e))
                                             (error 'smtp-tls-error :message "The TLS handshake failed"
                                                                    :cause e)))))
                     (start-tls backend (%stream connection)
                                :hostname (%tls-hostname connection)
                                :verify (let ((v (%verify connection))) (and v (not (functionp v))))
                                :ca-file (%ca-file connection)
                                :client-certificate (%client-certificate connection)
                                :client-key (%client-key connection)
                                :client-key-password (%client-key-password connection)
                                :timeout timeout))))
              #+sbcl
              (sb-sys:deadline-timeout ()
                (error 'smtp-timeout :operation "negotiating TLS" :seconds timeout))
              (smtp-error (e) (error e))
              (stream-error (e)
                (error 'smtp-tls-error :message "The connection failed during the TLS handshake"
                                       :cause e)))
            (connection-tls-backend connection) backend
            (connection-tls-p connection) t)
      (when (functionp (%verify connection))
        ;; A custom check of the server's certificates, such as DANE.
        (handler-bind ((error (lambda (e)
                                (declare (ignore e))
                                (setf (connection-state connection) :broken))))
          (funcall (%verify connection) backend (%stream connection)))))))

(defun %parse-extensions (lines)
  (let ((extensions '()))
    (dolist (line lines)
      (let* ((words (remove "" (loop with start = 0
                                     for pos = (position #\Space line :start start)
                                     collect (subseq line start pos)
                                     while pos do (setf start (1+ pos)))
                            :test #'string=))
             (keyword (string-upcase (or (first words) ""))))
        (cond ((zerop (length keyword)))
              ((string-prefix-p "AUTH=" keyword)
               ;; Pre-standard AUTH=MECH syntax; used only if AUTH is absent.
               (unless (assoc "AUTH" extensions :test #'string=)
                 (push (cons "AUTH" (mapcar #'string-upcase
                                            (cons (subseq keyword 5) (rest words))))
                       extensions)))
              (t
               (setf extensions (remove keyword extensions :key #'car :test #'string=))
               (push (cons keyword (if (string= keyword "AUTH")
                                       (mapcar #'string-upcase (rest words))
                                       (rest words)))
                     extensions)))))
    (nreverse extensions)))

(defun %ehlo (connection &key (allow-helo t))
  (let* ((line (format nil "EHLO ~a" (connection-local-name connection)))
         (reply (command connection line :expect nil)))
    (cond ((= (reply-class reply) 2)
           (setf (%extensions connection) (%parse-extensions (rest (reply-lines reply)))
                 (connection-esmtp-p connection) t))
          ((and allow-helo (member (reply-code reply) '(500 502)))
           (command connection (format nil "HELO ~a" (connection-local-name connection)))
           (setf (%extensions connection) '()
                 (connection-esmtp-p connection) nil))
          (t (check-reply connection reply line '(2))))))

(defun %starttls (connection &key opportunistic)
  "Upgrade CONNECTION to TLS. If OPPORTUNISTIC, a refusal (a reply other
than 220, the session being otherwise unchanged) returns NIL and the
session goes on in plaintext (RFC 3207 section 4.1 leaves this to the
client)."
  (let ((reply (command connection "STARTTLS" :expect nil)))
    (unless (= (reply-code reply) 220)
      (if (and opportunistic (/= (reply-code reply) 421))
          (return-from %starttls nil)
          (check-reply connection reply "STARTTLS" '(220)))))
  ;; Anything already received was sent before the handshake and would be
  ;; read as if it came over TLS (CVE-2011-0411 style injection).
  (when (with-io (connection "checking for injected data") (listen (%stream connection)))
    (setf (connection-state connection) :broken)
    (error 'smtp-protocol-error
           :message "The server sent data after its STARTTLS reply; refusing to continue"))
  (%start-tls-session connection)
  (setf (%extensions connection) '())
  (%ehlo connection :allow-helo nil))

(defun %default-local-name (connection)
  (let ((host (ignore-errors (usocket:get-host-name))))
    (or (and host (find #\. host) (ignore-errors (domain-to-ascii host)))
        (let ((address (ignore-errors (usocket:get-local-address (%socket connection)))))
          (cond ((and (vectorp address) (= (length address) 4))
                 (format nil "[~a]" (usocket:vector-quad-to-dotted-quad address)))
                ((and (vectorp address) (= (length address) 16))
                 (format nil "[IPv6:~a]" (usocket:vector-to-ipv6-host address)))
                (t "[127.0.0.1]"))))))

(defun open-connection (host &key port (tls :starttls) credentials auth-mechanism
                               (verify t) ca-file tls-hostname
                               client-certificate client-key client-key-password
                               local-name (connect-timeout 30) (timeout 300) (data-timeout 600)
                               allow-insecure-auth (trace *trace*) (tls-backend *tls-backend*))
  "Connect to the SMTP server HOST and return a CONNECTION ready for mail.

TLS is :STARTTLS (the default; port 587; fails if the server does not offer
STARTTLS), :IMPLICIT (port 465), :OPPORTUNISTIC (STARTTLS when offered,
otherwise plaintext; port 25) or :NONE (port 25).

Certificates are verified against the system trust store, or CA-FILE, and
must match TLS-HOSTNAME (default HOST). VERIFY NIL disables verification,
which should only be done for testing. VERIFY may instead be a function of
the TLS backend and the TLS stream, called after the handshake in place of
the usual checks; it signals an error to reject the server (DANE uses this).
TLS-HOSTNAME is still sent as the server name (SNI). CLIENT-CERTIFICATE and CLIENT-KEY
are PEM files for TLS client authentication.

CREDENTIALS (see MAKE-CREDENTIALS, or a plist of its arguments) authenticate
after TLS; AUTH-MECHANISM forces :PLAIN, :LOGIN, :XOAUTH2 or :OAUTHBEARER.
Credentials are never sent over an unencrypted connection unless
ALLOW-INSECURE-AUTH is true.

CONNECT-TIMEOUT bounds connecting, TIMEOUT every other read or write, and
DATA-TIMEOUT the wait for the server to accept the message. LOCAL-NAME is
the name sent with EHLO (default: this host's name, or its address).
TRACE overrides *TRACE*. TLS-BACKEND chooses the TLS implementation,
:OPENSSL or :PURE-TLS (see *TLS-BACKEND*).

An IP address is verified against the certificate's IP address entries;
pass the server's name as TLS-HOSTNAME when its certificate names it
instead."
  (check-type host string)
  (check-type tls (member :starttls :implicit :opportunistic :none))
  (let* ((port (or port (ecase tls (:starttls 587) (:implicit 465) ((:opportunistic :none) 25))))
         (host (%normalize-host host))
         (wire-host (if (%ip-literal-p host) host (domain-to-ascii host)))
         (tls-hostname (and tls-hostname (%normalize-host tls-hostname)))
         ;; Resolve the backend now, so a missing one is a configuration
         ;; error rather than a failure in the middle of the conversation.
         (tls-backend (if (eq tls :none) tls-backend (resolve-tls-backend tls-backend)))
         (connection (make-instance 'connection
                                    :host wire-host :port port
                                    :local-name local-name
                                    :timeout timeout :data-timeout data-timeout
                                    :tls-hostname (cond ((null tls-hostname) wire-host)
                                                        ((%ip-literal-p tls-hostname) tls-hostname)
                                                        (t (domain-to-ascii tls-hostname)))
                                    :verify verify :ca-file ca-file
                                    :client-certificate client-certificate
                                    :client-key client-key
                                    :client-key-password client-key-password
                                    :allow-insecure-auth allow-insecure-auth
                                    :tls-backend tls-backend
                                    :trace trace))
         (ok nil))
    (when local-name
      (setf (connection-local-name connection)
            (or (ignore-errors
                 (if (%address-literal-p local-name)
                     (progn (%validate-address-literal local-name local-name) local-name)
                     (domain-to-ascii local-name)))
                (error 'mail-format-error :message (format nil "Invalid :local-name ~s" local-name)))))
    (unwind-protect
         (progn
           (%connect connection wire-host port connect-timeout)
           (unless local-name
             (setf (connection-local-name connection) (%default-local-name connection)))
           (when (eq tls :implicit)
             (%start-tls-session connection))
           (let ((greeting (read-reply connection)))
             (setf (connection-greeting connection) greeting)
             (check-reply connection greeting "connection greeting" '(220)))
           (%ehlo connection)
           (when (and (member tls '(:starttls :opportunistic))
                      (not (connection-tls-p connection)))
             (cond ((nth-value 1 (connection-extension connection "STARTTLS"))
                    (%starttls connection :opportunistic (eq tls :opportunistic)))
                   ((eq tls :starttls)
                    (error 'smtp-unsupported-extension
                           :name "STARTTLS"
                           :message "TLS is required; use :tls :opportunistic or :none to allow plaintext"))))
           (when credentials
             (authenticate connection credentials :mechanism auth-mechanism))
           (setf ok t)
           connection)
      (unless ok
        (close-connection connection)))))

(defun close-connection (connection &key (quit t))
  "Close CONNECTION, first sending QUIT if it is healthy and QUIT is true.
Errors while quitting are ignored. Closing a closed connection does nothing."
  (when (and quit (eq (connection-state connection) :open))
    (handler-case (command connection "QUIT" :expect nil
                                              :timeout (min 10 (or (connection-timeout connection) 10)))
      (smtp-error () nil)))
  (let ((stream (%stream connection))
        (socket (%socket connection)))
    (setf (connection-state connection) :closed
          (%stream connection) nil
          (%socket connection) nil)
    (when stream (ignore-errors (close stream :abort t)))
    (when socket (ignore-errors (usocket:socket-close socket))))
  nil)

(defmacro with-connection ((var host &rest options) &body body)
  "Evaluate BODY with VAR bound to a connection opened with OPEN-CONNECTION,
closing it afterwards."
  `(let ((,var (open-connection ,host ,@options)))
     (unwind-protect (progn ,@body)
       (close-connection ,var))))

(defun noop (connection)
  "Send NOOP, for example to check that a pooled connection is still alive."
  (command connection "NOOP"))

(defun rset (connection)
  "Abort any mail transaction in progress."
  (prog1 (command connection "RSET")
    (setf (%in-transaction connection) nil)))
