;;; auth.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; SMTP AUTH (RFC 4954) with SASL PLAIN (RFC 4616), LOGIN, XOAUTH2 and
;;; OAUTHBEARER (RFC 7628).

(in-package #:smtp)

(defclass credentials ()
  ((username :initarg :username :reader credentials-username)
   (password :initarg :password :initform nil :reader %password)
   (token :initarg :token :initform nil :reader %token)
   (authorization-identity :initarg :authorization-identity :initform nil
                           :reader credentials-authorization-identity)))

(defmethod print-object ((c credentials) stream)
  ;; Never print secrets.
  (print-unreadable-object (c stream :type t)
    (format stream "~s ~:[password~;OAuth 2.0 token~]" (credentials-username c) (%token c))))

(defun make-credentials (&key username password oauth2-token authorization-identity)
  "Credentials for AUTHENTICATE: USERNAME with either PASSWORD or an
OAUTH2-TOKEN (a bearer access token). PASSWORD and OAUTH2-TOKEN may be
functions of no arguments, called when the secret is needed, so it need not
be kept in memory."
  (check-type username string)
  (unless (alexandria:xor password oauth2-token)
    (error 'smtp-error :message "Credentials need exactly one of :password or :oauth2-token"))
  (make-instance 'credentials :username username :password password :token oauth2-token
                              :authorization-identity authorization-identity))

(defun ensure-credentials (designator)
  (etypecase designator
    (credentials designator)
    (list (apply #'make-credentials designator))))

(defun %secret (value what)
  (let ((secret (if (functionp value) (funcall value) value)))
    (unless (stringp secret)
      (error 'smtp-error :message (format nil "The ~a must be a string" what)))
    ;; NUL and SOH delimit SASL PLAIN and OAuth messages.
    (when (find-if (lambda (c) (or (line-break-char-p c) (member (char-code c) '(0 1)))) secret)
      (error 'smtp-error :message (format nil "The ~a contains NUL, SOH or a line break" what)))
    secret))

(defun %choose-mechanism (credentials offered requested)
  (let ((candidates (if (%token credentials)
                        '(:oauthbearer :xoauth2)
                        '(:plain :login))))
    (flet ((offered-p (mech) (member (symbol-name mech) offered :test #'string-equal)))
      (cond (requested
             (unless (member requested candidates)
               (error 'smtp-error
                      :message (format nil "Mechanism ~a cannot be used with these credentials"
                                       requested)))
             (unless (offered-p requested)
               (error 'smtp-unsupported-extension
                      :name (format nil "AUTH ~a" requested)
                      :message (format nil "the server offers ~{~a~^ ~}" offered)))
             requested)
            ((find-if #'offered-p candidates))
            (t (error 'smtp-unsupported-extension
                      :name "a usable authentication mechanism"
                      :message (format nil "the server offers ~{~a~^ ~}" offered)))))))

(defun %auth-command (connection line mechanism &key (initial (string-prefix-p "AUTH " line)))
  "Send a SASL line, tracing it with the secret part redacted."
  (send-command connection line
                :max-length 12288
                :trace-as (if initial
                              (format nil "AUTH ~a~:[~; [credentials redacted]~]"
                                      mechanism
                                      (find #\Space line :start 5))
                              "[credentials redacted]"))
  (read-reply connection))

(defun %auth-failed (connection reply mechanism &optional detail)
  (when (= (reply-code reply) 421)
    (setf (connection-state connection) :broken))
  (error 'smtp-authentication-failed :reply reply :mechanism mechanism :detail detail
                                     :command (format nil "AUTH ~a" mechanism)))

(defun %finish-auth (connection reply mechanism &key (abort-response ""))
  "Handle the final reply of an exchange. An OAuth server reports failure with
a 334 challenge carrying a JSON error, which the client acknowledges before
the server sends the real failure reply."
  (cond ((= (reply-code reply) 235) t)
        ((= (reply-code reply) 334)
         ;; Either an OAuth error challenge, or a challenge we did not expect:
         ;; answer it (with "*" to cancel, RFC 4954) so the session stays in step.
         (let* ((detail (and abort-response
                             (ignore-errors (utf8-string (base64-decode (reply-text reply))))))
                (final (%auth-command connection (or abort-response "*") mechanism :initial nil)))
           (when (= (reply-code final) 334)
             (setf (connection-state connection) :broken))
           (%auth-failed connection final mechanism detail)))
        (t (%auth-failed connection reply mechanism))))

(defun %sasl-plain (connection credentials)
  (let ((user (%secret (credentials-username credentials) "username"))
        (authz (let ((a (credentials-authorization-identity credentials)))
                 (if a (%secret a "authorization identity") "")))
        (password (%secret (%password credentials) "password")))
    (let* ((message (format nil "~a~c~a~c~a" authz (code-char 0) user (code-char 0) password))
           (encoded (base64-encode message))
           (reply (%auth-command connection (format nil "AUTH PLAIN ~a" encoded) "PLAIN")))
      (when (and (= (reply-code reply) 334) (zerop (length (reply-text reply))))
        ;; A server that ignores the initial response asks for it.
        (setf reply (%auth-command connection encoded "PLAIN" :initial nil)))
      (%finish-auth connection reply "PLAIN" :abort-response nil))))

(defun %sasl-login (connection credentials)
  (let ((user (%secret (credentials-username credentials) "username"))
        (password (%secret (%password credentials) "password")))
    (let ((reply (%auth-command connection "AUTH LOGIN" "LOGIN")))
      (unless (= (reply-code reply) 334) (%auth-failed connection reply "LOGIN"))
      (setf reply (%auth-command connection (base64-encode user) "LOGIN" :initial nil))
      (unless (= (reply-code reply) 334) (%auth-failed connection reply "LOGIN"))
      (setf reply (%auth-command connection (base64-encode password) "LOGIN" :initial nil))
      (%finish-auth connection reply "LOGIN" :abort-response nil))))

(defun %sasl-xoauth2 (connection credentials)
  (let* ((user (%secret (credentials-username credentials) "username"))
         (token (%secret (%token credentials) "OAuth 2.0 token"))
         (message (format nil "user=~a~cauth=Bearer ~a~c~c"
                          user (code-char 1) token (code-char 1) (code-char 1))))
    (%finish-auth connection
                  (%auth-command connection (format nil "AUTH XOAUTH2 ~a" (base64-encode message))
                                 "XOAUTH2")
                  "XOAUTH2"
                  :abort-response "")))

(defun %gs2-saslname (string)
  (with-output-to-string (s)
    (loop for c across string
          do (case c
               (#\, (write-string "=2C" s))
               (#\= (write-string "=3D" s))
               (t (write-char c s))))))

(defun %sasl-oauthbearer (connection credentials)
  (let* ((user (%secret (credentials-username credentials) "username"))
         (token (%secret (%token credentials) "OAuth 2.0 token"))
         (sep (code-char 1))
         (message (format nil "n,a=~a,~chost=~a~cport=~d~cauth=Bearer ~a~c~c"
                          (%gs2-saslname user) sep
                          (connection-host connection) sep
                          (connection-port connection) sep
                          token sep sep)))
    (%finish-auth connection
                  (%auth-command connection (format nil "AUTH OAUTHBEARER ~a" (base64-encode message))
                                 "OAUTHBEARER")
                  "OAUTHBEARER"
                  :abort-response (base64-encode (string sep)))))

(defun authenticate (connection credentials &key mechanism)
  "Authenticate with CREDENTIALS (see MAKE-CREDENTIALS, or a plist of its
arguments), choosing the strongest mechanism the server offers that suits
them unless MECHANISM is given. Refuses to run over plaintext unless the
connection allows insecure authentication. Signals
SMTP-AUTHENTICATION-FAILED if the server refuses."
  (let ((credentials (ensure-credentials credentials)))
    (unless (or (connection-tls-p connection) (%allow-insecure-auth connection))
      (error 'smtp-insecure-authentication))
    (multiple-value-bind (offered present) (connection-extension connection "AUTH")
      (unless present
        (error 'smtp-unsupported-extension :name "AUTH"
                                           :message "the server does not offer authentication"))
      (ecase (%choose-mechanism credentials offered mechanism)
        (:plain (%sasl-plain connection credentials))
        (:login (%sasl-login connection credentials))
        (:xoauth2 (%sasl-xoauth2 connection credentials))
        (:oauthbearer (%sasl-oauthbearer connection credentials)))
      (setf (connection-authenticated-p connection) t))))
