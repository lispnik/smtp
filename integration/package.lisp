;;; package.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(defpackage #:smtp/integration
  (:use #:cl #:fiveam #:smtp)
  (:local-nicknames (#:jzon #:com.inuoe.jzon))
  (:export #:run-tests))

(in-package #:smtp/integration)

(def-suite :smtp/integration
  :description "The smtp client against real servers in Docker; see integration/compose.yaml.")

;;; Where the servers are. The defaults match integration/compose.yaml; the
;;; environment overrides them, for instance to reach Docker on another host.

(defun env (name default)
  (let ((v (uiop:getenv name)))
    (if (and v (plusp (length v))) v default)))

(defun env-port (name default)
  (parse-integer (env name (princ-to-string default))))

(defparameter *host* (env "SMTP_IT_HOST" "127.0.0.1"))
(defparameter *mailpit-smtp-port* (env-port "SMTP_IT_MAILPIT_SMTP" 11025))
(defparameter *mailpit-api-port* (env-port "SMTP_IT_MAILPIT_API" 18025))
(defparameter *postfix-smtp-port* (env-port "SMTP_IT_POSTFIX_SMTP" 10025))
(defparameter *postfix-submission-port* (env-port "SMTP_IT_POSTFIX_SUBMISSION" 10587))
(defparameter *postfix-smtps-port* (env-port "SMTP_IT_POSTFIX_SMTPS" 10465))

;;; The account in integration/postfix/Dockerfile.
(defparameter *credentials* '(:username "user@example.test" :password "secret"))

(defun certificate (name)
  (namestring (asdf:system-relative-pathname "smtp" (format nil "integration/certs/~a" name))))

(defun run-tests ()
  "Run the integration tests; true if they all passed."
  (unless (uiop:symbol-call :smtp/integration :mailpit-reachable-p)
    (error "Mailpit's API is not answering at ~a:~d; start the servers with make integration-up"
           *host* *mailpit-api-port*))
  (fiveam:run! :smtp/integration))
