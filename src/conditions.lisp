;;; conditions.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp)

(define-condition smtp-error (error)
  ((message :initarg :message :initform nil :reader smtp-error-message))
  (:report (lambda (c s)
             (format s "~a" (or (smtp-error-message c) (type-of c)))))
  (:documentation "The root of every condition this library signals."))

;;; Problems with a message or address, found before anything is sent.

(define-condition mail-format-error (smtp-error) ()
  (:documentation "A message, address or header cannot be represented safely."))

(define-condition invalid-address (mail-format-error)
  ((address :initarg :address :initform nil :reader invalid-address-address))
  (:report (lambda (c s)
             (format s "Invalid email address ~s: ~a"
                     (invalid-address-address c) (smtp-error-message c)))))

(define-condition invalid-header (mail-format-error)
  ((name :initarg :name :initform nil :reader invalid-header-name))
  (:report (lambda (c s)
             (format s "Invalid header ~@[~s~]: ~a"
                     (invalid-header-name c) (smtp-error-message c)))))

;;; Transport problems.

(define-condition smtp-connection-error (smtp-error)
  ((cause :initarg :cause :initform nil :reader smtp-error-cause))
  (:report (lambda (c s)
             (format s "~a~@[: ~a~]" (smtp-error-message c) (smtp-error-cause c)))))

(define-condition smtp-connection-closed (smtp-connection-error) ()
  (:default-initargs :message "The server closed the connection"))

(define-condition smtp-timeout (smtp-connection-error)
  ((operation :initarg :operation :initform nil :reader smtp-timeout-operation)
   (seconds :initarg :seconds :initform nil :reader smtp-timeout-seconds))
  (:report (lambda (c s)
             (format s "Timed out after ~a seconds while ~a"
                     (smtp-timeout-seconds c) (smtp-timeout-operation c)))))

(define-condition smtp-tls-error (smtp-connection-error) ()
  (:documentation "TLS could not be established, including failed certificate
or hostname verification."))

;;; Protocol problems.

(define-condition smtp-protocol-error (smtp-error) ()
  (:documentation "The server violated the protocol, for example with a
malformed reply."))

(define-condition smtp-reply-error (smtp-error)
  ((reply :initarg :reply :initform nil :reader smtp-error-reply)
   (command :initarg :command :initform nil :reader smtp-error-command))
  (:report (lambda (c s)
             (let ((reply (smtp-error-reply c)))
               (format s "~@[~a: ~]server replied ~:[nothing~;~:*~a~]~@[ to ~a~]"
                       (smtp-error-message c)
                       (and reply (format nil "~d ~a" (reply-code reply)
                                          (reply-text reply)))
                       (smtp-error-command c)))))
  (:documentation "The server answered a command with an unexpected reply."))

(define-condition smtp-transient-error (smtp-reply-error) ()
  (:documentation "A 4xx reply: the operation may succeed if retried later."))

(define-condition smtp-permanent-error (smtp-reply-error) ()
  (:documentation "A 5xx reply: retrying the same operation will not help."))

(define-condition smtp-authentication-failed (smtp-reply-error)
  ((mechanism :initarg :mechanism :initform nil :reader smtp-authentication-mechanism)
   (detail :initarg :detail :initform nil :reader smtp-authentication-detail))
  (:report (lambda (c s)
             (format s "Authentication~@[ with ~a~] failed~@[: ~d ~a~]~@[ (~a)~]"
                     (smtp-authentication-mechanism c)
                     (and (smtp-error-reply c) (reply-code (smtp-error-reply c)))
                     (and (smtp-error-reply c) (reply-text (smtp-error-reply c)))
                     (smtp-authentication-detail c)))))

(define-condition smtp-insecure-authentication (smtp-error) ()
  (:default-initargs
   :message "Refusing to send credentials over an unencrypted connection; use TLS or pass :allow-insecure-auth t")
  (:documentation "Credentials would have been sent without TLS."))

(define-condition smtp-unsupported-extension (smtp-error)
  ((name :initarg :name :initform nil :reader smtp-unsupported-extension-name))
  (:report (lambda (c s)
             (format s "The server does not support ~a~@[: ~a~]"
                     (smtp-unsupported-extension-name c) (smtp-error-message c)))))

(define-condition smtp-message-too-large (smtp-error)
  ((size :initarg :size :reader smtp-message-size)
   (limit :initarg :limit :reader smtp-message-limit))
  (:report (lambda (c s)
             (format s "The message is ~:d octets but the server accepts at most ~:d"
                     (smtp-message-size c) (smtp-message-limit c)))))

(define-condition smtp-recipients-rejected (smtp-error)
  ((accepted :initarg :accepted :initform nil :reader smtp-recipients-rejected-accepted)
   (rejected :initarg :rejected :initform nil :reader smtp-recipients-rejected-rejected))
  (:report (lambda (c s)
             (format s "The server rejected ~d recipient~:p~{~&  ~a~}~@[~&(~d accepted)~]"
                     (length (smtp-recipients-rejected-rejected c))
                     (mapcar (lambda (r)
                               (format nil "~a: ~d ~a" (car r) (reply-code (cdr r))
                                       (reply-text (cdr r))))
                             (smtp-recipients-rejected-rejected c))
                     (let ((n (length (smtp-recipients-rejected-accepted c))))
                       (and (plusp n) n)))))
  (:documentation "Some or all recipients were refused. REJECTED is an alist of
(address . reply). When some were accepted, the SEND-TO-ACCEPTED restart
delivers the message to them."))
