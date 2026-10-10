;;; tls.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; The interface between connections and TLS implementations. The smtp
;;; system adds an OpenSSL backend (via cl+ssl); smtp/pure-tls adds one
;;; written entirely in Lisp (via pure-tls). Either, or both, may be loaded.

(in-package #:smtp)

(defvar *tls-backend* nil
  "The TLS implementation new connections use: :OPENSSL (loaded by the smtp
system) or :PURE-TLS (loaded by smtp/pure-tls). NIL means OpenSSL if it is
loaded, otherwise whichever backend is.")

(defvar *tls-backends* '()
  "The names of the loaded TLS backends.")

(defvar *tls-condition-types* '()
  "Condition types of the loaded TLS implementations. During I/O they are
translated to SMTP-CONNECTION-ERROR.")

(defvar *random-bytes-function* nil
  "A function of a count returning that many octets from a CSPRNG, supplied
by a TLS backend. Without one, /dev/urandom is read.")

(defun register-tls-backend (name &key condition-types random-bytes)
  "Make backend NAME available. Called when a backend's system is loaded."
  (pushnew name *tls-backends*)
  (dolist (type condition-types) (pushnew type *tls-condition-types* :test #'equal))
  (when (and random-bytes (null *random-bytes-function*))
    (setf *random-bytes-function* random-bytes))
  name)

(defun resolve-tls-backend (requested)
  (cond ((null *tls-backends*)
         (error 'smtp-tls-error
                :message "No TLS backend is loaded; load the smtp or smtp/pure-tls system"))
        ((null requested)
         (if (member :openssl *tls-backends*) :openssl (first *tls-backends*)))
        ((member requested *tls-backends*) requested)
        (t (error 'smtp-tls-error
                  :message (format nil "The TLS backend ~s is not loaded (loaded: ~{~s~^, ~})"
                                   requested *tls-backends*)))))

(defgeneric start-tls (backend stream &key hostname verify ca-file
                                        client-certificate client-key client-key-password
                                        timeout)
  (:documentation "Perform a TLS client handshake over the octet STREAM and
return the encrypted stream. When VERIFY is true the server's certificate
chain must be verified against the system trust store or CA-FILE, and the
certificate must match HOSTNAME, a DNS name or an IP address literal.
Failures are signalled as SMTP-TLS-ERROR, or SMTP-TIMEOUT when the
handshake takes longer than TIMEOUT seconds."))

(defun tls-condition-p (condition)
  (some (lambda (type) (typep condition type)) *tls-condition-types*))

(defun random-octets (n)
  "N octets from a cryptographically secure source."
  (cond (*random-bytes-function*
         (funcall *random-bytes-function* n))
        ((probe-file "/dev/urandom")
         (with-open-file (in "/dev/urandom" :element-type 'octet)
           (let ((octets (make-array n :element-type 'octet)))
             (unless (= n (read-sequence octets in))
               (error 'smtp-error :message "Short read from /dev/urandom"))
             octets)))
        (t (error 'smtp-error :message "No secure random source is available; load a TLS backend"))))
