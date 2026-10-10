;;; tls-pure.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; The pure Lisp TLS backend, through pure-tls: TLS 1.3 only, no foreign
;;; libraries. pure-tls verifies the chain and the name (DNS or IP SAN)
;;; during the handshake, using the system trust store unless a CA file is
;;; given.
;;;
;;; Session resumption is disabled. pure-tls keeps one process-wide ticket
;;; cache keyed by host name alone, and a resumed TLS 1.3 handshake carries
;;; no certificate, so a connection could inherit a session established
;;; under different trust settings (another CA file, another port, or
;;; verification turned off). Each handshake here sees an empty cache and so
;;; always verifies the certificate itself.

(in-package #:smtp)

(defun %pure-tls-error (e hostname)
  (error 'smtp-tls-error
         :message (if (typep e 'pure-tls:tls-verification-error)
                      (let ((text (princ-to-string e)))
                        (if (search "does not match" text)
                            (format nil "The server's certificate does not match ~a" hostname)
                            (format nil "The server's certificate for ~a could not be verified (~a)"
                                    hostname text)))
                      (format nil "The server's certificate for ~a could not be verified (~a)"
                              hostname e))))

(defmethod start-tls ((backend (eql :pure-tls)) stream
                      &key hostname verify ca-file client-certificate client-key
                        client-key-password timeout)
  (when client-key-password
    (error 'smtp-tls-error :message "The pure-tls backend cannot use encrypted client keys"))
  (when (and ca-file (not (probe-file ca-file)))
    (error 'smtp-tls-error :message (format nil "The CA file ~a does not exist" ca-file)))
  (let ((mode (if verify pure-tls:+verify-required+ pure-tls:+verify-none+)))
    (handler-case
        (%call-with-deadline
         timeout
         (lambda ()
           (let ((pure-tls:*session-ticket-cache* (make-hash-table :test 'equal)))
             (pure-tls:make-tls-client-stream
              stream
              :hostname hostname
              :context (pure-tls:make-tls-context :verify-mode mode
                                                  :ca-file (and ca-file (namestring ca-file)))
              :verify mode
              :client-certificate (and client-certificate (namestring client-certificate))
              :client-key (and client-key (namestring client-key))))))
      #+sbcl
      (sb-sys:deadline-timeout ()
        (error 'smtp-timeout :operation "negotiating TLS" :seconds timeout))
      (smtp-error (e) (error e))
      (pure-tls:tls-certificate-error (e) (%pure-tls-error e hostname))
      (pure-tls:tls-error (e)
        (error 'smtp-tls-error :message "The TLS handshake failed" :cause e))
      (stream-error (e)
        (error 'smtp-tls-error :message "The connection failed during the TLS handshake"
                               :cause e)))))

(register-tls-backend :pure-tls
                      :condition-types '(pure-tls:tls-error)
                      :random-bytes #'pure-tls:random-bytes)
