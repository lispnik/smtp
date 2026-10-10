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
;;; Session resumption is disabled in both directions. pure-tls keeps one
;;; process-wide ticket cache keyed by host name alone, and a resumed TLS 1.3
;;; handshake carries no certificate, so a connection could inherit a session
;;; established under different trust settings (another CA file, another
;;; port, or verification turned off). Each handshake here sees an empty
;;; cache, and the stream is left unable to mint tickets from the
;;; NewSessionTicket messages servers send after the handshake, so nothing is
;;; added to the shared cache for other pure-tls users either.

(in-package #:smtp)

;;; Contexts hold the parsed trust store; building one parses the whole
;;; system CA bundle, so they are kept per (verify, CA file) configuration.

(defvar *pure-tls-contexts* (make-hash-table :test 'equal))
(defvar *pure-tls-contexts-lock* (bt:make-lock "smtp pure-tls contexts"))

(defun %pure-tls-context (verify ca-file)
  (let* ((path (and ca-file (namestring (truename ca-file))))
         (key (list (and verify t) path (and path (file-write-date path)))))
    (bt:with-lock-held (*pure-tls-contexts-lock*)
      (or (gethash key *pure-tls-contexts*)
          (setf (gethash key *pure-tls-contexts*)
                (handler-case
                    (pure-tls:make-tls-context
                     :verify-mode (if verify pure-tls:+verify-required+ pure-tls:+verify-none+)
                     :ca-file path)
                  (pure-tls:tls-error (e)
                    ;; A local configuration problem, before any server contact.
                    (error 'smtp-tls-error
                           :message (format nil "The CA file ~a cannot be used: ~a" ca-file e)))))))))

(defun %pure-tls-mismatch-p (e)
  (and (typep e 'pure-tls:tls-verification-error)
       (or (pure-tls::tls-verification-error-hostname e)
           (search "does not match" (princ-to-string e)))
       t))

(defun %pure-tls-error (e hostname)
  (error 'smtp-tls-error
         :message (if (%pure-tls-mismatch-p e)
                      (format nil "The server's certificate does not match ~a" hostname)
                      (format nil "The server's certificate for ~a could not be verified (~a)"
                              hostname e))))

(defun %forget-resumption-secret (tls)
  ;; Without it pure-tls cannot turn a NewSessionTicket into a cache entry.
  (setf (pure-tls::client-handshake-resumption-master-secret (pure-tls::tls-stream-handshake tls))
        nil))

(defmethod start-tls ((backend (eql :pure-tls)) stream
                      &key hostname verify ca-file client-certificate client-key
                        client-key-password timeout)
  (declare (ignore timeout))
  (when client-key-password
    (error 'smtp-tls-error :message "The pure-tls backend cannot use encrypted client keys"))
  (when (and ca-file (not (probe-file ca-file)))
    (error 'smtp-tls-error :message (format nil "The CA file ~a does not exist" ca-file)))
  (let ((context (%pure-tls-context verify ca-file))
        (mode (if verify pure-tls:+verify-required+ pure-tls:+verify-none+))
        ;; An address must not be sent as SNI (RFC 6066), and pure-tls uses
        ;; its :hostname for both, so an address is checked after the handshake.
        (address (%ip-literal-p hostname)))
    (handler-case
        (let ((tls (let ((pure-tls:*session-ticket-cache* (make-hash-table :test 'equal)))
                     (pure-tls:make-tls-client-stream
                      stream
                      :hostname (and (not address) hostname)
                      :context context
                      :verify mode
                      :client-certificate (and client-certificate (namestring client-certificate))
                      :client-key (and client-key (namestring client-key))))))
          (%forget-resumption-secret tls)
          (when (and verify address)
            (handler-case (pure-tls:verify-hostname (pure-tls:tls-peer-certificate tls) hostname)
              (error (e)
                (ignore-errors (close tls :abort t))
                (error e))))
          tls)
      (pure-tls:tls-certificate-error (e) (%pure-tls-error e hostname))
      (pure-tls:tls-error (e)
        (error 'smtp-tls-error :message "The TLS handshake failed" :cause e)))))

(register-tls-backend :pure-tls
                      :condition-types '(pure-tls:tls-error)
                      :random-bytes #'pure-tls:random-bytes)
