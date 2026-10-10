;;; tls-openssl.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; The OpenSSL TLS backend, through cl+ssl.
;;;
;;; Certificate and name verification are done by OpenSSL inside the
;;; handshake: SSL_VERIFY_PEER checks the chain, and X509_VERIFY_PARAM_set1_host
;;; (or _set1_ip_asc for an address) makes a mismatch a verification failure.
;;; cl+ssl's own after-the-fact hostname check is not used; it calls
;;; functions OpenSSL 4 removed.

(in-package #:smtp)

(defconstant +tls-1.2+ #x0303)
(defconstant +x509-check-flag-no-partial-wildcards+ 4)
(defconstant +x509-v-ok+ 0)
(defconstant +x509-v-err-hostname-mismatch+ 62)
(defconstant +x509-v-err-ip-address-mismatch+ 64)

(cffi:defcfun ("SSL_CTX_get0_param" %ssl-ctx-get0-param) :pointer
  (ctx :pointer))

(cffi:defcfun ("X509_VERIFY_PARAM_set1_host" %x509-verify-param-set1-host) :int
  (param :pointer) (name :string) (namelen :size))

(cffi:defcfun ("X509_VERIFY_PARAM_set1_ip_asc" %x509-verify-param-set1-ip-asc) :int
  (param :pointer) (address :string))

(cffi:defcfun ("X509_VERIFY_PARAM_set_hostflags" %x509-verify-param-set-hostflags) :void
  (param :pointer) (flags :unsigned-int))

(defun %openssl-context (hostname verify ca-file)
  (when (and ca-file (not (probe-file ca-file)))
    (error 'smtp-tls-error :message (format nil "The CA file ~a does not exist" ca-file)))
  (let ((ctx (cl+ssl:make-context :min-proto-version +tls-1.2+
                                  :verify-mode (if verify
                                                   cl+ssl:+ssl-verify-peer+
                                                   cl+ssl:+ssl-verify-none+)
                                  :verify-location (if ca-file (namestring ca-file) :default))))
    (when verify
      (let ((param (%ssl-ctx-get0-param ctx)))
        (%x509-verify-param-set-hostflags param +x509-check-flag-no-partial-wildcards+)
        (unless (= 1 (if (%ip-literal-p hostname)
                         (%x509-verify-param-set1-ip-asc param hostname)
                         (%x509-verify-param-set1-host param hostname 0)))
          (cl+ssl:ssl-ctx-free ctx)
          (error 'smtp-tls-error :message (format nil "Cannot verify the name ~a" hostname)))))
    ctx))

(defun %handshake-verify-code (e)
  "The X.509 verification result recorded on a failed handshake, if any."
  (let ((note (ignore-errors (cl+ssl::ssl-error-ssl-verify-error e))))
    (and note
         (let ((colon (position #\: note)))
           (and colon (parse-integer note :start (1+ colon) :junk-allowed t))))))

(defun %openssl-verify-error (hostname code)
  (error 'smtp-tls-error
         :message (if (member code (list +x509-v-err-hostname-mismatch+
                                         +x509-v-err-ip-address-mismatch+))
                      (format nil "The server's certificate does not match ~a" hostname)
                      (format nil "The server's certificate for ~a could not be verified (~(~a~))"
                              hostname (or (cl+ssl::ssl-verify-error-keyword code) code)))))

(defmethod start-tls ((backend (eql :openssl)) stream
                      &key hostname verify ca-file client-certificate client-key
                        client-key-password timeout)
  (declare (ignore timeout))
  (let ((tls
          (handler-case
              (cl+ssl:with-global-context ((%openssl-context hostname verify ca-file)
                                           :auto-free-p t)
                (cl+ssl:make-ssl-client-stream
                 stream
                 ;; For SNI only (never an address); verification is in the context.
                 :hostname (and (not (%ip-literal-p hostname)) hostname)
                 :verify nil
                 :certificate (and client-certificate (namestring client-certificate))
                 :key (and client-key (namestring client-key))
                 :password client-key-password))
            (cl+ssl:ssl-error-verify (e)
              (%openssl-verify-error hostname (cl+ssl::ssl-error-code e)))
            (cl+ssl::ssl-error-ssl (e)
              (let ((code (%handshake-verify-code e)))
                (if code
                    (%openssl-verify-error hostname code)
                    (error 'smtp-tls-error :message "The TLS handshake failed" :cause e))))
            (cl+ssl::cl+ssl-error (e)
              (error 'smtp-tls-error :message "The TLS handshake failed" :cause e)))))
    (when verify
      ;; Belt and braces: the handshake would have failed otherwise.
      (let ((result (cl+ssl::ssl-get-verify-result (cl+ssl::ssl-stream-handle tls))))
        (unless (eql result +x509-v-ok+)
          (ignore-errors (close tls :abort t))
          (%openssl-verify-error hostname result))))
    tls))

(register-tls-backend :openssl
                      :condition-types '(cl+ssl::cl+ssl-error)
                      :random-bytes #'cl+ssl:random-bytes)
