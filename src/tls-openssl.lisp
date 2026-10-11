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

;;; Certificates for DANE (RFC 7672)

(cffi:defcfun ("SSL_get_peer_cert_chain" %ssl-get-peer-cert-chain) :pointer (ssl :pointer))
(cffi:defcfun ("OPENSSL_sk_num" %sk-num) :int (stack :pointer))
(cffi:defcfun ("OPENSSL_sk_value" %sk-value) :pointer (stack :pointer) (i :int))
(cffi:defcfun ("OPENSSL_sk_new_null" %sk-new-null) :pointer)
(cffi:defcfun ("OPENSSL_sk_push" %sk-push) :int (stack :pointer) (item :pointer))
(cffi:defcfun ("OPENSSL_sk_free" %sk-free) :void (stack :pointer))
(cffi:defcfun ("i2d_X509" %i2d-x509) :int (x509 :pointer) (out :pointer))
(cffi:defcfun ("d2i_X509" %d2i-x509) :pointer (x509 :pointer) (in :pointer) (length :long))
(cffi:defcfun ("X509_free" %x509-free) :void (x509 :pointer))
(cffi:defcfun ("X509_STORE_new" %x509-store-new) :pointer)
(cffi:defcfun ("X509_STORE_free" %x509-store-free) :void (store :pointer))
(cffi:defcfun ("X509_STORE_add_cert" %x509-store-add-cert) :int (store :pointer) (x509 :pointer))
(cffi:defcfun ("X509_STORE_CTX_new" %x509-store-ctx-new) :pointer)
(cffi:defcfun ("X509_STORE_CTX_free" %x509-store-ctx-free) :void (ctx :pointer))
(cffi:defcfun ("X509_STORE_CTX_init" %x509-store-ctx-init) :int
  (ctx :pointer) (store :pointer) (x509 :pointer) (chain :pointer))
(cffi:defcfun ("X509_STORE_CTX_get0_param" %x509-store-ctx-get0-param) :pointer (ctx :pointer))
(cffi:defcfun ("X509_STORE_CTX_set_purpose" %x509-store-ctx-set-purpose) :int (ctx :pointer) (purpose :int))
(cffi:defcfun ("X509_STORE_CTX_get_error" %x509-store-ctx-get-error) :int (ctx :pointer))
(cffi:defcfun ("X509_VERIFY_PARAM_set_flags" %x509-verify-param-set-flags) :int
  (param :pointer) (flags :unsigned-long))
(cffi:defcfun ("X509_VERIFY_PARAM_add1_host" %x509-verify-param-add1-host) :int
  (param :pointer) (name :string) (namelen :size))
(cffi:defcfun ("X509_verify_cert" %x509-verify-cert) :int (ctx :pointer))

(defconstant +x509-v-flag-partial-chain+ #x80000)
(defconstant +x509-purpose-ssl-server+ 2)

(defun %x509-der (x509)
  (let ((n (%i2d-x509 x509 (cffi:null-pointer))))
    (when (plusp n)
      (cffi:with-foreign-objects ((buffer :unsigned-char n) (out :pointer))
        (setf (cffi:mem-ref out :pointer) buffer)
        (%i2d-x509 x509 out)
        (let ((octets (make-array n :element-type 'octet)))
          (dotimes (i n octets)
            (setf (aref octets i) (cffi:mem-aref buffer :unsigned-char i))))))))

(defun %der-x509 (octets)
  (let ((n (length octets)))
    (cffi:with-foreign-objects ((buffer :unsigned-char n) (in :pointer))
      (dotimes (i n) (setf (cffi:mem-aref buffer :unsigned-char i) (aref octets i)))
      (setf (cffi:mem-ref in :pointer) buffer)
      (let ((x509 (%d2i-x509 (cffi:null-pointer) in n)))
        (when (cffi:null-pointer-p x509)
          (error 'smtp-tls-error :message "A certificate could not be decoded"))
        x509))))

(defmethod tls-peer-certificates ((backend (eql :openssl)) stream)
  (let ((chain (%ssl-get-peer-cert-chain (cl+ssl::ssl-stream-handle stream))))
    (unless (cffi:null-pointer-p chain)
      (loop for i below (%sk-num chain)
            for der = (%x509-der (%sk-value chain i))
            when der collect der))))

(defmethod tls-verify-chain ((backend (eql :openssl)) chain anchor &key hostnames)
  (let ((certs '()) (store (cffi:null-pointer)) (ctx (cffi:null-pointer))
        (untrusted (cffi:null-pointer)))
    (unwind-protect
         (let ((leaf (%der-x509 (first chain)))
               (ta (%der-x509 anchor)))
           (setf certs (list leaf ta)
                 store (%x509-store-new)
                 ctx (%x509-store-ctx-new)
                 untrusted (%sk-new-null))
           (%x509-store-add-cert store ta)
           (dolist (der (rest chain))
             (let ((x (%der-x509 der)))
               (push x certs)
               (%sk-push untrusted x)))
           (unless (= 1 (%x509-store-ctx-init ctx store leaf untrusted))
             (error 'smtp-tls-error :message "Cannot set up certificate verification"))
           (%x509-store-ctx-set-purpose ctx +x509-purpose-ssl-server+)
           (let ((param (%x509-store-ctx-get0-param ctx)))
             ;; The anchor need not be self-signed.
             (%x509-verify-param-set-flags param +x509-v-flag-partial-chain+)
             (%x509-verify-param-set-hostflags param +x509-check-flag-no-partial-wildcards+)
             (dolist (name hostnames)
               (%x509-verify-param-add1-host param name 0)))
           (unless (= 1 (%x509-verify-cert ctx))
             (let ((code (%x509-store-ctx-get-error ctx)))
               (error 'smtp-tls-error
                      :message (format nil "The server's certificate does not chain to the DANE trust anchor~
                                            ~@[ or match ~{~a~^, ~}~] (~(~a~))"
                                       hostnames (or (cl+ssl::ssl-verify-error-keyword code) code)))))
           t)
      (unless (cffi:null-pointer-p untrusted) (%sk-free untrusted))
      (unless (cffi:null-pointer-p ctx) (%x509-store-ctx-free ctx))
      (unless (cffi:null-pointer-p store) (%x509-store-free store))
      (dolist (x certs) (%x509-free x)))))

(register-tls-backend :openssl
                      :condition-types '(cl+ssl::cl+ssl-error)
                      :random-bytes #'cl+ssl:random-bytes)
