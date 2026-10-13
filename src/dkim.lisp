;;; dkim.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; DKIM signing (RFC 6376) with rsa-sha256 and ed25519-sha256 (RFC 8463).

(defpackage #:smtp/dkim
  (:use #:cl)
  (:export #:dkim-signer
           #:dkim-key-error
           #:dkim-key-password-error
           #:make-dkim-signer
           #:dkim-signer-domain
           #:dkim-signer-selector
           #:dkim-signer-algorithm
           #:load-dkim-private-key
           #:dkim-dns-record
           #:dkim-sign
           #:canonicalize-header
           #:canonicalize-body
           #:split-message))

(in-package #:smtp/dkim)

;;; DER, just enough for private keys and public key records

(define-condition dkim-key-error (smtp:smtp-error) ()
  (:documentation "A DKIM private key cannot be read or used."))

(define-condition dkim-key-password-error (dkim-key-error) ()
  (:documentation "An encrypted DKIM private key's password is missing or wrong."))

(defun %key-error (format &rest args)
  (error 'dkim-key-error :message (apply #'format nil format args)))

(defun %der-read (octets start)
  "The tag, content start and content end of the DER element at START."
  (let* ((tag (aref octets start))
         (len-byte (aref octets (1+ start)))
         (pos (+ start 2))
         (len (if (< len-byte 128)
                  len-byte
                  (let ((n (logand len-byte 127)) (v 0))
                    (dotimes (i n) (setf v (+ (* v 256) (aref octets (+ pos i)))))
                    (incf pos n)
                    v))))
    (when (> (+ pos len) (length octets))
      (%key-error "Truncated DER data in private key"))
    (values tag pos (+ pos len))))

(defun %der-children (octets start end)
  (loop with pos = start
        while (< pos end)
        collect (multiple-value-bind (tag s e) (%der-read octets pos)
                  (setf pos e)
                  (list tag s e))))

(defun %der-integer (octets start end)
  (let ((v 0))
    (loop for i from start below end do (setf v (+ (* v 256) (aref octets i))))
    v))

(defun %der-length (n)
  (if (< n 128)
      (list n)
      (let ((bytes (loop for v = n then (ash v -8) while (plusp v) collect (logand v 255))))
        (cons (logior 128 (length bytes)) (nreverse bytes)))))

(defun %der (tag content)
  (concatenate '(vector (unsigned-byte 8)) (list tag) (%der-length (length content)) content))

(defun %der-encode-integer (n)
  (let ((bytes (or (nreverse (loop for v = n then (ash v -8) while (plusp v) collect (logand v 255)))
                   (list 0))))
    (when (>= (first bytes) 128) (push 0 bytes))
    (%der 2 bytes)))

;;; Keys

(defun %pem-decode (text)
  "The label, DER octets and headers (an alist) of the first PEM block in TEXT."
  (let* ((begin (search "-----BEGIN " text))
         (label-end (and begin (search "-----" text :start2 (+ begin 11))))
         (body-start (and label-end (+ label-end 5)))
         (end (and body-start (search "-----END " text :start2 body-start))))
    (unless end
      (%key-error "Not a PEM-encoded key"))
    (let ((headers '()) (body (make-string-output-stream)))
      ;; RFC 1421 headers (Proc-Type, DEK-Info) precede the base64 text.
      (dolist (line (uiop:split-string (subseq text body-start end) :separator '(#\Newline #\Return)))
        (let ((colon (position #\: line)))
          (if colon
              (push (cons (string-trim " " (subseq line 0 colon))
                          (string-trim " " (subseq line (1+ colon))))
                    headers)
              (write-string line body))))
      (values (subseq text (+ begin 11) label-end)
              (handler-case (smtp:base64-decode (get-output-stream-string body))
                (smtp:smtp-error () (%key-error "The PEM key is not valid base64")))
              (nreverse headers)))))

(defun %oid (dotted)
  "The DER content octets of the object identifier DOTTED (\"1.2.840...\")."
  (let* ((arcs (mapcar #'parse-integer (uiop:split-string dotted :separator ".")))
         (octets (list (+ (* 40 (first arcs)) (second arcs)))))
    (dolist (arc (cddr arcs))
      (let ((groups (loop for v = arc then (ash v -7)
                          collect (logand v 127)
                          while (> v 127))))
        (setf octets (append octets
                             (loop for (g . more) on (reverse groups)
                                   collect (if more (logior g 128) g))))))
    (coerce octets '(vector (unsigned-byte 8)))))

(defun %oid-string (octets)
  (let ((arcs '()) (v 0))
    (loop for o across octets
          do (setf v (+ (* v 128) (logand o 127)))
             (when (< o 128) (push v arcs) (setf v 0)))
    (setf arcs (nreverse arcs))
    (format nil "~d.~d~{.~d~}" (min 2 (floor (first arcs) 40))
            (- (first arcs) (* 40 (min 2 (floor (first arcs) 40)))) (rest arcs))))

(defparameter +oid-rsa+ (%oid "1.2.840.113549.1.1.1"))
(defparameter +oid-ed25519+ (%oid "1.3.101.112"))
(defparameter +oid-pbes2+ (%oid "1.2.840.113549.1.5.13"))
(defparameter +oid-pbkdf2+ (%oid "1.2.840.113549.1.5.12"))
(defparameter +oid-scrypt+ (%oid "1.3.6.1.4.1.11591.4.11"))

(defparameter *pbkdf2-prfs*
  (list (cons (%oid "1.2.840.113549.2.7") :sha1)
        (cons (%oid "1.2.840.113549.2.8") :sha224)
        (cons (%oid "1.2.840.113549.2.9") :sha256)
        (cons (%oid "1.2.840.113549.2.10") :sha384)
        (cons (%oid "1.2.840.113549.2.11") :sha512)))

(defparameter *key-ciphers*
  ;; (OID PEM-name ironclad-cipher key-length)
  (list (list (%oid "2.16.840.1.101.3.4.1.2") "AES-128-CBC" :aes 16)
        (list (%oid "2.16.840.1.101.3.4.1.22") "AES-192-CBC" :aes 24)
        (list (%oid "2.16.840.1.101.3.4.1.42") "AES-256-CBC" :aes 32)
        (list (%oid "1.2.840.113549.3.7") "DES-EDE3-CBC" :3des 24))
  "Ciphers for encrypted keys: those OpenSSL uses for PKCS #8 and
traditional encrypted keys.")

(defun %password-octets (password)
  (let ((p (if (functionp password) (funcall password) password)))
    (typecase p
      (null (error 'dkim-key-password-error
                   :message "The private key is encrypted; give its password with :password"))
      (string (babel:string-to-octets p :encoding :utf-8))
      ((vector (unsigned-byte 8)) (coerce p '(simple-array (unsigned-byte 8) (*))))
      (t (%key-error "The private key password must be a string or octet vector")))))

(defun %wrong-password ()
  (error 'dkim-key-password-error :message "The password for the private key is wrong"))

(defun %decrypt-key (cipher key iv data)
  "DATA decrypted with CIPHER in CBC mode, unpadded (PKCS #7), and checked to
be one whole DER structure. A wrong key almost always fails these checks."
  (let ((block (ironclad:block-length cipher)))
    (unless (and (plusp (length data)) (zerop (mod (length data) block)) (= (length iv) block))
      (%key-error "The encrypted private key is malformed"))
    (let ((out (make-array (length data) :element-type '(unsigned-byte 8))))
      (ironclad:decrypt (ironclad:make-cipher cipher :key key :mode :cbc :initialization-vector iv)
                        (coerce data '(simple-array (unsigned-byte 8) (*))) out)
      (let ((pad (aref out (1- (length out)))))
        (unless (and (<= 1 pad block)
                     (loop for i from (- (length out) pad) below (length out)
                           always (= pad (aref out i))))
          (%wrong-password))
        (let ((der (subseq out 0 (- (length out) pad))))
          (unless (ignore-errors
                   (multiple-value-bind (tag start end) (%der-read der 0)
                     (declare (ignore start))
                     (and (= tag #x30) (= end (length der)))))
            (%wrong-password))
          der)))))

(defun %element (der element)
  "The content octets of ELEMENT, a (tag start end) list."
  (subseq der (second element) (third element)))

(defun %decrypt-pkcs8 (der password)
  "The PrivateKeyInfo DER inside the EncryptedPrivateKeyInfo DER (RFC 5958, PBES2 of RFC 8018)."
  (handler-case
      (destructuring-bind ((atag as ae) (dtag ds de))
          (multiple-value-bind (tag start end) (%der-read der 0)
            (declare (ignore tag))
            (%der-children der start end))
        (declare (ignore atag))
        (unless (= dtag 4) (%key-error "Malformed encrypted private key"))
        (destructuring-bind (scheme params) (%der-children der as ae)
          (unless (equalp (%element der scheme) +oid-pbes2+)
            (%key-error "The private key is encrypted with an unsupported scheme (~a); ~
                         re-encrypt it with: openssl pkcs8 -topk8 -v2 aes-256-cbc"
                        (%oid-string (%element der scheme))))
          (destructuring-bind (kdf enc) (%der-children der (second params) (third params))
            (destructuring-bind (kdf-oid kdf-params) (%der-children der (second kdf) (third kdf))
              (destructuring-bind (cipher-oid iv) (%der-children der (second enc) (third enc))
                (let ((cipher (find (%element der cipher-oid) *key-ciphers* :key #'first :test #'equalp))
                      (fields (%der-children der (second kdf-params) (third kdf-params))))
                  (unless cipher
                    (%key-error "The private key is encrypted with an unsupported cipher (~a); ~
                                 use AES-128, AES-192 or AES-256 in CBC mode, or DES-EDE3-CBC"
                                (%oid-string (%element der cipher-oid))))
                  (flet ((int (e) (%der-integer der (second e) (third e))))
                    (let* ((password (%password-octets password))
                           (salt (%element der (first fields)))
                           (key-length (fourth cipher))
                           (key (cond ((equalp (%element der kdf-oid) +oid-pbkdf2+)
                                       (let* ((more (cddr fields))
                                              (prf-element (find #x30 more :key #'first))
                                              (prf (if prf-element
                                                       (cdr (assoc (%element der (first (%der-children der (second prf-element) (third prf-element))))
                                                                   *pbkdf2-prfs* :test #'equalp))
                                                       :sha1)))
                                         (unless prf (%key-error "The private key uses an unsupported PBKDF2 hash"))
                                         (ironclad:derive-key (ironclad:make-kdf :pbkdf2 :digest prf)
                                                              password salt (int (second fields)) key-length)))
                                      ((equalp (%element der kdf-oid) +oid-scrypt+)
                                       (destructuring-bind (n r p &rest rest) (rest fields)
                                         (declare (ignore rest))
                                         (ironclad:derive-key (ironclad:make-kdf :scrypt-kdf :n (int n) :r (int r) :p (int p))
                                                              password salt 1 key-length)))
                                      (t (%key-error "The private key uses an unsupported key derivation (~a)"
                                                     (%oid-string (%element der kdf-oid)))))))
                      (%decrypt-key (third cipher) key (%element der iv) (subseq der ds de))))))))))
    ;; Structural surprises in the outer layers: report them as a bad key.
    ((or type-error program-error) ()
      (%key-error "Malformed encrypted private key"))))

(defun %evp-bytes-to-key (password salt length)
  "OpenSSL's EVP_BytesToKey with MD5 and one iteration, for traditional PEM encryption."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (previous (make-array 0 :element-type '(unsigned-byte 8))))
    (loop while (< (length out) length)
          do (setf previous (ironclad:digest-sequence
                             :md5 (concatenate '(vector (unsigned-byte 8)) previous password salt)))
             (loop for o across previous do (vector-push-extend o out)))
    (subseq out 0 length)))

(defun %decrypt-traditional (der headers password)
  "DER decrypted by the RFC 1421 Proc-Type/DEK-Info headers OpenSSL writes."
  (let* ((dek (cdr (assoc "DEK-Info" headers :test #'string-equal)))
         (comma (and dek (position #\, dek)))
         (name (and comma (string-upcase (subseq dek 0 comma))))
         (cipher (find name *key-ciphers* :key #'second :test #'equal)))
    (unless comma (%key-error "The encrypted private key has no valid DEK-Info header"))
    (unless cipher
      (%key-error "The private key is encrypted with an unsupported cipher (~a); ~
                   use AES-128-CBC, AES-192-CBC, AES-256-CBC or DES-EDE3-CBC" name))
    (let ((iv (handler-case (ironclad:hex-string-to-byte-array (string-trim " " (subseq dek (1+ comma))))
                (error () (%key-error "The encrypted private key has a malformed IV")))))
      (when (< (length iv) 8) (%key-error "The encrypted private key has a malformed IV"))
      (%decrypt-key (third cipher)
                    (%evp-bytes-to-key (%password-octets password) (subseq iv 0 8) (fourth cipher))
                    iv der))))

(defun %rsa-key-from-pkcs1 (der start end)
  (let ((fields (%der-children der start end)))
    (unless (>= (length fields) 4) (%key-error "Malformed RSA private key"))
    (flet ((int (i) (destructuring-bind (tag s e) (nth i fields)
                      (declare (ignore tag))
                      (%der-integer der s e))))
      (list :rsa (ironclad:make-private-key :rsa :n (int 1) :d (int 3)) (int 1) (int 2)))))

(defun %parse-private-key (der)
  "A list (algorithm key n e) for RSA or (algorithm key) for Ed25519."
  (multiple-value-bind (tag start end) (%der-read der 0)
    (unless (= tag #x30) (%key-error "Malformed private key"))
    (let ((fields (%der-children der start end)))
      (if (and (>= (length fields) 3) (= (first (second fields)) #x30))
          ;; PKCS #8 PrivateKeyInfo
          (destructuring-bind ((vtag vs ve) (atag as ae) (ktag ks ke) &rest rest) fields
            (declare (ignore vtag vs ve atag ke rest))
            (let* ((alg (first (%der-children der as ae)))
                   (oid (subseq der (second alg) (third alg))))
              (unless (= ktag 4) (%key-error "Malformed PKCS #8 key"))
              (cond ((equalp oid +oid-rsa+)
                     (multiple-value-bind (itag is ie) (%der-read der ks)
                       (declare (ignore itag))
                       (%rsa-key-from-pkcs1 der is ie)))
                    ((equalp oid +oid-ed25519+)
                     (multiple-value-bind (itag is ie) (%der-read der ks)
                       (unless (and (= itag 4) (= (- ie is) 32))
                         (%key-error "Malformed Ed25519 key"))
                       (let ((seed (subseq der is ie)))
                         (list :ed25519
                               (ironclad:make-private-key
                                :ed25519 :x seed :y (ironclad:ed25519-public-key seed))))))
                    (t (%key-error "Unsupported key type; use RSA or Ed25519")))))
          ;; PKCS #1 RSAPrivateKey
          (%rsa-key-from-pkcs1 der start end)))))

(defun load-dkim-private-key (source &key password)
  "Read a PEM private key (PKCS #1 RSA, or PKCS #8 RSA or Ed25519) from SOURCE,
a pathname or a string holding the PEM text. Encrypted keys need PASSWORD: a
string (used as UTF-8), an octet vector, or a function returning either,
called only when the key is encrypted. Both PKCS #8 encryption (PBES2 with
PBKDF2 or scrypt) and OpenSSL's traditional Proc-Type/DEK-Info encryption
are read, with AES-128/192/256-CBC or DES-EDE3-CBC. Problems are signalled
as DKIM-KEY-ERROR, a missing or wrong password as DKIM-KEY-PASSWORD-ERROR.
Returns a list (algorithm key [n e])."
  (let ((text (if (and (stringp source) (search "-----BEGIN" source))
                  source
                  (handler-case (uiop:read-file-string source :external-format :latin-1)
                    (file-error (e)
                      (%key-error "Cannot read the private key ~a: ~a" source e))))))
    (multiple-value-bind (label der headers) (%pem-decode text)
      (%parse-private-key
       (cond ((string= label "ENCRYPTED PRIVATE KEY") (%decrypt-pkcs8 der password))
             ((search "ENCRYPTED" (or (cdr (assoc "Proc-Type" headers :test #'string-equal)) ""))
              (%decrypt-traditional der headers password))
             (t der))))))

;;; Signers

(defparameter *default-signed-headers*
  '("from" "sender" "reply-to" "subject" "date" "message-id" "to" "cc"
    "in-reply-to" "references" "mime-version" "content-type"
    "content-transfer-encoding" "list-unsubscribe" "list-unsubscribe-post")
  "Headers signed by default, when present.")

(defparameter *default-oversigned-headers*
  '("from" "sender" "reply-to" "subject" "date" "to" "cc" "message-id")
  "Headers signed once more than they occur, so that adding another instance
(or one where there was none) breaks the signature.")

(defclass dkim-signer ()
  ((domain :initarg :domain :reader dkim-signer-domain)
   (selector :initarg :selector :reader dkim-signer-selector)
   (algorithm :initarg :algorithm :reader dkim-signer-algorithm)
   (key :initarg :key :reader %key)
   (rsa-n :initarg :rsa-n :initform nil :reader %rsa-n)
   (rsa-e :initarg :rsa-e :initform nil :reader %rsa-e)
   (headers :initarg :headers :reader %headers)
   (oversign :initarg :oversign :reader %oversign)
   (header-canonicalization :initarg :header-canonicalization :reader %header-c)
   (body-canonicalization :initarg :body-canonicalization :reader %body-c)
   (expiration :initarg :expiration :reader %expiration)
   (identity :initarg :identity :reader %identity)))

(defmethod print-object ((s dkim-signer) stream)
  (print-unreadable-object (s stream :type t)
    (format stream "~a._domainkey.~a ~(~a~)" (dkim-signer-selector s) (dkim-signer-domain s)
            (dkim-signer-algorithm s))))

(defun %check-tag-value (value what)
  (unless (and (stringp value) (plusp (length value))
               (every (lambda (c) (and (< 32 (char-code c) 127) (not (find c ";=")))) value))
    (error 'smtp:smtp-error :message (format nil "Invalid DKIM ~a ~s" what value)))
  value)

(defun make-dkim-signer (&key domain selector private-key password
                           (headers *default-signed-headers*)
                           (oversign *default-oversigned-headers*)
                           (canonicalization '(:relaxed :relaxed))
                           expiration identity)
  "A DKIM signer for DOMAIN (the d= tag) with SELECTOR (s=), signing with
PRIVATE-KEY: a PEM pathname or string, with PASSWORD if it is encrypted
(see LOAD-DKIM-PRIVATE-KEY). RSA keys
give rsa-sha256, Ed25519 keys ed25519-sha256 (sign with both to support
verifiers that lack Ed25519; pass a list of signers to SEND-MESSAGE).

HEADERS are the header names signed when present; OVERSIGN names those
protected against being added. CANONICALIZATION is (header body), each
:RELAXED or :SIMPLE. EXPIRATION, in seconds, sets x=. IDENTITY sets i=."
  (%check-tag-value selector "selector")
  (dolist (name (append headers oversign))
    ;; A header field name (RFC 5322 ftext) that cannot end the h= tag.
    (unless (and (stringp name) (plusp (length name))
                 (every (lambda (c) (and (< 32 (char-code c) 127) (not (find c ":;")))) name))
      (error 'smtp:smtp-error :message (format nil "Invalid header name to sign ~s" name))))
  (let ((ascii-domain (smtp:domain-to-ascii domain)))
    (when identity
      (unless (and (stringp identity)
                   (every (lambda (c) (and (< 32 (char-code c) 127) (char/= c #\;))) identity))
        (error 'smtp:smtp-error :message (format nil "Invalid DKIM identity ~s" identity)))
      (let ((at (position #\@ identity)))
        (unless (and at (let ((d (string-downcase (subseq identity (1+ at)))))
                          (or (string= d ascii-domain)
                              (alexandria:ends-with-subseq (concatenate 'string "." ascii-domain) d))))
          (error 'smtp:smtp-error
                 :message "The DKIM identity must be in the signing domain or a subdomain"))))
    (destructuring-bind (header-c body-c) canonicalization
      (check-type header-c (member :relaxed :simple))
      (check-type body-c (member :relaxed :simple))
      (destructuring-bind (algorithm key &optional n e) (load-dkim-private-key private-key :password password)
        (when (and (eq algorithm :rsa) (< (integer-length n) 1024))
          (error 'smtp:smtp-error :message "RSA keys for DKIM must have at least 1024 bits (2048 recommended)"))
        (make-instance 'dkim-signer
                       :domain ascii-domain :selector selector
                       :algorithm (if (eq algorithm :rsa) :rsa-sha256 :ed25519-sha256)
                       :key key :rsa-n n :rsa-e e
                       :headers (mapcar #'string-downcase headers)
                       :oversign (mapcar #'string-downcase oversign)
                       :header-canonicalization header-c
                       :body-canonicalization body-c
                       :expiration expiration :identity identity)))))

(defun dkim-dns-record (signer)
  "The TXT record to publish at SELECTOR._domainkey.DOMAIN for SIGNER."
  (ecase (dkim-signer-algorithm signer)
    (:rsa-sha256
     (let* ((rsa-public (%der #x30 (concatenate '(vector (unsigned-byte 8))
                                                (%der-encode-integer (%rsa-n signer))
                                                (%der-encode-integer (%rsa-e signer)))))
            (spki (%der #x30 (concatenate '(vector (unsigned-byte 8))
                                          (%der #x30 (concatenate '(vector (unsigned-byte 8))
                                                                  (%der 6 +oid-rsa+)
                                                                  (%der 5 #())))
                                          (%der 3 (concatenate '(vector (unsigned-byte 8))
                                                               #(0) rsa-public))))))
       (format nil "v=DKIM1; k=rsa; p=~a" (smtp:base64-encode (coerce spki 'smtp::octets)))))
    (:ed25519-sha256
     (format nil "v=DKIM1; k=ed25519; p=~a"
             (smtp:base64-encode (ironclad:ed25519-key-y (%key signer)))))))

;;; Canonicalization (RFC 6376 section 3.4)

(defun %latin1 (octets &key (start 0) (end (length octets)))
  ;; Octets as characters one-for-one, so that UTF-8 survives untouched.
  (map 'string #'code-char (subseq octets start end)))

(defun %octets (string)
  (map 'smtp::octets #'char-code string))

(defun split-message (octets)
  "The header fields of OCTETS, a list of strings (each a raw field with its
continuation lines and final CRLF, one character per octet), and the start
of the body."
  (let* ((sep (search #(13 10 13 10) octets))
         (header-end (if sep (+ sep 2) (length octets)))
         (body-start (if sep (+ sep 4) (length octets)))
         (text (%latin1 octets :end header-end))
         (fields '()))
    (loop with start = 0
          while (< start (length text))
          do (let ((pos start))
               ;; A field ends at a CRLF not followed by whitespace.
               (loop for crlf = (search (coerce '(#\Return #\Linefeed) 'string) text :start2 pos)
                     do (cond ((null crlf) (setf pos (length text)) (return))
                              ((and (< (+ crlf 2) (length text))
                                    (member (char text (+ crlf 2)) '(#\Space #\Tab)))
                               (setf pos (+ crlf 2)))
                              (t (setf pos (+ crlf 2)) (return))))
               (push (subseq text start pos) fields)
               (setf start pos)))
    (values (nreverse fields) body-start)))

(defun %field-name (field)
  (string-downcase (string-right-trim '(#\Space #\Tab) (subseq field 0 (or (position #\: field) 0)))))

(defun %compress-wsp (string)
  (with-output-to-string (s)
    (let ((in-wsp nil))
      (loop for c across string
            do (if (member c '(#\Space #\Tab))
                   (setf in-wsp t)
                   (progn (when in-wsp (write-char #\Space s) (setf in-wsp nil))
                          (write-char c s))))
      (when in-wsp (write-char #\Space s)))))

(defun canonicalize-header (field method)
  "Canonicalize header FIELD (a raw field string ending in CRLF)."
  (ecase method
    (:simple field)
    (:relaxed
     (let* ((colon (position #\: field))
            (name (string-downcase (string-right-trim '(#\Space #\Tab) (subseq field 0 colon))))
            (value (remove #\Linefeed (remove #\Return (subseq field (1+ colon)))))
            (value (string-trim '(#\Space) (%compress-wsp value))))
       (format nil "~a:~a~c~c" name value #\Return #\Linefeed)))))

(defun canonicalize-body (octets start method)
  "The canonical body of OCTETS from START, as octets."
  (let* ((lines (smtp::split-lines (%latin1 octets :start start)))
         (lines (if (and lines (string= (car (last lines)) ""))
                    (butlast lines)
                    lines))
         (lines (ecase method
                  (:simple lines)
                  (:relaxed (mapcar (lambda (l)
                                      (string-right-trim '(#\Space) (%compress-wsp l)))
                                    lines))))
         (lines (let ((end (position "" lines :test-not #'string= :from-end t)))
                  (if end (subseq lines 0 (1+ end)) '()))))
    (%octets
     (if (and (null lines) (eq method :simple))
         (format nil "~c~c" #\Return #\Linefeed)
         (format nil "~{~a~c~c~}"
                 (loop for l in lines collect l collect #\Return collect #\Linefeed))))))

;;; Signing

(defparameter +sha256-digest-info+
  #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x01 #x05 #x00 #x04 #x20))

(defun %rsa-sign (signer digest)
  "RSASSA-PKCS1-v1_5 (RFC 8017 section 8.2) over the SHA-256 DIGEST."
  (let* ((n (%rsa-n signer))
         (k (ceiling (integer-length n) 8))
         (tlen (+ (length +sha256-digest-info+) (length digest)))
         (em (concatenate '(vector (unsigned-byte 8))
                          #(0 1)
                          (make-array (- k tlen 3) :initial-element #xff)
                          #(0)
                          +sha256-digest-info+
                          digest))
         (d (getf (ironclad:destructure-private-key (%key signer)) :d))
         (m (ironclad:octets-to-integer (coerce em 'smtp::octets)))
         ;; Blinding: the private-key operation works on m*r^e, a value
         ;; unrelated to the message, and r^-1 removes r afterwards.
         (r (loop for r = (+ 2 (ironclad:strong-random (- n 3)))
                  when (= 1 (gcd r n)) return r))
         (blinded (mod (* m (ironclad:expt-mod r (%rsa-e signer) n)) n))
         (s (mod (* (ironclad:expt-mod blinded d n) (%mod-inverse r n)) n)))
    (ironclad:integer-to-octets s :n-bits (* 8 k))))

(defun %mod-inverse (a n)
  "The inverse of A modulo N, which must be coprime."
  (let ((r0 n) (r1 (mod a n)) (t0 0) (t1 1))
    (loop until (zerop r1)
          do (let ((q (floor r0 r1)))
               (psetf r0 r1 r1 (- r0 (* q r1))
                      t0 t1 t1 (- t0 (* q t1)))))
    (mod t0 n)))

(defun %select-headers (fields names)
  "The fields to sign for header names NAMES, each name taking the last
unused instance (RFC 6376 section 5.4.2). Names with no instance left sign
nothing."
  (let ((used (make-hash-table :test 'eq)))
    (loop for name in names
          for field = (find-if (lambda (f) (and (not (gethash f used))
                                                (string= (%field-name f) name)))
                               fields :from-end t)
          when field
            do (setf (gethash field used) t)
            and collect field)))

(defun %chunk (string size)
  (loop for i from 0 below (length string) by size
        collect (subseq string i (min (length string) (+ i size)))))

(defun dkim-sign (signer octets &key (time (- (get-universal-time) #.(encode-universal-time 0 0 0 1 1 1970 0))))
  "OCTETS with a DKIM-Signature header field by SIGNER prepended. TIME is the
signing time in seconds since the Unix epoch."
  (multiple-value-bind (fields body-start) (split-message octets)
    (let* ((present (mapcar #'%field-name fields))
           (h-names (append (loop for name in (%headers signer)
                                  append (make-list (count name present :test #'string=)
                                                    :initial-element name))
                            ;; Absent headers are signed as empty, so they cannot be added.
                            (%oversign signer)))
           (h-names (or h-names (list "from")))
           (body-hash (ironclad:digest-sequence
                       :sha256 (canonicalize-body octets body-start (%body-c signer))))
           (value (format nil "v=1; a=~(~a~); c=~(~a/~a~); d=~a; s=~a; t=~d;~@[ x=~d;~]~@[ i=~a;~] h=~{~a~^:~}; bh=~a; b="
                          (dkim-signer-algorithm signer)
                          (%header-c signer) (%body-c signer)
                          (dkim-signer-domain signer) (dkim-signer-selector signer)
                          time
                          (and (%expiration signer) (+ time (%expiration signer)))
                          (%identity signer)
                          h-names
                          (smtp:base64-encode body-hash)))
           (unsigned (concatenate 'string (smtp::fold-header "DKIM-Signature" value)
                                  (coerce '(#\Return #\Linefeed) 'string)))
           (data (with-output-to-string (s)
                   (dolist (f (%select-headers fields h-names))
                     (write-string (canonicalize-header f (%header-c signer)) s))
                   (let ((c (canonicalize-header unsigned (%header-c signer))))
                     ;; The signature field itself is hashed without its CRLF.
                     (write-string c s :end (- (length c) 2)))))
           (digest (ironclad:digest-sequence :sha256 (%octets data)))
           (signature (ecase (dkim-signer-algorithm signer)
                        (:rsa-sha256 (%rsa-sign signer digest))
                        (:ed25519-sha256 (ironclad:sign-message (%key signer) digest))))
           (b (smtp:base64-encode signature))
           (header (format nil "~a~{~a~^~c~c ~}~c~c"
                           (subseq unsigned 0 (- (length unsigned) 2))
                           (loop for (chunk . more) on (%chunk b 64)
                                 collect chunk
                                 when more collect #\Return and collect #\Linefeed)
                           #\Return #\Linefeed)))
      (concatenate 'smtp::octets (%octets header) octets))))

(defmethod smtp:sign-message-octets ((signer dkim-signer) octets)
  (dkim-sign signer octets))
