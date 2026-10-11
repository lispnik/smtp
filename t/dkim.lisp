;;; dkim.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/dkim :in :smtp :description "DKIM signing.")
(in-suite :smtp/dkim)

(test relaxed-canonicalization-rfc6376-example
  ;; RFC 6376 section 3.4.6.
  (let ((message (octets (crlf "A: X" (format nil "B : Y~c" #\Tab) (format nil "~cZ  " #\Tab)
                               "" " C " (format nil "D ~c E" #\Tab) "" "" ""))))
    (multiple-value-bind (fields body-start) (smtp/dkim:split-message message)
      (is (equal (list (crlf "a:X" "") (crlf "b:Y Z" ""))
                 (mapcar (lambda (f) (smtp/dkim:canonicalize-header f :relaxed)) fields)))
      (is (string= (crlf " C" "D E" "")
                   (text (smtp/dkim:canonicalize-body message body-start :relaxed))))
      (is (string= (crlf " C " (format nil "D ~c E" #\Tab) "")
                   (text (smtp/dkim:canonicalize-body message body-start :simple)))))))

(test empty-body-canonicalization
  (let ((message (octets (crlf "A: X" "" ""))))
    (multiple-value-bind (fields start) (smtp/dkim:split-message message)
      (declare (ignore fields))
      (is (string= "" (text (smtp/dkim:canonicalize-body message start :relaxed))))
      (is (string= (crlf "" "") (text (smtp/dkim:canonicalize-body message start :simple)))))))

(defun dkim-tags (signed)
  "The tags of the DKIM-Signature at the top of SIGNED, as an alist."
  (let* ((fields (smtp/dkim:split-message signed))
         (field (first fields))
         (value (remove-if (lambda (c) (member c '(#\Return #\Linefeed #\Space #\Tab)))
                           (subseq field (1+ (position #\: field))))))
    (loop for tag in (uiop:split-string value :separator ";")
          for eq = (position #\= tag)
          when eq collect (cons (subseq tag 0 eq) (subseq tag (1+ eq))))))

(defun signed-data (signed tags)
  "Recompute the data a verifier hashes for the signature at the top of SIGNED."
  (multiple-value-bind (fields) (smtp/dkim:split-message signed)
    (let* ((signature-field (first fields))
           (others (rest fields))
           (method (if (search "relaxed/" (cdr (assoc "c" tags :test #'string=))) :relaxed :simple))
           (names (uiop:split-string (cdr (assoc "h" tags :test #'string=)) :separator ":"))
           (used '())
           (out (make-string-output-stream)))
      (dolist (name names)
        (let ((field (find-if (lambda (f)
                                (and (not (member f used))
                                     (string-equal name (subseq f 0 (position #\: f)))))
                              others :from-end t)))
          (when field
            (push field used)
            (write-string (smtp/dkim:canonicalize-header field method) out))))
      ;; The signature field with its b= value removed, without the final CRLF.
      (let* ((b (loop for pos = (search "b=" signature-field) then (search "b=" signature-field :start2 (1+ pos))
                      while pos
                      when (let ((prev (position-if-not (lambda (c) (member c '(#\Space #\Tab #\Return #\Linefeed)))
                                                        signature-field :end pos :from-end t)))
                             (and prev (char= (char signature-field prev) #\;)))
                        return pos))
             (stripped (concatenate 'string (subseq signature-field 0 (+ b 2))
                                    (coerce '(#\Return #\Linefeed) 'string)))
             (c (smtp/dkim:canonicalize-header stripped method)))
        (write-string c out :end (- (length c) 2)))
      (map '(vector (unsigned-byte 8)) #'char-code (get-output-stream-string out)))))

(defun openssl-available-p ()
  (ignore-errors (zerop (nth-value 2 (uiop:run-program '("openssl" "version") :ignore-error-status t)))))

(defun openssl-verifies-p (algorithm public-key data signature)
  "Verify SIGNATURE over DATA with the openssl command line tool."
  (uiop:with-temporary-file (:pathname data-file :type "bin" :element-type '(unsigned-byte 8)
                             :stream ds :direction :output)
    (write-sequence (if (eq algorithm :ed25519)
                        (ironclad:digest-sequence :sha256 data)
                        data)
                    ds)
    (finish-output ds)
    (uiop:with-temporary-file (:pathname sig-file :type "sig" :element-type '(unsigned-byte 8)
                               :stream ss :direction :output)
      (write-sequence signature ss)
      (finish-output ss)
      (let ((command (if (eq algorithm :ed25519)
                         (list "openssl" "pkeyutl" "-verify" "-pubin" "-inkey" (namestring public-key)
                               "-rawin" "-in" (namestring data-file) "-sigfile" (namestring sig-file))
                         (list "openssl" "dgst" "-sha256" "-verify" (namestring public-key)
                               "-signature" (namestring sig-file) (namestring data-file)))))
        (zerop (nth-value 2 (uiop:run-program command :ignore-error-status t
                                                      :output nil :error-output nil)))))))

(defparameter *test-message*
  (render-message (simple-message :text (format nil "Body  with   spaces  ~%~%~%")
                                  :date 3969000000 :message-id "fixed@example.com")))

(defun sign-test-message (signer)
  (smtp/dkim:dkim-sign signer *test-message* :time 1760000000))

(test rsa-signature-verifies
  (let* ((signer (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s2026"
                                             :private-key (fixture "dkim-rsa-pkcs1.pem")))
         (signed (sign-test-message signer))
         (tags (dkim-tags signed)))
    (is (string= "rsa-sha256" (cdr (assoc "a" tags :test #'string=))))
    (is (string= "relaxed/relaxed" (cdr (assoc "c" tags :test #'string=))))
    (is (string= "example.com" (cdr (assoc "d" tags :test #'string=))))
    (is (string= "1760000000" (cdr (assoc "t" tags :test #'string=))))
    ;; From is oversigned.
    (is (= 2 (count "from" (uiop:split-string (cdr (assoc "h" tags :test #'string=)) :separator ":")
                    :test #'string=)))
    ;; The body hash matches an independent computation of the relaxed body.
    (is (string= (base64-encode (ironclad:digest-sequence
                                 :sha256 (octets (crlf "Body with spaces" ""))))
                 (cdr (assoc "bh" tags :test #'string=))))
    (is (every (lambda (l) (<= (length l) 998)) (lines-of (text signed))))
    (if (openssl-available-p)
        (is-true (openssl-verifies-p :rsa (fixture "dkim-rsa-pub.pem") (signed-data signed tags)
                                     (base64-decode (cdr (assoc "b" tags :test #'string=)))))
        (skip "openssl is not installed"))))

(test pkcs1-and-pkcs8-keys-agree
  (let ((a (sign-test-message (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                          :private-key (fixture "dkim-rsa-pkcs1.pem"))))
        (b (sign-test-message (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                          :private-key (fixture "dkim-rsa-pkcs8.pem")))))
    (is (string= (cdr (assoc "b" (dkim-tags a) :test #'string=))
                 (cdr (assoc "b" (dkim-tags b) :test #'string=))))))

(test ed25519-signature-verifies
  (let* ((signer (smtp/dkim:make-dkim-signer :domain "example.com" :selector "ed"
                                             :private-key (fixture "dkim-ed25519.pem")))
         (signed (sign-test-message signer))
         (tags (dkim-tags signed)))
    (is (string= "ed25519-sha256" (cdr (assoc "a" tags :test #'string=))))
    (if (openssl-available-p)
        (is-true (openssl-verifies-p :ed25519 (fixture "dkim-ed25519-pub.pem")
                                     (signed-data signed tags)
                                     (base64-decode (cdr (assoc "b" tags :test #'string=)))))
        (skip "openssl is not installed"))))

(test tampering-breaks-the-signature
  (when (openssl-available-p)
    (let* ((signer (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                               :private-key (fixture "dkim-rsa-pkcs8.pem")))
           (signed (text (sign-test-message signer)))
           (pos (search "Subject: Hello" signed))
           (tampered (octets (concatenate 'string (subseq signed 0 pos) "Subject: Hellp"
                                          (subseq signed (+ pos 14)))))
           (tags (dkim-tags tampered)))
      (is-false (openssl-verifies-p :rsa (fixture "dkim-rsa-pub.pem") (signed-data tampered tags)
                                    (base64-decode (cdr (assoc "b" tags :test #'string=))))))))

(defun pem-body (path)
  (let ((text (uiop:read-file-string path)))
    (remove-if (lambda (c) (member c '(#\Return #\Newline)))
               (subseq text (+ 5 (search "-----" text :start2 5))
                       (search "-----END" text)))))

(test dns-records
  (let ((rsa (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                         :private-key (fixture "dkim-rsa-pkcs1.pem")))
        (ed (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                        :private-key (fixture "dkim-ed25519.pem"))))
    (is (string= (format nil "v=DKIM1; k=rsa; p=~a" (pem-body (fixture "dkim-rsa-pub.pem")))
                 (smtp/dkim:dkim-dns-record rsa)))
    ;; The Ed25519 record holds the raw key: the last 32 octets of the SPKI.
    (let ((spki (base64-decode (pem-body (fixture "dkim-ed25519-pub.pem")))))
      (is (string= (format nil "v=DKIM1; k=ed25519; p=~a" (base64-encode (subseq spki (- (length spki) 32))))
                   (smtp/dkim:dkim-dns-record ed))))))

(test signer-validation
  (signals smtp-error (smtp/dkim:make-dkim-signer :domain "example.com" :selector "bad;sel"
                                                  :private-key (fixture "dkim-ed25519.pem")))
  (signals smtp-error (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                  :identity "user@other.org"
                                                  :private-key (fixture "dkim-ed25519.pem")))
  (signals smtp-error (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                  :private-key "not a key")))

(test signing-over-the-wire
  (let ((signers (list (smtp/dkim:make-dkim-signer :domain "example.com" :selector "ed"
                                                   :private-key (fixture "dkim-ed25519.pem"))
                       (smtp/dkim:make-dkim-signer :domain "example.com" :selector "rsa"
                                                   :private-key (fixture "dkim-rsa-pkcs8.pem")))))
    (with-mock-server (port s (standard-server))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (send-message c (simple-message) :dkim signers))
      (let ((data (text (third (first (session-messages s))))))
        (is (= 2 (count-matches "DKIM-Signature:" data)))))))

(defun count-matches (needle haystack)
  (loop with start = 0
        for pos = (search needle haystack :start2 start)
        while pos count t do (setf start (1+ pos))))

(test dkim-identity-is-validated
  (signals smtp-error (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                  :identity "a;d=evil.com@example.com"
                                                  :private-key (fixture "dkim-ed25519.pem"))))

;;; Encrypted keys (fixtures made by generate.sh)

(defparameter *encrypted-keys*
  '(("dkim-rsa-pkcs8-aes256.pem" :rsa "dkim-test")
    ("dkim-rsa-pkcs8-aes128-sha1.pem" :rsa "pässwörd")
    ("dkim-rsa-pkcs8-aes192-sha512.pem" :rsa "dkim-test")
    ("dkim-rsa-pkcs8-scrypt.pem" :rsa "dkim-test")
    ("dkim-rsa-pkcs8-des3.pem" :rsa "dkim-test")
    ("dkim-ed25519-aes256.pem" :ed25519 "dkim-test")
    ("dkim-rsa-legacy-aes256.pem" :rsa "dkim-test")
    ("dkim-rsa-legacy-aes128.pem" :rsa "dkim-test")
    ("dkim-rsa-legacy-des3.pem" :rsa "dkim-test"))
  "(file algorithm password): PKCS #8 with PBKDF2 (several hashes) or scrypt,
and OpenSSL's traditional DEK-Info encryption.")

(defun signature-of (signed)
  (cdr (assoc "b" (dkim-tags signed) :test #'string=)))

(test encrypted-keys-sign
  (let ((plain (list :rsa (signature-of (sign-test-message
                                         (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                                     :private-key (fixture "dkim-rsa-pkcs8.pem"))))
                     :ed25519 (signature-of (sign-test-message
                                             (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                                         :private-key (fixture "dkim-ed25519.pem")))))))
    (loop for (file algorithm password) in *encrypted-keys*
          do (let* ((signed (sign-test-message
                             (smtp/dkim:make-dkim-signer :domain "example.com" :selector "s"
                                                         :private-key (fixture file)
                                                         ;; A function, called only when needed.
                                                         :password (lambda () password))))
                    (tags (dkim-tags signed)))
               ;; RSA PKCS #1 v1.5 and Ed25519 signatures are deterministic.
               (is (string= (getf plain algorithm) (signature-of signed)) "~a" file)
               (when (openssl-available-p)
                 (is-true (openssl-verifies-p algorithm
                                              (fixture (if (eq algorithm :rsa) "dkim-rsa-pub.pem" "dkim-ed25519-pub.pem"))
                                              (signed-data signed tags)
                                              (base64-decode (cdr (assoc "b" tags :test #'string=))))
                          "~a" file))))))

(test encrypted-key-passwords
  (loop for (file) in *encrypted-keys*
        do (signals smtp/dkim:dkim-key-password-error
             (smtp/dkim:load-dkim-private-key (fixture file)))
           (signals smtp/dkim:dkim-key-password-error
             (smtp/dkim:load-dkim-private-key (fixture file) :password "wrong password")))
  ;; The password as octets.
  (is (eq :rsa (first (smtp/dkim:load-dkim-private-key
                       (fixture "dkim-rsa-pkcs8-aes128-sha1.pem")
                       :password (babel:string-to-octets "pässwörd" :encoding :utf-8)))))
  ;; A password for an unencrypted key is ignored, and never asked for.
  (is (eq :rsa (first (smtp/dkim:load-dkim-private-key
                       (fixture "dkim-rsa-pkcs8.pem") :password (lambda () (error "not needed")))))))

(test unsupported-key-encryption
  (let ((e (handler-case (smtp/dkim:load-dkim-private-key (fixture "dkim-rsa-pkcs8-camellia.pem")
                                                          :password "dkim-test")
             (smtp/dkim:dkim-key-error (e) e))))
    (is (typep e 'smtp/dkim:dkim-key-error))
    (is (not (typep e 'smtp/dkim:dkim-key-password-error)))
    (is (search "unsupported cipher" (princ-to-string e))))
  ;; Corrupted ciphertext is a key error, not a raw decoding error.
  (let ((pem (uiop:read-file-string (fixture "dkim-rsa-legacy-aes256.pem"))))
    (signals smtp/dkim:dkim-key-error
      (smtp/dkim:load-dkim-private-key (substitute #\A #\B (substitute #\Q #\M pem :count 3 :from-end t)
                                                   :count 3 :from-end t)
                                       :password "dkim-test"))))
