;;; encoding.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/encoding :in :smtp :description "Transfer and header encodings.")
(in-suite :smtp/encoding)

(defun canonical (string)
  "STRING with line endings made CRLF."
  (format nil "~{~a~^~c~c~}"
          (loop for (l . more) on (smtp::split-lines string)
                collect l when more collect #\Return and collect #\Linefeed)))

(defun decode-encoded-word (word)
  "Decode one RFC 2047 encoded-word to a string."
  (assert (and (string-prefix-p "=?UTF-8?" word) (string= "?=" word :start2 (- (length word) 2))))
  (let ((kind (char word 8))
        (payload (subseq word 10 (- (length word) 2))))
    (text (ecase kind
            (#\B (base64-decode payload))
            (#\Q (quoted-printable-decode (substitute #\Space #\_ payload)))))))

;;; Base64

(test base64-rfc4648-vectors
  (loop for (in out) in '(("" "") ("f" "Zg==") ("fo" "Zm8=") ("foo" "Zm9v")
                          ("foob" "Zm9vYg==") ("fooba" "Zm9vYmE=") ("foobar" "Zm9vYmFy"))
        do (is (string= out (base64-encode in)))
           (is (string= in (text (base64-decode out))))))

(test base64-round-trip-and-lines
  (dotimes (i 50)
    (let* ((data (let ((v (make-array (random 400) :element-type '(unsigned-byte 8))))
                   (dotimes (j (length v) v) (setf (aref v j) (random 256)))))
           (encoded (base64-encode data :line-length 76)))
      (is (equalp data (base64-decode encoded)))
      (is (every (lambda (l) (<= (length l) 76)) (lines-of encoded))))))

(test base64-rejects-garbage
  (signals smtp-error (base64-decode "Zm9v!"))
  (signals smtp-error (base64-decode "Zg==Zg==")))

;;; Quoted-printable

(test qp-basics
  (is (string= "caf=C3=A9" (quoted-printable-encode "café")))
  (is (string= "a=3Db" (quoted-printable-encode "a=b")))
  (is (string= "trailing=20" (quoted-printable-encode "trailing ")))
  (is (string= "tab=09" (quoted-printable-encode (format nil "tab~c" #\Tab))))
  (is (string= (crlf "=2E" "line") (quoted-printable-encode (format nil ".~%line"))))
  (is (string= (crlf "a" "b" "c") (quoted-printable-encode (format nil "a~c~cb~cc" #\Return #\Linefeed #\Return)))))

(test qp-soft-breaks
  (let* ((input (make-string 200 :initial-element #\x))
         (encoded (quoted-printable-encode input))
         (lines (lines-of encoded)))
    (is (> (length lines) 2))
    (is (every (lambda (l) (<= (length l) 76)) lines))
    (is (every (lambda (l) (char= #\= (char l (1- (length l))))) (butlast lines)))
    (is (string= input (text (quoted-printable-decode encoded))))))

(test qp-never-splits-escapes
  ;; Every possible alignment of a three-character escape against the limit.
  (loop for prefix from 70 to 76
        do (let* ((input (concatenate 'string (make-string prefix :initial-element #\a) "é=é"))
                  (encoded (quoted-printable-encode input)))
             (is (every (lambda (l) (<= (length l) 76)) (lines-of encoded)))
             (is (string= input (text (quoted-printable-decode encoded)))))))

(test qp-property-round-trip
  (dotimes (i 300)
    (let* ((input (random-string (random 300)))
           (encoded (quoted-printable-encode input)))
      (is (every (lambda (c) (or (char= c #\Tab) (< 31 (char-code c) 127)))
                 (remove #\Linefeed (remove #\Return encoded))))
      (is (every (lambda (l) (<= (length l) 76)) (lines-of encoded)))
      (is (equalp (octets (canonical input)) (quoted-printable-decode encoded))))))

;;; Encoded-words

(test encoded-words-limits-and-round-trip
  (dotimes (i 300)
    (let* ((input (remove-if (lambda (c) (member c '(#\Return #\Newline #\Tab)))
                             (random-string (1+ (random 200)))))
           (words (encode-header-words input)))
      (is (every (lambda (w) (<= (length w) 75)) words))
      ;; Each word decodes alone, so no character was split between words.
      (is (string= input (format nil "~{~a~}" (mapcar #'decode-encoded-word words)))))))

(test encoded-words-q-and-b
  (is (equal '("=?UTF-8?Q?caf=C3=A9_au_lait?=") (encode-header-words "café au lait" :encoding :q)))
  (is (equal '("=?UTF-8?B?5Lit5paH?=") (encode-header-words "中文" :encoding :b))))

(test unstructured-header-encoding
  (is (string= "Plain subject" (smtp::encode-unstructured "Plain subject")))
  (is (string-prefix-p "=?UTF-8?" (smtp::encode-unstructured "Grüße")))
  ;; Text that looks like an encoded-word is encoded so it reads back literally.
  (is (string-prefix-p "=?UTF-8?" (smtp::encode-unstructured "=?UTF-8?B?Zm9v?=")))
  (is (string= "Grüße" (smtp::encode-unstructured "Grüße" :utf8 t))))

;;; Folding

(defun unfold (string)
  (let ((s string))
    (loop for pos = (search (crlf "" " ") s)
          while pos do (setf s (concatenate 'string (subseq s 0 pos) (subseq s (+ pos 2)))))
    s))

(test fold-header-property
  (dotimes (i 200)
    (let* ((words (loop repeat (random 40)
                        collect (random-string (1+ (random 15)) :alphabet "abcdefghij0123456789")))
           (value (format nil "~{~a~^ ~}" words))
           (folded (smtp::fold-header "Subject" value)))
      (is (every (lambda (l) (<= (length l) 78)) (lines-of folded)))
      (is (string= (string-right-trim " " (format nil "Subject: ~a" value)) (unfold folded)))
      (is (notany (lambda (l) (every #'smtp::wsp-char-p l)) (rest (lines-of folded)))))))

(test fold-header-keeps-quoted-strings-whole
  (let ((folded (smtp::fold-header "To" (format nil "~{~a~^, ~}"
                                                (loop repeat 6 collect "\"Some Long Name\" <someone@example.com>")))))
    (dolist (line (lines-of folded))
      (is (evenp (count #\" line))))))

(test fold-header-rejects-bad-values
  (signals invalid-header (smtp::fold-header "X" (format nil "a~cb" #\Newline)))
  (signals invalid-header (smtp::fold-header "X" (format nil "a~cb" #\Return)))
  (signals invalid-header (smtp::fold-header "X" (make-string 1200 :initial-element #\a))))

;;; MIME parameters

(test mime-parameters
  (is (equal '("name=report.pdf") (smtp::format-mime-parameter "name" "report.pdf")))
  (is (equal '("name=\"my report.pdf\"") (smtp::format-mime-parameter "name" "my report.pdf")))
  (is (equal '("name=\"a\\\"b\"") (smtp::format-mime-parameter "name" "a\"b")))
  (is (equal '("filename=\"'\"") (smtp::format-mime-parameter "filename" "'")))
  (is (equal '("filename=\"it's.txt\"") (smtp::format-mime-parameter "filename" "it's.txt")))
  (is (equal '("filename*=UTF-8''r%C3%A9sum%C3%A9.pdf")
             (smtp::format-mime-parameter "filename" "résumé.pdf")))
  (let ((parts (smtp::format-mime-parameter "filename" (make-string 40 :initial-element #\é))))
    (is (> (length parts) 1))
    (is (string-prefix-p "filename*0*=UTF-8''" (first parts)))
    (is (string-prefix-p "filename*1*=" (second parts)))
    ;; Segments end on character boundaries: every segment is whole %C3%A9 pairs.
    (dolist (p parts)
      (let ((value (subseq p (1+ (position #\= p)))))
        (is (zerop (mod (count #\% value) 2))))))
  (signals invalid-header (smtp::format-mime-parameter "name" (format nil "a~%b"))))

;;; Dates

(test rfc5322-dates
  (let ((noon (encode-universal-time 0 0 12 1 1 2026 0)))
    (is (string= "Thu, 1 Jan 2026 12:00:00 +0000" (format-rfc5322-date noon 0)))
    (is (string= "Thu, 1 Jan 2026 07:00:00 -0500" (format-rfc5322-date noon 5)))
    (is (string= "Thu, 1 Jan 2026 17:30:00 +0530" (format-rfc5322-date noon -11/2)))
    (is (string= "Thu, 1 Jan 2026 17:45:00 +0545" (format-rfc5322-date noon -23/4)))
    (is (string= "Wed, 31 Dec 2025 22:30:00 -1330" (format-rfc5322-date noon 27/2)))))

(test rfc5322-date-local-zone-is-consistent
  ;; The offset must agree with the printed local time, for any second.
  (let* ((ut (get-universal-time))
         (date (format-rfc5322-date ut)))
    (multiple-value-bind (s m h) (decode-universal-time ut)
      (is (search (format nil "~2,'0d:~2,'0d:~2,'0d" h m s) date)))
    (let* ((zone (subseq date (- (length date) 5)))
           (minutes (* (if (char= (char zone 0) #\-) -1 1)
                       (+ (* 60 (parse-integer zone :start 1 :end 3))
                          (parse-integer zone :start 3)))))
      (is (zerop (mod minutes 15))))))

;;; Punycode and domains

(test punycode-vectors
  (loop for (unicode ascii) in '(("bücher" "bcher-kva")
                                  ("münchen" "mnchen-3ya")
                                  ("ليهمابتكلموشعربي؟" "egbpdaj6bu4bxfgehfvwxn")
                                  ("他们为什么不说中文" "ihqwcrb4cv8a8dqg056pqjye")
                                  ("例え" "r8jz45g")
                                  ("テスト" "zckzah"))
        do (is (string= ascii (punycode-encode unicode)))
           (is (string= unicode (punycode-decode ascii)))))

(test punycode-round-trip
  (dotimes (i 200)
    (let ((s (random-string (1+ (random 20)) :alphabet "abcxyz019-éüñ中文字日本語한국어ЖжΩ")))
      (is (string= s (punycode-decode (punycode-encode s)))))))

(test domain-to-ascii
  (is (string= "example.com" (domain-to-ascii "Example.COM")))
  (is (string= "xn--bcher-kva.example" (domain-to-ascii "Bücher.example")))
  (is (string= "xn--r8jz45g.xn--zckzah" (domain-to-ascii "例え.テスト")))
  (is (string= "xn--r8jz45g.xn--zckzah" (domain-to-ascii "例え。テスト")))
  (is (string= "example.com" (domain-to-ascii "example.com.")))
  ;; UTS #46 mapping: full-width forms, ignored characters, case folding.
  (is (string= "example.com" (domain-to-ascii "ＥＸＡＭＰＬＥ．ｃｏｍ")))
  (is (string= "example.com" (domain-to-ascii (format nil "exam~cple.com" (code-char #xAD)))))
  (is (string= "xn--fa-hia.de" (domain-to-ascii "Faß.de")))
  ;; Bidi (RFC 5893) and joiner (RFC 5892) rules.
  (signals invalid-address (domain-to-ascii (format nil "1~c.example" (code-char #x05D0))))
  (signals invalid-address (domain-to-ascii (format nil "a~cb.example" (code-char #x200D))))
  (dolist (bad (list "" "a..b" "-a.com" "a-.com" "a_b.com" "a b.com"
                     (format nil "~a.com" (make-string 64 :initial-element #\a))
                     (format nil "~{~a~^.~}" (make-list 60 :initial-element "abcd"))))
    (signals invalid-address (domain-to-ascii bad))))

(defun unescape-idna-test (string)
  "STRING with IdnaTestV2's \\uXXXX and \\x{X...} escapes replaced."
  (with-output-to-string (out)
    (loop with i = 0
          while (< i (length string))
          do (let ((next (and (char= (char string i) #\\) (< (1+ i) (length string))
                              (char string (1+ i)))))
               (case next
                 (#\u (write-char (code-char (parse-integer string :start (+ i 2) :end (+ i 6) :radix 16)) out)
                  (incf i 6))
                 (#\x (let ((end (position #\} string :start i)))
                        (write-char (code-char (parse-integer string :start (+ i 3) :end end :radix 16)) out)
                        (setf i (1+ end))))
                 (t (write-char (char string i) out)
                  (incf i)))))))

(test uts46-conformance
  ;; Every ToASCII case (nontransitional, all checks on) of the Unicode
  ;; conformance file for the Unicode version of SBCL's character data.
  (let ((failures '()) (count 0))
    (with-open-file (in (fixture "IdnaTestV2.txt") :external-format :utf-8)
      (loop for line = (read-line in nil)
            while line
            unless (or (zerop (length line)) (char= (char line 0) #\#))
              do (destructuring-bind (source to-unicode unicode-status ascii ascii-status &rest rest)
                     (mapcar (lambda (f) (string-trim " " f)) (uiop:split-string line :separator ";"))
                   (declare (ignore rest))
                   (let* ((source (unescape-idna-test source))
                          (to-unicode (if (string= "" to-unicode) source (unescape-idna-test to-unicode)))
                          (expected (if (string= "" ascii) to-unicode (unescape-idna-test ascii)))
                          (status (if (string= "" ascii-status) unicode-status ascii-status))
                          (error-expected (not (member status '("" "[]") :test #'string=)))
                          (got (smtp::%uts46-to-ascii source)))
                     (incf count)
                     (unless (if error-expected (null got) (equal got expected))
                       (push (list source status expected got) failures))))))
    (is (= 6235 count))
    (is (null failures) "~d failures, first ~s" (length failures) (first failures))))

(test base64-rejects-truncation-and-bad-padding
  (dolist (bad '("Q" "QQ" "QUI" "Q===" "QUJD=" "QUJDRA=" "QUJDRA===" "QQ=" "QQ==="))
    (signals smtp-error (base64-decode bad) "~s was accepted" bad))
  (is (equalp (octets "A") (base64-decode "QQ==")))
  (is (equalp (octets "AB") (base64-decode "QUI=")))
  (is (equalp (octets "ABC") (base64-decode (format nil "QU~%JD"))))
  (is (equalp #() (base64-decode ""))))
