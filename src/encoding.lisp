;;; encoding.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Transfer and header encodings: base64 and quoted-printable (RFC 2045),
;;; encoded-words (RFC 2047), parameter values (RFC 2231), header folding and
;;; dates (RFC 5322).

(in-package #:smtp)

;;; Base64

(defparameter +base64-alphabet+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode-to-buffer (octets buffer &key (line-length 76))
  "Append the base64 encoding of OCTETS to BUFFER, breaking lines with CRLF
every LINE-LENGTH characters (a multiple of 4), or never if NIL. No line
break follows the last line."
  (let ((col 0) (n (length octets)))
    (flet ((out (code)
             (when (and line-length (= col line-length))
               (buffer-crlf buffer)
               (setf col 0))
             (buffer-push code buffer)
             (incf col))
           (sextet (word position)
             (char-code (char +base64-alphabet+ (ldb (byte 6 position) word)))))
      (loop for i from 0 below n by 3
            do (let* ((b0 (aref octets i))
                      (b1 (if (< (+ i 1) n) (aref octets (+ i 1)) 0))
                      (b2 (if (< (+ i 2) n) (aref octets (+ i 2)) 0))
                      (word (logior (ash b0 16) (ash b1 8) b2)))
                 (out (sextet word 18))
                 (out (sextet word 12))
                 (out (if (< (+ i 1) n) (sextet word 6) 61))
                 (out (if (< (+ i 2) n) (sextet word 0) 61))))))
  buffer)

(defun base64-encode (data &key line-length)
  "Base64-encode DATA (octets, or a string encoded as UTF-8) to a string.
LINE-LENGTH, if given, inserts CRLF line breaks."
  (let ((octets (if (stringp data) (utf8-octets data) data))
        (buffer (make-octet-buffer)))
    (base64-encode-to-buffer octets buffer
                             :line-length (and line-length (* 4 (floor line-length 4))))
    (map 'string #'code-char buffer)))

(defun base64-decode (string)
  "Decode base64 STRING to octets. Whitespace is ignored; any other character
outside the alphabet, or data after padding, is an error."
  (let ((buffer (make-octet-buffer (length string)))
        (bits 0) (nbits 0) (padding 0))
    (loop for c across string
          do (cond ((find c '(#\Space #\Tab #\Return #\Linefeed)))
                   ((char= c #\=) (incf padding))
                   (t
                    (let ((v (position c +base64-alphabet+)))
                      (unless (and v (zerop padding))
                        (error 'smtp-protocol-error
                               :message (format nil "Invalid base64 data ~s" string)))
                      (setf bits (logior (ash bits 6) v))
                      (incf nbits 6)
                      (when (>= nbits 8)
                        (decf nbits 8)
                        (buffer-push (ldb (byte 8 nbits) bits) buffer)
                        (setf bits (ldb (byte nbits 0) bits)))))))
    (buffer-octets buffer)))

(defun base64-body-to-buffer (octets buffer)
  "Append OCTETS as a base64 body (76-character lines) to BUFFER."
  (base64-encode-to-buffer octets buffer :line-length 76))

;;; Quoted-printable (RFC 2045 section 6.7)

(defun %qp-literal-p (octet column last)
  (cond ((= octet 61) nil)                        ; =
        ((and (= octet 46) (zerop column)) nil)   ; leading . (belt and braces for SMTP)
        ((<= 33 octet 126) t)
        ((or (= octet 32) (= octet 9)) (not last)) ; trailing whitespace is encoded
        (t nil)))

(defun %qp-line (octets buffer)
  "Encode one line of OCTETS (no line break) into BUFFER, inserting soft line
breaks so that no encoded line exceeds 76 characters."
  (let ((col 0) (n (length octets)))
    (dotimes (i n)
      (let* ((octet (aref octets i))
             (last (= i (1- n)))
             (limit (if last 76 75)))
        (flet ((width () (if (%qp-literal-p octet col last) 1 3)))
          (when (> (+ col (width)) limit)
            (buffer-push 61 buffer)
            (buffer-crlf buffer)
            (setf col 0))
          (cond ((%qp-literal-p octet col last)
                 (buffer-push octet buffer)
                 (incf col))
                (t
                 (buffer-ascii buffer (format nil "=~:@(~2,'0x~)" octet))
                 (incf col 3))))))
    buffer))

(defun quoted-printable-to-buffer (string buffer)
  "Append STRING, as UTF-8 quoted-printable with CRLF line breaks, to BUFFER."
  (loop for (line . more) on (split-lines string)
        do (%qp-line (utf8-octets line) buffer)
           (when more (buffer-crlf buffer)))
  buffer)

(defun quoted-printable-encode (string)
  "Encode STRING as UTF-8 quoted-printable text with CRLF line breaks."
  (utf8-string (quoted-printable-to-buffer string (make-octet-buffer))))

(defun quoted-printable-decode (string)
  "Decode quoted-printable STRING to octets. Soft line breaks are removed and
hard line breaks become CRLF."
  (let ((buffer (make-octet-buffer)) (i 0) (n (length string)))
    (flet ((hex (c) (digit-char-p c 16)))
      (loop while (< i n)
            do (let ((c (char string i)))
                 (cond ((and (char= c #\=) (< (+ i 2) n)
                             (hex (char string (+ i 1))) (hex (char string (+ i 2))))
                        (buffer-push (+ (* 16 (hex (char string (+ i 1))))
                                        (hex (char string (+ i 2))))
                                     buffer)
                        (incf i 3))
                       ((and (char= c #\=) (< (+ i 2) n)
                             (char= (char string (+ i 1)) #\Return)
                             (char= (char string (+ i 2)) #\Linefeed))
                        (incf i 3))
                       ((and (char= c #\=) (< (+ i 1) n)
                             (char= (char string (+ i 1)) #\Linefeed))
                        (incf i 2))
                       ((char= c #\Linefeed)
                        (buffer-crlf buffer)
                        (incf i))
                       ((char= c #\Return)
                        (incf i))
                       (t
                        (buffer-append buffer (utf8-octets (string c)))
                        (incf i)))))
      (buffer-octets buffer))))

;;; Choosing a body encoding

(defun choose-text-encoding (string)
  "The Content-Transfer-Encoding for text STRING: :7BIT when it is short-lined
ASCII, :BASE64 when it is mostly non-ASCII, else :QUOTED-PRINTABLE. Every
choice produces a 7-bit body, so no server extension is ever needed."
  (let ((non-ascii 0) (bad nil) (col 0))
    (loop for c across string
          for code = (char-code c)
          do (cond ((line-break-char-p c) (setf col 0))
                   (t (incf col)
                      (when (> col 997) (setf bad t))
                      (cond ((> code 127) (incf non-ascii))
                            ((or (zerop code) (and (control-char-p c) (char/= c #\Tab)))
                             (setf bad t))))))
    (cond ((and (zerop non-ascii) (not bad)) :7bit)
          ((> non-ascii (floor (length string) 3)) :base64)
          (t :quoted-printable))))

(defun text-body-to-buffer (string encoding buffer)
  (ecase encoding
    (:7bit
     (loop for (line . more) on (split-lines string)
           do (buffer-ascii buffer line)
              (when more (buffer-crlf buffer))))
    (:quoted-printable (quoted-printable-to-buffer string buffer))
    (:base64
     (let ((canonical (format nil "~{~a~^~c~c~}"
                              (loop for (line . more) on (split-lines string)
                                    collect line
                                    when more collect #\Return and collect #\Linefeed))))
       (base64-body-to-buffer (utf8-octets canonical) buffer))))
  buffer)

;;; Encoded-words (RFC 2047)

(defun %q-word-safe-p (char)
  ;; The restrictive set allowed in a phrase (RFC 2047 section 5 rule 3).
  (and (< (char-code char) 128)
       (or (alphanumericp char) (find char "!*+-/"))))

(defun %encode-word-q (octets)
  (with-output-to-string (s)
    (loop for o across octets
          do (cond ((= o 32) (write-char #\_ s))
                   ((%q-word-safe-p (code-char o)) (write-char (code-char o) s))
                   (t (format s "=~:@(~2,'0x~)" o))))))

(defun encode-header-words (string &key (encoding :auto))
  "Encode STRING as a list of RFC 2047 encoded-words in UTF-8, each at most
75 characters. Multi-octet characters are never split across words.
ENCODING is :B, :Q or :AUTO (Q for mostly-ASCII text)."
  (let* ((encoding (if (eq encoding :auto)
                       (if (> (count-if (lambda (c) (> (char-code c) 127)) string)
                              (floor (length string) 4))
                           :b :q)
                       encoding))
         (prefix (if (eq encoding :b) "=?UTF-8?B?" "=?UTF-8?Q?"))
         (budget (- 75 (length prefix) 2))
         (words '())
         (chunk (make-octet-buffer 64)))
    (labels ((encoded (octets)
               (if (eq encoding :b)
                   (base64-encode octets)
                   (%encode-word-q octets)))
             (flush ()
               (when (plusp (length chunk))
                 (push (concatenate 'string prefix (encoded (buffer-octets chunk)) "?=")
                       words)
                 (setf (fill-pointer chunk) 0))))
      (loop for c across string
            for octets = (utf8-octets (string c))
            do (let ((trial (make-octet-buffer)))
                 (buffer-append trial chunk)
                 (buffer-append trial octets)
                 (when (> (length (encoded (buffer-octets trial))) budget)
                   (flush))
                 (buffer-append chunk octets)))
      (flush))
    (nreverse words)))

(defun needs-encoded-words-p (string)
  "True if unstructured header text STRING cannot be sent as is: it has
non-ASCII characters, something that looks like an encoded-word, or a word
too long to fold."
  (or (not (ascii-p string))
      (search "=?" string)
      (some (lambda (word) (> (length word) 900))
            (loop with start = 0
                  for pos = (position #\Space string :start start)
                  collect (subseq string start pos)
                  while pos do (setf start (1+ pos))))))

(defun encode-unstructured (string &key utf8 name)
  "Header text for unstructured STRING (Subject, comments). With UTF8, raw
UTF-8 is allowed (RFC 6532) and only text resembling encoded-words or with
overlong words forces encoding. Control characters other than tab are an
error."
  (when (find-if (lambda (c) (and (control-char-p c) (char/= c #\Tab))) string)
    (error 'invalid-header :name name
                           :message "the value contains a line break or control character"))
  (if (if utf8
          (needs-encoded-words-p (remove-if-not (lambda (c) (< (char-code c) 128)) string))
          (needs-encoded-words-p string))
      (format nil "~{~a~^ ~}" (encode-header-words string))
      string))

;;; Header folding (RFC 5322 section 2.2.3)

(defun %fold-tokens (value)
  "Split VALUE into tokens at the whitespace before each run of non-space
characters, ignoring whitespace inside quoted strings. Every token but the
first begins with whitespace, so a line break may be put before any of them."
  (let ((tokens '()) (start 0) (in-quote nil) (escape nil) (n (length value)))
    (loop for i from 0 below n
          for c = (char value i)
          do (cond (escape (setf escape nil))
                   ((and in-quote (char= c #\\)) (setf escape t))
                   ((char= c #\") (setf in-quote (not in-quote)))
                   ((and (not in-quote) (wsp-char-p c) (> i start)
                         (not (wsp-char-p (char value (1- i)))))
                    (push (subseq value start i) tokens)
                    (setf start i))))
    (push (subseq value start) tokens)
    (nreverse tokens)))

(defun fold-header (name value &key (limit 78))
  "The header field NAME: VALUE, folded at whitespace so that lines are at most
LIMIT characters where possible, without the final CRLF. Signals
INVALID-HEADER if a line would exceed the hard limit of 998 characters or if
VALUE contains a line break."
  (unless (and (stringp name) (plusp (length name))
               (every (lambda (c) (and (< 32 (char-code c) 127) (char/= c #\:))) name))
    (error 'invalid-header :name name :message "invalid header name"))
  (when (has-line-break-p value)
    (error 'invalid-header :name name :message "the value contains a line break"))
  (when (search "=?" value)
    ;; RFC 2047: a line containing an encoded-word is at most 76 characters.
    (setf limit (min limit 76)))
  (let ((lines '())
        (line (format nil "~a:" name))
        (first t))
    (dolist (token (%fold-tokens value))
      (let ((piece (if (and first (plusp (length token)) (not (wsp-char-p (char token 0))))
                       (concatenate 'string " " token)
                       token)))
        (if (and (> (+ (length line) (length piece)) limit)
                 (notevery #'wsp-char-p piece)
                 ;; The first token may go on its own line when that makes it fit.
                 (or (not first) (<= (length piece) limit)))
            (progn (push line lines)
                   (setf line piece))
            (setf line (concatenate 'string line piece)))
        (setf first nil)))
    (push line lines)
    (setf lines (nreverse lines))
    (when (some (lambda (l) (> (length (utf8-octets l)) 998)) lines)
      (error 'invalid-header :name name
                             :message "a line would exceed 998 octets"))
    (format nil "~{~a~^~c~c~}"
            (loop for (l . more) on lines
                  collect l
                  when more collect #\Return and collect #\Linefeed))))

;;; MIME parameters (RFC 2045, RFC 2231)

(defun %tspecial-p (char)
  (find char "()<>@,;:\\\"/[]?="))

(defun %token-p (string)
  (and (plusp (length string))
       (every (lambda (c) (and (< 32 (char-code c) 127) (not (%tspecial-p c)))) string)))

(defun %quote-string (string)
  (with-output-to-string (s)
    (write-char #\" s)
    (loop for c across string
          do (when (find c "\"\\") (write-char #\\ s))
             (write-char c s))
    (write-char #\" s)))

(defun %attr-char-p (char)
  (and (< (char-code char) 128)
       (or (alphanumericp char) (find char "!#$&+-.^_`|~"))))

(defun %percent-encode-char (char)
  (if (%attr-char-p char)
      (string char)
      (format nil "~{%~:@(~2,'0x~)~}" (coerce (utf8-octets (string char)) 'list))))

(defun format-mime-parameter (name value)
  "A list of NAME=VALUE parameter strings for VALUE: a token, a quoted string,
or, for non-ASCII values, RFC 2231 extended values split into continuations
of at most 60 characters that never split a character."
  (cond ((has-line-break-p value)
         (error 'invalid-header :name name :message "parameter value contains a line break"))
        ((and (ascii-p value) (notany #'control-char-p value) (<= (length value) 200))
         (list (format nil "~a=~a" name (if (%token-p value) value (%quote-string value)))))
        ((and (ascii-p value) (notany #'control-char-p value))
         ;; RFC 2231 continuations keep long values foldable.
         (loop for start from 0 below (length value) by 60
               for i from 0
               collect (format nil "~a*~d=~a" name i
                               (%quote-string (subseq value start (min (length value) (+ start 60)))))))
        (t
         (let ((segments '()) (current (make-string-output-stream)) (len 0))
           (loop for c across value
                 for enc = (%percent-encode-char c)
                 do (when (> (+ len (length enc)) 60)
                      (push (get-output-stream-string current) segments)
                      (setf len 0))
                    (write-string enc current)
                    (incf len (length enc)))
           (push (get-output-stream-string current) segments)
           (setf segments (nreverse segments))
           (if (null (cdr segments))
               (list (format nil "~a*=UTF-8''~a" name (first segments)))
               (loop for seg in segments
                     for i from 0
                     collect (format nil "~a*~d*=~:[~;UTF-8''~]~a" name i (zerop i) seg)))))))

(defun format-content-header (value parameters)
  "VALUE followed by \"; name=value\" for each (name . value) in PARAMETERS,
with values encoded by FORMAT-MIME-PARAMETER."
  (format nil "~a~{; ~a~}" value
          (loop for (name . v) in parameters
                when v append (format-mime-parameter name v))))

;;; Dates (RFC 5322 section 3.3)

(defun format-rfc5322-date (&optional (universal-time (get-universal-time)) time-zone)
  "UNIVERSAL-TIME as an RFC 5322 date-time, in the local time zone or in
TIME-ZONE (hours west of Greenwich, as for DECODE-UNIVERSAL-TIME). The
offset comes from the same decoding as the fields, so it is always
consistent with them."
  (multiple-value-bind (sec min hour day month year dow dst-p tz)
      (if time-zone
          (decode-universal-time universal-time time-zone)
          (decode-universal-time universal-time))
    (let* ((offset (round (* -60 (- tz (if dst-p 1 0))))) ; minutes east
           (abs-offset (abs offset)))
      (format nil "~a, ~d ~a ~d ~2,'0d:~2,'0d:~2,'0d ~:[+~;-~]~2,'0d~2,'0d"
              (aref #("Mon" "Tue" "Wed" "Thu" "Fri" "Sat" "Sun") dow)
              day
              (aref #("Jan" "Feb" "Mar" "Apr" "May" "Jun"
                      "Jul" "Aug" "Sep" "Oct" "Nov" "Dec")
                    (1- month))
              year hour min sec
              (minusp offset)
              (floor abs-offset 60) (mod abs-offset 60)))))
