;;; util.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp)

(deftype octet () '(unsigned-byte 8))
(deftype octets () '(simple-array (unsigned-byte 8) (*)))

;;; Growable octet buffers. Messages are assembled into one of these so that
;;; their exact size is known before sending (SIZE, BDAT) and so that signing
;;; sees the same octets the server will.

(defun make-octet-buffer (&optional (size 4096))
  (make-array size :element-type 'octet :adjustable t :fill-pointer 0))

(declaim (inline buffer-push))
(defun buffer-push (octet buffer)
  (vector-push-extend octet buffer (max 4096 (length buffer))))

(defun buffer-append (buffer octets &key (start 0) (end (length octets)))
  (let* ((old (fill-pointer buffer))
         (new (+ old (- end start))))
    (when (> new (array-dimension buffer 0))
      (setf buffer (adjust-array buffer (max new (* 2 (array-dimension buffer 0))))))
    (setf (fill-pointer buffer) new)
    (replace buffer octets :start1 old :start2 start :end2 end)
    buffer))

(defun buffer-ascii (buffer string)
  "Append STRING, which must be 7-bit, to BUFFER."
  (loop for c across string
        for code = (char-code c)
        do (if (< code 128)
               (buffer-push code buffer)
               (error "Internal error: non-ASCII character ~s in 7-bit output" c)))
  buffer)

(defun buffer-utf8 (buffer string)
  (buffer-append buffer (utf8-octets string)))

(defun buffer-crlf (buffer)
  (buffer-push 13 buffer)
  (buffer-push 10 buffer)
  buffer)

(defun buffer-octets (buffer)
  "A fresh simple octet vector with BUFFER's contents."
  (let ((result (make-array (length buffer) :element-type 'octet)))
    (replace result buffer)
    result))

(defun utf8-octets (string)
  (babel:string-to-octets string :encoding :utf-8))

(defun utf8-string (octets &key (start 0) (end (length octets)))
  "Decode OCTETS leniently: malformed sequences become replacement characters."
  (babel:octets-to-string octets :encoding :utf-8 :start start :end end :errorp nil))

;;; Character classes.

(defun ascii-p (string)
  (every (lambda (c) (< (char-code c) 128)) string))

(defun control-char-p (char)
  "Whether CHAR is a C0 or C1 control character, DEL, or one of the Unicode
line and paragraph separators, which some readers also take as line breaks."
  (let ((code (char-code char)))
    (or (< code 32) (<= 127 code 159) (= code #x2028) (= code #x2029))))

(defun line-break-char-p (char)
  (or (char= char #\Return) (char= char #\Linefeed)))

(defun has-line-break-p (string)
  (find-if #'line-break-char-p string))

(defun atext-char-p (char)
  "RFC 5322 atext, extended to non-ASCII characters by RFC 6532."
  (or (alphanumericp char)
      (find char "!#$%&'*+-/=?^_`{|}~")
      (> (char-code char) 127)))

(defun wsp-char-p (char)
  (or (char= char #\Space) (char= char #\Tab)))

;;; Secure randomness, for Message-IDs, boundaries and Content-IDs.

(defparameter +base32-alphabet+ "abcdefghijklmnopqrstuvwxyz234567")

(defun random-token (&optional (octets 16))
  "A random lowercase base32 string carrying OCTETS octets of entropy from a
CSPRNG."
  (let ((bytes (random-octets octets))
        (bits 0) (nbits 0))
    (with-output-to-string (s)
      (loop for b across bytes
            do (setf bits (logior (ash bits 8) b))
               (incf nbits 8)
               (loop while (>= nbits 5)
                     do (decf nbits 5)
                        (write-char (char +base32-alphabet+ (ldb (byte 5 nbits) bits)) s))
               (setf bits (ldb (byte nbits 0) bits)))
      (when (plusp nbits)
        (write-char (char +base32-alphabet+ (ash bits (- 5 nbits))) s)))))

;;; Lines.

(defun split-lines (string)
  "Split STRING at CRLF, CR or LF. A trailing line break yields a final empty
line, so joining the result with CRLF canonicalizes STRING's line endings."
  (let ((lines '()) (start 0) (i 0) (n (length string)))
    (loop while (< i n)
          do (let ((c (char string i)))
               (cond ((char= c #\Return)
                      (push (subseq string start i) lines)
                      (when (and (< (1+ i) n) (char= (char string (1+ i)) #\Linefeed))
                        (incf i))
                      (setf start (1+ i)))
                     ((char= c #\Linefeed)
                      (push (subseq string start i) lines)
                      (setf start (1+ i)))))
             (incf i))
    (push (subseq string start) lines)
    (nreverse lines)))

(defun string-prefix-p (prefix string &key (test #'char-equal))
  (and (<= (length prefix) (length string))
       (every test prefix string)))
