;;; idna.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Internationalized domain names: Punycode (RFC 3492) and conversion of
;;; domains to their ASCII form for use on the wire. Labels are normalized
;;; to NFC and lowercased; the full IDNA2008 / UTS #46 tables are not applied.

(in-package #:smtp)

(defconstant +puny-base+ 36)
(defconstant +puny-tmin+ 1)
(defconstant +puny-tmax+ 26)
(defconstant +puny-skew+ 38)
(defconstant +puny-damp+ 700)
(defconstant +puny-initial-bias+ 72)
(defconstant +puny-initial-n+ 128)

(defun %puny-adapt (delta numpoints first-time)
  (setf delta (if first-time (floor delta +puny-damp+) (floor delta 2)))
  (incf delta (floor delta numpoints))
  (loop with k = 0
        while (> delta (floor (* (- +puny-base+ +puny-tmin+) +puny-tmax+) 2))
        do (setf delta (floor delta (- +puny-base+ +puny-tmin+)))
           (incf k +puny-base+)
        finally (return (+ k (floor (* (+ (- +puny-base+ +puny-tmin+) 1) delta)
                                    (+ delta +puny-skew+))))))

(defun %puny-digit (d)
  (if (< d 26) (code-char (+ d 97)) (code-char (+ (- d 26) 48))))

(defun %puny-value (c)
  (cond ((char<= #\a (char-downcase c) #\z) (- (char-code (char-downcase c)) 97))
        ((char<= #\0 c #\9) (+ 26 (- (char-code c) 48)))
        (t nil)))

(defun %puny-threshold (k bias)
  (cond ((<= k bias) +puny-tmin+)
        ((>= k (+ bias +puny-tmax+)) +puny-tmax+)
        (t (- k bias))))

(defun punycode-encode (string)
  "The Punycode encoding of STRING (RFC 3492), without the xn-- prefix."
  (let* ((codes (map 'list #'char-code string))
         (output (make-string-output-stream))
         (basic (count-if (lambda (c) (< c 128)) codes))
         (h basic)
         (n +puny-initial-n+)
         (delta 0)
         (bias +puny-initial-bias+))
    (dolist (c codes)
      (when (< c 128) (write-char (code-char c) output)))
    (when (plusp basic) (write-char #\- output))
    (loop while (< h (length codes))
          do (let ((m (loop for c in codes when (>= c n) minimize c)))
               (incf delta (* (- m n) (1+ h)))
               (setf n m)
               (dolist (c codes)
                 (when (< c n) (incf delta))
                 (when (= c n)
                   (let ((q delta))
                     (loop for k from +puny-base+ by +puny-base+
                           for tt = (%puny-threshold k bias)
                           until (< q tt)
                           do (write-char (%puny-digit (+ tt (mod (- q tt) (- +puny-base+ tt))))
                                          output)
                              (setf q (floor (- q tt) (- +puny-base+ tt))))
                     (write-char (%puny-digit q) output)
                     (setf bias (%puny-adapt delta (1+ h) (= h basic)))
                     (setf delta 0)
                     (incf h))))
               (incf delta)
               (incf n)))
    (get-output-stream-string output)))

(defun punycode-decode (string)
  "Decode Punycode STRING (without the xn-- prefix)."
  (let* ((dash (position #\- string :from-end t))
         (output (if dash (map 'list #'char-code (subseq string 0 dash)) '()))
         (i 0)
         (n +puny-initial-n+)
         (bias +puny-initial-bias+)
         (pos (if dash (1+ dash) 0))
         (len (length string)))
    (flet ((fail () (error 'invalid-address :address string
                                            :message "malformed Punycode")))
      (when (some (lambda (c) (>= c 128)) output) (fail))
      (loop while (< pos len)
            do (let ((oldi i) (w 1))
                 (loop for k from +puny-base+ by +puny-base+
                       do (when (>= pos len) (fail))
                          (let ((digit (%puny-value (char string pos))))
                            (incf pos)
                            (unless digit (fail))
                            (incf i (* digit w))
                            (let ((tt (%puny-threshold k bias)))
                              (when (< digit tt) (return))
                              (setf w (* w (- +puny-base+ tt))))))
                 (let ((count (1+ (length output))))
                   (setf bias (%puny-adapt (- i oldi) count (zerop oldi)))
                   (incf n (floor i count))
                   (setf i (mod i count))
                   (when (> n #x10FFFF) (fail))
                   (setf output (append (subseq output 0 i) (list n) (nthcdr i output)))
                   (incf i))))
      (map 'string #'code-char output))))

(defun %normalize-label (label)
  (string-downcase
   #+sbcl (sb-unicode:normalize-string label :nfc)
   #-sbcl label))

(defun %ldh-label-p (label)
  (and (plusp (length label))
       (every (lambda (c) (or (char<= #\a c #\z) (char<= #\0 c #\9) (char= c #\-))) label)
       (char/= (char label 0) #\-)
       (char/= (char label (1- (length label))) #\-)))

(defun domain-to-ascii (domain)
  "The ASCII (A-label) form of DOMAIN, lowercased, for use in SMTP commands
and headers. Signals INVALID-ADDRESS if DOMAIN is not a valid host name."
  (flet ((fail (why) (error 'invalid-address :address domain :message why)))
    (let* ((dotted (substitute-if #\. (lambda (c) (find c '(#\U+3002 #\U+FF0E #\U+FF61)))
                                  domain))
           (trimmed (if (and (plusp (length dotted))
                             (char= (char dotted (1- (length dotted))) #\.))
                        (subseq dotted 0 (1- (length dotted)))
                        dotted))
           (labels (loop with start = 0
                         for pos = (position #\. trimmed :start start)
                         collect (subseq trimmed start pos)
                         while pos do (setf start (1+ pos)))))
      (when (zerop (length trimmed)) (fail "empty domain"))
      (let ((ascii
              (format nil "~{~a~^.~}"
                      (mapcar (lambda (label)
                                (let* ((norm (%normalize-label label))
                                       (a (if (ascii-p norm)
                                              norm
                                              (progn
                                                (when (some (lambda (c)
                                                              (and (< (char-code c) 128)
                                                                   (not (or (alphanumericp c)
                                                                            (char= c #\-)))))
                                                            norm)
                                                  (fail "invalid character in label"))
                                                (concatenate 'string "xn--"
                                                             (punycode-encode norm))))))
                                  (unless (%ldh-label-p a)
                                    (fail (format nil "invalid label ~s" label)))
                                  (when (and (string-prefix-p "xn--" a)
                                             (not (ignore-errors
                                                   (let ((u (punycode-decode (subseq a 4))))
                                                     (and (not (ascii-p u))
                                                          (notany (lambda (c)
                                                                    (or (control-char-p c)
                                                                        (<= 128 (char-code c) 159)))
                                                                  u)
                                                          (string= a (concatenate 'string "xn--"
                                                                                  (punycode-encode u))))))))
                                    (fail (format nil "invalid A-label ~s" label)))
                                  (when (> (length a) 63)
                                    (fail (format nil "label ~s is longer than 63 octets" label)))
                                  a))
                              labels))))
        (when (> (length ascii) 253) (fail "longer than 253 octets"))
        ascii))))
