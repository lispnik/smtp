;;; idna.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Internationalized domain names: Punycode (RFC 3492) and conversion of
;;; domains to their ASCII form for use on the wire by UTS #46 (Unicode IDNA
;;; Compatibility Processing) with nontransitional processing and every
;;; check on: UseSTD3ASCIIRules, CheckHyphens, CheckBidi, CheckJoiners and
;;; VerifyDnsLength. The tables in idna-table.lisp are generated from the
;;; Unicode version SBCL's character data uses, so normalization, bidi
;;; classes and combining classes agree with them.

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

;;; Table lookup

(defun %run-index (starts code)
  "The index of the last run in STARTS beginning at or before CODE."
  (declare (type (simple-array (unsigned-byte 32) (*)) starts))
  (let ((lo 0) (hi (1- (length starts))))
    (loop while (< lo hi)
          do (let ((mid (ceiling (+ lo hi) 2)))
               (if (<= (aref starts mid) code) (setf lo mid) (setf hi (1- mid)))))
    lo))

(defun %idna-status (char)
  "CHAR's UTS #46 status: :VALID, :DISALLOWED or :IGNORED, or a string of
the characters it maps to."
  (let ((value (aref *idna-values* (%run-index *idna-starts* (char-code char)))))
    (case value
      (-1 :valid)
      (-2 :disallowed)
      (-3 :ignored)
      (t (multiple-value-bind (offset length) (floor value 32)
           (map 'string #'code-char (subseq *idna-mappings* offset (+ offset length))))))))

(defun %joining-type (char)
  (svref #(:u :l :d :r :t :c)
         (aref *joining-types* (%run-index *joining-starts* (char-code char)))))

(defun %nfc (string)
  #+sbcl (sb-unicode:normalize-string string :nfc)
  #-sbcl string)

(defun %mark-p (char)
  #+sbcl (member (sb-unicode:general-category char) '(:mn :mc :me))
  #-sbcl nil)

(defun %virama-p (char)
  #+sbcl (= 9 (sb-unicode:combining-class char))
  #-sbcl nil)

(defun %bidi-class (char)
  #+sbcl (sb-unicode:bidi-class char)
  #-sbcl (if (< (char-code char) 128) :l :on))

;;; Validity criteria (UTS #46 section 4.1, RFC 5892 appendix A, RFC 5893)

(defun %context-j-p (label i)
  "Whether the ZERO WIDTH (NON-)JOINER at I in LABEL is allowed (RFC 5892 A.1, A.2)."
  (or (and (plusp i) (%virama-p (char label (1- i))))
      (and (char= (char label i) #\U+200C)
           ;; (L|D) T* ZWNJ T* (R|D)
           (let ((before (loop for j downfrom (1- i) to 0
                               for type = (%joining-type (char label j))
                               unless (eq type :t) return type))
                 (after (loop for j from (1+ i) below (length label)
                              for type = (%joining-type (char label j))
                              unless (eq type :t) return type)))
             (and (member before '(:l :d)) (member after '(:r :d)))))))

(defun %label-error (label)
  "Why LABEL (Unicode, nonempty) fails the validity criteria, or NIL."
  (let ((n (length label)))
    (cond ((string/= label (%nfc label)) "is not in normalization form C")
          ((and (>= n 4) (char= (char label 2) #\-) (char= (char label 3) #\-))
           "has hyphens in the third and fourth positions")
          ((or (char= (char label 0) #\-) (char= (char label (1- n)) #\-))
           "begins or ends with a hyphen")
          ((find #\. label) "contains a full stop")
          ((%mark-p (char label 0)) "begins with a combining mark")
          ((find-if (lambda (c) (not (eq (%idna-status c) :valid))) label)
           "contains a character not allowed in domain names")
          ((loop for i below n
                 thereis (and (member (char label i) '(#\U+200C #\U+200D))
                              (not (%context-j-p label i))))
           "contains a joiner in a context where it is not allowed"))))

(defun %rtl-label-p (label)
  (some (lambda (c) (member (%bidi-class c) '(:r :al :an))) label))

(defun %bidi-error (label)
  "Why LABEL, in a domain with right-to-left labels, breaks RFC 5893, or NIL."
  (let* ((classes (map 'list #'%bidi-class label))
         (last (find :nsm classes :test-not #'eq :from-end t)))
    (case (first classes)
      ((:r :al)
       (cond ((notevery (lambda (c) (member c '(:r :al :an :en :es :cs :et :on :bn :nsm))) classes)
              "mixes directions")
             ((not (member last '(:r :al :en :an))) "ends with a character of the wrong direction")
             ((and (member :en classes) (member :an classes)) "mixes European and Arabic digits")))
      (:l
       (cond ((notevery (lambda (c) (member c '(:l :en :es :cs :et :on :bn :nsm))) classes)
              "mixes directions")
             ((not (member last '(:l :en))) "ends with a character of the wrong direction")))
      (t "begins with a character of no strong direction"))))

;;; Processing (UTS #46 section 4) and ToASCII (section 4.2)

(defun %uts46-labels (domain)
  "Map, normalize and split DOMAIN: a list of Unicode labels, and the first
problem found, or NIL."
  (let ((problem nil)
        (mapped (make-string-output-stream)))
    (loop for c across domain
          for status = (%idna-status c)
          do (case status
               (:valid (write-char c mapped))
               (:ignored)
               (:disallowed
                (unless problem
                  (setf problem (format nil "contains the character U+~4,'0X, which is not allowed"
                                        (char-code c))))
                (write-char c mapped))
               (t (write-string status mapped))))
    (let* ((normalized (%nfc (get-output-stream-string mapped)))
           (labels (loop with start = 0
                         for pos = (position #\. normalized :start start)
                         collect (subseq normalized start pos)
                         while pos do (setf start (1+ pos))))
           (unicode
             (loop for label in labels
                   collect
                   (flet ((note (why)
                            (unless problem
                              (setf problem (format nil "label ~s ~a" label why)))))
                     (cond ((zerop (length label)) label)
                           ((string-prefix-p "xn--" label :test #'char=)
                            (let ((u (ignore-errors (punycode-decode (subseq label 4)))))
                              (cond ((or (null u) (zerop (length u)) (ascii-p u)
                                         (notevery (lambda (c) (< (char-code c) 128)) label)
                                         ;; Only the canonical encoding of U is an A-label.
                                         (string/= (subseq label 4) (punycode-encode u)))
                                     (note "is not a valid A-label")
                                     label)
                                    (t (let ((why (%label-error u))) (when why (note why)))
                                       u))))
                           (t (let ((why (%label-error label))) (when why (note why)))
                              label))))))
      (when (and (not problem) (some #'%rtl-label-p unicode))
        (loop for label in unicode
              for why = (and (plusp (length label)) (%bidi-error label))
              when why do (setf problem (format nil "label ~s ~a" label why)) (return)))
      (values unicode problem))))

(defun %uts46-to-ascii (domain)
  "DOMAIN converted by UTS #46 ToASCII, or NIL and the reason it is invalid.
A trailing full stop (the root label) is kept."
  (multiple-value-bind (labels problem) (%uts46-labels domain)
    (let* ((ascii (mapcar (lambda (label)
                            (if (ascii-p label)
                                label
                                (concatenate 'string "xn--" (punycode-encode label))))
                          labels))
           (root (and (cdr ascii) (string= "" (car (last ascii)))))
           (named (if root (butlast ascii) ascii))
           (result (format nil "~{~a~^.~}" ascii)))
      (cond (problem (values nil problem))
            ((find "" named :test #'string=) (values nil "has an empty label"))
            ((find-if (lambda (l) (> (length l) 63)) named)
             (values nil (format nil "label ~s is longer than 63 octets"
                                 (find-if (lambda (l) (> (length l) 63)) named))))
            ((> (- (length result) (if root 1 0)) 253) (values nil "is longer than 253 octets"))
            (t result)))))

(defun domain-to-ascii (domain)
  "The ASCII (A-label) form of DOMAIN, lowercased, for use in SMTP commands
and headers, by UTS #46 with nontransitional processing. A trailing full
stop is removed. Signals INVALID-ADDRESS if DOMAIN is not a valid host name."
  (multiple-value-bind (ascii problem) (%uts46-to-ascii domain)
    (unless ascii
      (error 'invalid-address :address domain
                              :message (if (zerop (length domain))
                                           "empty domain"
                                           (format nil "the domain ~a" problem))))
    (if (and (> (length ascii) 1) (char= (char ascii (1- (length ascii))) #\.))
        (subseq ascii 0 (1- (length ascii)))
        ascii)))
