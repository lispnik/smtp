;;; reply.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; SMTP replies (RFC 5321 section 4.2) and enhanced status codes (RFC 3463).

(in-package #:smtp)

(defstruct (reply (:constructor make-reply (code lines &optional enhanced-status)))
  "A server reply: the three-digit CODE, the text of each line, and the
RFC 3463 enhanced status code (\"5.1.1\") when the server gave one."
  (code 0 :type (integer 0 999) :read-only t)
  (lines '() :type list :read-only t)
  (enhanced-status nil :type (or null string) :read-only t))

(defmethod print-object ((r reply) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "~d ~a" (reply-code r) (reply-text r))))

(defun reply-text (reply)
  "The reply's lines joined with spaces."
  (format nil "~{~a~^ ~}" (reply-lines reply)))

(defun reply-class (reply)
  (floor (reply-code reply) 100))

(defun reply-positive-p (reply)
  (member (reply-class reply) '(2 3)))

(defconstant +max-reply-lines+ 1000)

(defun parse-reply-line (line)
  "Parse one reply line. Returns the code, whether more lines follow, and the
text. Signals SMTP-PROTOCOL-ERROR unless LINE is a well-formed reply line."
  (flet ((fail ()
           (error 'smtp-protocol-error
                  :message (format nil "Malformed reply line ~s"
                                   (if (> (length line) 80)
                                       (concatenate 'string (subseq line 0 80) "...")
                                       line)))))
    (unless (and (>= (length line) 3)
                 (char<= #\2 (char line 0) #\5)
                 (char<= #\0 (char line 1) #\5)
                 (char<= #\0 (char line 2) #\9))
      (fail))
    (let ((code (parse-integer line :end 3)))
      (cond ((= (length line) 3) (values code nil ""))
            ((char= (char line 3) #\Space) (values code nil (subseq line 4)))
            ((char= (char line 3) #\-) (values code t (subseq line 4)))
            (t (fail))))))

(defun parse-enhanced-status (code text)
  "The enhanced status code at the start of TEXT, if it is well-formed and its
class agrees with CODE."
  (let* ((end (or (position #\Space text) (length text)))
         (token (subseq text 0 end))
         (parts (loop with start = 0
                      for pos = (position #\. token :start start)
                      collect (subseq token start pos)
                      while pos do (setf start (1+ pos)))))
    (when (and (= (length parts) 3)
               (every (lambda (p) (and (<= 1 (length p) 3) (every #'digit-char-p p))) parts)
               (= (length (first parts)) 1)
               (= (parse-integer (first parts)) (floor code 100)))
      token)))

(defun assemble-reply (lines)
  "Make a reply from parsed lines, a list of (code . text). Every line must
carry the same code."
  (let ((code (car (first lines))))
    (unless (every (lambda (l) (= (car l) code)) lines)
      (error 'smtp-protocol-error
             :message (format nil "Reply lines disagree about the code: ~{~a~^, ~}"
                              (mapcar #'car lines))))
    (let ((texts (mapcar #'cdr lines)))
      (make-reply code texts (parse-enhanced-status code (first texts))))))
