;;; package.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(defpackage #:smtp/test
  (:use #:cl #:fiveam #:smtp)
  (:local-nicknames (#:d #:smtp/delivery)))

(in-package #:smtp/test)

(def-suite :smtp :description "All smtp tests.")

(defun fixture (name)
  (asdf:system-relative-pathname "smtp" (format nil "t/fixtures/~a" name)))

(defun octets (string)
  (babel:string-to-octets string :encoding :utf-8))

(defun text (octets)
  (babel:octets-to-string octets :encoding :utf-8))

(defun crlf (&rest lines)
  "LINES joined with CRLF."
  (format nil "~{~a~^~c~c~}"
          (loop for (l . more) on lines collect l when more collect #\Return and collect #\Linefeed)))

(defun lines-of (string)
  "STRING split at CRLF. Signals an error on a bare CR or LF."
  (let ((lines '()) (start 0))
    (loop for i from 0 below (length string)
          for c = (char string i)
          do (cond ((and (char= c #\Return) (< (1+ i) (length string))
                         (char= (char string (1+ i)) #\Linefeed))
                    (push (subseq string start i) lines)
                    (setf start (+ i 2)))
                   ((and (char= c #\Linefeed) (or (zerop i) (char/= (char string (1- i)) #\Return)))
                    (error "bare LF at ~d" i))
                   ((and (char= c #\Return) (not (and (< (1+ i) (length string))
                                                      (char= (char string (1+ i)) #\Linefeed))))
                    (error "bare CR at ~d" i))))
    (push (subseq string start) lines)
    (nreverse lines)))

(defun random-string (length &key (alphabet nil))
  "A random string; by default mixing ASCII, Latin, CJK, emoji, whitespace and
line breaks."
  (let ((pool (or alphabet
                  (concatenate 'string
                               "abcxyzABC0189 .=_-?!\"'\\<>@,;:()[]"
                               (string #\Tab) (string #\Newline) (string #\Return)
                               "éüñßøÅçЖж中文字日本語한국어"
                               (string (code-char #x1F600)) (string (code-char #x1F4E7))))))
    (let ((s (make-string length)))
      (dotimes (i length s)
        (setf (char s i) (char pool (random (length pool))))))))

(defun string-prefix-p (prefix string)
  (and (<= (length prefix) (length string))
       (string= prefix string :end2 (length prefix))))
