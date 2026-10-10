;;; reply.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/reply :in :smtp :description "Reply parsing and data preparation.")
(in-suite :smtp/reply)

(test parse-reply-lines
  (is (equal '(250 nil "OK") (multiple-value-list (smtp::parse-reply-line "250 OK"))))
  (is (equal '(250 t "SIZE 100") (multiple-value-list (smtp::parse-reply-line "250-SIZE 100"))))
  (is (equal '(354 nil "") (multiple-value-list (smtp::parse-reply-line "354"))))
  (dolist (bad '("" "25" "OK" "2500 x" "250x" "600 x" "190 x" "2a0 x" "260 x"))
    (signals smtp-protocol-error (smtp::parse-reply-line bad))))

(test assemble-replies
  (let ((r (smtp::assemble-reply '((250 . "mail.test") (250 . "PIPELINING") (250 . "SIZE 10")))))
    (is (= 250 (reply-code r)))
    (is (equal '("mail.test" "PIPELINING" "SIZE 10") (reply-lines r))))
  (signals smtp-protocol-error (smtp::assemble-reply '((250 . "a") (550 . "b")))))

(test enhanced-status-codes
  (is (string= "5.1.1" (reply-enhanced-status (smtp::assemble-reply '((550 . "5.1.1 No such user"))))))
  (is (string= "2.0.0" (reply-enhanced-status (smtp::assemble-reply '((250 . "2.0.0 OK"))))))
  ;; The class must agree with the reply code.
  (is (null (reply-enhanced-status (smtp::assemble-reply '((550 . "2.1.1 odd"))))))
  (is (null (reply-enhanced-status (smtp::assemble-reply '((250 . "1.2 not one")))))))

(test prepare-data-canonicalizes-and-stuffs
  (flet ((prep (string &rest args)
           (text (apply #'smtp::prepare-data (octets string) args))))
    (is (string= (crlf "a" "b" "") (prep (format nil "a~%b"))))
    (is (string= (crlf "a" "b" "c" "") (prep (format nil "a~c~cb~cc~c" #\Return #\Linefeed #\Return #\Linefeed))))
    (is (string= (crlf ".." "..x" "y.z" "") (prep (format nil ".~%.x~%y.z~%"))))
    (is (string= (crlf "." ".x" "") (prep (format nil ".~%.x") :dot-stuff nil)))
    (is (string= "" (prep "")))
    (signals mail-format-error (prep (make-string 999 :initial-element #\a)))))

(test prepare-data-defeats-smuggling
  ;; Sequences that some servers treat as end of data must not end it here:
  ;; after preparation the only way a line can be "." is the real terminator.
  (dolist (payload (list (format nil "x~c.~cMAIL FROM:<evil@x>" #\Linefeed #\Linefeed)
                         (format nil "x~c.~c~cRCPT TO:<evil@x>" #\Linefeed #\Return #\Linefeed)
                         (format nil "x~c~c.~cDATA" #\Return #\Linefeed #\Linefeed)
                         (format nil "x~c.~cQUIT" #\Return #\Return)
                         (format nil "x~c~c.~c~cQUIT" #\Return #\Linefeed #\Return #\Linefeed)))
    (let ((lines (lines-of (text (smtp::prepare-data (octets payload))))))
      (is (notany (lambda (l) (string= l ".")) lines)))))

(test random-tokens
  (let ((tokens (loop repeat 1000 collect (smtp::random-token 16))))
    (is (= 1000 (length (remove-duplicates tokens :test #'string=))))
    (is (every (lambda (tk) (= 26 (length tk))) tokens))
    (is (every (lambda (tk) (every (lambda (c) (find c "abcdefghijklmnopqrstuvwxyz234567")) tk)) tokens))))
