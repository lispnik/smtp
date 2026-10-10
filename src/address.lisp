;;; address.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Mailboxes: parsing, validation and formatting (RFC 5321, RFC 5322,
;;; RFC 6531/6532 for internationalized addresses).

(in-package #:smtp)

(defstruct (mailbox (:constructor %make-mailbox (local-part domain display-name)))
  "An email address with an optional display name. LOCAL-PART is the
unquoted local part; DOMAIN is the domain as given (possibly Unicode) or an
address literal such as \"[192.0.2.1]\"."
  (local-part "" :type string :read-only t)
  (domain "" :type string :read-only t)
  (display-name nil :type (or null string) :read-only t))

(defmethod print-object ((m mailbox) stream)
  (print-unreadable-object (m stream :type t)
    (format stream "~a" (format-mailbox m :utf8 t))))

(defun %address-error (address fmt &rest args)
  (error 'invalid-address :address address :message (apply #'format nil fmt args)))

(defun %check-no-controls (string what)
  (when (find-if #'control-char-p string)
    (%address-error string "~a contains a control character or line break" what)))

;;; Local parts

(defun %dot-atom-p (string)
  (and (plusp (length string))
       (char/= (char string 0) #\.)
       (char/= (char string (1- (length string))) #\.)
       (not (search ".." string))
       (every (lambda (c) (or (char= c #\.) (atext-char-p c))) string)))

(defun %unquote (string address)
  "The content of quoted-string STRING (including its quotes), unescaped."
  (with-output-to-string (s)
    (loop with i = 1
          with end = (1- (length string))
          while (< i end)
          do (let ((c (char string i)))
               (cond ((char= c #\\)
                      (when (>= (1+ i) end)
                        (%address-error address "dangling backslash in quoted string"))
                      (write-char (char string (1+ i)) s)
                      (incf i 2))
                     ((char= c #\")
                      (%address-error address "unescaped quote in quoted string"))
                     (t (write-char c s) (incf i)))))))

(defun %quoted-p (string)
  (and (>= (length string) 2)
       (char= (char string 0) #\")
       (char= (char string (1- (length string))) #\")))

(defun %format-local-part (local)
  (if (%dot-atom-p local) local (%quote-string local)))

;;; Domains

(defun %validate-address-literal (literal address)
  (let ((inner (subseq literal 1 (1- (length literal)))))
    (cond ((string-prefix-p "IPv6:" inner)
           (let* ((v6 (subseq inner 5))
                  (groups (loop with start = 0
                                for pos = (position #\: v6 :start start)
                                collect (subseq v6 start pos)
                                while pos do (setf start (1+ pos)))))
             (unless (and (every (lambda (c) (or (digit-char-p c 16) (find c ":."))) v6)
                          (<= 3 (length groups) 8)
                          (<= (count "" groups :test #'string=) 3)
                          (<= (count-if (lambda (g) (zerop (length g))) (butlast (rest groups))) 1)
                          (every (lambda (g) (or (<= (length g) 4) (find #\. g))) groups))
               (%address-error address "invalid IPv6 address literal"))))
          (t
           (let ((parts (loop with start = 0
                              for pos = (position #\. inner :start start)
                              collect (subseq inner start pos)
                              while pos do (setf start (1+ pos)))))
             (unless (and (= (length parts) 4)
                          (every (lambda (p)
                                   (and (<= 1 (length p) 3)
                                        (every #'digit-char-p p)
                                        (<= (parse-integer p) 255)))
                                 parts))
               (%address-error address "invalid IPv4 address literal")))))))

(defun %address-literal-p (domain)
  (and (plusp (length domain)) (char= (char domain 0) #\[)))

(defun %ascii-domain (domain)
  (if (%address-literal-p domain) domain (domain-to-ascii domain)))

;;; Parsing

(defun %find-unquoted (char string &key from-end)
  "Position of CHAR in STRING outside quoted strings."
  (let ((in-quote nil) (escape nil) (found nil))
    (loop for i from 0 below (length string)
          for c = (char string i)
          do (cond (escape (setf escape nil))
                   ((and in-quote (char= c #\\)) (setf escape t))
                   ((char= c #\") (setf in-quote (not in-quote)))
                   ((and (not in-quote) (char= c char))
                    (setf found i)
                    (unless from-end (return)))))
    found))

(defun %parse-addr-spec (spec original display-name)
  (let ((at (%find-unquoted #\@ spec :from-end t)))
    (unless at (%address-error original "missing @"))
    (let ((raw-local (subseq spec 0 at))
          (domain (subseq spec (1+ at))))
      (when (zerop (length raw-local)) (%address-error original "empty local part"))
      (when (zerop (length domain)) (%address-error original "empty domain"))
      (let ((local (cond ((%quoted-p raw-local) (%unquote raw-local original))
                         ((%dot-atom-p raw-local) raw-local)
                         (t (%address-error original "invalid local part ~s" raw-local)))))
        (when (> (length (utf8-octets (%format-local-part local))) 64)
          (%address-error original "local part is longer than 64 octets"))
        (if (%address-literal-p domain)
            (progn
              (unless (char= (char domain (1- (length domain))) #\])
                (%address-error original "unterminated address literal"))
              (%validate-address-literal domain original))
            (handler-case (domain-to-ascii domain)
              (invalid-address (e)
                (%address-error original "invalid domain: ~a" (smtp-error-message e)))))
        (let ((mailbox (%make-mailbox local domain display-name)))
          (when (> (length (utf8-octets (mailbox-address mailbox))) 254)
            (%address-error original "address is longer than 254 octets"))
          mailbox)))))

(defun %parse-display-name (raw original)
  (let ((name (string-trim '(#\Space #\Tab) raw)))
    (cond ((zerop (length name)) nil)
          ((%quoted-p name) (let ((s (%unquote name original)))
                              (if (zerop (length s)) nil s)))
          (t name))))

(defun parse-mailbox (string)
  "Parse STRING as one mailbox: \"local@domain\", \"<local@domain>\" or
\"Display Name <local@domain>\" (the name may be quoted). Signals
INVALID-ADDRESS for anything that is not a valid, safely transmissible
address."
  (check-type string string)
  (%check-no-controls string "address")
  (let ((s (string-trim '(#\Space #\Tab) string)))
    (when (zerop (length s)) (%address-error string "empty address"))
    (if (char= (char s (1- (length s))) #\>)
        (let ((open (%find-unquoted #\< s :from-end t)))
          (unless open (%address-error string "unbalanced angle brackets"))
          (let ((spec (subseq s (1+ open) (1- (length s))))
                (name (%parse-display-name (subseq s 0 open) string)))
            (when (or (find #\< spec) (find #\> spec))
              (%address-error string "unbalanced angle brackets"))
            (%parse-addr-spec spec string name)))
        (progn
          (when (or (%find-unquoted #\< s) (%find-unquoted #\> s))
            (%address-error string "unbalanced angle brackets"))
          (when (%find-unquoted #\Space s)
            (%address-error string "unexpected whitespace; use \"Name <address>\""))
          (%parse-addr-spec s string nil)))))

(defun parse-mailbox-list (string)
  "Parse a comma-separated list of mailboxes."
  (check-type string string)
  (let ((items '()) (start 0) (in-quote nil) (escape nil) (in-angle nil))
    (loop for i from 0 below (length string)
          for c = (char string i)
          do (cond (escape (setf escape nil))
                   ((and in-quote (char= c #\\)) (setf escape t))
                   ((char= c #\") (setf in-quote (not in-quote)))
                   (in-quote)
                   ((char= c #\<) (setf in-angle t))
                   ((char= c #\>) (setf in-angle nil))
                   ((and (char= c #\,) (not in-angle))
                    (push (subseq string start i) items)
                    (setf start (1+ i)))))
    (push (subseq string start) items)
    (loop for item in (nreverse items)
          unless (every #'wsp-char-p item)
            collect (parse-mailbox item))))

(defun make-mailbox (address &optional display-name)
  "A mailbox for the bare ADDRESS (local@domain) with DISPLAY-NAME."
  (check-type address string)
  (when display-name
    (check-type display-name string)
    (%check-no-controls display-name "display name"))
  (%check-no-controls address "address")
  (%parse-addr-spec (string-trim '(#\Space #\Tab) address) address
                    (and display-name (plusp (length display-name)) display-name)))

(defun ensure-mailbox (designator)
  (etypecase designator
    (mailbox designator)
    (string (parse-mailbox designator))))

(defun ensure-mailbox-list (designator)
  (etypecase designator
    (null '())
    (mailbox (list designator))
    (string (parse-mailbox-list designator))
    (list (mapcar #'ensure-mailbox designator))))

;;; Formatting

(defun mailbox-utf8-p (mailbox)
  "True if MAILBOX's local part needs SMTPUTF8 (RFC 6531)."
  (not (ascii-p (mailbox-local-part mailbox))))

(defun mailbox-address (mailbox)
  "The address as it appears on the wire: local@domain with an ASCII domain."
  (format nil "~a@~a" (%format-local-part (mailbox-local-part mailbox))
          (%ascii-domain (mailbox-domain mailbox))))

(defun %format-phrase (phrase utf8)
  (cond ((and (not utf8) (not (ascii-p phrase)))
         (format nil "~{~a~^ ~}" (encode-header-words phrase)))
        ((and (not (search "=?" phrase))
              (let ((words (loop with start = 0
                                 for pos = (position #\Space phrase :start start)
                                 collect (subseq phrase start pos)
                                 while pos do (setf start (1+ pos)))))
                (every (lambda (w) (and (plusp (length w)) (every #'atext-char-p w))) words)))
         phrase)
        (t (%quote-string phrase))))

(defun format-mailbox (mailbox &key utf8)
  "MAILBOX formatted for a header. Display names are quoted when needed and
encoded as RFC 2047 words when non-ASCII, unless UTF8 (RFC 6532) is true."
  (let ((address (mailbox-address mailbox))
        (name (mailbox-display-name mailbox)))
    (if name
        (format nil "~a <~a>" (%format-phrase name utf8) address)
        address)))

(defun mailbox= (a b)
  "Whether A and B are the same address: the local part compares exactly and
the domain without regard to case."
  (and (string= (mailbox-local-part a) (mailbox-local-part b))
       (string= (%ascii-domain (mailbox-domain a)) (%ascii-domain (mailbox-domain b)))))
