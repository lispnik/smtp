;;; address.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/address :in :smtp :description "Address parsing and formatting.")
(in-suite :smtp/address)

(test parse-mailbox-forms
  (let ((m (parse-mailbox "alice@example.com")))
    (is (string= "alice" (mailbox-local-part m)))
    (is (string= "example.com" (mailbox-domain m)))
    (is (null (mailbox-display-name m))))
  (is (string= "alice@example.com" (mailbox-address (parse-mailbox "  <alice@example.com> "))))
  (let ((m (parse-mailbox "Alice Liddell <alice@example.com>")))
    (is (string= "Alice Liddell" (mailbox-display-name m)))
    (is (string= "alice@example.com" (mailbox-address m))))
  (let ((m (parse-mailbox "\"Liddell, Alice \\\"Al\\\"\" <alice@example.com>")))
    (is (string= "Liddell, Alice \"Al\"" (mailbox-display-name m))))
  (let ((m (parse-mailbox "\"john smith\"@example.com")))
    (is (string= "john smith" (mailbox-local-part m)))
    (is (string= "\"john smith\"@example.com" (mailbox-address m))))
  (is (string= "first.last+tag@example.com" (mailbox-address (parse-mailbox "first.last+tag@example.com"))))
  (is (string= "user@[192.0.2.1]" (mailbox-address (parse-mailbox "user@[192.0.2.1]"))))
  (is (string= "user@[IPv6:2001:db8::1]" (mailbox-address (parse-mailbox "user@[IPv6:2001:db8::1]")))))

(test internationalized-addresses
  (let ((m (parse-mailbox "user@bücher.example")))
    (is (string= "user@xn--bcher-kva.example" (mailbox-address m)))
    (is (not (mailbox-utf8-p m))))
  (let ((m (parse-mailbox "用户@例え.テスト")))
    (is (mailbox-utf8-p m))
    (is (string= "用户@xn--r8jz45g.xn--zckzah" (mailbox-address m)))))

(test rejects-invalid-addresses
  (dolist (bad (list "" "alice" "alice@" "@example.com" "a..b@example.com" ".a@example.com"
                     "a.@example.com" "a b@example.com" "alice@exa mple.com" "alice@-x.com"
                     "Alice <alice@example.com" "alice@example.com>" "<<a@b.com>>"
                     "user@[300.1.1.1]" "user@[1.2.3]"
                     (format nil "~a@example.com" (make-string 65 :initial-element #\a))
                     (format nil "alice@example.com~cBcc: x@evil.com" #\Return)
                     (format nil "alice@example.com~cRCPT TO:<x@evil.com>" #\Linefeed)
                     (format nil "Alice~c <alice@example.com>" #\Linefeed)
                     (format nil "alice~c@example.com" (code-char 0))))
    (signals invalid-address (parse-mailbox bad))))

(test mailbox-lists
  (let ((list (parse-mailbox-list "a@example.com, \"Doe, John\" <john@example.com>,,  Bob <bob@example.org>")))
    (is (= 3 (length list)))
    (is (string= "Doe, John" (mailbox-display-name (second list))))
    (is (string= "bob@example.org" (mailbox-address (third list)))))
  ;; Unquoted commas separate entries, and "Doe" alone is not an address.
  (signals invalid-address (parse-mailbox-list "Doe, John <john@example.com>")))

(test format-mailbox-quoting-and-encoding
  (is (string= "alice@example.com" (format-mailbox (parse-mailbox "alice@example.com"))))
  (is (string= "Alice <alice@example.com>" (format-mailbox (make-mailbox "alice@example.com" "Alice"))))
  (is (string= "\"Doe, John\" <john@example.com>"
               (format-mailbox (make-mailbox "john@example.com" "Doe, John"))))
  (is (string= "\"a \\\"b\\\" \\\\c\" <x@example.com>"
               (format-mailbox (make-mailbox "x@example.com" "a \"b\" \\c"))))
  (is (string= "=?UTF-8?Q?Ren=C3=A9_Fran=C3=A7ois?= <rene@example.com>"
               (format-mailbox (make-mailbox "rene@example.com" "René François"))))
  (is (string= "René <rene@example.com>"
               (format-mailbox (make-mailbox "rene@example.com" "René") :utf8 t)))
  (signals invalid-address (make-mailbox "x@example.com" (format nil "a~cb" #\Linefeed))))

(test format-parse-round-trip
  (dolist (name '("Alice" "Doe, John" "a \"quoted\" name" "with (parens) and <angles>"
                  "trailing\\backslash" "x@y" "semi;colon"))
    (let* ((m (make-mailbox "user@example.com" name))
           (back (parse-mailbox (format-mailbox m :utf8 t))))
      (is (string= name (mailbox-display-name back)))
      (is (string= "user@example.com" (mailbox-address back))))))

(test stricter-literals-and-a-labels
  (signals invalid-address (parse-mailbox "a@[IPv6::::]"))
  (signals invalid-address (parse-mailbox "a@xn--zzzzzzzzzzzz-.example"))
  (signals invalid-address (domain-to-ascii "xn--a.example"))
  (is (string= "a@[IPv6:::1]" (mailbox-address (parse-mailbox "a@[IPv6:::1]")))))

(test only-ascii-digits-are-numbers
  ;; SBCL's DIGIT-CHAR-P accepts every Unicode decimal digit.
  (signals invalid-address (parse-mailbox (format nil "user@[~c27.0.0.1]" (code-char #x0661))))
  (signals invalid-address (parse-mailbox (format nil "user@[IPv6:~c::1]" (code-char #xFF11))))
  (is (null (smtp::%ip-literal-p (format nil "~c27.0.0.1" (code-char #xFF11))))))
