;;; smtp.asd
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(asdf:defsystem #:smtp
  :description "A modern, secure SMTP client and MIME message builder."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.1.0"
  :homepage    "https://github.com/lispnik/smtp"
  :source-control (:git "https://github.com/lispnik/smtp.git")
  :bug-tracker "https://github.com/lispnik/smtp/issues"
  :depends-on  ("alexandria" "babel" "cffi" "usocket" "cl+ssl")
  :serial t
  :components ((:file "src/package")
               (:file "src/reply")
               (:file "src/conditions")
               (:file "src/util")
               (:file "src/encoding")
               (:file "src/idna")
               (:file "src/address")
               (:file "src/mime-types")
               (:file "src/message")
               (:file "src/connection")
               (:file "src/auth")
               (:file "src/transaction"))
  :in-order-to ((asdf:test-op (asdf:test-op "smtp/test"))))

(asdf:defsystem #:smtp/dkim
  :description "DKIM (RFC 6376, RFC 8463) signing for smtp messages."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.1.0"
  :depends-on  ("smtp" "ironclad")
  :serial t
  :components ((:file "src/dkim")))

(asdf:defsystem #:smtp/test
  :description "FiveAM tests for smtp, run against an in-process mock server."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.1.0"
  :depends-on  ("smtp" "smtp/dkim" "fiveam" "bordeaux-threads")
  :serial t
  :components ((:file "t/package")
               (:file "t/mock-server")
               (:file "t/encoding")
               (:file "t/address")
               (:file "t/message")
               (:file "t/reply")
               (:file "t/protocol")
               (:file "t/tls")
               (:file "t/dkim"))
  :perform (asdf:test-op (o c)
             (unless (uiop:symbol-call :fiveam :run! :smtp)
               (error "smtp tests failed"))))
