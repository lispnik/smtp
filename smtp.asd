;;; smtp.asd
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(asdf:defsystem #:smtp/core
  :description "The smtp client without a TLS backend; load smtp or smtp/pure-tls instead."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.2.1"
  :depends-on  ("alexandria" "babel" "usocket")
  :serial t
  :components ((:file "src/package")
               (:file "src/reply")
               (:file "src/conditions")
               (:file "src/tls")
               (:file "src/util")
               (:file "src/encoding")
               (:file "src/idna")
               (:file "src/address")
               (:file "src/mime-types")
               (:file "src/message")
               (:file "src/connection")
               (:file "src/auth")
               (:file "src/transaction")))

(asdf:defsystem #:smtp
  :description "A modern, secure SMTP client and MIME message builder (TLS via OpenSSL)."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.2.1"
  :homepage    "https://github.com/lispnik/smtp"
  :source-control (:git "https://github.com/lispnik/smtp.git")
  :bug-tracker "https://github.com/lispnik/smtp/issues"
  :depends-on  ("smtp/core" "cffi" "cl+ssl")
  :components ((:file "src/tls-openssl"))
  :in-order-to ((asdf:test-op (asdf:test-op "smtp/test"))))

(asdf:defsystem #:smtp/pure-tls
  :description "The smtp client with TLS 1.3 from pure-tls: no foreign libraries."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.2.1"
  :depends-on  ("smtp/core" "pure-tls")
  :components ((:file "src/tls-pure")))

(asdf:defsystem #:smtp/dkim
  :description "DKIM (RFC 6376, RFC 8463) signing for smtp messages."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.2.1"
  :depends-on  ("smtp/core" "ironclad")
  :serial t
  :components ((:file "src/dkim")))

(asdf:defsystem #:smtp/delivery
  :description "Direct delivery to recipients' mail servers: MX lookup, DANE
(RFC 7672), MTA-STS (RFC 8461) and a retry queue."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.2.1"
  :depends-on  ("smtp/core" "ironclad" "bordeaux-threads")
  :serial t
  :components ((:file "src/delivery/package")
               (:file "src/delivery/dns")
               (:file "src/delivery/dane")
               (:file "src/delivery/mta-sts")
               (:file "src/delivery/deliver")
               (:file "src/delivery/queue")))

(asdf:defsystem #:smtp/test
  :description "FiveAM tests for smtp, run against an in-process mock server."
  :author      "Matthew Kennedy"
  :license     "MIT"
  :version     "0.2.1"
  :depends-on  ("smtp" "smtp/pure-tls" "smtp/dkim" "smtp/delivery" "fiveam" "bordeaux-threads")
  :serial t
  :components ((:file "t/package")
               (:file "t/mock-server")
               (:file "t/encoding")
               (:file "t/address")
               (:file "t/message")
               (:file "t/reply")
               (:file "t/protocol")
               (:file "t/tls")
               (:file "t/dkim")
               (:file "t/delivery"))
  :perform (asdf:test-op (o c)
             (unless (uiop:symbol-call :fiveam :run! :smtp)
               (error "smtp tests failed"))))
