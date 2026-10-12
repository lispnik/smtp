;;; tests.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

;;; Messages are sent to Mailpit directly, through Postfix (which relays
;;; them to Mailpit) and to Stalwart, then read back through Mailpit's API or
;;; Stalwart's JMAP and compared with what was sent. Mailpit (Go) and
;;; Stalwart (Rust) parse messages with their own libraries, independently
;;; of ours; Postfix is a strict, widely deployed server.

(in-package #:smtp/integration)

(in-suite :smtp/integration)

;;; Routes: ways of reaching a server, each a plist of OPEN-CONNECTION options
;;; plus :name and :server.

(defun tls-options (backend)
  (list :ca-file (certificate "ca.pem") :tls-hostname "localhost" :tls-backend backend))

(defun routes ()
  (append
   (list (list :name "mailpit plain" :server :mailpit :port *mailpit-smtp-port* :tls :none))
   (loop for backend in '(:openssl :pure-tls)
         collect (list* :name (format nil "mailpit STARTTLS ~(~a~)" backend) :server :mailpit
                        :port *mailpit-smtp-port* :tls :starttls (tls-options backend)))
   (submission-routes "postfix" :postfix *postfix-smtp-port* *postfix-submission-port*
                      *postfix-smtps-port* *credentials*)
   (submission-routes "stalwart" :stalwart *stalwart-smtp-port* *stalwart-submission-port*
                      *stalwart-smtps-port* *stalwart-credentials*)))

(defun submission-routes (name server smtp-port submission-port smtps-port credentials)
  "The routes to a full mail server: port 25 in plaintext and with STARTTLS,
and submission with AUTH after STARTTLS and over implicit TLS."
  (append
   (list (list :name (format nil "~a plain" name) :server server :port smtp-port :tls :none))
   (loop for backend in '(:openssl :pure-tls)
         collect (list* :name (format nil "~a STARTTLS ~(~a~)" name backend) :server server
                        :port smtp-port :tls :starttls (tls-options backend))
         collect (list* :name (format nil "~a submission ~(~a~)" name backend) :server server
                        :port submission-port :tls :starttls :credentials credentials
                        (tls-options backend))
         collect (list* :name (format nil "~a smtps ~(~a~)" name backend) :server server
                        :port smtps-port :tls :implicit :credentials credentials
                        (tls-options backend)))))

(defun route (name)
  (or (find name (routes) :key (lambda (r) (getf r :name)) :test #'string=)
      (error "No route ~s" name)))

(defun connection-options (route)
  (let ((options (copy-list route)))
    (remf options :name)
    (remf options :server)
    (list* :local-name "client.example.test" :timeout 30 options)))

(defun send-via (route message &rest send-options)
  (apply #'send-mail *host* message (append send-options (connection-options route))))

(defvar *counter* 0)

(defun unique-id ()
  (format nil "<it-~d-~d-~d@example.test>" (get-universal-time) (random 1000000000) (incf *counter*)))

(defun crlf->lf (string)
  (with-output-to-string (out)
    (loop for i below (length string)
          for c = (char string i)
          unless (and (char= c #\Return) (< (1+ i) (length string))
                      (char= (char string (1+ i)) #\Linefeed))
            do (write-char c out))))

(defun same-text-p (sent received)
  "Bodies compare equal after line endings are normalized, ignoring the
final line break that MIME encoding may add or drop."
  (string= (string-right-trim '(#\Newline) (crlf->lf sent))
           (string-right-trim '(#\Newline) (crlf->lf (or received "")))))

(defun random-octets (n &optional (seed 1))
  (let ((rng (sb-ext:seed-random-state seed))
        (v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (random 256 rng)))))

(defun wait-for-received (route message-id recipient)
  "MESSAGE-ID as received over ROUTE: from Mailpit, or from RECIPIENT's
mailbox on Stalwart."
  (if (eq (getf route :server) :stalwart)
      (wait-for-stalwart recipient message-id)
      (mailpit-received (wait-for-message-id message-id))))

(defun header-values (received name)
  (cdr (assoc name (received-headers received) :test #'string-equal)))

;;; Round trips: each message, over every route.

(defparameter *unicode-text*
  (format nil "Grüße aus Zürich! 日本語のテキスト。한국어 텍스트.~%Emoji: ~c~c, and a long line: ~a~%"
          (code-char #x1F600) (code-char #x1F4E7)
          (with-output-to-string (s) (dotimes (i 120) (format s "ü~d " i)))))

(defun check-round-trip (route message &key (text (message-text message)) attachments
                                         (envelope-from nil) (expect-bcc '()) send-options)
  "Send MESSAGE over ROUTE and check what arrived: headers, bodies and
ATTACHMENTS, a list of (filename content-type octets). Returns the
RECEIVED message."
  (let* ((name (getf route :name))
         (result (apply #'send-via route message send-options))
         (got (wait-for-received route (delivery-result-message-id result)
                                 (or (first expect-bcc) (mailbox-address (first (message-to message))))))
         (from (message-from message)))
    (is (equal (message-subject message) (received-subject got)) "~a: subject" name)
    (is (equal (cons (or (mailbox-display-name from) "") (mailbox-address from)) (received-from got))
        "~a: From ~s" name (received-from got))
    (is (equal (mapcar (lambda (m) (cons (or (mailbox-display-name m) "") (mailbox-address m)))
                       (message-to message))
               (received-to got))
        "~a: To ~s" name (received-to got))
    (when expect-bcc
      ;; Bcc is never sent in the headers. Mailpit works it out from the
      ;; envelope and records it in a Bcc: line of its own, above Return-Path;
      ;; Stalwart delivered it to the Bcc recipient's mailbox.
      (when (eq (getf route :server) :mailpit)
        (is (equal expect-bcc (received-bcc got))))
      (let ((raw (babel:octets-to-string (received-raw got) :encoding :latin-1)))
        (is (not (search (format nil "~%Bcc:") raw :start2 (or (search "Return-Path:" raw) 0)))
            "~a: Bcc header was sent" name)))
    (when text
      (is (same-text-p text (received-text got))
          "~a: text body differs:~%sent ~s~%got  ~s" name text (received-text got)))
    (when (message-html message)
      (is (same-text-p (message-html message) (received-html got)) "~a: HTML body differs" name))
    ;; The envelope sender, as recorded by the receiving server (Stalwart
    ;; records it only for mail arriving on port 25).
    (when (or (not (eq (getf route :server) :stalwart)) (received-return-path got))
      (is (equal (format nil "<~a>" (or envelope-from (mailbox-address from)))
                 (received-return-path got))
          "~a: Return-Path ~s" name (received-return-path got)))
    (let ((parts (received-attachments got)))
      (is (= (length attachments) (length parts))
          "~a: expected ~d attachments, got ~d" name (length attachments) (length parts))
      (loop for (filename content-type octets) in attachments
            for part = (find filename parts :key #'first :test #'equal)
            do (is (not (null part)) "~a: no attachment named ~s among ~s"
                   name filename (mapcar #'first parts))
               (when part
                 (is (equal content-type (second part)) "~a: ~s has type ~s" name filename (second part))
                 (is (equalp octets (third part)) "~a: attachment ~s content differs" name filename))))
    got))

(defmacro def-round-trip (name (route) &body body)
  "A test running BODY once for every route, with ROUTE bound to it."
  `(test ,name
     (dolist (,route (routes))
       ,@body)))

(def-round-trip plain-ascii (route)
  (check-round-trip route (make-message :from "Alice <alice@example.test>"
                                        :to "Bob <bob@example.test>, carol@example.test"
                                        :subject (format nil "Plain ASCII via ~a" (getf route :name))
                                        :text (format nil "Hello Bob,~%~%This is a test.~%")
                                        :message-id (unique-id))))

(def-round-trip unicode-headers-and-body (route)
  (check-round-trip route (make-message :from "Ålice Ünïcode <alice@example.test>"
                                        :to "山田 太郎 <bob@example.test>"
                                        :subject (format nil "Grüße, 日本語, 한국어 ~c — a long subject that has to be folded across several lines (~a)"
                                                         (code-char #x1F600) (getf route :name))
                                        :text *unicode-text*
                                        :message-id (unique-id))))

(def-round-trip utf8-addresses (route)
  ;; SMTPUTF8: a UTF-8 local part and an internationalized domain.
  (check-round-trip route (make-message :from "alice@example.test"
                                        :to (list "José <josé@example.test>" "erik@bücher.test")
                                        :subject (format nil "SMTPUTF8 via ~a" (getf route :name))
                                        :text "Hola."
                                        :message-id (unique-id))))

(def-round-trip attachments (route)
  (let ((binary (random-octets 200000 7))
        (text (babel:string-to-octets (format nil "a,b~%1,2~%") :encoding :utf-8)))
    (check-round-trip route (make-message :from "alice@example.test" :to "bob@example.test"
                                          :subject (format nil "Attachments via ~a" (getf route :name))
                                          :text "See attached."
                                          :attachments (list (make-attachment binary :filename "résumé (final).bin"
                                                                                     :content-type "application/octet-stream")
                                                             (make-attachment text :filename "日本語の表.csv"
                                                                                   :content-type "text/csv"))
                                          :message-id (unique-id))
                      :attachments `(("résumé (final).bin" "application/octet-stream" ,binary)
                                     ("日本語の表.csv" "text/csv" ,text)))))

(def-round-trip html-with-inline-image (route)
  (let ((png (random-octets 3000 3)))
    (check-round-trip route (make-message :from "alice@example.test" :to "bob@example.test"
                                          :subject (format nil "HTML via ~a" (getf route :name))
                                          :text "Plain version."
                                          :html "<p>HTML version with <img src=\"cid:logo@example.test\"> and ünïcödé.</p>"
                                          :attachments (list (make-attachment png :filename "logo.png"
                                                                                  :content-type "image/png"
                                                                                  :inline t
                                                                                  :content-id "logo@example.test"))
                                          :message-id (unique-id))
                      :attachments `(("logo.png" "image/png" ,png)))))

(def-round-trip dots-and-long-lines (route)
  ;; Lines that need dot-stuffing (or none, with BDAT) and lines far beyond
  ;; the 998-octet limit, which must be encoded rather than broken.
  (let ((text (format nil ".~%..leading dots~%. space~%~a~%.~%end~%"
                      (make-string 3000 :initial-element #\x))))
    (check-round-trip route (make-message :from "alice@example.test" :to "bob@example.test"
                                          :subject (format nil "Dots via ~a" (getf route :name))
                                          :text text :message-id (unique-id)))))

(def-round-trip bcc (route)
  (check-round-trip route (make-message :from "alice@example.test" :to "bob@example.test"
                                        :bcc "dave@example.test"
                                        :subject (format nil "Bcc via ~a" (getf route :name))
                                        :text "Blind copy." :message-id (unique-id))
                    :expect-bcc '("dave@example.test")))

(test large-message
  ;; 8 MB of attachment: under Postfix's 10 MB limit once base64-encoded.
  (let ((big (random-octets (* 6 1024 1024) 11)))
    (dolist (name '("mailpit plain" "postfix STARTTLS openssl" "postfix submission pure-tls"))
      (check-round-trip (route name)
                        (make-message :from "alice@example.test" :to "bob@example.test"
                                      :subject (format nil "Large via ~a" name) :text "Big."
                                      :attachments (list (make-attachment big :filename "big.bin"
                                                                              :content-type "application/octet-stream"))
                                      :message-id (unique-id))
                        :attachments `(("big.bin" "application/octet-stream" ,big))))))

;;; Protocol details against Postfix

(defun traced-send (route message &rest send-options)
  "Send MESSAGE and return the result and the client's side of the conversation."
  (let ((lines '()))
    (values (apply #'send-mail *host* message
                   :trace (lambda (direction line) (when (eq direction :client) (push line lines)))
                   (append send-options (connection-options route)))
            (reverse lines))))

(defun simple (subject &rest options)
  ;; OPTIONS come first: the leftmost of duplicate keywords wins.
  (apply #'make-message (append options (list :from "alice@example.test" :to "bob@example.test"
                                              :subject subject :text "Body." :message-id (unique-id)))))

(test bdat-and-data
  (let ((route (route "postfix plain")))
    (multiple-value-bind (result lines) (traced-send route (simple "BDAT"))
      (is (find-if (lambda (l) (search "BDAT" l)) lines))
      (is (not (find "DATA" lines :test #'string=)))
      (wait-for-message-id (delivery-result-message-id result)))
    (multiple-value-bind (result lines) (traced-send route (simple "DATA") :chunking nil)
      (is (find "DATA" lines :test #'string=))
      (is (not (find-if (lambda (l) (search "BDAT" l)) lines)))
      (wait-for-message-id (delivery-result-message-id result)))))

(test rejected-recipients
  (let ((route (route "postfix plain")))
    (let ((c (handler-case (progn (send-via route (simple "Rejected" :to "bob@example.test, nobody@example.test"))
                                  nil)
               (smtp-recipients-rejected (c) c))))
      (is (not (null c)))
      (when c
        (is (equal '("bob@example.test") (smtp-recipients-rejected-accepted c)))
        (is (equal '("nobody@example.test") (mapcar #'car (smtp-recipients-rejected-rejected c))))
        (is (= 550 (reply-code (cdr (first (smtp-recipients-rejected-rejected c))))))))
    ;; With :skip, the message goes to the accepted recipient only.
    (let ((result (send-via route (simple "Skip rejected" :to "bob@example.test, nobody@example.test")
                            :on-rejected-recipient :skip)))
      (is (equal '("bob@example.test") (delivery-result-accepted result)))
      (wait-for-message-id (delivery-result-message-id result)))))

(test relaying-needs-authentication
  ;; Port 25 accepts mail only for its own domains; submission relays
  ;; anywhere once authenticated.
  (signals smtp-recipients-rejected
    (send-via (route "postfix plain") (simple "Relay" :to "someone@example.org")))
  (let ((result (send-via (route "postfix submission openssl") (simple "Relay" :to "someone@example.org"))))
    (wait-for-message-id (delivery-result-message-id result))))

(test submission-without-credentials-is-refused
  (signals smtp-error
    (send-via (list* :name "x" :server :postfix :port *postfix-submission-port* :tls :starttls
                     (tls-options :openssl))
              (simple "No credentials" :to "someone@example.org"))))

(test wrong-password
  (dolist (mechanism '(:plain :login))
    (signals smtp-authentication-failed
      (open-connection *host* :port *postfix-submission-port* :tls :starttls
                              :credentials '(:username "user@example.test" :password "wrong")
                              :auth-mechanism mechanism
                              :local-name "client.example.test"
                              :ca-file (certificate "ca.pem") :tls-hostname "localhost"))))

(test auth-mechanisms
  (dolist (mechanism '(:plain :login))
    (let ((c (open-connection *host* :port *postfix-submission-port* :tls :starttls
                                     :credentials *credentials* :auth-mechanism mechanism
                                     :local-name "client.example.test"
                                     :ca-file (certificate "ca.pem") :tls-hostname "localhost")))
      (unwind-protect
           (is (wait-for-message-id
                (delivery-result-message-id (send-message c (simple (format nil "AUTH ~a" mechanism))))))
        (close-connection c)))))

(test no-credentials-without-tls
  ;; Port 587 offers AUTH only after STARTTLS; without TLS the client must
  ;; fail without ever sending them.
  (let ((lines '()))
    (signals smtp-error
      (open-connection *host* :port *postfix-submission-port* :tls :none
                              :credentials *credentials* :local-name "client.example.test"
                              :trace (lambda (direction line)
                                       (when (eq direction :client) (push line lines)))))
    (is (notany (lambda (l) (search "AUTH" l)) lines))))

(test certificate-verification
  ;; Without the test CA, the server's certificate is not trusted; with the
  ;; wrong name, it does not match.
  (dolist (backend '(:openssl :pure-tls))
    (signals smtp-tls-error
      (open-connection *host* :port *postfix-smtp-port* :tls :starttls :tls-backend backend
                              :local-name "client.example.test" :tls-hostname "localhost"))
    (signals smtp-tls-error
      (open-connection *host* :port *postfix-smtp-port* :tls :starttls :tls-backend backend
                              :local-name "client.example.test"
                              :ca-file (certificate "ca.pem") :tls-hostname "mail.example.org"))))

(test message-too-large
  ;; Postfix advertises SIZE 10485760: the client refuses before sending, and
  ;; the connection is still usable.
  (let ((c (apply #'open-connection *host* (connection-options (route "postfix plain")))))
    (unwind-protect
         (progn
           (signals smtp-message-too-large
             (send-message c (simple "Too large"
                                     :attachments (list (make-attachment (random-octets (* 9 1024 1024))
                                                                         :filename "huge.bin")))))
           (wait-for-message-id (delivery-result-message-id (send-message c (simple "After too large")))))
      (close-connection c))))

(test several-messages-per-connection
  (let ((c (apply #'open-connection *host* (connection-options (route "postfix STARTTLS openssl"))))
        (ids '()))
    (unwind-protect
         (dotimes (i 20)
           (push (delivery-result-message-id (send-message c (simple (format nil "Same connection ~d" i))))
                 ids))
      (close-connection c))
    (is (= 20 (length (remove-duplicates ids :test #'equal))))
    (dolist (id ids) (is (wait-for-message-id id)))))

(test delivery-status-notification
  ;; Postfix sends a "relayed" DSN when it hands the message to Mailpit,
  ;; which does not support DSN itself.
  (let* ((envid (format nil "it~d" (random 1000000000)))
         (result (send-via (route "postfix plain") (simple "DSN")
                           :dsn-notify '(:success) :dsn-return :headers :dsn-envelope-id envid)))
    (wait-for-message-id (delivery-result-message-id result))
    ;; Earlier runs' reports may still be in Mailpit: find this one by its
    ;; envelope id.
    (is (wait-for (lambda (m)
                    (and (equal (map 'list (lambda (a) (j a "Address")) (j m "To")) '("alice@example.test"))
                         (search "Delivery" (j m "Subject"))
                         (search (format nil "Original-Envelope-Id: ~a" envid)
                                 (babel:octets-to-string (mailpit-raw m) :encoding :latin-1))))
                  :what "delivery status notification"))))

(test connection-pool
  (let ((pool (apply #'make-connection-pool *host* :max-connections 4
                     (connection-options (route "postfix submission openssl"))))
        (ids '())
        (lock (bt:make-lock)))
    (flet ((worker (th)
             (lambda ()
               (dotimes (i 10)
                 (let ((r (pool-send-message pool (simple (format nil "Pool ~d/~d" th i)))))
                   (bt:with-lock-held (lock)
                     (push (delivery-result-message-id r) ids)))))))
      (unwind-protect
           (mapc #'bt:join-thread (loop for th below 8 collect (bt:make-thread (worker th))))
        (close-connection-pool pool)))
    (is (= 80 (length (remove-duplicates ids :test #'equal))))
    (dolist (id ids) (is (wait-for-message-id id)))))

;;; DKIM, verified by Stalwart against the keys published by the dns service
;;; (integration/dns). Stalwart records its verdicts in Authentication-Results
;;; for mail arriving on port 25.

(defun dkim-key (name)
  (asdf:system-relative-pathname "smtp" (format nil "t/fixtures/~a" name)))

(defun signer (selector &rest options &key (domain "example.test") &allow-other-keys)
  (remf options :domain)
  (apply #'smtp/dkim:make-dkim-signer :domain domain :selector selector
         :private-key (dkim-key (if (equal selector "ed") "dkim-ed25519.pem" "dkim-rsa-pkcs8.pem"))
         options))

(defun dkim-results (received)
  "The DKIM verdicts in RECEIVED's Authentication-Results, as a list of
(selector . result) strings, and the DMARC result."
  (let ((ar (format nil "~{~a~^; ~}" (header-values received "Authentication-Results")))
        (dkim '()))
    (loop with start = 0
          for i = (search "dkim=" ar :start2 start)
          while i
          do (let* ((end (or (position #\; ar :start i) (length ar)))
                    (clause (subseq ar i end))
                    (result (subseq clause 5 (position-if (lambda (c) (member c '(#\Space #\())) clause :start 5)))
                    (s (search "header.s=" clause)))
               (push (cons (and s (subseq clause (+ s 9) (position #\Space clause :start s))) result) dkim)
               (setf start end)))
    (values (sort dkim #'string< :key #'car)
            (let ((i (search "dmarc=" ar)))
              (and i (subseq ar (+ i 6) (position-if (lambda (c) (member c '(#\Space #\; #\())) ar :start (+ i 6))))))))

(defun send-signed (message signers &rest send-options &key (route "stalwart plain") &allow-other-keys)
  "Send MESSAGE signed by SIGNERS to Stalwart; return the DKIM verdicts and
the DMARC result."
  (remf send-options :route)
  (let ((result (apply #'send-via (route route) message :dkim signers send-options)))
    (dkim-results (wait-for-stalwart (mailbox-address (first (message-to message)))
                                     (delivery-result-message-id result)))))

(defun dkim-test-messages ()
  "Messages whose canonicalization is not trivial: Unicode headers folded
over several lines, attachments, HTML, dot-stuffed and over-long lines."
  (list (make-message :from "Ålice Ünïcode <alice@example.test>" :to "山田 太郎 <bob@example.test>"
                      :cc "carol@example.test"
                      :subject (format nil "Grüße, 日本語 ~c — a subject long enough to be folded across lines" (code-char #x1F600))
                      :text *unicode-text* :message-id (unique-id)
                      :headers '(("X-Extra" . "  spaces   inside  and trailing   ")))
        (make-message :from "alice@example.test" :to "bob@example.test" :subject "DKIM attachments"
                      :text "See attached." :html "<p>HTML <b>part</b></p>" :message-id (unique-id)
                      :attachments (list (make-attachment (random-octets 100000 5) :filename "data.bin")
                                         (make-attachment (random-octets 2000 6) :filename "logo.png"
                                                                                 :content-type "image/png"
                                                                                 :inline t :content-id "logo@example.test")))
        (make-message :from "alice@example.test" :to "bob@example.test" :subject "DKIM dots"
                      :text (format nil ".~%..two~%~a~%trailing spaces   ~%~%~%" (make-string 2000 :initial-element #\y))
                      :message-id (unique-id))))

(test dkim-signatures-verify
  ;; Both algorithms, every canonicalization, over DATA and BDAT.
  (dolist (canonicalization '((:relaxed :relaxed) (:simple :simple) (:relaxed :simple) (:simple :relaxed)))
    (dolist (chunking '(:auto nil))
      (dolist (message (dkim-test-messages))
        (multiple-value-bind (dkim dmarc)
            (send-signed message (list (signer "rsa" :canonicalization canonicalization)
                                       (signer "ed" :canonicalization canonicalization))
                         :chunking chunking)
          (is (equal '(("ed" . "pass") ("rsa" . "pass")) dkim)
              "~s ~s, chunking ~s: ~s" (message-subject message) canonicalization chunking dkim)
          (is (equal "pass" dmarc) "~s: DMARC ~s" (message-subject message) dmarc))))))

(test dkim-over-tls
  (dolist (route '("stalwart STARTTLS openssl" "stalwart STARTTLS pure-tls"))
    (is (equal '(("ed" . "pass") ("rsa" . "pass"))
               (send-signed (simple (format nil "DKIM over ~a" route))
                            (list (signer "rsa") (signer "ed")) :route route)))))

(test dkim-options
  ;; Expiration, an identity, and signing headers that are absent.
  (is (equal '(("rsa" . "pass"))
             (send-signed (simple "DKIM options")
                          (list (signer "rsa" :expiration 3600 :identity "alice@example.test"
                                              :headers '("From" "To" "Subject" "Date" "Message-ID"
                                                         "Reply-To" "In-Reply-To" "List-Id")))))))

(test dkim-wrong-key-fails
  ;; The "wrong" selector publishes a different key: Stalwart must report a
  ;; failure, which also shows the passing tests are not vacuous.
  (multiple-value-bind (dkim dmarc) (send-signed (simple "DKIM wrong key") (list (signer "wrong")))
    (is (equal '(("wrong" . "fail")) dkim))
    (is (equal "fail" dmarc))))

(test dkim-internationalized-domain
  ;; d= is the A-label of bücher.test, which Stalwart looks up in DNS.
  (is (equal '(("ed" . "pass"))
             (send-signed (make-message :from "Erik <erik@bücher.test>" :to "bob@example.test"
                                        :subject "DKIM for bücher.test" :text "Hej." :message-id (unique-id))
                          (list (signer "ed" :domain "bücher.test"))))))

;;; Stalwart's own rules

(test stalwart-rejections
  (let ((c (handler-case (progn (send-via (route "stalwart plain")
                                          (simple "Rejected" :to "bob@example.test, nobody@example.test"))
                                nil)
             (smtp-recipients-rejected (c) c))))
    (is (not (null c)))
    (when c
      (is (equal '("nobody@example.test") (mapcar #'car (smtp-recipients-rejected-rejected c))))
      (is (<= 500 (reply-code (cdr (first (smtp-recipients-rejected-rejected c)))) 599))))
  ;; No relaying without authentication.
  (signals smtp-recipients-rejected
    (send-via (route "stalwart plain") (simple "Relay" :to "someone@example.org")))
  ;; An authenticated account may send only as itself.
  (signals smtp-permanent-error
    (send-via (route "stalwart submission openssl")
              (simple "Spoofed" :from "carol@example.test")))
  (dolist (mechanism '(:plain :login))
    (signals smtp-authentication-failed
      (open-connection *host* :port *stalwart-submission-port* :tls :starttls
                              :credentials (list :username "alice@example.test" :password "wrong password")
                              :auth-mechanism mechanism :local-name "client.example.test"
                              :ca-file (certificate "ca.pem") :tls-hostname "localhost"))))

(test stalwart-bdat-and-data
  (dolist (chunking '(:auto nil))
    (multiple-value-bind (result lines)
        (traced-send (route "stalwart STARTTLS openssl") (simple (format nil "Chunking ~s" chunking))
                     :chunking chunking)
      (is (eq (eq chunking :auto) (and (find-if (lambda (l) (search "BDAT" l)) lines) t)))
      (is (wait-for-stalwart "bob@example.test" (delivery-result-message-id result))))))

(test stalwart-no-credentials-without-tls
  ;; Before STARTTLS, Stalwart's port 587 offers AUTH (OAUTHBEARER and
  ;; XOAUTH2), so the client itself must refuse to send credentials.
  (let ((lines '()))
    (signals smtp-insecure-authentication
      (open-connection *host* :port *stalwart-submission-port* :tls :none
                              :credentials (list :username "alice@example.test" :oauth2-token "token")
                              :local-name "client.example.test"
                              :trace (lambda (direction line)
                                       (when (eq direction :client) (push line lines)))))
    (is (notany (lambda (l) (search "AUTH" l)) lines))))
