;;; tests.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

;;; Messages are sent to Mailpit directly and through Postfix (which relays
;;; them to Mailpit), then read back through Mailpit's API and compared with
;;; what was sent. Mailpit parses with Go's mail libraries, independently of
;;; ours; Postfix is a strict, widely deployed server.

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
   (list (list :name "postfix plain" :server :postfix :port *postfix-smtp-port* :tls :none))
   (loop for backend in '(:openssl :pure-tls)
         collect (list* :name (format nil "postfix STARTTLS ~(~a~)" backend) :server :postfix
                        :port *postfix-smtp-port* :tls :starttls (tls-options backend))
         collect (list* :name (format nil "postfix submission ~(~a~)" backend) :server :postfix
                        :port *postfix-submission-port* :tls :starttls :credentials *credentials*
                        (tls-options backend))
         collect (list* :name (format nil "postfix smtps ~(~a~)" backend) :server :postfix
                        :port *postfix-smtps-port* :tls :implicit :credentials *credentials*
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

(defun addresses (list)
  (map 'list (lambda (a) (j a "Address")) list))

(defun names (list)
  (map 'list (lambda (a) (j a "Name")) list))

;;; Round trips: each message, over every route.

(defparameter *unicode-text*
  (format nil "Grüße aus Zürich! 日本語のテキスト。한국어 텍스트.~%Emoji: ~c~c, and a long line: ~a~%"
          (code-char #x1F600) (code-char #x1F4E7)
          (with-output-to-string (s) (dotimes (i 120) (format s "ü~d " i)))))

(defun check-round-trip (route message &key (text (message-text message)) attachments
                                         (envelope-from nil) (expect-bcc '()))
  "Send MESSAGE over ROUTE and check what arrived: headers, bodies and
ATTACHMENTS, a list of (filename content-type octets)."
  (let* ((result (send-via route message))
         (got (wait-for-message-id (delivery-result-message-id result))))
    (is (equal (message-subject message) (j got "Subject")))
    (is (equal (mailbox-address (message-from message)) (j got "From" "Address")))
    (is (equal (or (mailbox-display-name (message-from message)) "") (j got "From" "Name")))
    (is (equal (mapcar #'mailbox-address (message-to message)) (addresses (j got "To"))))
    (is (equal (mapcar (lambda (m) (or (mailbox-display-name m) "")) (message-to message))
               (names (j got "To"))))
    (when expect-bcc
      ;; Bcc is never sent in the headers. Mailpit works it out from the
      ;; envelope and records it in a Bcc: line of its own, above Return-Path.
      (is (equal expect-bcc (addresses (j got "Bcc"))))
      (let ((raw (babel:octets-to-string (mailpit-raw got) :encoding :latin-1)))
        (is (not (search "Bcc:" raw :start2 (or (search "Return-Path:" raw) 0))))))
    (when text
      (is (same-text-p text (j got "Text"))
          "~a: text body differs:~%sent ~s~%got  ~s" (getf route :name) text (j got "Text")))
    (when (message-html message)
      (is (same-text-p (message-html message) (j got "HTML"))))
    ;; The envelope sender, as recorded by the receiving server.
    (is (equal (format nil "<~a>" (or envelope-from (mailbox-address (message-from message))))
               (first (coerce (gethash "Return-Path" (mailpit-headers got)) 'list))))
    (let ((parts (concatenate 'list (j got "Attachments") (j got "Inline"))))
      (is (= (length attachments) (length parts))
          "~a: expected ~d attachments, got ~d" (getf route :name) (length attachments) (length parts))
      (loop for (filename content-type octets) in attachments
            for part = (find filename parts :key (lambda (p) (j p "FileName")) :test #'equal)
            do (is (not (null part)) "~a: no attachment named ~s among ~s"
                   (getf route :name) filename (map 'list (lambda (p) (j p "FileName")) parts))
               (when part
                 (is (equal content-type (j part "ContentType")))
                 (is (equalp octets (mailpit-part got (j part "PartID")))
                     "~a: attachment ~s content differs" (getf route :name) filename))))
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
                                        :to (list "José <josé@example.test>" "erik@bücher.example")
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
    (let ((report (wait-for (lambda (m)
                              (and (equal (addresses (j m "To")) '("alice@example.test"))
                                   (search "Delivery" (j m "Subject"))))
                            :what "delivery status notification")))
      (is (search (format nil "Original-Envelope-Id: ~a" envid)
                  (babel:octets-to-string (mailpit-raw report) :encoding :latin-1))))))

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
