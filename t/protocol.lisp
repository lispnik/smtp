;;; protocol.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/protocol :in :smtp :description "SMTP conversations with a mock server.")
(in-suite :smtp/protocol)

(defun message-text-of (session &optional (n 0))
  (text (third (nth n (session-messages session)))))

(test send-plain-message
  (with-mock-server (port s (standard-server))
    (let ((result (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
                    (send-message c (make-message :from "Alice <alice@example.com>"
                                                  :to "bob@example.net"
                                                  :cc "carol@example.org"
                                                  :bcc "dave@example.com"
                                                  :subject "Hi" :text "Hello")))))
      (is (equal '("bob@example.net" "carol@example.org" "dave@example.com")
                 (delivery-result-accepted result)))
      (is (= 250 (reply-code (delivery-result-reply result))))
      (is (string-prefix-p "<" (delivery-result-message-id result))))
    (is (equal '("EHLO client.test") (sent-commands s "EHLO")))
    (is (equal '("MAIL FROM:<alice@example.com>") (sent-commands s "MAIL")))
    (is (= 3 (length (sent-commands s "RCPT"))))
    (is (equal '("QUIT") (sent-commands s "QUIT")))
    (destructuring-bind (from rcpts data) (first (session-messages s))
      (is (string= "alice@example.com" from))
      (is (equal '("bob@example.net" "carol@example.org" "dave@example.com") rcpts))
      (is (null (search "dave@example.com" (text data)))))
    (is (null (session-violations s)))
    (is (null (session-error s)))))

(test send-mail-convenience
  (with-mock-server (port s (standard-server))
    (send-mail "127.0.0.1" (simple-message) :port port :tls :none :local-name "client.test")
    (is (= 1 (length (session-messages s))))))

(test helo-fallback
  (with-mock-server (port s (standard-server :ehlo-reply "502 5.5.1 EHLO not supported"))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (is (null (connection-extensions c)))
      (send-message c (simple-message)))
    (is (equal '("HELO client.test") (sent-commands s "HELO")))
    (is (= 1 (length (session-messages s))))))

(test starttls-required-by-default
  (with-mock-server (port s (standard-server))
    (signals smtp-unsupported-extension
      (open-connection "127.0.0.1" :port port :local-name "client.test" :timeout 5))
    ;; The client said goodbye and never sent mail.
    (is (null (sent-commands s "MAIL")))))

(test opportunistic-tls-falls-back-to-plaintext
  (with-mock-server (port s (standard-server))
    (with-connection (c "127.0.0.1" :port port :tls :opportunistic :local-name "client.test")
      (is (not (connection-tls-p c)))
      (send-message c (simple-message)))
    (is (= 1 (length (session-messages s))))))

(test no-credentials-over-plaintext
  (with-mock-server (port s (standard-server :extensions '("AUTH PLAIN LOGIN")))
    (signals smtp-insecure-authentication
      (connect port :credentials '(:username "alice" :password "secret")))
    (is (null (sent-commands s "AUTH")))))

(test auth-plain-and-login
  (with-mock-server (port s (standard-server :extensions '("AUTH PLAIN LOGIN")))
    (let ((c (connect port :credentials '(:username "alice" :password "secret")
                           :allow-insecure-auth t)))
      (is (connection-authenticated-p c))
      (close-connection c))
    (is (string-prefix-p "AUTH PLAIN " (first (sent-commands s "AUTH")))))
  (with-mock-server (port s (standard-server :extensions '("AUTH LOGIN")))
    (let ((c (connect port :credentials '(:username "alice" :password "secret")
                           :allow-insecure-auth t)))
      (is (connection-authenticated-p c))
      (close-connection c))
    (is (equal '("AUTH LOGIN") (sent-commands s "AUTH"))))
  (with-mock-server (port s (standard-server :extensions '("AUTH PLAIN LOGIN")))
    (let ((c (connect port :credentials '(:username "alice" :password "secret")
                           :auth-mechanism :login :allow-insecure-auth t)))
      (close-connection c))
    (is (equal '("AUTH LOGIN") (sent-commands s "AUTH")))))

(test auth-failure
  (with-mock-server (port s (standard-server :extensions '("AUTH PLAIN")))
    (let ((condition (handler-case
                         (connect port :credentials '(:username "alice" :password "wrong")
                                       :allow-insecure-auth t)
                       (smtp-authentication-failed (e) e))))
      (is (typep condition 'smtp-authentication-failed))
      (is (= 535 (reply-code (smtp-error-reply condition))))
      (is (string= "5.7.8" (reply-enhanced-status (smtp-error-reply condition)))))))

(test auth-mechanism-unavailable
  (with-mock-server (port s (standard-server :extensions '("AUTH CRAM-MD5")))
    (signals smtp-unsupported-extension
      (connect port :credentials '(:username "alice" :password "secret") :allow-insecure-auth t)))
  (with-mock-server (port s (standard-server :extensions '()))
    (signals smtp-unsupported-extension
      (connect port :credentials '(:username "alice" :password "secret") :allow-insecure-auth t))))

(test oauth-mechanisms
  (with-mock-server (port s (standard-server :extensions '("AUTH PLAIN XOAUTH2")))
    (let ((c (connect port :credentials '(:username "alice" :oauth2-token "good-token")
                           :allow-insecure-auth t)))
      (is (connection-authenticated-p c))
      (close-connection c))
    (let ((initial (%b64 (subseq (first (sent-commands s "AUTH")) 13))))
      (is (string= (format nil "user=alice~cauth=Bearer good-token~c~c"
                           (code-char 1) (code-char 1) (code-char 1))
                   initial))))
  (with-mock-server (port s (standard-server :extensions '("AUTH XOAUTH2 OAUTHBEARER")))
    (let ((c (connect port :credentials (make-credentials :username "alice"
                                                          :oauth2-token (lambda () "good-token"))
                           :allow-insecure-auth t)))
      (close-connection c))
    (let ((initial (%b64 (subseq (first (sent-commands s "AUTH")) 17))))
      (is (string-prefix-p "n,a=alice," initial))
      (is (search (format nil "~cport=~d~c" (code-char 1) port (code-char 1)) initial))))
  (with-mock-server (port s (standard-server :extensions '("AUTH XOAUTH2")))
    (let ((condition (handler-case
                         (connect port :credentials '(:username "alice" :oauth2-token "expired")
                                       :allow-insecure-auth t)
                       (smtp-authentication-failed (e) e))))
      (is (typep condition 'smtp-authentication-failed))
      (is (= 535 (reply-code (smtp-error-reply condition))))
      (is (search "invalid_token" (princ-to-string condition))))
    ;; The client acknowledged the error challenge with an empty response.
    (is (member "" (session-commands s) :test #'string=))))

(test trace-redacts-credentials
  (let ((trace '()))
    (with-mock-server (port s (standard-server :extensions '("AUTH PLAIN")))
      (let ((c (connect port :credentials '(:username "alice" :password "secret")
                             :allow-insecure-auth t
                             :trace (lambda (direction line) (push (cons direction line) trace)))))
        (send-message c (simple-message :text "the body is private"))
        (close-connection c)))
    (let ((all (format nil "~{~a~%~}" (mapcar #'cdr trace)))
          (encoded (base64-encode (format nil "~calice~csecret" (code-char 0) (code-char 0)))))
      (is (search "AUTH PLAIN [credentials redacted]" all))
      (is (null (search "secret" all)))
      (is (null (search encoded all)))
      (is (null (search "the body is private" all)))
      (is (search "octets of message data" all)))))

(test rejected-recipients
  (flet ((server () (standard-server :reject-recipients '("nobody@example.net"))))
    ;; Default: signal, without sending the message.
    (with-mock-server (port s (server))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (let ((condition (handler-case
                             (send-message c (simple-message :to '("bob@example.net" "nobody@example.net")))
                           (smtp-recipients-rejected (e) e))))
          (is (typep condition 'smtp-recipients-rejected))
          (is (equal '("bob@example.net") (smtp-recipients-rejected-accepted condition)))
          (is (equal '("nobody@example.net")
                     (mapcar #'car (smtp-recipients-rejected-rejected condition)))))
        ;; The transaction was reset and the connection is still good.
        (is (= 1 (length (sent-commands s "RSET"))))
        (send-message c (simple-message)))
      (is (= 1 (length (session-messages s))))
      (is (= 1 (length (sent-commands s "DATA"))) "DATA was only sent for the second message"))
    ;; The restart delivers to the accepted recipients.
    (with-mock-server (port s (server))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (handler-bind ((smtp-recipients-rejected
                         (lambda (e) (declare (ignore e)) (invoke-restart 'send-to-accepted))))
          (let ((result (send-message c (simple-message :to '("bob@example.net" "nobody@example.net")))))
            (is (equal '("bob@example.net") (delivery-result-accepted result)))
            (is (= 1 (length (delivery-result-rejected result)))))))
      (is (equal '("bob@example.net") (second (first (session-messages s))))))
    ;; :skip delivers without signalling.
    (with-mock-server (port s (server))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (let ((result (send-message c (simple-message :to '("bob@example.net" "nobody@example.net"))
                                    :on-rejected-recipient :skip)))
          (is (equal '("nobody@example.net") (mapcar #'car (delivery-result-rejected result)))))))
    ;; All rejected: always an error, and no restart to deliver to nobody.
    (with-mock-server (port s (server))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (handler-bind ((smtp-recipients-rejected
                         (lambda (e) (is (null (find-restart 'send-to-accepted e))))))
          (signals smtp-recipients-rejected
            (send-message c (simple-message :to "nobody@example.net")
                          :on-rejected-recipient :skip)))))))

(test transient-and-permanent-errors
  (with-mock-server (port s (standard-server :mail-reply "451 4.3.0 Try again later"))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (let ((e (handler-case (send-message c (simple-message)) (smtp-reply-error (e) e))))
        (is (typep e 'smtp-transient-error))
        (is (string= "4.3.0" (reply-enhanced-status (smtp-error-reply e)))))))
  (with-mock-server (port s (standard-server :data-reply "554 5.7.1 Rejected as spam"))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (signals smtp-permanent-error (send-message c (simple-message)))
      ;; The transaction is over but the session continues.
      (is (= 250 (reply-code (noop c)))))))

(test pipelining
  (with-mock-server (port s (standard-server :extensions '("PIPELINING")))
    (with-connection (c (format nil "127.0.0.1") :port port :tls :none :local-name "client.test")
      (send-message c (simple-message :to '("a@example.net" "b@example.net"))))
    (is-true (session-pipelined s)))
  (with-mock-server (port s (standard-server :extensions '()))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (send-message c (simple-message :to '("a@example.net" "b@example.net"))))
    (is-false (session-pipelined s))))

(test size-extension
  (with-mock-server (port s (standard-server :extensions '("SIZE 500")))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (signals smtp-message-too-large
        (send-message c (simple-message :text (make-string 1000 :initial-element #\a))))
      (send-message c (simple-message)))
    ;; Only the small message's MAIL was sent; it declared its exact size.
    (let* ((mail (sent-commands s "MAIL"))
           (size (parse-integer (subseq (first mail) (+ 5 (search "SIZE=" (first mail)))))))
      (is (= 1 (length mail)))
      ;; The declared size is that of the data as transmitted, without the terminator.
      (is (= size (length (smtp::prepare-data (render-message (simple-message)) :dot-stuff nil)))))))

(test smtputf8
  (let ((message (make-message :from "用户@例え.テスト" :to "bob@example.net" :text "x")))
    (with-mock-server (port s (standard-server :extensions '("8BITMIME")))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (signals smtp-unsupported-extension (send-message c message))))
    (with-mock-server (port s (standard-server :extensions '("8BITMIME" "SMTPUTF8")))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (send-message c message))
      (is (string= "MAIL FROM:<用户@xn--r8jz45g.xn--zckzah> BODY=8BITMIME SMTPUTF8"
                   (first (sent-commands s "MAIL")))))))

(test eightbit-raw-messages
  (let ((raw (format nil "From: a@example.com~%To: b@example.net~%Subject: x~%~%Ünïcödé body~%")))
    (with-mock-server (port s (standard-server :extensions '()))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (signals smtp-unsupported-extension
          (send-raw-message c raw :envelope-from "a@example.com" :recipients "b@example.net"))))
    (with-mock-server (port s (standard-server :extensions '("8BITMIME")))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (send-raw-message c raw :envelope-from "a@example.com" :recipients "b@example.net"))
      (is (search "BODY=8BITMIME" (first (sent-commands s "MAIL"))))
      (is (search "Ünïcödé body" (message-text-of s))))))

(test null-reverse-path
  (with-mock-server (port s (standard-server))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (send-message c (simple-message) :envelope-from ""))
    (is (equal '("MAIL FROM:<>") (sent-commands s "MAIL")))))

(test delivery-status-notifications
  (with-mock-server (port s (standard-server :extensions '("DSN")))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (send-message c (simple-message) :dsn-notify '(:success :failure) :dsn-return :headers
                                       :dsn-envelope-id "id+1"))
    (is (equal '("MAIL FROM:<alice@example.com> RET=HDRS ENVID=id+2B1") (sent-commands s "MAIL")))
    (is (equal '("RCPT TO:<bob@example.net> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;bob@example.net")
               (sent-commands s "RCPT"))))
  (with-mock-server (port s (standard-server :extensions '()))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (send-message c (simple-message) :dsn-notify :never))
    (is (equal '("RCPT TO:<bob@example.net>") (sent-commands s "RCPT")))))

(test chunking
  (let ((body (format nil "first~%.~%.leading dot~%last")))
    (with-mock-server (port s (standard-server :extensions '("CHUNKING" "PIPELINING")))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (send-message c (simple-message :text body)))
      (is (= 1 (length (sent-commands s "BDAT"))))
      (is (null (sent-commands s "DATA")))
      (is (search (crlf "first" "." ".leading dot" "last") (message-text-of s))))
    (let ((smtp::*bdat-chunk-size* 100))
      (with-mock-server (port s (standard-server :extensions '("CHUNKING")))
        (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
          (send-message c (simple-message :text body)))
        (is (> (length (sent-commands s "BDAT")) 2))
        (is (search " LAST" (car (last (sent-commands s "BDAT")))))
        (is (search (crlf "first" "." ".leading dot" "last") (message-text-of s)))))
    (with-mock-server (port s (standard-server :extensions '("CHUNKING")))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (send-message c (simple-message :text body) :chunking nil))
      (is (null (sent-commands s "BDAT")))
      (is (search (crlf "first" "." ".leading dot" "last") (message-text-of s))))))

(test dot-stuffing-and-smuggling-over-the-wire
  (let ((raw (format nil "Subject: smuggle~%~%line~%.~%MAIL FROM:<evil@x>~c~c.~c~cRCPT TO:<evil@x>~c.~cend"
                     #\Return #\Linefeed #\Return #\Linefeed #\Linefeed #\Linefeed)))
    (with-mock-server (port s (standard-server))
      (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
        (send-raw-message c raw :envelope-from "a@example.com" :recipients "b@example.net"))
      ;; One message arrived, intact, and nothing was taken as a command.
      (is (= 1 (length (session-messages s))))
      (is (= 1 (length (sent-commands s "MAIL"))))
      (is (= 1 (length (sent-commands s "RCPT"))))
      (is (string= (crlf "Subject: smuggle" "" "line" "." "MAIL FROM:<evil@x>" "." "RCPT TO:<evil@x>"
                         "." "end" "")
                   (message-text-of s)))
      (is (null (session-violations s))))))

(test several-messages-per-connection
  (with-mock-server (port s (standard-server))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (dotimes (i 5) (send-message c (simple-message :subject (format nil "n~d" i)))))
    (is (= 5 (length (session-messages s))))
    (is (= 1 (length (sent-commands s "EHLO"))))))

(test command-injection-through-addresses-is-refused
  (with-mock-server (port s (standard-server))
    (with-connection (c "127.0.0.1" :port port :tls :none :local-name "client.test")
      (signals invalid-address
        (send-raw-message c "x" :envelope-from "a@example.com"
                                :recipients (format nil "b@example.net>~cRCPT TO:<evil@x" #\Linefeed)))
      (signals mail-format-error (smtp::send-command c (format nil "NOOP~cRSET" #\Linefeed))))
    (is (null (sent-commands s "RCPT")))))

;;; Misbehaving servers

(defun scripted (&rest steps)
  "A handler that runs STEPS: strings are sent, :read reads a line, :sleep N
pauses, :close ends the session."
  (lambda (s)
    (block script
      (dolist (step steps)
        (cond ((stringp step) (srv-send-raw s step))
              ((eq step :read) (srv-read-line s))
              ((and (consp step) (eq (car step) :sleep)) (sleep (cdr step)))
              ((eq step :close) (return-from script))))
      ;; Drain until the client hangs up.
      (loop while (srv-read-line s)))))

(defun crlf* (&rest lines) (format nil "~{~a~c~c~}" (loop for l in lines collect l collect #\Return collect #\Linefeed)))

(test greeting-rejected
  (with-mock-server (port s (scripted (crlf* "554 5.7.1 No service for you")))
    (signals smtp-permanent-error (connect port))))

(test malformed-replies
  (dolist (bad (list (crlf* "hello there")
                     (crlf* "220-first" "250 second")
                     (crlf* (format nil "220 ~a" (make-string 5000 :initial-element #\x)))))
    (with-mock-server (port s (scripted bad))
      (signals smtp-protocol-error (connect port)))))

(test server-hangs-up
  (with-mock-server (port s (scripted (crlf* "220 hi") :read :close))
    (signals smtp-connection-closed (connect port))))

(test 421-breaks-the-connection
  (with-mock-server (port s (scripted (crlf* "220 hi") :read (crlf* "250 hello")
                                      :read (crlf* "421 4.3.2 Shutting down")))
    (let ((c (connect port)))
      (signals smtp-transient-error (send-message c (simple-message)))
      (signals smtp-connection-error (send-message c (simple-message)))
      (close-connection c))))

(test timeouts
  (with-mock-server (port s (scripted (cons :sleep 3)))
    (let ((start (get-internal-real-time)))
      (signals smtp-timeout (connect port :timeout 1))
      (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 2.5))))
  (with-mock-server (port s (scripted (crlf* "220 hi") :read (crlf* "250 hello") :read (cons :sleep 3)))
    (let ((c (connect port :timeout 1)))
      (signals smtp-timeout (send-message c (simple-message)))
      (is (eq :broken (smtp::connection-state c)))
      (close-connection c))))

(test connection-refused
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0))
         (port (usocket:get-local-port listener)))
    (usocket:socket-close listener)
    (signals smtp-connection-error (connect port))))

(test starttls-response-injection
  ;; A man in the middle appends a reply to the STARTTLS response, hoping the
  ;; client will read it as if it came over TLS.
  (with-mock-server (port s (scripted (crlf* "220 hi") :read (crlf* "250-hello" "250 STARTTLS")
                                      :read (crlf* "220 go ahead" "250 injected")))
    (signals smtp-protocol-error
      (open-connection "127.0.0.1" :port port :local-name "client.test" :timeout 5))))

(test closing-is-safe
  (with-mock-server (port s (standard-server))
    (let ((c (connect port)))
      (close-connection c)
      (close-connection c)
      (signals smtp-connection-error (noop c)))
    (is (equal '("QUIT") (sent-commands s "QUIT")))))

;;; Regressions from review

(test unexpected-sasl-challenge-is-cancelled
  ;; A server that keeps challenging after PLAIN's initial response: the client
  ;; cancels with "*" so the session stays in step.
  (with-mock-server (port s (scripted (crlf* "220 hi") :read (crlf* "250-hello" "250 AUTH PLAIN")
                                      :read (crlf* "334 Zm9v") :read (crlf* "501 5.7.0 Cancelled")
                                      :read (crlf* "250 2.0.0 OK") :read (crlf* "221 bye")))
    (let ((c (connect port :allow-insecure-auth t)))
      (signals smtp-authentication-failed (authenticate c '(:username "alice" :password "x")))
      (is (= 250 (reply-code (noop c))))
      (close-connection c))
    (is (member "*" (session-commands s) :test #'string=))))

(test 421-during-rcpt-is-transient
  (with-mock-server (port s (scripted (crlf* "220 hi") :read (crlf* "250 hello")
                                      :read (crlf* "250 OK") :read (crlf* "421 4.4.2 Closing")
                                      :close))
    (let ((c (connect port)))
      (signals smtp-transient-error (send-message c (simple-message :to '("a@example.net" "b@example.net"))))
      (close-connection c))
    ;; The second RCPT was never sent to a closing server.
    (is (= 1 (length (sent-commands s "RCPT"))))))

(test reply-text-is-sanitized
  (with-mock-server (port s (scripted (format nil "220 hi~c[31mred~cthere~c~c" (code-char 27) #\Return #\Return #\Linefeed)
                                      :read (crlf* "250 hello")))
    (let ((c (connect port)))
      (is (notany (lambda (ch) (smtp::control-char-p ch)) (reply-text (connection-greeting c))))
      (close-connection c))))

(test local-name-is-sent-in-ascii
  (with-mock-server (port s (standard-server))
    (close-connection (open-connection "127.0.0.1" :port port :tls :none :local-name "bücher.example"))
    (is (equal '("EHLO xn--bcher-kva.example") (sent-commands s "EHLO"))))
  (signals mail-format-error (open-connection "127.0.0.1" :port 1 :tls :none :local-name "[foo bar]")))

(test interrupted-message-data-does-not-hang
  ;; A non-SMTP error while the message data is being sent leaves the server
  ;; reading data: RSET would be read as part of the message, and its reply
  ;; never comes. The connection is broken instead.
  (with-mock-server (port s (standard-server))
    (let ((c (connect port :trace (lambda (direction line)
                                    (when (and (eq direction :client) (string-prefix-p "[" line))
                                      (error "trace failed")))))
          (start (get-internal-real-time)))
      (unwind-protect
           (progn
             (signals simple-error (send-message c (simple-message)))
             (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 2))
             (is (eq :broken (smtp::connection-state c))))
        (close-connection c)))
    (is (null (sent-commands s "RSET")))))


(defun reply-when-idle-server (largest)
  "A pipelining server that answers commands only once the client stops
sending, calling LARGEST with the most commands it ever received before
answering. A client that never stops to read replies would, with real
socket buffers, deadlock against a server that blocks writing them."
  (lambda (session)
    (let ((most 0) (pending '()))
      (labels ((more-p ()
                 (or (listen (session-stream session))
                     (usocket:wait-for-input (session-socket session) :timeout 0.2 :ready-only t)))
               (answer ()
                 (setf most (max most (length pending)))
                 (apply #'srv-send session (nreverse pending))
                 (setf pending '())))
        (srv-send session "220 idle.test ESMTP")
        (loop for line = (srv-read-line session :record nil)
              while line
              do (let ((verb (%verb line)))
                   (cond ((string= verb "EHLO") (srv-send session "250-idle.test" "250 PIPELINING"))
                         ((member verb '("MAIL" "RCPT") :test #'string=)
                          (push "250 ok" pending)
                          (unless (more-p) (answer)))
                         ((string= verb "DATA")
                          (when pending (answer))
                          (srv-send session "354 go")
                          (srv-read-data session)
                          (srv-send session "250 queued"))
                         ((string= verb "QUIT") (srv-send session "221 bye") (return))
                         (t (srv-send session "250 ok")))))
        (funcall largest most)))))

(test pipelining-reads-replies-as-it-goes
  ;; RFC 2920 section 3.1: a client must not send so many commands without
  ;; reading replies that both directions' buffers fill and the two sides
  ;; deadlock. Thousands of recipients go out in bounded batches.
  (let ((recipients (loop for i below 5000 collect (format nil "r~d@example.org" i)))
        (largest nil))
    (with-mock-server (port s (reply-when-idle-server (lambda (n) (setf largest n))))
      (let ((c (connect port)))
        (unwind-protect
             (is (= 5000 (length (delivery-result-accepted
                                  (send-raw-message c (render-message (simple-message))
                                                    :envelope-from "alice@example.com"
                                                    :recipients recipients)))))
          (close-connection c))))
    (is (<= largest 1000) "~d commands were sent before a reply was read" largest)))

(defun refusing-starttls-server (session)
  "A server that offers STARTTLS but answers it with 454."
  (srv-send session "220 refusing.test ESMTP")
  (loop for line = (srv-read-line session)
        while line
        do (let ((verb (%verb line)))
             (cond ((string= verb "EHLO") (srv-send session "250-refusing.test" "250 STARTTLS"))
                   ((string= verb "STARTTLS") (srv-send session "454 4.7.0 TLS not available"))
                   ((string= verb "DATA")
                    (srv-send session "354 go")
                    (setf (session-messages session)
                          (append (session-messages session) (list (list nil nil (srv-read-data session)))))
                    (srv-send session "250 queued"))
                   ((string= verb "QUIT") (srv-send session "221 bye") (return))
                   (t (srv-send session "250 ok"))))))

(test opportunistic-tls-continues-after-a-refused-starttls
  (with-mock-server (port s #'refusing-starttls-server)
    (with-connection (c "127.0.0.1" :port port :tls :opportunistic :local-name "client.test" :timeout 5)
      (is (not (connection-tls-p c)))
      (is (send-message c (simple-message))))
    (is (= 1 (length (session-messages s)))))
  ;; Required TLS still fails.
  (with-mock-server (port s #'refusing-starttls-server)
    (signals smtp-transient-error
      (open-connection "127.0.0.1" :port port :tls :starttls :local-name "client.test" :timeout 5))))

(test pipelining-batch-must-be-positive
  (with-mock-server (port s (standard-server))
    (let ((c (connect port)))
      (unwind-protect
           (let ((smtp::*pipelining-batch* 0))
             (signals type-error (sb-ext:with-timeout 3 (send-message c (simple-message)))))
        (close-connection c)))))
