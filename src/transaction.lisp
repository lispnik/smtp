;;; transaction.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Mail transactions: MAIL, RCPT, DATA or BDAT (RFC 3030), with SIZE
;;; (RFC 1870), PIPELINING (RFC 2920), 8BITMIME (RFC 6152), SMTPUTF8
;;; (RFC 6531) and DSN (RFC 3461).

(in-package #:smtp)

(defstruct delivery-result
  "The outcome of a successful transaction: the recipient addresses the server
accepted, the rejected ones as an alist of (address . reply), the server's
final reply and the message's Message-ID."
  (accepted '())
  (rejected '())
  reply
  message-id)

(defgeneric sign-message-octets (signer octets)
  (:documentation "Return OCTETS, a rendered message, signed by SIGNER. The
smtp/dkim system defines a method for DKIM signers."))

(defmethod sign-message-octets ((signers list) octets)
  (reduce (lambda (data signer) (sign-message-octets signer data)) signers
          :initial-value octets))

(defun prepare-data (octets &key (dot-stuff t))
  "OCTETS with every line ending made CRLF, ending in CRLF and, if DOT-STUFF,
with a dot added to each line that starts with one (RFC 5321 section 4.5.2).
A bare CR or LF can therefore never form an end-of-data sequence (SMTP
smuggling). Signals MAIL-FORMAT-ERROR for a line over 998 octets as sent.
The second value is the number of dots added."
  (let ((out (make-octet-buffer (+ (length octets) 1024)))
        (bol t) (column 0) (stuffed 0) (n (length octets)) (i 0))
    (flet ((newline ()
             (buffer-crlf out)
             (setf bol t column 0)))
      (loop while (< i n)
            do (let ((o (aref octets i)))
                 (cond ((= o 13)
                        (newline)
                        (when (and (< (1+ i) n) (= (aref octets (1+ i)) 10)) (incf i)))
                       ((= o 10) (newline))
                       (t
                        (when (and bol dot-stuff (= o 46))
                          (buffer-push 46 out)
                          (incf stuffed)
                          (incf column))
                        (buffer-push o out)
                        (setf bol nil)
                        (when (> (incf column) 998)
                          (error 'mail-format-error
                                 :message "The message has a line longer than 998 octets")))))
               (incf i))
      (unless bol (newline)))
    (values out stuffed)))

(defun %xtext (string)
  "RFC 3461 xtext encoding."
  (with-output-to-string (s)
    (loop for o across (utf8-octets string)
          do (if (and (<= 33 o 126) (/= o 43) (/= o 61))
                 (write-char (code-char o) s)
                 (format s "+~:@(~2,'0x~)" o)))))

(defun %size-limit (connection)
  (let ((params (connection-extension connection "SIZE")))
    (and params
         (let ((n (ignore-errors (parse-integer (first params)))))
           (and n (plusp n) n)))))

(defun %notify-param (notify)
  (when notify
    (let ((values (alexandria:ensure-list notify)))
      (dolist (v values)
        (unless (member v '(:success :failure :delay :never))
          (error 'smtp-error :message (format nil "Invalid DSN notify value ~s" v))))
      (when (and (member :never values) (rest values))
        (error 'smtp-error :message "DSN :never cannot be combined with other values"))
      (format nil "~{~a~^,~}" (mapcar #'symbol-name values)))))

(defun %envelope-commands (from recipients &key size eightbit smtputf8 dsn notify ret envid)
  (cons (format nil "MAIL FROM:<~a>~@[ SIZE=~d~]~:[~; BODY=8BITMIME~]~:[~; SMTPUTF8~]~@[ RET=~a~]~@[ ENVID=~a~]"
                (if from (mailbox-address from) "")
                size eightbit smtputf8
                (and dsn ret (ecase ret (:full "FULL") (:headers "HDRS")))
                (and dsn envid (%xtext envid)))
        (mapcar (lambda (rcpt)
                  (format nil "RCPT TO:<~a>~@[ NOTIFY=~a~]~@[ ORCPT=rfc822;~a~]"
                          (mailbox-address rcpt)
                          (and dsn notify)
                          (and dsn (not (mailbox-utf8-p rcpt))
                               (%xtext (mailbox-address rcpt)))))
                recipients)))

(defun %send-envelope (connection commands)
  "Send MAIL and RCPT COMMANDS, pipelined when the server allows it, and
return their replies. A failed MAIL is signalled at once."
  (if (nth-value 1 (connection-extension connection "PIPELINING"))
      (progn
        (%send-commands connection commands)
        (let ((replies (loop for line in commands
                             for reply = (read-reply connection)
                             collect reply
                             ;; The server is closing; nothing more will come.
                             do (when (= (reply-code reply) 421)
                                  (check-reply connection reply line '(2))))))
          (check-reply connection (first replies) (first commands) '(2))
          replies))
      (let ((mail (command connection (first commands))))
        (cons mail
              (mapcar (lambda (rcpt)
                        (let ((reply (command connection rcpt :expect nil)))
                          (when (= (reply-code reply) 421)
                            (check-reply connection reply rcpt '(2)))
                          reply))
                      (rest commands))))))

(defun %send-data (connection data)
  (command connection "DATA" :expect '(354))
  (%trace connection :client (format nil "[~:d octets of message data]" (length data)))
  (%write-octets connection data)
  (send-command connection ".")
  (read-reply connection :timeout (connection-data-timeout connection)))

(defparameter *bdat-chunk-size* (* 1024 1024))

(defun %send-bdat (connection data)
  (let ((n (length data)))
    (if (zerop n)
        (progn (send-command connection "BDAT 0 LAST")
               (read-reply connection :timeout (connection-data-timeout connection)))
        (loop for start from 0 below n by *bdat-chunk-size*
              for end = (min n (+ start *bdat-chunk-size*))
              for last = (= end n)
              do (let ((line (format nil "BDAT ~d~:[~; LAST~]" (- end start) last)))
                   (send-command connection line)
                   (%trace connection :client (format nil "[~:d octets of message data]" (- end start)))
                   (%write-octets connection data :start start :end end)
                   (let ((reply (read-reply connection
                                            :timeout (if last
                                                         (connection-data-timeout connection)
                                                         (connection-timeout connection)))))
                     (if last
                         (return reply)
                         (check-reply connection reply line '(2)))))))))

(defun send-raw-message (connection data &key envelope-from recipients smtputf8
                                            (on-rejected-recipient :error)
                                            dsn-notify dsn-return dsn-envelope-id
                                            (chunking :auto) message-id)
  "Send DATA, a complete RFC 5322 message (octets, or a string sent as
UTF-8), from ENVELOPE-FROM (a mailbox designator, or \"\" for the null
reverse-path of a bounce) to RECIPIENTS.

Line endings are canonicalized and the data is dot-stuffed, so DATA cannot
end the transaction early. The size is checked against the server's SIZE
limit before anything is sent. SMTPUTF8 is used when an address needs it or
SMTPUTF8 is true, and BODY=8BITMIME when DATA has 8-bit octets; if the
server lacks either extension, SMTP-UNSUPPORTED-EXTENSION is signalled.

If some recipients are rejected and ON-REJECTED-RECIPIENT is :ERROR (the
default), SMTP-RECIPIENTS-REJECTED is signalled with a SEND-TO-ACCEPTED
restart; with :SKIP the message goes to the accepted ones. If every
recipient is rejected, the condition is always signalled.

DSN-NOTIFY (:never, or a list of :success, :failure and :delay),
DSN-RETURN (:full or :headers) and DSN-ENVELOPE-ID request delivery status
notifications when the server supports DSN; otherwise they are ignored.
CHUNKING true (the default, :AUTO) uses BDAT when the server supports it;
NIL always uses DATA.

Returns a DELIVERY-RESULT. A 4xx or 5xx reply signals SMTP-TRANSIENT-ERROR
or SMTP-PERMANENT-ERROR; the connection stays usable for another message."
  (%ensure-open connection)
  (check-type on-rejected-recipient (member :error :skip))
  (let* ((octets (etypecase data
                   (string (utf8-octets data))
                   ((vector (unsigned-byte 8)) data)))
         (from (if (equal envelope-from "")
                   nil
                   (if envelope-from
                       (ensure-mailbox envelope-from)
                       (error 'mail-format-error :message "No envelope sender (:envelope-from)"))))
         (rcpts (remove-duplicates (ensure-mailbox-list recipients) :test #'mailbox= :from-end t))
         (eightbit (and (find-if (lambda (o) (> o 127)) octets) t))
         (smtputf8 (or smtputf8
                       (and from (mailbox-utf8-p from))
                       (some #'mailbox-utf8-p rcpts)))
         (bdat (and chunking (nth-value 1 (connection-extension connection "CHUNKING"))))
         (payload nil)
         (size (multiple-value-bind (data stuffed) (prepare-data octets :dot-stuff (not bdat))
                 ;; RFC 1870: the size excludes dot-stuffing.
                 (setf payload data)
                 (- (length data) stuffed)))
         (dsn (and (or dsn-notify dsn-return dsn-envelope-id)
                   (nth-value 1 (connection-extension connection "DSN"))))
         (size-supported (nth-value 1 (connection-extension connection "SIZE")))
         (limit (%size-limit connection)))
    (unless rcpts
      (error 'mail-format-error :message "No recipients"))
    (when (and smtputf8 (not (nth-value 1 (connection-extension connection "SMTPUTF8"))))
      (error 'smtp-unsupported-extension :name "SMTPUTF8"
                                         :message "an address or header needs UTF-8"))
    (when (and eightbit (not smtputf8)
               (not (nth-value 1 (connection-extension connection "8BITMIME"))))
      (error 'smtp-unsupported-extension :name "8BITMIME"
                                         :message "the message contains 8-bit data"))
    (when (and limit (> size limit))
      (error 'smtp-message-too-large :size size :limit limit))
    (when (%in-transaction connection)
      (rset connection))
    (let ((commands (%envelope-commands from rcpts
                                        :size (and size-supported size)
                                        :eightbit (and eightbit
                                                       (nth-value 1 (connection-extension
                                                                     connection "8BITMIME")))
                                        :smtputf8 smtputf8
                                        :dsn dsn
                                        :notify (%notify-param dsn-notify)
                                        :ret dsn-return
                                        :envid dsn-envelope-id))
          (done nil))
      (setf (%in-transaction connection) t)
      (unwind-protect
           (let* ((replies (%send-envelope connection commands))
                  (accepted '())
                  (rejected '()))
             (loop for rcpt in rcpts
                   for reply in (rest replies)
                   do (if (= (reply-class reply) 2)
                          (push (mailbox-address rcpt) accepted)
                          (progn
                            (when (= (reply-code reply) 421)
                              (check-reply connection reply "RCPT" '(2)))
                            (push (cons (mailbox-address rcpt) reply) rejected))))
             (setf accepted (nreverse accepted)
                   rejected (nreverse rejected))
             (when rejected
               (when (or (null accepted) (eq on-rejected-recipient :error))
                 (restart-case (error 'smtp-recipients-rejected
                                        :accepted accepted :rejected rejected)
                     (send-to-accepted ()
                       :report "Deliver the message to the accepted recipients only."
                       :test (lambda (c) (declare (ignore c)) accepted)
                       nil))))
             (let ((final (if bdat
                              (%send-bdat connection payload)
                              (%send-data connection payload))))
               (setf (%in-transaction connection) nil)
               (check-reply connection final "end of message data" '(2))
               (setf done t)
               (make-delivery-result :accepted accepted :rejected rejected
                                     :reply final :message-id message-id)))
        (unless done
          (when (and (%in-transaction connection) (eq (connection-state connection) :open))
            (handler-case (rset connection) (smtp-error () nil)))
          (setf (%in-transaction connection) nil))))))

(defun send-message (connection message &key envelope-from recipients dkim
                                          (on-rejected-recipient :error)
                                          dsn-notify dsn-return dsn-envelope-id
                                          (chunking :auto))
  "Render MESSAGE and send it over CONNECTION. ENVELOPE-FROM defaults to the
Sender, else the From, address; RECIPIENTS to the To, Cc and Bcc addresses.
DKIM is a signer (see smtp/dkim) or list of signers. The other keywords are
as for SEND-RAW-MESSAGE. Returns a DELIVERY-RESULT."
  (multiple-value-bind (octets utf8) (render-message message)
    (when dkim
      (setf octets (sign-message-octets dkim octets)))
    (send-raw-message connection octets
                      :envelope-from (or envelope-from
                                         (message-sender message)
                                         (message-from message))
                      :recipients (or recipients (message-envelope-recipients message))
                      :smtputf8 utf8
                      :on-rejected-recipient on-rejected-recipient
                      :dsn-notify dsn-notify :dsn-return dsn-return
                      :dsn-envelope-id dsn-envelope-id
                      :chunking chunking
                      :message-id (message-id message))))

(defparameter +send-keys+
  '(:envelope-from :recipients :dkim :on-rejected-recipient
    :dsn-notify :dsn-return :dsn-envelope-id :chunking))

(defun send-mail (host message &rest options &key &allow-other-keys)
  "Connect to HOST, send MESSAGE and disconnect. OPTIONS are those of
OPEN-CONNECTION and SEND-MESSAGE. Returns a DELIVERY-RESULT."
  (let ((send-options (loop for (k v) on options by #'cddr
                            when (member k +send-keys+) append (list k v)))
        (connection-options (loop for (k v) on options by #'cddr
                                  unless (member k +send-keys+) append (list k v))))
    (let ((connection (apply #'open-connection host connection-options)))
      (unwind-protect (apply #'send-message connection message send-options)
        (close-connection connection)))))
