;;; stalwart.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

;;; Reading mail back from Stalwart's mailboxes over JMAP (RFC 8620, 8621).
;;; Stalwart parses messages with its own Rust libraries, a third parser
;;; independent of ours and Mailpit's.

(in-package #:smtp/integration)

(defun basic-auth (user)
  (format nil "Basic ~a"
          (cl-base64:usb8-array-to-base64-string
           (babel:string-to-octets (format nil "~a:~a" user *stalwart-password*) :encoding :utf-8))))

(defun stalwart-get (user path)
  (multiple-value-bind (status body)
      (http "GET" path :port *stalwart-http-port* :headers `(("Authorization" . ,(basic-auth user))))
    (unless (= status 200)
      (error "Stalwart GET ~a as ~a: HTTP ~d" path user status))
    body))

(defvar *jmap-accounts* (make-hash-table :test 'equal))

(defun jmap-account (user)
  "USER's JMAP account id."
  (or (gethash user *jmap-accounts*)
      (setf (gethash user *jmap-accounts*)
            (j (jzon:parse (babel:octets-to-string (stalwart-get user "/jmap/session") :encoding :utf-8))
               "primaryAccounts" "urn:ietf:params:jmap:mail"))))

(defun jmap (user &rest calls)
  "Make the JMAP method CALLS, each (name arguments-hash-table id), as USER;
return the list of responses."
  (let ((request (jzon:stringify
                  (alexandria:plist-hash-table
                   (list "using" #("urn:ietf:params:jmap:core" "urn:ietf:params:jmap:mail")
                         "methodCalls" (coerce (mapcar (lambda (c) (coerce c 'vector)) calls) 'vector))
                   :test 'equal))))
    (multiple-value-bind (status body)
        (http "POST" "/jmap/" :port *stalwart-http-port* :body request
                              :headers `(("Authorization" . ,(basic-auth user))
                                         ("Content-Type" . "application/json")))
      (unless (= status 200)
        (error "Stalwart JMAP as ~a: HTTP ~d ~a" user status
               (babel:octets-to-string body :encoding :utf-8 :errorp nil)))
      (let ((responses (coerce (j (jzon:parse (babel:octets-to-string body :encoding :utf-8))
                                  "methodResponses")
                               'list)))
        (dolist (r responses responses)
          (when (equal (aref r 0) "error")
            (error "JMAP error as ~a: ~a" user (jzon:stringify (aref r 1)))))))))

(defun args (&rest plist)
  (alexandria:plist-hash-table plist :test 'equal))

(defparameter +email-properties+
  #("subject" "from" "to" "messageId" "blobId" "textBody" "htmlBody" "attachments" "bodyValues"
    "header:Return-Path:asText" "header:Authentication-Results:asText:all"))

(defun stalwart-find (user message-id)
  "USER's email with MESSAGE-ID, or NIL."
  (let* ((account (jmap-account user))
         (responses (jmap user
                          (list "Email/query"
                                (args "accountId" account
                                      "sort" (vector (args "property" "receivedAt" "isAscending" nil))
                                      "limit" 200)
                                "q")
                          (list "Email/get"
                                (args "accountId" account
                                      "#ids" (args "resultOf" "q" "name" "Email/query" "path" "/ids")
                                      "properties" #("messageId"))
                                "g")))
         (id (bare-id message-id))
         (found (find-if (lambda (e) (find id (j e "messageId") :test #'equal))
                         (j (second responses) 1 "list"))))
    (and found
         (j (first (jmap user (list "Email/get"
                                    (args "accountId" account "ids" (vector (j found "id"))
                                          "properties" +email-properties+
                                          "fetchTextBodyValues" t "fetchHTMLBodyValues" t)
                                    "g")))
            1 "list" 0))))

(defun stalwart-download (user blob-id)
  (stalwart-get user (format nil "/jmap/download/~a/~a/blob?accept=application/octet-stream"
                             (jmap-account user) blob-id)))

(defun str (value)
  "VALUE if it is a string; JSON null parses as the symbol NULL."
  (and (stringp value) value))

(defun stalwart-received (user email)
  (flet ((mailbox (a) (cons (or (str (j a "name")) "") (j a "email")))
         (body (parts)
           (apply #'concatenate 'string
                  (map 'list (lambda (p) (j email "bodyValues" (j p "partId") "value")) parts))))
    (make-received
     :subject (j email "subject")
     :from (mailbox (j email "from" 0))
     :to (map 'list #'mailbox (j email "to"))
     :text (body (j email "textBody"))
     :html (body (j email "htmlBody"))
     :attachments (map 'list (lambda (p)
                               (list (str (j p "name")) (j p "type") (stalwart-download user (j p "blobId"))))
                       (j email "attachments"))
     :return-path (let ((v (str (j email "header:Return-Path:asText"))))
                    (and v (string-trim " " v)))
     :raw (stalwart-download user (j email "blobId"))
     :headers (list (cons "Authentication-Results"
                          (coerce (j email "header:Authentication-Results:asText:all") 'list))))))

(defun wait-for-stalwart (user message-id &key (timeout 30))
  "The message MESSAGE-ID in USER's mailbox, once it has arrived."
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop
      (let ((email (stalwart-find user message-id)))
        (when email (return (stalwart-received user email))))
      (when (> (get-internal-real-time) deadline)
        (error "Message ~a did not arrive in ~a's Stalwart mailbox within ~d s" message-id user timeout))
      (sleep 0.2))))

(defun stalwart-reachable-p ()
  (ignore-errors (jmap-account "bob@example.test")))
