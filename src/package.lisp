;;; package.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(defpackage #:smtp
  (:use #:cl)
  (:export
   ;; conditions
   #:smtp-error
   #:smtp-error-message
   #:mail-format-error
   #:invalid-address
   #:invalid-header
   #:smtp-connection-error
   #:smtp-connection-closed
   #:smtp-timeout
   #:smtp-timeout-operation
   #:smtp-tls-error
   #:smtp-protocol-error
   #:smtp-reply-error
   #:smtp-error-reply
   #:smtp-error-command
   #:smtp-transient-error
   #:smtp-permanent-error
   #:smtp-authentication-failed
   #:smtp-insecure-authentication
   #:smtp-unsupported-extension
   #:smtp-unsupported-extension-name
   #:smtp-message-too-large
   #:smtp-recipients-rejected
   #:smtp-recipients-rejected-accepted
   #:smtp-recipients-rejected-rejected
   #:send-to-accepted
   ;; encodings
   #:base64-encode
   #:base64-decode
   #:quoted-printable-encode
   #:quoted-printable-decode
   #:encode-header-words
   #:format-rfc5322-date
   ;; internationalized domain names
   #:punycode-encode
   #:punycode-decode
   #:domain-to-ascii
   ;; addresses
   #:mailbox
   #:make-mailbox
   #:mailbox-display-name
   #:mailbox-local-part
   #:mailbox-domain
   #:mailbox-address
   #:mailbox-utf8-p
   #:parse-mailbox
   #:parse-mailbox-list
   #:format-mailbox
   ;; messages
   #:message
   #:make-message
   #:message-from
   #:message-sender
   #:message-to
   #:message-cc
   #:message-bcc
   #:message-reply-to
   #:message-subject
   #:message-text
   #:message-html
   #:message-attachments
   #:message-headers
   #:message-date
   #:message-id
   #:message-envelope-recipients
   #:attachment
   #:make-attachment
   #:attachment-filename
   #:attachment-content-type
   #:attachment-content-id
   #:attachment-inline-p
   #:mime-type-for-filename
   #:render-message
   ;; replies
   #:reply
   #:reply-code
   #:reply-enhanced-status
   #:reply-lines
   #:reply-text
   ;; TLS backends
   #:*tls-backend*
   #:start-tls
   #:tls-peer-certificates
   #:tls-verify-chain
   #:register-tls-backend
   ;; connections
   #:*trace*
   #:connection-tls-backend
   #:connection
   #:open-connection
   #:close-connection
   #:with-connection
   #:connection-host
   #:connection-port
   #:connection-tls-p
   #:connection-authenticated-p
   #:connection-greeting
   #:connection-extensions
   #:connection-extension
   #:make-credentials
   #:authenticate
   #:noop
   #:rset
   ;; sending
   #:send-message
   #:send-raw-message
   #:send-mail
   #:delivery-result
   #:delivery-result-accepted
   #:delivery-result-rejected
   #:delivery-result-reply
   #:delivery-result-message-id
   ;; message signing hook (see smtp/dkim)
   #:sign-message-octets
   ;; connection pools
   #:connection-pool
   #:make-connection-pool
   #:close-connection-pool
   #:with-pooled-connection
   #:retry-with-fresh-connection
   #:pool-send-message
   #:connection-pool-statistics
   #:smtp-pool-timeout
   #:smtp-pool-closed))
