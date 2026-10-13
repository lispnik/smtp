;;; package.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(defpackage #:smtp/delivery
  (:use #:cl #:smtp)
  (:documentation "Direct delivery to recipients' mail servers: MX lookup,
DANE, MTA-STS and a retry queue.")
  (:export
   ;; DNS
   #:dns-error
   #:resolver
   #:make-resolver
   #:*resolver*
   #:dns-query
   #:dns-answer
   #:dns-answer-status
   #:dns-answer-records
   #:dns-answer-secure
   #:dns-answer-canonical-name
   ;; DANE
   #:tlsa
   #:make-tlsa
   #:make-dane-verifier
   #:certificate-spki
   ;; MTA-STS
   #:mta-sts-policy
   #:mta-sts-policy-mode
   #:mta-sts-policy-mx
   #:mta-sts-policy-max-age
   #:mta-sts-policy-expires
   #:mta-sts-policy-id
   #:parse-mta-sts-policy
   #:mta-sts-cache
   #:mta-sts-cache-get
   #:mta-sts-cache-put
   #:*mta-sts-cache*
   ;; delivery
   #:delivery-failed
   #:mail-exchangers
   #:deliver-message
   #:deliver-raw-message
   #:recipient-status
   #:recipient-status-recipient
   #:recipient-status-status
   #:recipient-status-reply
   #:recipient-status-message
   #:recipient-status-host
   #:recipient-status-security
   ;; queue
   #:delivery-queue
   #:make-delivery-queue
   #:enqueue-message
   #:enqueue-raw-message
   #:run-delivery-queue
   #:delivery-queue-messages
   #:queued-message
   #:queued-message-id
   #:queued-message-octets
   #:queued-message-envelope-from
   #:queued-message-smtputf8
   #:queued-message-queued-at
   #:queued-message-recipients
   #:queued-message-attempts
   #:queued-message-next-attempt
   #:queued-message-statuses
   #:*default-retry-schedule*))
