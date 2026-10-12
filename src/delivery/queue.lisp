;;; queue.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Retrying deferred deliveries (RFC 5321 4.5.4.1): an in-memory queue of
;;; rendered messages and their outstanding recipients, retried on a
;;; schedule until delivered or until they have been queued too long.
;;; The application runs RUN-DELIVERY-QUEUE periodically, and keeps the
;;; items elsewhere if they must survive a restart.

(in-package #:smtp/delivery)

(defstruct (queued-message (:constructor %make-queued-message))
  "A message waiting for delivery: its rendered OCTETS, ENVELOPE-FROM, the
RECIPIENTS still outstanding, when it was QUEUED-AT and is next due
(NEXT-ATTEMPT, universal times), the number of ATTEMPTS so far and the
latest RECIPIENT-STATUS for each recipient in STATUSES."
  id octets envelope-from recipients smtputf8 queued-at next-attempt (attempts 0) statuses)

(defparameter *default-retry-schedule* '(1800 3600 7200 14400 28800)
  "Seconds to wait before each retry; the last interval repeats. RFC 5321
asks for at least 30 minutes between attempts.")

(defclass delivery-queue ()
  ((items :initform '() :accessor %items)
   (lock :initform (bt:make-lock "smtp delivery queue") :reader %queue-lock)
   (retry-schedule :initarg :retry-schedule :reader delivery-queue-retry-schedule)
   (give-up-after :initarg :give-up-after :reader delivery-queue-give-up-after)
   (on-delivered :initarg :on-delivered :reader %on-delivered)
   (on-failed :initarg :on-failed :reader %on-failed)
   (on-deferred :initarg :on-deferred :reader %on-deferred)
   (options :initarg :options :reader delivery-queue-options))
  (:documentation "Messages waiting for delivery or retry. Safe to use from
several threads; attempts are made outside the lock."))

(defun make-delivery-queue (&rest options &key (retry-schedule *default-retry-schedule*)
                                            (give-up-after (* 5 24 3600))
                                            on-delivered on-failed on-deferred
                            &allow-other-keys)
  "A queue for DELIVER-RAW-MESSAGE with OPTIONS (such as :LOCAL-NAME
or :RESOLVER). GIVE-UP-AFTER seconds after a
message is queued its outstanding recipients fail. ON-DELIVERED, ON-FAILED
and ON-DEFERRED are called with the QUEUED-MESSAGE and the recipient
statuses of an attempt in that state, so that the application can, for
example, send a bounce for failed recipients."
  (make-instance 'delivery-queue
                 :retry-schedule retry-schedule :give-up-after give-up-after
                 :on-delivered on-delivered :on-failed on-failed :on-deferred on-deferred
                 :options (alexandria:remove-from-plist options :retry-schedule :give-up-after
                                                        :on-delivered :on-failed :on-deferred)))

(defun enqueue-message (queue message &key envelope-from recipients dkim (now (get-universal-time)))
  "Render MESSAGE (signing it with DKIM) and queue it for delivery now.
Returns the QUEUED-MESSAGE."
  (multiple-value-bind (octets utf8) (render-message message)
    (when dkim (setf octets (sign-message-octets dkim octets)))
    (enqueue-raw-message queue octets
                         :envelope-from (or envelope-from (smtp::message-sender message)
                                            (smtp::message-from message))
                         :recipients (or recipients (message-envelope-recipients message))
                         :smtputf8 utf8 :id (message-id message) :now now)))

(defun enqueue-raw-message (queue octets &key envelope-from recipients smtputf8 id
                                           (now (get-universal-time)))
  "Queue the rendered OCTETS for delivery now."
  (let ((item (%make-queued-message
               :id (or id (smtp::random-token 12)) :octets octets
               :envelope-from (if (equal envelope-from "") "" (mailbox-address (smtp::ensure-mailbox envelope-from)))
               :recipients (mapcar #'mailbox-address (smtp::ensure-mailbox-list recipients))
               :smtputf8 smtputf8 :queued-at now :next-attempt now)))
    (bt:with-lock-held ((%queue-lock queue))
      (setf (%items queue) (append (%items queue) (list item))))
    item))

(defun delivery-queue-messages (queue)
  "The queued messages, oldest first."
  (bt:with-lock-held ((%queue-lock queue)) (copy-list (%items queue))))

(defun %retry-delay (queue attempts)
  (let ((schedule (delivery-queue-retry-schedule queue)))
    (or (nth (1- attempts) schedule) (car (last schedule)))))

(defun %notify (fn item statuses)
  "Call FN with ITEM and STATUSES, if there are any. The attempt is already
recorded, so an error in FN is only reported: it must not stop the other
callbacks, or have the item retried."
  (when (and fn statuses)
    (handler-case (funcall fn item statuses)
      (error (e)
        (warn "A delivery queue callback failed for ~a: ~a" (queued-message-id item) e)))))

(defun %process-item (queue item now)
  (let* ((statuses (apply #'deliver-raw-message (queued-message-octets item)
                          :envelope-from (queued-message-envelope-from item)
                          :recipients (queued-message-recipients item)
                          :smtputf8 (queued-message-smtputf8 item)
                          (delivery-queue-options queue)))
         (expired (>= (- now (queued-message-queued-at item)) (delivery-queue-give-up-after queue))))
    (flet ((with-status (status)
             (remove status statuses :key #'recipient-status-status :test-not #'eq)))
      (let ((delivered (with-status :delivered))
            (failed (with-status :failed))
            (deferred (with-status :deferred)))
        (when expired
          ;; Out of time: what is still deferred has failed.
          (setf failed (append failed
                               (mapcar (lambda (s)
                                         (let ((s (copy-recipient-status s)))
                                           (setf (recipient-status-status s) :failed
                                                 (recipient-status-message s)
                                                 (format nil "Gave up after ~d attempts: ~a"
                                                         (1+ (queued-message-attempts item))
                                                         (recipient-status-message s)))
                                           s))
                                       deferred))
                deferred '()))
        (bt:with-lock-held ((%queue-lock queue))
          (incf (queued-message-attempts item))
          (setf (queued-message-statuses item)
                (append (remove-if (lambda (s) (member (recipient-status-recipient s) statuses
                                                       :key #'recipient-status-recipient :test #'string-equal))
                                   (queued-message-statuses item))
                        delivered failed deferred)
                (queued-message-recipients item) (mapcar #'recipient-status-recipient deferred)
                (queued-message-next-attempt item)
                (+ now (%retry-delay queue (queued-message-attempts item))))
          (unless deferred
            (setf (%items queue) (remove item (%items queue)))))
        (%notify (%on-delivered queue) item delivered)
        (%notify (%on-failed queue) item failed)
        (%notify (%on-deferred queue) item deferred)))))

(defun %attempt-failed (queue item now condition)
  (let ((expired (>= (- now (queued-message-queued-at item)) (delivery-queue-give-up-after queue)))
        (failed '()))
    (bt:with-lock-held ((%queue-lock queue))
      (incf (queued-message-attempts item))
      (if expired
          (let ((message (format nil "Gave up after ~d attempts: ~a"
                                 (queued-message-attempts item) condition)))
            (setf failed (mapcar (lambda (r) (%status r :failed :message message))
                                 (queued-message-recipients item))
                  (queued-message-statuses item)
                  (append (remove-if (lambda (s) (member (recipient-status-recipient s)
                                                         (queued-message-recipients item)
                                                         :test #'string-equal))
                                     (queued-message-statuses item))
                          failed)
                  (queued-message-recipients item) '()
                  (%items queue) (remove item (%items queue))))
          (setf (queued-message-next-attempt item)
                (+ now (%retry-delay queue (queued-message-attempts item))))))
    (%notify (%on-failed queue) item failed)))

(defun run-delivery-queue (queue &key (now (get-universal-time)))
  "Attempt every message that is due. Returns the number attempted."
  (let ((due (bt:with-lock-held ((%queue-lock queue))
               (let ((due (remove-if (lambda (item) (> (queued-message-next-attempt item) now))
                                     (%items queue))))
                 ;; Claim them, so that a concurrent run does not try them too.
                 (dolist (item due)
                   (setf (queued-message-next-attempt item) most-positive-fixnum))
                 due))))
    (dolist (item due)
      (handler-case (%process-item queue item now)
        (error (e)
          ;; A bug or a local problem: keep the message and try later,
          ;; unless it has been queued too long.
          (warn "Delivery of ~a failed: ~a" (queued-message-id item) e)
          (%attempt-failed queue item now e))))
    (length due)))
