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
  (unless (and retry-schedule (every (lambda (n) (typep n '(real 0))) retry-schedule))
    (error 'type-error :datum retry-schedule :expected-type '(cons (real 0) list)))
  (check-type give-up-after (real 0))
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
                                           (now (get-universal-time)) (queued-at now) (attempts 0))
  "Queue the rendered OCTETS for delivery now. QUEUED-AT and ATTEMPTS restore
a message saved from an earlier queue, so that it still gives up on time."
  (unless envelope-from (error 'mail-format-error :message "No envelope sender (:envelope-from)"))
  (unless recipients (error 'mail-format-error :message "No recipients"))
  (let ((item (%make-queued-message
               :id (or id (smtp::random-token 12)) :octets octets
               :envelope-from (if (equal envelope-from "") "" (mailbox-address (smtp::ensure-mailbox envelope-from)))
               :recipients (remove-duplicates (mapcar #'mailbox-address (smtp::ensure-mailbox-list recipients))
                                              :test #'string-equal :from-end t)
               :smtputf8 smtputf8 :queued-at queued-at :attempts attempts :next-attempt now)))
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

(defun %give-up (statuses attempts)
  "STATUSES, for recipients still outstanding when a message is given up
after ATTEMPTS attempts, as failures."
  (mapcar (lambda (s)
            (let ((s (copy-recipient-status s)))
              (setf (recipient-status-status s) :failed
                    (recipient-status-message s)
                    (format nil "Gave up after ~d attempts: ~a" attempts (recipient-status-message s)))
              s))
          statuses))

(defun %record-attempt (queue item now delivered failed deferred)
  "Record an attempt's outcome, under the lock. If the message has been
queued too long, what is still deferred fails. Returns the statuses
delivered, failed and deferred, for the callbacks."
  (bt:with-lock-held ((%queue-lock queue))
    (let ((attempts (incf (queued-message-attempts item))))
      (when (>= (- now (queued-message-queued-at item)) (delivery-queue-give-up-after queue))
        (setf failed (append failed (%give-up deferred attempts))
              deferred '()))
      (let ((statuses (append delivered failed deferred)))
        (setf (queued-message-statuses item)
              (append (remove-if (lambda (s) (member (recipient-status-recipient s) statuses
                                                     :key #'recipient-status-recipient
                                                     :test #'string-equal))
                                 (queued-message-statuses item))
                      statuses)
              (queued-message-recipients item) (mapcar #'recipient-status-recipient deferred)
              (queued-message-next-attempt item) (+ now (%retry-delay queue attempts))))
      (unless deferred
        (setf (%items queue) (remove item (%items queue))))
      (values delivered failed deferred))))

(defun %process-item (queue item now)
  "Attempt ITEM and record the outcome. Returns the callbacks to make, as a
list of (function statuses)."
  (let ((statuses (apply #'deliver-raw-message (queued-message-octets item)
                         :envelope-from (queued-message-envelope-from item)
                         :recipients (queued-message-recipients item)
                         :smtputf8 (queued-message-smtputf8 item)
                         (delivery-queue-options queue))))
    (flet ((with-status (status)
             (remove status statuses :key #'recipient-status-status :test-not #'eq)))
      (multiple-value-bind (delivered failed deferred)
          (%record-attempt queue item now
                           (with-status :delivered) (with-status :failed) (with-status :deferred))
        (list (list (%on-delivered queue) delivered)
              (list (%on-failed queue) failed)
              (list (%on-deferred queue) deferred))))))

(defun %attempt-failed (queue item now condition)
  "Record an attempt that failed with CONDITION, a local problem rather than
a reply: every outstanding recipient is deferred. Returns the callbacks to
make, as %PROCESS-ITEM does."
  (let ((message (format nil "~a" condition)))
    (multiple-value-bind (delivered failed deferred)
        (%record-attempt queue item now '() '()
                         (mapcar (lambda (r) (%status r :deferred :message message))
                                 (queued-message-recipients item)))
      (declare (ignore delivered))
      (list (list (%on-failed queue) failed)
            (list (%on-deferred queue) deferred)))))

(defun run-delivery-queue (queue &key (now (get-universal-time)))
  "Attempt every message that is due. Returns the number attempted."
  (let* ((claimed '())
         (due (bt:with-lock-held ((%queue-lock queue))
                (let ((due (remove-if (lambda (item) (> (queued-message-next-attempt item) now))
                                      (%items queue))))
                  ;; Claim them, so that a concurrent run does not try them too.
                  (dolist (item due)
                    (push (cons item (queued-message-next-attempt item)) claimed)
                    (setf (queued-message-next-attempt item) most-positive-fixnum))
                  due))))
    (unwind-protect
         (dolist (item due)
           (let ((callbacks
                   (handler-case (%process-item queue item now)
                     ;; A bug or a local problem: keep the message and try
                     ;; later, unless it has been queued too long.
                     (error (e)
                       (prog1 (%attempt-failed queue item now e)
                         (warn "Delivery of ~a failed: ~a" (queued-message-id item) e))))))
             (setf claimed (remove item claimed :key #'car))
             (loop for (fn statuses) in callbacks
                   do (%notify fn item statuses))))
      ;; Unwound part way (a warning made an error, say): release the
      ;; claims on the items not attempted, so that they are not stranded.
      (when claimed
        (bt:with-lock-held ((%queue-lock queue))
          (loop for (item . next) in claimed
                when (= (queued-message-next-attempt item) most-positive-fixnum)
                  do (setf (queued-message-next-attempt item) next)))))
    (length due)))
