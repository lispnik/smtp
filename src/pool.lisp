;;; pool.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Connection pools: a bounded set of connections to one server, shared by
;;; any number of threads. Connections are opened when first needed and
;;; reused while they are healthy and young enough.
;;;
;;; Liveness: an idle connection whose socket has become readable (the server
;;; sent something unprompted, usually 421 before closing, or closed it) is
;;; discarded when checked out, at no cost. One idle for more than
;;; CHECK-AFTER seconds is first sent NOOP. Even so, a server can close a
;;; connection just as it is reused, so POOL-SEND-MESSAGE retries once on a
;;; fresh connection when a reused one fails before the server accepted MAIL
;;; FROM; by then no message data has been sent, so a retry cannot deliver
;;; the message twice.
;;;
;;; All pool state is guarded by one lock, and no network I/O is done while
;;; holding it.

(in-package #:smtp)

(define-condition smtp-pool-timeout (smtp-error)
  ((seconds :initarg :seconds :initform nil :reader smtp-pool-timeout-seconds))
  (:report (lambda (c s)
             (format s "No pooled connection became available within ~a seconds"
                     (smtp-pool-timeout-seconds c))))
  (:documentation "Every connection of a pool stayed in use for the pool's
WAIT-TIMEOUT."))

(define-condition smtp-pool-closed (smtp-error) ()
  (:default-initargs :message "The connection pool is closed"))

(defstruct (%pooled (:constructor %make-pooled (connection)))
  connection
  (created (%now))
  (last-used (%now))
  (messages 0)
  (reused nil)
  (discard nil))

(defun %now ()
  (/ (get-internal-real-time) internal-time-units-per-second))

(defclass connection-pool ()
  ((host :initarg :host :reader connection-pool-host)
   (options :initarg :options :reader %pool-options)
   (max-connections :initarg :max-connections :reader %pool-max-connections)
   (max-idle :initarg :max-idle :reader %pool-max-idle)
   (idle-timeout :initarg :idle-timeout :reader %pool-idle-timeout)
   (max-messages :initarg :max-messages :reader %pool-max-messages)
   (max-age :initarg :max-age :reader %pool-max-age)
   (wait-timeout :initarg :wait-timeout :reader %pool-wait-timeout)
   (check-after :initarg :check-after :reader %pool-check-after)
   (lock :initform (bt2:make-lock :name "smtp connection pool") :reader %pool-lock)
   (available :initform (bt2:make-condition-variable :name "smtp connection pool")
              :reader %pool-available)
   ;; Guarded by LOCK:
   (idle :initform '() :accessor %pool-idle
         :documentation "Idle entries, most recently used first.")
   (size :initform 0 :accessor %pool-size
         :documentation "Connections idle, in use or being opened.")
   (closed :initform nil :accessor %pool-closed)
   (opened :initform 0 :accessor %pool-opened)
   (reuses :initform 0 :accessor %pool-reuses)
   (waiting :initform 0 :accessor %pool-waiting))
  (:documentation "A thread-safe pool of connections to one SMTP server."))

(defmethod print-object ((pool connection-pool) stream)
  (print-unreadable-object (pool stream :type t :identity t)
    (format stream "~a ~d/~d~:[~; closed~]" (connection-pool-host pool)
            (%pool-size pool) (%pool-max-connections pool) (%pool-closed pool))))

(defun make-connection-pool (host &rest options
                             &key (max-connections 4) max-idle (idle-timeout 60)
                               (max-messages-per-connection 100) (max-connection-age 600)
                               (wait-timeout 30) (check-after 10)
                             &allow-other-keys)
  "A pool of at most MAX-CONNECTIONS connections to HOST, opened when needed
by OPEN-CONNECTION with the remaining OPTIONS (:port, :tls, :credentials and
so on).

Up to MAX-IDLE (default MAX-CONNECTIONS) unused connections are kept open.
A connection is closed instead of reused once it has been idle for
IDLE-TIMEOUT seconds, has carried MAX-MESSAGES-PER-CONNECTION transactions,
or is MAX-CONNECTION-AGE seconds old; any of these may be NIL for no limit.
A connection idle for more than CHECK-AFTER seconds is sent NOOP before
reuse. A thread wanting a connection while all are in use waits up to
WAIT-TIMEOUT seconds (NIL: indefinitely) before SMTP-POOL-TIMEOUT is
signalled."
  (check-type host string)
  (check-type max-connections (integer 1))
  (check-type max-idle (or null (integer 0)))
  (flet ((limit (name value)
           (unless (or (null value) (and (realp value) (>= value 0)))
             (error 'type-error :datum value :expected-type '(or null (real 0))
                                :context name))
           value))
    (make-instance 'connection-pool
                   :host host
                   :options (alexandria:remove-from-plist
                             options :max-connections :max-idle :idle-timeout
                                     :max-messages-per-connection :max-connection-age
                                     :wait-timeout :check-after)
                   :max-connections max-connections
                   :max-idle (or max-idle max-connections)
                   :idle-timeout (limit :idle-timeout idle-timeout)
                   :max-messages (limit :max-messages-per-connection max-messages-per-connection)
                   :max-age (limit :max-connection-age max-connection-age)
                   :wait-timeout (limit :wait-timeout wait-timeout)
                   :check-after (limit :check-after check-after))))

(defun connection-pool-statistics (pool)
  "A plist describing POOL: :CONNECTIONS (open or opening), :IDLE, :IN-USE,
:WAITING (threads), :OPENED and :REUSED (totals since it was made) and
:CLOSED."
  (bt2:with-lock-held ((%pool-lock pool))
    (let ((idle (length (%pool-idle pool))))
      (list :connections (%pool-size pool) :idle idle :in-use (- (%pool-size pool) idle)
            :waiting (%pool-waiting pool) :opened (%pool-opened pool)
            :reused (%pool-reuses pool) :closed (%pool-closed pool)))))

;;; Checking connections out and in

(defun %expired-p (pool entry now)
  (let ((idle-timeout (%pool-idle-timeout pool))
        (max-age (%pool-max-age pool))
        (max-messages (%pool-max-messages pool)))
    (or (and idle-timeout (> (- now (%pooled-last-used entry)) idle-timeout))
        (and max-age (> (- now (%pooled-created entry)) max-age))
        (and max-messages (>= (%pooled-messages entry) max-messages)))))

(defun %readable-p (connection)
  "Whether the server has sent anything, or closed the connection, while
CONNECTION was idle. Either way it cannot be used."
  (let ((socket (%socket connection))
        (stream (%stream connection)))
    (or (null socket) (null stream)
        (handler-case (or (listen stream)
                          (and (usocket:wait-for-input socket :timeout 0 :ready-only t) t))
          (error () t)))))

(defun %usable-p (connection)
  (and (eq (connection-state connection) :open)
       (not (%in-transaction connection))
       (not (%readable-p connection))))

(defun %discard (entries)
  "Close ENTRIES, which no longer count towards their pool's size. Called
without the lock held."
  (dolist (entry entries)
    (close-connection (%pooled-connection entry))))

(defun %release-slot (pool)
  (bt2:with-lock-held ((%pool-lock pool))
    (decf (%pool-size pool))
    (bt2:condition-notify (%pool-available pool))))

(defun %take (pool fresh deadline)
  "Under the lock, take an idle entry or reserve a slot for a new connection.
Returns the entry (or NIL to open a new one) and expired entries to close."
  (let ((stale '()) (lock (%pool-lock pool)))
    (bt2:with-lock-held (lock)
      (loop
        (when (%pool-closed pool)
          (return-from %take (values :closed stale)))
        (let ((now (%now)))
          (unless fresh
            (loop for entry = (pop (%pool-idle pool))
                  while entry
                  do (if (%expired-p pool entry now)
                         (progn (push entry stale) (decf (%pool-size pool)))
                         (return-from %take (values entry stale)))))
          (when (and fresh (%pool-idle pool) (>= (%pool-size pool) (%pool-max-connections pool)))
            ;; Make room by closing the least recently used idle connection.
            (let ((oldest (car (last (%pool-idle pool)))))
              (setf (%pool-idle pool) (butlast (%pool-idle pool)))
              (push oldest stale)
              (decf (%pool-size pool))))
          (when (< (%pool-size pool) (%pool-max-connections pool))
            (incf (%pool-size pool))
            (when stale
              ;; Retiring them may have freed slots for other threads too.
              (bt2:condition-broadcast (%pool-available pool)))
            (return-from %take (values nil stale)))
          (let ((remaining (and deadline (- deadline now))))
            (when (and remaining (<= remaining 0))
              (return-from %take (values :timeout stale)))
            (incf (%pool-waiting pool))
            (unwind-protect
                 (bt2:condition-wait (%pool-available pool) lock :timeout remaining)
              (decf (%pool-waiting pool)))))))))

(defun %open-entry (pool)
  (let ((ok nil))
    (unwind-protect
         (let ((entry (%make-pooled (apply #'open-connection (connection-pool-host pool)
                                           (%pool-options pool)))))
           (bt2:with-lock-held ((%pool-lock pool))
             (incf (%pool-opened pool)))
           (setf ok t)
           entry)
      (unless ok (%release-slot pool)))))

(defun %alive-p (pool entry)
  "Whether an idle ENTRY may be reused, checking it with NOOP if it has been
idle longer than the pool's CHECK-AFTER."
  (let ((connection (%pooled-connection entry))
        (check-after (%pool-check-after pool)))
    (and (%usable-p connection)
         (or (null check-after)
             (<= (- (%now) (%pooled-last-used entry)) check-after)
             (handler-case
                 (progn (command connection "NOOP"
                                 :timeout (min 10 (or (connection-timeout connection) 10)))
                        t)
               (smtp-error () nil))))))

(defun %checkout (pool &key fresh)
  (let ((deadline (let ((w (%pool-wait-timeout pool))) (and w (+ (%now) w)))))
    (loop
      (multiple-value-bind (entry stale) (%take pool fresh deadline)
        (%discard stale)
        (case entry
          (:closed (error 'smtp-pool-closed))
          (:timeout (error 'smtp-pool-timeout :seconds (%pool-wait-timeout pool)))
          ((nil) (return (%open-entry pool)))
          (t (if (%alive-p pool entry)
                 (progn (setf (%pooled-reused entry) t)
                        (bt2:with-lock-held ((%pool-lock pool))
                          (incf (%pool-reuses pool)))
                        (return entry))
                 (progn (%discard (list entry))
                        (%release-slot pool)))))))))

(defun %checkin (pool entry)
  (let* ((connection (%pooled-connection entry))
         (keep (and (not (%pooled-discard entry))
                    (%usable-p connection)
                    (not (%expired-p pool entry (%now))))))
    (setf (%pooled-last-used entry) (%now)
          (%pooled-reused entry) nil)
    (bt2:with-lock-held ((%pool-lock pool))
      (if (and keep (not (%pool-closed pool))
               (< (length (%pool-idle pool)) (%pool-max-idle pool)))
          (push entry (%pool-idle pool))
          (setf keep nil))
      (unless keep (decf (%pool-size pool)))
      (bt2:condition-notify (%pool-available pool)))
    (unless keep
      (close-connection connection))))

(defun %call-with-entry (pool function &key fresh)
  "Call FUNCTION with a checked-out connection and its entry, counting the
transactions it starts, and check the connection in again afterwards. One
left broken, closed, mid-transaction or desynchronised is closed instead of
being returned to the pool."
  (let ((entry (%checkout pool :fresh fresh)))
    (unwind-protect
         (let* ((connection (%pooled-connection entry))
                (outer *mail-accepted-hook*)
                (*mail-accepted-hook*
                  (lambda (c)
                    (when (eq c connection) (incf (%pooled-messages entry)))
                    (when outer (funcall outer c)))))
           (funcall function connection entry))
      (%checkin pool entry))))

(defun call-with-pooled-connection (pool function)
  "Call FUNCTION with a connection from POOL, returning it to the pool
afterwards."
  (%call-with-entry pool (lambda (connection entry)
                           (declare (ignore entry))
                           (funcall function connection))))

(defmacro with-pooled-connection ((var pool) &body body)
  "Evaluate BODY with VAR bound to a connection from POOL, which is returned
to the pool afterwards, or closed if BODY left it unusable or in the middle
of a transaction. BODY must not keep the connection or give it to another
thread."
  `(call-with-pooled-connection ,pool (lambda (,var) (declare (ignorable ,var)) ,@body)))

(defun %stale-error-p (condition)
  (or (typep condition 'smtp-connection-error)
      (and (typep condition 'smtp-reply-error)
           (smtp-error-reply condition)
           (= 421 (reply-code (smtp-error-reply condition))))))

(defun pool-send-message (pool message &rest options)
  "Send MESSAGE over a connection from POOL, as SEND-MESSAGE does with
OPTIONS, and return the DELIVERY-RESULT. If a reused connection turns out to
be dead (the server closed it or replied 421) before the server accepted
MAIL FROM, the message is sent once more over a new connection; nothing has
been delivered at that point, so it cannot arrive twice. Any other failure
is signalled as by SEND-MESSAGE, with its restarts."
  (flet ((attempt (fresh)
           (block attempt
             (%call-with-entry
              pool
              (lambda (connection entry)
                (let* ((mail-accepted nil)
                       (outer *mail-accepted-hook*)
                       (*mail-accepted-hook*
                         (lambda (c)
                           (when (eq c connection) (setf mail-accepted t))
                           (when outer (funcall outer c)))))
                  (handler-bind ((smtp-error
                                   (lambda (e)
                                     (when (and (%pooled-reused entry)
                                                (not fresh)
                                                (not mail-accepted)
                                                (%stale-error-p e))
                                       (setf (%pooled-discard entry) t)
                                       (return-from attempt (values nil t))))))
                    (values (apply #'send-message connection message options) nil))))
              :fresh fresh))))
    (multiple-value-bind (result retry) (attempt nil)
      (if retry
          (values (attempt t))
          result))))

(defun close-connection-pool (pool)
  "Close POOL's idle connections; those in use are closed when returned.
Afterwards the pool hands out no connections and SMTP-POOL-CLOSED is
signalled to threads that ask for one, including any waiting."
  (let ((idle '()))
    (bt2:with-lock-held ((%pool-lock pool))
      (setf (%pool-closed pool) t
            idle (%pool-idle pool)
            (%pool-idle pool) '())
      (decf (%pool-size pool) (length idle))
      (bt2:condition-broadcast (%pool-available pool)))
    (%discard idle)
    nil))
