;;; pool.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/pool :in :smtp :description "Connection pools.")
(in-suite :smtp/pool)

;;; A mock server accepting any number of connections, each served on its
;;; own thread by (funcall HANDLER session index), index counting from 0.

(defclass pool-server ()
  ((lock :initform (bt:make-lock "pool server") :reader server-lock)
   (sessions :initform '() :accessor server-sessions)
   (active :initform 0 :accessor server-active)
   (max-active :initform 0 :accessor server-max-active)))

(defun server-session-list (server)
  (bt:with-lock-held ((server-lock server)) (reverse (server-sessions server))))

(defun server-message-count (server)
  (reduce #'+ (server-session-list server) :key (lambda (s) (length (session-messages s)))))

(defun call-with-pool-server (handler function)
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :backlog 32
                                                        :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (server (make-instance 'pool-server))
         (stop nil)
         (threads '())
         (acceptor
           (bt:make-thread
            (lambda ()
              (loop until stop
                    do (when (usocket:wait-for-input listener :timeout 0.05 :ready-only t)
                         (let* ((socket (usocket:socket-accept listener))
                                (session (make-instance 'session))
                                (index nil))
                           (setf (session-socket session) socket
                                 (session-stream session) (usocket:socket-stream socket))
                           (bt:with-lock-held ((server-lock server))
                             (setf index (length (server-sessions server)))
                             (push session (server-sessions server))
                             (setf (server-max-active server)
                                   (max (server-max-active server) (incf (server-active server)))))
                           (push (bt:make-thread
                                  (lambda ()
                                    (handler-case
                                        (sb-sys:with-deadline (:seconds 15)
                                          (funcall handler session index))
                                      (serious-condition (e) (setf (session-error session) e)))
                                    (bt:with-lock-held ((server-lock server))
                                      (decf (server-active server)))
                                    (ignore-errors (close (session-stream session)))
                                    (ignore-errors (usocket:socket-close socket)))
                                  :name "mock smtp session")
                                 threads)))))
            :name "mock smtp acceptor")))
    (unwind-protect (funcall function port server)
      (setf stop t)
      (bt:join-thread acceptor)
      (mapc #'bt:join-thread threads)
      (usocket:socket-close listener))))

(defmacro with-pool-server ((port server handler) &body body)
  `(call-with-pool-server ,handler (lambda (,port ,server)
                                     (declare (ignorable ,port ,server))
                                     ,@body)))

(defun scripted-server (&key (on-mail (constantly :ok)) (on-data (constantly :ok)) noop-reply)
  "A handler for a minimal server without PIPELINING. ON-MAIL and ON-DATA are
called with the session, its index and the number of messages it already
accepted, and return :OK, :CLOSE (drop the connection without replying) or
a reply line."
  (lambda (s index)
    (let ((from nil) (rcpts '()))
      (block session
        (flet ((act (result ok-reply)
                 (case result
                   (:ok (srv-send s ok-reply) t)
                   (:close (return-from session))
                   (t (srv-send s result) nil))))
          (srv-send s "220 mock.test ESMTP")
          (loop
            (let ((line (srv-read-line s)))
              (when (null line) (return))
              (let ((verb (%verb line)))
                (cond
                  ((string= verb "EHLO") (srv-send s "250-mock.test" "250 8BITMIME"))
                  ((string= verb "MAIL")
                   (when (act (funcall on-mail s index (length (session-messages s)))
                              "250 2.1.0 OK")
                     (setf from (%path (%arg line)))))
                  ((string= verb "RCPT") (push (%path (%arg line)) rcpts) (srv-send s "250 2.1.5 OK"))
                  ((string= verb "DATA")
                   (srv-send s "354 Go ahead")
                   (let ((data (srv-read-data s))
                         (result (funcall on-data s index (length (session-messages s)))))
                     (when (eq result :ok)
                       (setf (session-messages s)
                             (append (session-messages s) (list (list from (reverse rcpts) data)))))
                     (setf from nil rcpts '())
                     (act result "250 2.0.0 OK")))
                  ((string= verb "RSET") (setf from nil rcpts '()) (srv-send s "250 2.0.0 OK"))
                  ((string= verb "NOOP") (srv-send s (or noop-reply "250 2.0.0 OK")))
                  ((string= verb "QUIT") (srv-send s "221 2.0.0 Bye") (return))
                  (t (srv-send s "500 5.5.2 Command unrecognized")))))))))))

(defun one-session (handler)
  "HANDLER, a function of a session, as a pool server handler."
  (lambda (session index) (declare (ignore index)) (funcall handler session)))

(defun pool-for (port &rest options)
  (apply #'make-connection-pool "127.0.0.1"
         (append options (list :port port :tls :none :local-name "client.test" :timeout 5))))

(defun stat (pool key) (getf (connection-pool-statistics pool) key))

(defmacro with-pool ((var port &rest options) &body body)
  `(let ((,var (pool-for ,port ,@options)))
     (unwind-protect (progn ,@body)
       (close-connection-pool ,var))))

;;; Tests

(test pool-reuses-one-connection
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port)
      (dotimes (i 5)
        (is (equal '("bob@example.net")
                   (delivery-result-accepted (pool-send-message pool (simple-message))))))
      (is (= 1 (stat pool :opened)))
      (is (= 4 (stat pool :reused)))
      (is (= 1 (stat pool :idle))))
    (is (= 1 (length (server-session-list server))))
    (is (= 5 (server-message-count server)))
    ;; Closing the pool said goodbye.
    (is (equal '("QUIT") (sent-commands (first (server-session-list server)) "QUIT")))))

(test pool-bounds-concurrency
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 3 :wait-timeout 10)
      (let* ((errors '())
             (lock (bt:make-lock))
             (threads (loop repeat 8
                            collect (bt:make-thread
                                     (lambda ()
                                       (handler-case
                                           (dotimes (i 5) (pool-send-message pool (simple-message)))
                                         (error (e) (bt:with-lock-held (lock) (push e errors)))))))))
        (mapc #'bt:join-thread threads)
        (is (null errors))
        (is (<= (stat pool :opened) 3))
        (is (= 0 (stat pool :in-use)))))
    (is (<= (server-max-active server) 3))
    (is (= 40 (server-message-count server)))))

(test pool-wait-timeout
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 1 :wait-timeout 0.2)
      (let* ((holding (bt:make-semaphore))
             (release (bt:make-semaphore))
             (holder (bt:make-thread
                      (lambda ()
                        (with-pooled-connection (c pool)
                          (bt:signal-semaphore holding)
                          (bt:wait-on-semaphore release :timeout 5))))))
        (bt:wait-on-semaphore holding :timeout 5)
        (let ((start (get-internal-real-time)))
          (signals smtp-pool-timeout (with-pooled-connection (c pool) c))
          (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 1)))
        (bt:signal-semaphore release)
        (bt:join-thread holder)
        ;; Once returned, the connection is available again.
        (is (pool-send-message pool (simple-message)))
        (is (= 1 (stat pool :opened)))))))

(test waiting-thread-gets-returned-connection
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 1 :wait-timeout 5)
      (let* ((holding (bt:make-semaphore))
             (holder (bt:make-thread
                      (lambda ()
                        (with-pooled-connection (c pool)
                          (bt:signal-semaphore holding)
                          (sleep 0.2))))))
        (bt:wait-on-semaphore holding :timeout 5)
        (is (pool-send-message pool (simple-message)))
        (bt:join-thread holder)
        (is (= 1 (stat pool :opened)))))))

(test dead-idle-connection-is-replaced
  ;; The server drops the connection when the second transaction begins,
  ;; as if its idle timer had fired just then.
  (with-pool-server (port server (scripted-server
                                  :on-mail (lambda (s index n)
                                             (declare (ignore s))
                                             (if (and (= index 0) (= n 1)) :close :ok))))
    (with-pool (pool port)
      (pool-send-message pool (simple-message))
      (is (equal '("bob@example.net")
                 (delivery-result-accepted (pool-send-message pool (simple-message)))))
      (is (= 2 (stat pool :opened))))
    (is (= 2 (length (server-session-list server))))
    (is (= 2 (server-message-count server)))))

(test closing-421-at-mail-is-retried
  (with-pool-server (port server (scripted-server
                                  :on-mail (lambda (s index n)
                                             (declare (ignore s))
                                             (if (and (= index 0) (= n 1))
                                                 "421 4.4.2 mock.test closing idle connection"
                                                 :ok))))
    (with-pool (pool port)
      (pool-send-message pool (simple-message))
      (is (pool-send-message pool (simple-message)))
      (is (= 2 (stat pool :opened))))
    (is (= 2 (server-message-count server)))))

(test announced-close-is-noticed-before-reuse
  ;; The server says 421 and hangs up while the connection is idle.
  (with-pool-server (port server
                          (lambda (s index)
                            (funcall (scripted-server
                                      :on-data (lambda (s index n)
                                                 (declare (ignore n))
                                                 (if (= index 0)
                                                     (progn (srv-send s "250 2.0.0 OK")
                                                            (srv-send s "421 4.4.2 mock.test timeout")
                                                            :close)
                                                     :ok)))
                                     s index)))
    (with-pool (pool port)
      (pool-send-message pool (simple-message))
      (sleep 0.1)
      (is (pool-send-message pool (simple-message)))
      (is (= 2 (stat pool :opened))))
    (is (= 2 (length (server-session-list server))))
    ;; The second message was sent once, on the new connection.
    (is (= 1 (length (sent-commands (first (server-session-list server)) "MAIL"))))
    (is (= 1 (length (session-messages (second (server-session-list server))))))))

(test no-retry-after-message-data
  ;; The connection drops after the data was sent: the message may have been
  ;; delivered, so it must not be sent again.
  (with-pool-server (port server (scripted-server
                                  :on-data (lambda (s index n)
                                             (declare (ignore s))
                                             (if (and (= index 0) (= n 1)) :close :ok))))
    (with-pool (pool port)
      (pool-send-message pool (simple-message))
      (signals smtp-connection-closed (pool-send-message pool (simple-message)))
      (is (= 1 (stat pool :opened)))
      (is (= 0 (stat pool :connections))))
    (is (= 1 (length (server-session-list server))))))

(test no-retry-on-fresh-connection
  (with-pool-server (port server (scripted-server :on-mail (constantly :close)))
    (with-pool (pool port)
      (signals smtp-connection-closed (pool-send-message pool (simple-message)))
      (is (= 0 (stat pool :connections))))
    (is (= 1 (length (server-session-list server))))))

(test permanent-errors-are-not-retried
  (with-pool-server (port server (scripted-server
                                  :on-mail (lambda (s index n)
                                             (declare (ignore s index))
                                             (if (= n 1) "550 5.7.1 Not allowed" :ok))))
    (with-pool (pool port)
      (pool-send-message pool (simple-message))
      (signals smtp-permanent-error (pool-send-message pool (simple-message)))
      ;; The connection is still good and went back to the pool.
      (is (= 1 (stat pool :idle)))
      (is (= 1 (stat pool :opened))))
    (is (= 1 (length (server-session-list server))))))

(test recipient-restarts-pass-through
  (with-pool-server (port server (one-session (standard-server :reject-recipients '("carol@example.org"))))
    (with-pool (pool port)
      (let ((result (handler-bind ((smtp-recipients-rejected
                                     (lambda (c)
                                       (declare (ignore c))
                                       (invoke-restart 'send-to-accepted))))
                      (pool-send-message pool (simple-message :cc "carol@example.org")))))
        (is (equal '("bob@example.net") (delivery-result-accepted result))))
      (is (= 1 (stat pool :idle))))))

(test max-messages-per-connection-rotates
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-messages-per-connection 2)
      (dotimes (i 5) (pool-send-message pool (simple-message)))
      (is (= 3 (stat pool :opened))))
    (let ((sessions (server-session-list server)))
      (is (= 3 (length sessions)))
      (is (equal '(2 2 1) (mapcar (lambda (s) (length (session-messages s))) sessions)))
      ;; Retired connections were closed politely.
      (is (every (lambda (s) (sent-commands s "QUIT")) sessions)))))

(test retiring-connections-never-exceed-the-limit
  ;; A connection still counts until it is closed: retiring one (here after
  ;; every message) must not let a replacement open alongside it. The server
  ;; counts a connection gone when it reads QUIT, before it replies.
  (let ((lock (bt:make-lock)) (active 0) (peak 0))
    (with-pool-server (port server
                       (lambda (s index)
                         (declare (ignore index))
                         (bt:with-lock-held (lock) (setf peak (max peak (incf active))))
                         (let ((open t))
                           (unwind-protect
                                (progn
                                  (srv-send s "220 limit.test ESMTP")
                                  (loop for line = (srv-read-line s :record nil)
                                        while line
                                        do (let ((verb (%verb line)))
                                             (cond ((string= verb "QUIT")
                                                    (bt:with-lock-held (lock) (decf active))
                                                    (setf open nil)
                                                    (srv-send s "221 bye")
                                                    (return))
                                                   ((string= verb "DATA")
                                                    (srv-send s "354 go")
                                                    (srv-read-data s)
                                                    (srv-send s "250 queued")
                                                    ;; Slow to read what comes next, as
                                                    ;; a busy server is.
                                                    (sleep 0.05))
                                                   (t (srv-send s "250 ok"))))))
                             (when open (bt:with-lock-held (lock) (decf active)))))))
      (with-pool (pool port :max-connections 2 :max-messages-per-connection 1)
        (mapc #'bt:join-thread
              (loop repeat 4
                    collect (bt:make-thread
                             (lambda () (dotimes (i 10) (pool-send-message pool (simple-message)))))))
        (is (= 40 (stat pool :opened)))))
    (is (<= peak 2) "~d connections were open at once" peak)))

(test idle-timeout-closes-connections
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :idle-timeout 0.1)
      (pool-send-message pool (simple-message))
      (sleep 0.2)
      (pool-send-message pool (simple-message))
      (is (= 2 (stat pool :opened))))
    (is (= 2 (length (server-session-list server))))))

(test long-idle-connections-are-checked
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :check-after 0)
      (pool-send-message pool (simple-message))
      (sleep 0.01)
      (pool-send-message pool (simple-message)))
    (is (= 1 (length (sent-commands (first (server-session-list server)) "NOOP")))))
  ;; A failed check means a new connection, not an error.
  (with-pool-server (port server (scripted-server :noop-reply "421 4.3.2 going away"))
    (with-pool (pool port :check-after 0)
      (pool-send-message pool (simple-message))
      (sleep 0.01)
      (is (pool-send-message pool (simple-message)))
      (is (= 2 (stat pool :opened))))))

(test broken-connections-are-not-returned
  (with-pool-server (port server (scripted-server :noop-reply "garbage"))
    (with-pool (pool port)
      (with-pooled-connection (c pool)
        (signals smtp-protocol-error (noop c)))
      (is (= 0 (stat pool :connections)))
      (with-pooled-connection (c pool)
        (is (eq :open (smtp::connection-state c))))
      (is (= 2 (stat pool :opened))))))

(test unfinished-transactions-are-not-returned
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port)
      (with-pooled-connection (c pool)
        (setf (smtp::%in-transaction c) t))
      (is (= 0 (stat pool :connections))))))

(test non-local-exit-returns-a-healthy-connection
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port)
      (block done
        (with-pooled-connection (c pool)
          (send-message c (simple-message))
          (return-from done)))
      (is (= 1 (stat pool :idle)))
      (pool-send-message pool (simple-message))
      (is (= 1 (stat pool :opened))))))

(test closing-the-pool
  (with-pool-server (port server (scripted-server))
    (let ((pool (pool-for port :max-connections 2)))
      (pool-send-message pool (simple-message))
      (let* ((holding (bt:make-semaphore))
             (release (bt:make-semaphore))
             (holder (bt:make-thread
                      (lambda ()
                        (with-pooled-connection (c pool)
                          (bt:signal-semaphore holding)
                          (bt:wait-on-semaphore release :timeout 5)
                          (send-message c (simple-message)))))))
        (bt:wait-on-semaphore holding :timeout 5)
        (close-connection-pool pool)
        ;; The idle connection is gone; the one in use is still working.
        (is (= 1 (stat pool :connections)))
        (signals smtp-pool-closed (pool-send-message pool (simple-message)))
        (bt:signal-semaphore release)
        (bt:join-thread holder)
        (is (= 0 (stat pool :connections)))))
    (is (= 2 (server-message-count server)))
    (is (every (lambda (s) (sent-commands s "QUIT")) (server-session-list server)))))

(test closing-wakes-waiting-threads
  (with-pool-server (port server (scripted-server))
    (let* ((pool (pool-for port :max-connections 1 :wait-timeout 10))
           (holding (bt:make-semaphore))
           (result nil)
           (holder (bt:make-thread
                    (lambda ()
                      (with-pooled-connection (c pool)
                        (bt:signal-semaphore holding)
                        (sleep 0.3)))))
           (waiter (progn
                     (bt:wait-on-semaphore holding :timeout 5)
                     (bt:make-thread
                      (lambda ()
                        (setf result (handler-case (with-pooled-connection (c pool) :got)
                                       (smtp-pool-closed () :closed))))))))
      (loop repeat 100 until (= 1 (stat pool :waiting)) do (sleep 0.01))
      (close-connection-pool pool)
      (bt:join-thread waiter)
      (bt:join-thread holder)
      (is (eq :closed result)))))

(test open-failures-free-the-slot
  (with-pool-server (port server (one-session (standard-server :extensions '("AUTH PLAIN"))))
    ;; Wrong password: every open fails, and the slot is given back each time.
    (with-pool (pool port :max-connections 1 :wait-timeout 0.5
                          :credentials '(:username "alice" :password "wrong")
                          :allow-insecure-auth t)
      (dotimes (i 2)
        (signals smtp-authentication-failed (pool-send-message pool (simple-message))))
      (is (= 0 (stat pool :connections))))))

(test failing-close-frees-the-slot
  ;; Something other than an SMTP error escapes while a retired connection
  ;; is closed: its slot must still be given back.
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 1 :max-messages-per-connection 1 :wait-timeout 0.5
                          :trace (lambda (direction line)
                                   (when (and (eq direction :client) (string= line "QUIT"))
                                     (error "trace failed"))))
      (signals simple-error (pool-send-message pool (simple-message)))
      (is (= 0 (stat pool :connections)))
      (signals simple-error (pool-send-message pool (simple-message)))
      (is (= 2 (stat pool :opened))))
    (is (= 2 (server-message-count server)))))

(test expired-idle-connections-close-quickly
  ;; A server that has silently dropped an idle connection never answers
  ;; QUIT; the thread wanting a connection does not wait for it.
  (with-pool-server (port server
                     (lambda (s index)
                       (declare (ignore index))
                       (srv-send s "220 silent.test ESMTP")
                       (loop for line = (srv-read-line s)
                             while line
                             do (let ((verb (%verb line)))
                                  (cond ((string= verb "QUIT") (sleep 1.5) (return))
                                        ((string= verb "DATA")
                                         (srv-send s "354 go")
                                         (srv-read-data s)
                                         (srv-send s "250 queued"))
                                        (t (srv-send s "250 ok")))))))
    (with-pool (pool port :idle-timeout 0.1)
      (pool-send-message pool (simple-message))
      (sleep 0.2)
      (let ((start (get-internal-real-time)))
        (pool-send-message pool (simple-message))
        (is (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 1)))
      (is (= 2 (stat pool :opened))))
    (is (sent-commands (first (server-session-list server)) "QUIT"))))

(test fresh-checkout-replaces-one-idle-connection
  ;; A fresh connection wanted while the pool is full of idle ones takes the
  ;; slot of the least recently used, which is closed.
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 1)
      (pool-send-message pool (simple-message))
      (let ((entry (smtp::%checkout pool :fresh t)))
        (is (= 1 (stat pool :connections)))
        (is (= 0 (stat pool :idle)))
        (is (= 2 (stat pool :opened)))
        (smtp::%checkin pool entry))
      (is (= 1 (stat pool :idle))))
    (is (= 2 (length (server-session-list server))))
    (is (sent-commands (first (server-session-list server)) "QUIT"))))

(test failing-liveness-check-frees-the-slot
  ;; Something other than an SMTP error escapes the NOOP sent to check a
  ;; long-idle connection: its slot must still be given back.
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 1 :check-after 0 :wait-timeout 0.5
                          :trace (lambda (direction line)
                                   (when (and (eq direction :client) (string= line "NOOP"))
                                     (error "trace failed"))))
      (pool-send-message pool (simple-message))
      (sleep 0.01)
      (signals simple-error (pool-send-message pool (simple-message)))
      (is (= 0 (stat pool :connections))))))

(test freed-slots-wake-every-waiter
  ;; Every waiting thread is woken, so that one unwound before it takes the
  ;; slot cannot leave the others asleep beside a free slot.
  (with-pool-server (port server (scripted-server))
    (with-pool (pool port :max-connections 1)
      (let* ((lock (smtp::%pool-lock pool))
             (available (smtp::%pool-available pool))
             (prompt 0)
             (count-lock (bt:make-lock))
             (threads (loop repeat 2
                            collect (bt:make-thread
                                     (lambda ()
                                       (let ((start (get-internal-real-time)))
                                         (bt2:with-lock-held (lock)
                                           (bt2:condition-wait available lock :timeout 2))
                                         (when (< (- (get-internal-real-time) start)
                                                  internal-time-units-per-second)
                                           (bt:with-lock-held (count-lock) (incf prompt)))))))))
        (sleep 0.2)
        (bt2:with-lock-held (lock) (incf (smtp::%pool-size pool)))
        (smtp::%release-slot pool)
        (mapc #'bt:join-thread threads)
        (is (= 2 prompt))))))
