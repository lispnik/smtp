;;; mailpit.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

;;; Reading back what the servers received, through Mailpit's HTTP API
;;; (https://mailpit.axllent.org/docs/api-v1/). Postfix relays to Mailpit,
;;; so this serves both servers.

(in-package #:smtp/integration)

(defun http (method path)
  "Make an HTTP/1.0 request to Mailpit. Returns the status code and the body
as octets."
  (let ((socket (usocket:socket-connect *host* *mailpit-api-port*
                                        :element-type '(unsigned-byte 8) :timeout 10)))
    (unwind-protect
         (let ((stream (usocket:socket-stream socket)))
           (write-sequence (babel:string-to-octets
                            (format nil "~a ~a HTTP/1.0~c~cHost: localhost~c~c~c~c"
                                    method path #\Return #\Linefeed #\Return #\Linefeed
                                    #\Return #\Linefeed))
                           stream)
           (force-output stream)
           (let* ((response (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                                                     :adjustable t :fill-pointer 0))
                                  (buffer (make-array 65536 :element-type '(unsigned-byte 8))))
                              (loop for n = (read-sequence buffer stream)
                                    while (plusp n)
                                    do (loop for i below n do (vector-push-extend (aref buffer i) out)))
                              out))
                  (end (search #(13 10 13 10) response))
                  (head (babel:octets-to-string response :end end :encoding :latin-1)))
             (values (parse-integer head :start 9 :end 12)
                     (subseq response (+ end 4)))))
      (usocket:socket-close socket))))

(defun api (path &key (method "GET"))
  "Mailpit's JSON reply to PATH, parsed."
  (multiple-value-bind (status body) (http method path)
    (unless (= status 200)
      (error "Mailpit ~a ~a: HTTP ~d ~a" method path status
             (babel:octets-to-string body :encoding :utf-8 :errorp nil)))
    (jzon:parse (babel:octets-to-string body :encoding :utf-8))))

(defun j (object &rest keys)
  "Follow KEYS (strings for objects, integers for arrays) into parsed JSON."
  (dolist (k keys object)
    (setf object (if (integerp k) (aref object k) (gethash k object)))))

(defun bare-id (id)
  (string-trim "<>" id))

(defun delete-all-messages ()
  (http "DELETE" "/api/v1/messages"))

(defun find-messages (predicate)
  "Summaries of the stored messages satisfying PREDICATE, newest first."
  (remove-if-not predicate (coerce (j (api "/api/v1/messages?limit=1000") "messages") 'list)))

(defun wait-for (predicate &key (timeout 30) (what "message"))
  "Poll Mailpit until a message satisfying PREDICATE arrives; return its full
record. Postfix relays asynchronously, so this can take a moment."
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop
      (let ((found (first (find-messages predicate))))
        (when found
          (return (api (format nil "/api/v1/message/~a" (j found "ID"))))))
      (when (> (get-internal-real-time) deadline)
        (error "No ~a arrived in Mailpit within ~d s" what timeout))
      (sleep 0.1))))

(defun wait-for-message-id (id &key (timeout 30))
  (let ((id (bare-id id)))
    (wait-for (lambda (m) (equal (j m "MessageID") id))
              :timeout timeout :what (format nil "message <~a>" id))))

(defun mailpit-raw (record)
  (multiple-value-bind (status body) (http "GET" (format nil "/api/v1/message/~a/raw" (j record "ID")))
    (assert (= status 200))
    body))

(defun mailpit-headers (record)
  (api (format nil "/api/v1/message/~a/headers" (j record "ID"))))

(defun mailpit-part (record part-id)
  (multiple-value-bind (status body)
      (http "GET" (format nil "/api/v1/message/~a/part/~a" (j record "ID") part-id))
    (assert (= status 200))
    body))

(defun mailpit-reachable-p ()
  (ignore-errors (api "/api/v1/info")))
