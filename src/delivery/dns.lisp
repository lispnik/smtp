;;; dns.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; A small stub resolver (RFC 1035) for the lookups mail delivery needs:
;;; MX, A, AAAA, TXT and TLSA. Queries ask a recursive resolver for DNSSEC
;;; validation (the AD bit, RFC 6840); whether a validated answer is believed
;;; depends on the resolver being trusted, normally only one on this host,
;;; since the AD bit travels unprotected.

(in-package #:smtp/delivery)

(define-condition dns-error (smtp-connection-error)
  ((name :initarg :name :initform nil :reader dns-error-name)
   (rtype :initarg :rtype :initform nil :reader dns-error-type))
  (:documentation "A DNS lookup failed (timeout, SERVFAIL, refused or an
unusable response). For mail delivery this is a temporary failure."))

(defconstant +dns-a+ 1)
(defconstant +dns-cname+ 5)
(defconstant +dns-mx+ 15)
(defconstant +dns-txt+ 16)
(defconstant +dns-aaaa+ 28)
(defconstant +dns-opt+ 41)
(defconstant +dns-tlsa+ 52)

(defparameter *record-types*
  `((:a . ,+dns-a+) (:cname . ,+dns-cname+) (:mx . ,+dns-mx+) (:txt . ,+dns-txt+)
    (:aaaa . ,+dns-aaaa+) (:tlsa . ,+dns-tlsa+)))

(defun %type-code (type)
  (or (cdr (assoc type *record-types*)) (error "Unknown DNS record type ~s" type)))

(defun %type-name (code)
  (car (rassoc code *record-types*)))

;;; Resolvers

(defclass resolver ()
  ((nameservers :initarg :nameservers :reader resolver-nameservers
                :documentation "A list of (address . port).")
   (timeout :initarg :timeout :initform 5 :reader resolver-timeout
            :documentation "Seconds to wait for each answer.")
   (attempts :initarg :attempts :initform 2 :reader resolver-attempts)
   (trust-ad :initarg :trust-ad :reader resolver-trust-ad
             :documentation "Whether the resolver's DNSSEC validation (the AD
bit) is believed. Without it nothing is treated as secure and DANE is not
used."))
  (:documentation "A recursive resolver to send queries to."))

(defmethod print-object ((r resolver) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "~{~a~^ ~}~:[~; validating~]"
            (mapcar #'car (resolver-nameservers r)) (resolver-trust-ad r))))

(defun %loopback-p (address)
  (or (string= address "::1") (alexandria:starts-with-subseq "127." address)))

(defun %system-nameservers ()
  (with-open-file (in "/etc/resolv.conf" :if-does-not-exist nil)
    (when in
      (loop for line = (read-line in nil)
            while line
            for words = (remove "" (uiop:split-string (string-trim '(#\Space #\Tab) line)
                                                      :separator '(#\Space #\Tab))
                                :test #'string=)
            when (and (equal (first words) "nameserver") (second words))
              collect (let ((address (second words)))
                        ;; Drop an IPv6 zone index.
                        (subseq address 0 (position #\% address)))))))

(defun make-resolver (&key nameservers (port 53) (timeout 5) (attempts 2)
                        (trust-ad :loopback))
  "A resolver for NAMESERVERS (addresses, or (address . port) pairs; default
those in /etc/resolv.conf). TRUST-AD :LOOPBACK (the default) believes DNSSEC
validation only when every nameserver is on this host; T or NIL decide
outright. Point it at a validating resolver such as Unbound on 127.0.0.1 to
enable DANE."
  (let ((servers (mapcar (lambda (s) (if (consp s) s (cons s port)))
                         (or nameservers (%system-nameservers)
                             (error 'dns-error :message "No nameservers configured")))))
    (make-instance 'resolver
                   :nameservers servers :timeout timeout :attempts attempts
                   :trust-ad (if (eq trust-ad :loopback)
                                 (every (lambda (s) (%loopback-p (car s))) servers)
                                 (and trust-ad t)))))

(defvar *resolver* nil
  "The resolver used when none is given; NIL means one made from
/etc/resolv.conf when first needed.")

(defun default-resolver ()
  (or *resolver* (setf *resolver* (make-resolver))))

;;; Wire format

(defun %encode-name (name buffer)
  (let ((name (string-right-trim "." name)))
    (when (> (length name) 253)
      (error 'dns-error :name name :message (format nil "The name ~a is too long" name)))
    (unless (zerop (length name))
      (dolist (label (uiop:split-string name :separator "."))
        (when (or (zerop (length label)) (> (length label) 63) (not (smtp::ascii-p label)))
          (error 'dns-error :name name :message (format nil "~s is not a valid DNS name" name)))
        (smtp::buffer-push (length label) buffer)
        (smtp::buffer-ascii buffer label)))
    (smtp::buffer-push 0 buffer)))

(defun %u16 (buffer n)
  (smtp::buffer-push (ldb (byte 8 8) n) buffer)
  (smtp::buffer-push (ldb (byte 8 0) n) buffer))

(defun %make-query (id name type)
  (let ((b (smtp::make-octet-buffer 64)))
    (%u16 b id)
    ;; RD, and AD to ask for the validation result without DO's signatures.
    (%u16 b #x0120)
    (%u16 b 1) (%u16 b 0) (%u16 b 0) (%u16 b 1)
    (%encode-name name b)
    (%u16 b (%type-code type))
    (%u16 b 1)
    ;; EDNS(0) OPT: 1232-octet UDP payload, DO set so validating resolvers
    ;; that only report AD to DNSSEC-aware clients still do.
    (smtp::buffer-push 0 b)
    (%u16 b +dns-opt+) (%u16 b 1232)
    (%u16 b 0) (%u16 b #x8000)
    (%u16 b 0)
    (smtp::buffer-octets b)))

(defun %get-u16 (octets pos)
  (when (> (+ pos 2) (length octets))
    (error 'dns-error :message "Truncated DNS message"))
  (+ (ash (aref octets pos) 8) (aref octets (1+ pos))))

(defun %get-u32 (octets pos)
  (+ (ash (%get-u16 octets pos) 16) (%get-u16 octets (+ pos 2))))

(defun %read-name (octets pos)
  "The name at POS and the position after it, following compression pointers."
  (let ((labels '()) (end nil) (jumps 0))
    (loop
      (when (>= pos (length octets)) (error 'dns-error :message "Truncated DNS name"))
      (let ((len (aref octets pos)))
        (cond ((zerop len)
               (return (values (format nil "~{~a~^.~}" (nreverse labels)) (or end (1+ pos)))))
              ((= (logand len #xc0) #xc0)
               (when (> (incf jumps) 64) (error 'dns-error :message "DNS name compression loop"))
               (unless end (setf end (+ pos 2)))
               (setf pos (logand (%get-u16 octets pos) #x3fff)))
              ((zerop (logand len #xc0))
               (when (> (+ pos 1 len) (length octets)) (error 'dns-error :message "Truncated DNS label"))
               (push (string-downcase (map 'string #'code-char (subseq octets (1+ pos) (+ pos 1 len))))
                     labels)
               (incf pos (1+ len)))
              (t (error 'dns-error :message "Bad DNS label")))))))

(defun %ipv6-string (octets start)
  (format nil "~(~{~x~^:~}~)"
          (loop for i from start below (+ start 16) by 2
                collect (%get-u16 octets i))))

(defun %parse-rdata (octets type start length)
  (let ((end (+ start length)))
    (when (> end (length octets)) (error 'dns-error :message "Truncated DNS record"))
    (case type
      (:a (unless (= length 4) (error 'dns-error :message "Bad A record"))
       (format nil "~{~d~^.~}" (coerce (subseq octets start end) 'list)))
      (:aaaa (unless (= length 16) (error 'dns-error :message "Bad AAAA record"))
       (%ipv6-string octets start))
      (:cname (values (%read-name octets start)))
      (:mx (list (%get-u16 octets start) (values (%read-name octets (+ start 2)))))
      (:txt (with-output-to-string (s)
              ;; The strings of a record are concatenated (RFC 7208, 8461).
              (loop with pos = start
                    while (< pos end)
                    do (let ((n (aref octets pos)))
                         (when (> (+ pos 1 n) end) (error 'dns-error :message "Bad TXT record"))
                         (loop for i from (1+ pos) below (+ pos 1 n)
                               do (write-char (code-char (aref octets i)) s))
                         (incf pos (1+ n))))))
      (:tlsa (when (< length 3) (error 'dns-error :message "Bad TLSA record"))
       (list (aref octets start) (aref octets (+ start 1)) (aref octets (+ start 2))
             (subseq octets (+ start 3) end)))
      (t nil))))

(defstruct (dns-answer (:constructor %make-dns-answer))
  "The records of one type for a name. STATUS is :OK, :NODATA or :NXDOMAIN;
SECURE is true when a trusted resolver validated the answer with DNSSEC;
CANONICAL-NAME is the name after following CNAMEs."
  name type status records secure canonical-name)

(defun %parse-response (octets id name type)
  (when (< (length octets) 12) (error 'dns-error :name name :message "Short DNS response"))
  (let* ((flags (%get-u16 octets 2))
         (rcode (logand flags #xf))
         (qdcount (%get-u16 octets 4))
         (ancount (%get-u16 octets 6))
         (pos 12))
    (unless (and (= (%get-u16 octets 0) id) (logbitp 15 flags))
      (error 'dns-error :name name :message "DNS response does not match the query"))
    (when (logbitp 9 flags)
      (return-from %parse-response :truncated))
    (unless (= qdcount 1) (error 'dns-error :name name :message "Unexpected DNS question count"))
    (multiple-value-bind (qname next) (%read-name octets pos)
      (unless (and (string-equal (string-right-trim "." name) qname)
                   (= (%get-u16 octets next) (%type-code type)))
        (error 'dns-error :name name :message "DNS response is for another question"))
      (setf pos (+ next 4)))
    (case rcode
      ((0 3))
      (2 (error 'dns-error :name name :rtype type
                           :message (format nil "DNS lookup of ~a ~a failed (SERVFAIL)" name type)))
      (t (error 'dns-error :name name :rtype type
                           :message (format nil "DNS lookup of ~a ~a failed (rcode ~d)" name type rcode))))
    (let ((records '()) (cnames '()))
      (dotimes (i ancount)
        (multiple-value-bind (owner next) (%read-name octets pos)
          (let* ((rtype (%type-name (%get-u16 octets next)))
                 (rdlength (%get-u16 octets (+ next 8)))
                 (rdata (+ next 10)))
            (%get-u32 octets (+ next 4))
            (cond ((eq rtype :cname) (push (cons owner (%parse-rdata octets :cname rdata rdlength)) cnames))
                  ((eq rtype type) (push (cons owner (%parse-rdata octets type rdata rdlength)) records)))
            (setf pos (+ rdata rdlength)))))
      ;; Follow the CNAME chain from the question to the records' owner.
      (let ((canonical (string-downcase (string-right-trim "." name))))
        (loop repeat 16
              for next = (cdr (assoc canonical cnames :test #'string=))
              while next do (setf canonical next))
        (let ((mine (loop for (owner . data) in (nreverse records)
                          when (string= owner canonical) collect data)))
          (%make-dns-answer :name name :type type
                            :status (cond (mine :ok) ((= rcode 3) :nxdomain) (t :nodata))
                            :records mine
                            :secure (logbitp 5 flags)
                            :canonical-name canonical))))))

(defun %exchange-udp (server query timeout)
  (let ((socket (usocket:socket-connect (car server) (cdr server)
                                        :protocol :datagram :element-type 'smtp::octet)))
    (unwind-protect
         (progn
           (usocket:socket-send socket query (length query))
           (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
             (loop
               (let ((left (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
                 (when (<= left 0) (return nil))
                 (when (usocket:wait-for-input socket :timeout left :ready-only t)
                   (let ((buffer (make-array 65535 :element-type 'smtp::octet)))
                     (multiple-value-bind (b n) (usocket:socket-receive socket buffer 65535)
                       (declare (ignore b))
                       (when (and n (>= n 2)
                                  (= (%get-u16 buffer 0) (%get-u16 query 0)))
                         (return (subseq buffer 0 n))))))))))
      (usocket:socket-close socket))))

(defmacro %with-timeout ((seconds operation) &body body)
  "Run BODY within SECONDS, signalling SMTP-TIMEOUT (an ERROR) when they pass."
  `(handler-case (smtp::%call-with-deadline ,seconds (lambda () ,@body))
     #+sbcl
     (sb-sys:deadline-timeout ()
       (error 'smtp-timeout :operation ,operation :seconds ,seconds))))

(defun %exchange-tcp (server query timeout)
  (let ((socket (usocket:socket-connect (car server) (cdr server)
                                        :element-type 'smtp::octet :timeout timeout)))
    (unwind-protect
         (%with-timeout (timeout (format nil "querying ~a over TCP" (car server)))
            (let ((stream (usocket:socket-stream socket))
                  (length (make-array 2 :element-type 'smtp::octet)))
              (write-byte (ldb (byte 8 8) (length query)) stream)
              (write-byte (ldb (byte 8 0) (length query)) stream)
              (write-sequence query stream)
              (force-output stream)
              (unless (= 2 (read-sequence length stream))
                (error 'dns-error :message "DNS server closed the TCP connection"))
              (let* ((n (%get-u16 length 0))
                     (response (make-array n :element-type 'smtp::octet)))
                (unless (= n (read-sequence response stream))
                  (error 'dns-error :message "Truncated DNS response over TCP"))
                response)))
      (usocket:socket-close socket))))

(defun dns-query (name type &key (resolver (default-resolver)))
  "Look up the TYPE records (:A, :AAAA, :MX, :TXT or :TLSA) of NAME, an ASCII
domain name. Returns a DNS-ANSWER; its SECURE is true only when the
resolver is trusted and validated the answer. Signals DNS-ERROR when no
usable answer arrives. Records are strings for A, AAAA and TXT, (preference
exchange) for MX, and (usage selector matching-type data) for TLSA."
  (let ((last-error nil))
    (dotimes (attempt (resolver-attempts resolver))
      (dolist (server (resolver-nameservers resolver))
        (let* ((id (let ((r (smtp::random-octets 2))) (+ (ash (aref r 0) 8) (aref r 1))))
               (query (%make-query id name type)))
          (handler-case
              (let* ((timeout (resolver-timeout resolver))
                     (response (%exchange-udp server query timeout))
                     (answer (and response (%parse-response response id name type))))
                (when (eq answer :truncated)
                  (setf answer (%parse-response (%exchange-tcp server query timeout) id name type)))
                (cond ((dns-answer-p answer)
                       (unless (resolver-trust-ad resolver)
                         (setf (dns-answer-secure answer) nil))
                       (return-from dns-query answer))
                      (t (setf last-error (make-condition 'dns-error :name name :rtype type
                                                                     :message (format nil "DNS lookup of ~a ~a timed out" name type))))))
            (dns-error (e)
              (setf last-error e)
              ;; A SERVFAIL is the resolver's considered answer (often a
              ;; DNSSEC validation failure); asking again will not help.
              (when (search "SERVFAIL" (princ-to-string e))
                (error e)))
            (error (e)
              (setf last-error (make-condition 'dns-error :name name :rtype type
                                                          :message (format nil "DNS lookup of ~a ~a failed: ~a" name type e)
                                                          :cause e)))))))
    (error last-error)))
