;;; mta-sts.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; MTA-STS (RFC 8461): a domain announces with a TXT record at _mta-sts
;;; that it publishes a policy at https://mta-sts.DOMAIN/.well-known/mta-sts.txt
;;; listing its MX hosts and whether TLS with a valid certificate is required.
;;; Policies are cached for their max_age, which is what protects later
;;; deliveries from an attacker who strips the TXT record.

(in-package #:smtp/delivery)

(defstruct (mta-sts-policy (:constructor %make-mta-sts-policy))
  "A domain's MTA-STS policy: MODE (:ENFORCE, :TESTING or :NONE), MX
patterns, MAX-AGE in seconds, the TXT record's ID and the universal time it
EXPIRES."
  domain id mode mx max-age expires)

(defparameter *mta-sts-port* 443
  "The HTTPS port policies are fetched from (changed only for testing).")

(defparameter *mta-sts-timeout* 60
  "Seconds allowed for fetching a policy.")

(defconstant +mta-sts-max-size+ 65536)
(defconstant +mta-sts-max-age+ 31557600)

;;; The TXT record

(defun %txt-fields (string)
  (loop for field in (uiop:split-string string :separator ";")
        for trimmed = (string-trim '(#\Space #\Tab) field)
        for eq = (position #\= trimmed)
        unless (zerop (length trimmed))
          collect (if eq
                      (cons (subseq trimmed 0 eq) (subseq trimmed (1+ eq)))
                      (cons trimmed nil))))

(defun parse-mta-sts-txt (records)
  "The policy id from the _mta-sts TXT RECORDS, or NIL when there is not
exactly one valid STSv1 record."
  (let ((candidates (remove-if-not (lambda (r) (alexandria:starts-with-subseq "v=STSv1" r)) records)))
    (when (= 1 (length candidates))
      (let* ((fields (%txt-fields (first candidates)))
             (id (cdr (assoc "id" fields :test #'string=))))
        (and (equal (first fields) '("v" . "STSv1"))
             id (<= 1 (length id) 32) (every #'alphanumericp id) (every #'smtp::ascii-p (list id))
             id)))))

;;; The policy file

(defun parse-mta-sts-policy (text)
  "Parse the policy TEXT. Returns (values mode mx-patterns max-age), or NIL
if it is not a valid STSv1 policy."
  (let ((fields '()))
    (dolist (line (uiop:split-string text :separator '(#\Newline)))
      (let* ((line (string-right-trim '(#\Return) line))
             (colon (position #\: line)))
        (when colon
          (push (cons (string-trim '(#\Space #\Tab) (subseq line 0 colon))
                      (string-trim '(#\Space #\Tab) (subseq line (1+ colon))))
                fields))))
    (setf fields (nreverse fields))
    (flet ((field (name) (cdr (assoc name fields :test #'string=))))
      (let* ((version (field "version"))
             (mode (alexandria:switch ((field "mode") :test #'equal)
                     ("enforce" :enforce) ("testing" :testing) ("none" :none)))
             (age-text (field "max_age"))
             (max-age (and age-text (<= 1 (length age-text) 10) (every #'smtp::ascii-digit-p age-text)
                           (parse-integer age-text)))
             (mx (loop for (k . v) in fields
                       when (string= k "mx") collect (string-downcase (string-right-trim "." v)))))
        (when (and (equal version "STSv1") mode max-age (<= max-age +mta-sts-max-age+)
                   (or mx (eq mode :none)))
          (values mode mx max-age))))))

(defun mta-sts-mx-match-p (pattern host)
  "Whether the MX HOST matches PATTERN: an exact name, or *.suffix matching
exactly one more label on the left."
  (let ((host (string-downcase (string-right-trim "." host))))
    (if (alexandria:starts-with-subseq "*." pattern)
        (let ((suffix (subseq pattern 1)))
          (and (alexandria:ends-with-subseq suffix host)
               (let ((label (subseq host 0 (- (length host) (length suffix)))))
                 (and (plusp (length label)) (not (find #\. label))))))
        (string= pattern host))))

(defun mta-sts-policy-allows-p (policy host)
  (some (lambda (p) (mta-sts-mx-match-p p host)) (mta-sts-policy-mx policy)))

;;; Fetching

(defun %resolve-address (name resolver)
  "An address for NAME, IPv4 preferred."
  (dolist (type '(:a :aaaa))
    (let ((answer (ignore-errors (dns-query name type :resolver resolver))))
      (when (and answer (dns-answer-records answer))
        (return-from %resolve-address (first (dns-answer-records answer))))))
  (error 'dns-error :name name :message (format nil "~a has no address" name)))

(defun %read-http-line (stream)
  (let ((buffer (smtp::make-octet-buffer 128)))
    (loop for octet = (read-byte stream nil nil)
          do (cond ((null octet) (return))
                   ((= octet 10) (return))
                   ((> (length buffer) 8192) (error 'smtp-error :message "HTTP header line too long"))
                   (t (smtp::buffer-push octet buffer))))
    (string-right-trim '(#\Return) (map 'string #'code-char buffer))))

(defun %read-http-body (stream headers)
  (flet ((header (name) (cdr (assoc name headers :test #'string-equal)))
         (too-large () (error 'smtp-error :message "MTA-STS policy is larger than 64 KiB")))
    (let ((body (smtp::make-octet-buffer 4096)))
      (cond ((search "chunked" (or (header "Transfer-Encoding") "") :test #'char-equal)
             (loop for size-line = (%read-http-line stream)
                   for size = (parse-integer size-line :radix 16 :junk-allowed t)
                   do (unless size (error 'smtp-error :message "Bad chunked encoding"))
                      (when (zerop size) (return))
                      (when (> (+ (length body) size) +mta-sts-max-size+) (too-large))
                      (dotimes (i size)
                        (smtp::buffer-push (or (read-byte stream nil nil)
                                               (error 'smtp-error :message "Truncated HTTP body"))
                                           body))
                      (%read-http-line stream)))
            ((header "Content-Length")
             (let ((n (parse-integer (header "Content-Length") :junk-allowed t)))
               (unless (and n (<= 0 n)) (error 'smtp-error :message "Bad Content-Length"))
               (when (> n +mta-sts-max-size+) (too-large))
               (dotimes (i n)
                 (smtp::buffer-push (or (read-byte stream nil nil)
                                        (error 'smtp-error :message "Truncated HTTP body"))
                                    body))))
            (t (loop for octet = (read-byte stream nil nil)
                     while octet
                     do (when (>= (length body) +mta-sts-max-size+) (too-large))
                        (smtp::buffer-push octet body))))
      (smtp::utf8-string body))))

(defun fetch-mta-sts-policy-text (domain &key (resolver (default-resolver)) ca-file
                                          (tls-backend *tls-backend*))
  "GET https://mta-sts.DOMAIN/.well-known/mta-sts.txt with the certificate
verified, and return the body. Redirects are not followed, only 200 with a
text/plain body is accepted, and bodies are limited to 64 KiB."
  (let* ((host (format nil "mta-sts.~a" domain))
         (address (%resolve-address host resolver))
         (backend (smtp::resolve-tls-backend tls-backend))
         (socket nil))
    (unwind-protect
         (%with-timeout (*mta-sts-timeout* (format nil "fetching the MTA-STS policy from ~a" host))
            (setf socket (usocket:socket-connect address *mta-sts-port* :element-type 'smtp::octet
                                                                        :timeout *mta-sts-timeout*))
            (let ((tls (start-tls backend (usocket:socket-stream socket)
                                  :hostname host :verify t :ca-file ca-file
                                  :timeout *mta-sts-timeout*)))
              (unwind-protect
                   (progn
                     (write-sequence (smtp::utf8-octets
                                      (format nil "GET /.well-known/mta-sts.txt HTTP/1.1~c~cHost: ~a~c~cUser-Agent: smtp (Common Lisp)~c~cAccept: text/plain~c~cConnection: close~c~c~c~c"
                                              #\Return #\Linefeed host #\Return #\Linefeed
                                              #\Return #\Linefeed #\Return #\Linefeed
                                              #\Return #\Linefeed #\Return #\Linefeed))
                                     tls)
                     (force-output tls)
                     (let* ((status-line (%read-http-line tls))
                            (status (let ((words (uiop:split-string status-line :separator " ")))
                                      (and (alexandria:starts-with-subseq "HTTP/1." status-line)
                                           (second words)
                                           (parse-integer (second words) :junk-allowed t))))
                            (headers (loop for line = (%read-http-line tls)
                                           for colon = (position #\: line)
                                           until (zerop (length line))
                                           when colon
                                             collect (cons (subseq line 0 colon)
                                                           (string-trim " " (subseq line (1+ colon)))))))
                       (unless (eql status 200)
                         (error 'smtp-error :message (format nil "MTA-STS policy fetch from ~a returned ~s"
                                                             host status-line)))
                       (let ((type (cdr (assoc "Content-Type" headers :test #'string-equal))))
                         (unless (and type (alexandria:starts-with-subseq "text/plain" (string-downcase type)))
                           (error 'smtp-error :message (format nil "MTA-STS policy from ~a is not text/plain" host))))
                       (%read-http-body tls headers)))
                (ignore-errors (close tls)))))
      (when socket (ignore-errors (usocket:socket-close socket))))))

;;; The cache

(defclass mta-sts-cache ()
  ((policies :initform (make-hash-table :test 'equal) :reader %policies)
   (failures :initform (make-hash-table :test 'equal) :reader %failures)
   (lock :initform (bt:make-lock "smtp MTA-STS cache") :reader %cache-lock))
  (:documentation "Cached MTA-STS policies, by domain. Specialize
MTA-STS-CACHE-GET and MTA-STS-CACHE-PUT to keep them across restarts."))

(defgeneric mta-sts-cache-get (cache domain)
  (:method ((cache mta-sts-cache) domain)
    (bt:with-lock-held ((%cache-lock cache)) (gethash domain (%policies cache)))))

(defgeneric mta-sts-cache-put (cache domain policy)
  (:method ((cache mta-sts-cache) domain policy)
    (bt:with-lock-held ((%cache-lock cache)) (setf (gethash domain (%policies cache)) policy))))

(defvar *mta-sts-cache* (make-instance 'mta-sts-cache)
  "The process-wide policy cache.")

(defun %recent-failure-p (cache domain id now)
  (let ((when (bt:with-lock-held ((%cache-lock cache))
                (gethash (cons domain id) (%failures cache)))))
    ;; RFC 8461 3.3: at most one fetch per id every five minutes.
    (and when (< (- now when) 300))))

(defun %note-failure (cache domain id now)
  (bt:with-lock-held ((%cache-lock cache))
    (setf (gethash (cons domain id) (%failures cache)) now)))

(defun mta-sts-policy (domain &key (resolver (default-resolver)) (cache *mta-sts-cache*)
                                ca-file (tls-backend *tls-backend*) (now (get-universal-time)))
  "DOMAIN's current MTA-STS policy, or NIL if it has none. A cached policy
is used while unexpired unless the TXT record announces a new id; when the
TXT record is missing or a fetch fails, an unexpired cached policy still
applies (RFC 8461 3.3, 5.1)."
  (let* ((domain (string-downcase domain))
         (cached (let ((p (mta-sts-cache-get cache domain)))
                   (and p (> (mta-sts-policy-expires p) now) p)))
         (id (handler-case
                 (let ((answer (dns-query (format nil "_mta-sts.~a" domain) :txt :resolver resolver)))
                   (parse-mta-sts-txt (dns-answer-records answer)))
               (dns-error () nil))))
    (cond ((null id) cached)
          ((and cached (equal id (mta-sts-policy-id cached))) cached)
          ((%recent-failure-p cache domain id now) cached)
          (t (handler-case
                 (multiple-value-bind (mode mx max-age)
                     (parse-mta-sts-policy (fetch-mta-sts-policy-text domain :resolver resolver
                                                                             :ca-file ca-file
                                                                             :tls-backend tls-backend))
                   (unless mode (error 'smtp-error :message "Invalid MTA-STS policy"))
                   (let ((policy (%make-mta-sts-policy :domain domain :id id :mode mode :mx mx
                                                       :max-age max-age :expires (+ now max-age))))
                     (mta-sts-cache-put cache domain policy)
                     policy))
               (error ()
                 (%note-failure cache domain id now)
                 cached))))))
