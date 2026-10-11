;;; delivery.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Direct delivery: the DNS client against a mock DNS server, MTA-STS
;;; parsing and fetching, DANE matching, and whole deliveries against mock
;;; DNS, SMTP and HTTPS servers. The test domain is example.test, its MX
;;; hosts mx1 and mx2.example.test; every name resolves to 127.0.0.1 and
;;; each host is told apart by the port its SMTP server listens on.

(in-package #:smtp/test)

(def-suite :smtp/delivery :in :smtp :description "Direct delivery: DNS, MX, DANE, MTA-STS, queue.")
(in-suite :smtp/delivery)

;;; A mock DNS server

(defclass zone ()
  ((entries :initform (make-hash-table :test 'equal) :reader zone-entries)
   (insecure :initform '() :accessor zone-insecure
             :documentation "Names whose answers are not DNSSEC-validated.")
   (failing :initform '() :accessor zone-failing
            :documentation "(name . type) pairs answered with SERVFAIL.")
   (truncated :initform '() :accessor zone-truncated
              :documentation "Names whose UDP answers are truncated, forcing TCP.")
   (queries :initform '() :accessor zone-queries)
   (tcp-queries :initform 0 :accessor zone-tcp-queries)
   (lock :initform (bt:make-lock) :reader zone-lock)))

(defun zone-add (zone name type &rest records)
  (setf (gethash (cons (string-downcase name) type) (zone-entries zone))
        (append (gethash (cons (string-downcase name) type) (zone-entries zone)) records)))

(defun %name-octets (name)
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (dolist (label (remove "" (uiop:split-string (string-right-trim "." name) :separator ".")
                           :test #'string=))
      (vector-push-extend (length label) out)
      (loop for c across label do (vector-push-extend (char-code c) out)))
    (vector-push-extend 0 out)
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %u16-octets (n) (vector (ldb (byte 8 8) n) (ldb (byte 8 0) n)))

(defun %rdata (type data)
  (coerce
   (ecase type
     (:a (mapcar #'parse-integer (uiop:split-string data :separator ".")))
     (:aaaa (coerce (usocket:ipv6-host-to-vector data) 'list))
     (:cname (coerce (%name-octets data) 'list))
     (:mx (append (coerce (%u16-octets (first data)) 'list)
                  (coerce (%name-octets (second data)) 'list)))
     (:txt (loop for s in (alexandria:ensure-list data)
                 append (cons (length s) (map 'list #'char-code s))))
     (:tlsa (append (subseq data 0 3) (coerce (fourth data) 'list))))
   '(simple-array (unsigned-byte 8) (*))))

(defparameter *zone-types* '((1 . :a) (5 . :cname) (15 . :mx) (16 . :txt) (28 . :aaaa) (52 . :tlsa)))

(defun %zone-answer (zone name type)
  "The answer records ((owner type rdata)...), the rcode and whether secure."
  (let ((name (string-downcase (string-right-trim "." name))) (answers '()) (chain (list)))
    (loop repeat 8
          for cname = (first (gethash (cons name :cname) (zone-entries zone)))
          while (and cname (not (eq type :cname)))
          do (push (list name :cname cname) answers)
             (push name chain)
             (setf name cname))
    (push name chain)
    (dolist (r (gethash (cons name type) (zone-entries zone)))
      (push (list name type r) answers))
    (let ((exists (loop for key being the hash-keys of (zone-entries zone)
                        thereis (string= (car key) name))))
      (values (nreverse answers)
              (cond ((member (cons name type) (zone-failing zone) :test #'equal) 2)
                    ((or exists answers) 0)
                    (t 3))
              (notany (lambda (n) (member n (zone-insecure zone) :test #'string=)) chain)))))

(defun %dns-response (zone query &key tcp)
  (multiple-value-bind (qname qend) (d::%read-name query 12)
    (let* ((type (cdr (assoc (d::%get-u16 query qend) *zone-types*)))
           (question (subseq query 12 (+ qend 4)))
           (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
      (bt:with-lock-held ((zone-lock zone))
        (push (cons qname type) (zone-queries zone))
        (when tcp (incf (zone-tcp-queries zone))))
      (multiple-value-bind (answers rcode secure) (%zone-answer zone qname type)
        (let* ((truncate (and (not tcp) (member qname (zone-truncated zone) :test #'string-equal)))
               (answers (if (or truncate (= rcode 2)) '() answers))
               (flags (logior #x8000 #x0100 #x0080
                              (if (and secure (/= rcode 2)) #x0020 0)
                              (if truncate #x0200 0)
                              rcode)))
          (flet ((put (seq) (loop for o across seq do (vector-push-extend o out))))
            (put (subseq query 0 2))
            (put (%u16-octets flags))
            (put (%u16-octets 1)) (put (%u16-octets (length answers)))
            (put (%u16-octets 0)) (put (%u16-octets 0))
            (put question)
            (dolist (a answers)
              (destructuring-bind (owner rtype data) a
                (let ((rdata (%rdata rtype data)))
                  (put (%name-octets owner))
                  (put (%u16-octets (car (rassoc rtype *zone-types*))))
                  (put (%u16-octets 1))
                  (put #(0 0 1 44))
                  (put (%u16-octets (length rdata)))
                  (put rdata))))
            (coerce out '(simple-array (unsigned-byte 8) (*)))))))))

(defun call-with-mock-dns (zone function &key (trust-ad t))
  (let* ((tcp (usocket:socket-listen "127.0.0.1" 0 :reuse-address t :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port tcp))
         (udp (usocket:socket-connect nil nil :protocol :datagram :element-type '(unsigned-byte 8)
                                              :local-host "127.0.0.1" :local-port port))
         (stop nil)
         (threads
           (list
            (bt:make-thread
             (lambda ()
               (let ((buffer (make-array 2048 :element-type '(unsigned-byte 8))))
                 (loop until stop
                       do (ignore-errors
                           (when (usocket:wait-for-input udp :timeout 0.1 :ready-only t)
                             (multiple-value-bind (b n host from-port) (usocket:socket-receive udp buffer 2048)
                               (declare (ignore b))
                               (let ((response (%dns-response zone (subseq buffer 0 n))))
                                 (usocket:socket-send udp response (length response)
                                                      :host host :port from-port))))))))
             :name "mock dns udp")
            (bt:make-thread
             (lambda ()
               (loop until stop
                     do (ignore-errors
                         (when (usocket:wait-for-input tcp :timeout 0.1 :ready-only t)
                           (let* ((client (usocket:socket-accept tcp))
                                  (s (usocket:socket-stream client)))
                             (unwind-protect
                                  (let* ((n (+ (ash (read-byte s) 8) (read-byte s)))
                                         (query (make-array n :element-type '(unsigned-byte 8))))
                                    (read-sequence query s)
                                    (let ((response (%dns-response zone query :tcp t)))
                                      (write-byte (ldb (byte 8 8) (length response)) s)
                                      (write-byte (ldb (byte 8 0) (length response)) s)
                                      (write-sequence response s)
                                      (force-output s)))
                               (usocket:socket-close client)))))))
             :name "mock dns tcp"))))
    (unwind-protect
         (funcall function (d:make-resolver :nameservers (list (cons "127.0.0.1" port))
                                            :timeout 2 :attempts 1 :trust-ad trust-ad))
      (setf stop t)
      (mapc #'bt:join-thread threads)
      (usocket:socket-close udp)
      (usocket:socket-close tcp))))

(defmacro with-mock-dns ((resolver zone &rest options) &body body)
  `(call-with-mock-dns ,zone (lambda (,resolver) ,@body) ,@options))

(defun example-zone (&key (mx '((10 "mx1.example.test") (20 "mx2.example.test"))))
  (let ((zone (make-instance 'zone)))
    (when mx (apply #'zone-add zone "example.test" :mx mx))
    (dolist (host '("mx1.example.test" "mx2.example.test" "mta-sts.example.test" "example.test"))
      (zone-add zone host :a "127.0.0.1"))
    zone))

;;; Certificates

(defun pem-der (fixture-name)
  "The DER of the first certificate in the PEM fixture."
  (let* ((text (uiop:read-file-string (fixture fixture-name)))
         (start (+ (search "-----BEGIN CERTIFICATE-----" text) 27))
         (end (search "-----END CERTIFICATE-----" text :start2 start)))
    (base64-decode (remove-if (lambda (c) (member c '(#\Newline #\Return))) (subseq text start end)))))

(defun sha256 (octets) (ironclad:digest-sequence :sha256 octets))

(defun server-tlsa (&key (usage 3) (selector 1) (fixture "delivery-server.pem"))
  (let* ((der (pem-der fixture))
         (selected (if (= selector 1) (d:certificate-spki der) der)))
    (list usage selector 1 (sha256 selected))))

;;; Deliveries

(defvar *closed-port*
  ;; A server that closes every connection at once. (A port that nothing
  ;; listens on is not enough: some environments drop such connections
  ;; silently rather than refusing them, and the port may be reused.)
  (let ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                                       :element-type '(unsigned-byte 8))))
    (bt:make-thread (lambda ()
                      (loop (ignore-errors (usocket:socket-close (usocket:socket-accept listener)))))
                    :name "closing server")
    (usocket:get-local-port listener)))

(defun ports (&rest host-ports)
  (lambda (host address)
    (declare (ignore address))
    (or (getf host-ports (intern (string-upcase (subseq host 0 (position #\. host))) :keyword))
        *closed-port*)))

(defun deliver (resolver ports &rest options)
  (apply #'d:deliver-message (simple-message :to "bob@example.test")
         :resolver resolver :port ports :local-name "client.test"
         :connect-timeout 5 :timeout 5
         :mta-sts-cache (make-instance 'd:mta-sts-cache)
         options))

(defun status-of (statuses recipient)
  (find recipient statuses :key #'d:recipient-status-recipient :test #'string-equal))

(defmacro with-delivery-certificate ((&key (certificate "delivery-server.pem")
                                           (key "delivery-server-key.pem") chain)
                                     &body body)
  `(let ((*server-certificate* ,certificate) (*server-key* ,key) (*server-chain* ,chain))
     ,@body))

;;; DNS client

(test dns-records
  (let ((zone (example-zone)))
    (zone-add zone "example.test" :txt '("v=spf1 " "-all"))
    (zone-add zone "example.test" :aaaa "2001:db8::25")
    (zone-add zone "_25._tcp.mx1.example.test" :tlsa
              (list 3 1 1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (zone-add zone "alias.example.test" :cname "mx1.example.test")
    (with-mock-dns (r zone)
      (let ((mx (d:dns-query "example.test" :mx :resolver r)))
        (is (eq :ok (d:dns-answer-status mx)))
        (is (equal '((10 "mx1.example.test") (20 "mx2.example.test")) (d:dns-answer-records mx)))
        (is-true (d:dns-answer-secure mx)))
      (is (equal '("v=spf1 -all") (d:dns-answer-records (d:dns-query "example.test" :txt :resolver r))))
      (is (equal '("2001:db8:0:0:0:0:0:25")
                 (d:dns-answer-records (d:dns-query "example.test" :aaaa :resolver r))))
      (let ((tlsa (first (d:dns-answer-records (d:dns-query "_25._tcp.mx1.example.test" :tlsa :resolver r)))))
        (is (equal '(3 1 1) (subseq tlsa 0 3)))
        (is (= 32 (length (fourth tlsa)))))
      (let ((a (d:dns-query "alias.example.test" :a :resolver r)))
        (is (equal '("127.0.0.1") (d:dns-answer-records a)))
        (is (string= "mx1.example.test" (d:dns-answer-canonical-name a))))
      (is (eq :nodata (d:dns-answer-status (d:dns-query "mx1.example.test" :mx :resolver r))))
      (is (eq :nxdomain (d:dns-answer-status (d:dns-query "nowhere.example.test" :a :resolver r)))))))

(test dns-security-and-failures
  (let ((zone (example-zone)))
    (push "mx2.example.test" (zone-insecure zone))
    (push '("mx1.example.test" . :aaaa) (zone-failing zone))
    (with-mock-dns (r zone)
      (is-true (d:dns-answer-secure (d:dns-query "mx1.example.test" :a :resolver r)))
      (is-false (d:dns-answer-secure (d:dns-query "mx2.example.test" :a :resolver r)))
      (signals d:dns-error (d:dns-query "mx1.example.test" :aaaa :resolver r))
      (signals d:dns-error (d:dns-query "bad..name" :a :resolver r)))
    ;; An untrusted resolver's AD bit is ignored.
    (with-mock-dns (r zone :trust-ad nil)
      (is-false (d:dns-answer-secure (d:dns-query "mx1.example.test" :a :resolver r))))))

(test dns-falls-back-to-tcp
  (let ((zone (example-zone)))
    (push "example.test" (zone-truncated zone))
    (with-mock-dns (r zone)
      (is (= 2 (length (d:dns-answer-records (d:dns-query "example.test" :mx :resolver r)))))
      (is (= 1 (zone-tcp-queries zone))))))

(test dns-timeout
  ;; A nameserver that never answers.
  (let ((r (d:make-resolver :nameservers (list (cons "127.0.0.1" *closed-port*)) :timeout 0.5 :attempts 1)))
    (signals d:dns-error (d:dns-query "example.test" :mx :resolver r))))

(test dns-rejects-mismatched-responses
  ;; Another id for the same question.
  (let ((response (copy-seq (d::%make-query 1234 "example.test" :mx))))
    (setf (aref response 0) 0 (aref response 1) 1 (aref response 2) #x81)
    (signals d:dns-error (d::%parse-response response 1234 "example.test" :mx)))
  ;; The right id, another question.
  (let ((response (copy-seq (d::%make-query 1234 "evil.test" :mx))))
    (setf (aref response 2) #x81)
    (signals d:dns-error (d::%parse-response response 1234 "example.test" :mx))))

(test mx-ordering-null-and-implicit
  (let ((zone (example-zone :mx '((20 "b.example.test") (10 "a.example.test") (30 "c.example.test")))))
    (zone-add zone "nullmx.test" :mx '(0 ""))
    (zone-add zone "implicit.test" :a "127.0.0.1")
    (with-mock-dns (r zone)
      (is (equal '("a.example.test" "b.example.test" "c.example.test")
                 (d:mail-exchangers "example.test" :resolver r)))
      (is (equal '("implicit.test") (d:mail-exchangers "implicit.test" :resolver r)))
      (signals d:delivery-failed (d:mail-exchangers "nullmx.test" :resolver r))
      (signals d:delivery-failed (d:mail-exchangers "nowhere.test" :resolver r)))))

;;; MTA-STS

(test mta-sts-txt-records
  (is (equal "20260101" (d::parse-mta-sts-txt '("v=STSv1; id=20260101;"))))
  (is (equal "abc" (d::parse-mta-sts-txt '("v=STSv1;id=abc" "v=spf1 -all"))))
  (is (null (d::parse-mta-sts-txt '("v=STSv1; id=a" "v=STSv1; id=b"))))
  (is (null (d::parse-mta-sts-txt '("v=STSv1;"))))
  (is (null (d::parse-mta-sts-txt '("id=abc; v=STSv1"))))
  (is (null (d::parse-mta-sts-txt '("v=STSv1; id=bad-id"))))
  (is (null (d::parse-mta-sts-txt '()))))

(test mta-sts-policy-files
  (multiple-value-bind (mode mx age)
      (d:parse-mta-sts-policy (crlf "version: STSv1" "mode: enforce" "mx: mail.example.test"
                                    "mx: *.example.net" "max_age: 86400" "extra: ignored" ""))
    (is (eq :enforce mode))
    (is (equal '("mail.example.test" "*.example.net") mx))
    (is (= 86400 age)))
  ;; LF line endings, and a repeated field: the first counts.
  (is (eq :testing (d:parse-mta-sts-policy
                    (format nil "version: STSv1~%mode: testing~%mode: enforce~%mx: a.test~%max_age: 1~%"))))
  (is (eq :none (d:parse-mta-sts-policy (crlf "version: STSv1" "mode: none" "max_age: 1"))))
  (is (null (d:parse-mta-sts-policy (crlf "version: STSv2" "mode: enforce" "mx: a.test" "max_age: 1"))))
  (is (null (d:parse-mta-sts-policy (crlf "version: STSv1" "mode: strict" "mx: a.test" "max_age: 1"))))
  (is (null (d:parse-mta-sts-policy (crlf "version: STSv1" "mode: enforce" "max_age: 1"))))
  (is (null (d:parse-mta-sts-policy (crlf "version: STSv1" "mode: enforce" "mx: a.test"))))
  (is (null (d:parse-mta-sts-policy (crlf "version: STSv1" "mode: enforce" "mx: a.test" "max_age: 31557601")))))

(test mta-sts-mx-patterns
  (is-true (d::mta-sts-mx-match-p "mail.example.test" "MAIL.example.test."))
  (is-true (d::mta-sts-mx-match-p "*.example.test" "mx1.example.test"))
  (is-false (d::mta-sts-mx-match-p "*.example.test" "a.b.example.test"))
  (is-false (d::mta-sts-mx-match-p "*.example.test" "example.test"))
  (is-false (d::mta-sts-mx-match-p "*.example.test" "xexample.test"))
  (is-false (d::mta-sts-mx-match-p "mail.example.test" "mail.example.test.evil")))

(defun policy-text (&key (mode "enforce") (mx '("mx1.example.test" "mx2.example.test")) (max-age 86400))
  (apply #'crlf (append (list "version: STSv1" (format nil "mode: ~a" mode))
                        (mapcar (lambda (m) (format nil "mx: ~a" m)) mx)
                        (list (format nil "max_age: ~d" max-age) ""))))

(defun https-server (&key (status "200 OK") (content-type "text/plain") (body (policy-text)) headers)
  (lambda (s)
    (loop for line = (srv-read-line s) until (or (null line) (zerop (length line))))
    (srv-send-raw s (apply #'crlf
                           (append (list (format nil "HTTP/1.1 ~a" status))
                                   (and content-type (list (format nil "Content-Type: ~a" content-type)))
                                   (list (format nil "Content-Length: ~d" (length (octets body))))
                                   headers
                                   (list "Connection: close" "" body))))))

(defmacro with-policy-server ((&rest server-options) &body body)
  `(with-delivery-certificate ()
     (with-mock-server (https-port https-session (https-server ,@server-options) :implicit-tls t :timeout 5)
       (let ((d::*mta-sts-port* https-port))
         ,@body))))

(defun sts-zone (&key (id "1"))
  (let ((zone (example-zone)))
    (when id (zone-add zone "_mta-sts.example.test" :txt (format nil "v=STSv1; id=~a" id)))
    zone))

(def-tls-test mta-sts-policy-is-fetched-and-cached
  (let ((cache (make-instance 'd:mta-sts-cache)) (zone (sts-zone))
        ;; Refreshes after the policy server has gone fail at once.
        (d::*mta-sts-port* *closed-port*))
    (with-mock-dns (r zone)
      (with-policy-server ()
        (let ((policy (d:mta-sts-policy "example.test" :resolver r :cache cache
                                                       :ca-file (fixture "delivery-ca.pem"))))
          (is (eq :enforce (d:mta-sts-policy-mode policy)))
          (is (equal "1" (d:mta-sts-policy-id policy)))
          (is (equal '("mx1.example.test" "mx2.example.test") (d:mta-sts-policy-mx policy)))
          (is (search "GET /.well-known/mta-sts.txt HTTP/1.1" (first (session-commands https-session))))
          (is (member "Host: mta-sts.example.test" (session-commands https-session) :test #'string=))))
      ;; Cached: no second fetch while the id is unchanged (no server is running).
      (is (eq :enforce (d:mta-sts-policy-mode (d:mta-sts-policy "example.test" :resolver r :cache cache))))
      ;; The TXT record disappearing does not remove the cached policy.
      (remhash (cons "_mta-sts.example.test" :txt) (zone-entries zone))
      (is (eq :enforce (d:mta-sts-policy-mode (d:mta-sts-policy "example.test" :resolver r :cache cache))))
      ;; Nor does a failed refresh for a new id.
      (zone-add zone "_mta-sts.example.test" :txt "v=STSv1; id=2")
      (is (equal "1" (d:mta-sts-policy-id (d:mta-sts-policy "example.test" :resolver r :cache cache))))
      ;; Once expired, a policy no longer applies.
      (is (null (d:mta-sts-policy "example.test" :resolver r :cache cache
                                                  :now (+ (get-universal-time) 86401)))))))

(def-tls-test mta-sts-fetch-requirements
  (flet ((fetch (&rest server-options)
           (with-mock-dns (r (sts-zone))
             (with-delivery-certificate ()
               (with-mock-server (port s (apply #'https-server server-options) :implicit-tls t :timeout 5)
                 (let ((d::*mta-sts-port* port))
                   (d:mta-sts-policy "example.test" :resolver r :cache (make-instance 'd:mta-sts-cache)
                                                    :ca-file (fixture "delivery-ca.pem"))))))))
    (is-true (fetch))
    (is (null (fetch :status "301 Moved Permanently" :headers '("Location: https://evil.test/"))))
    (is (null (fetch :status "404 Not Found")))
    (is (null (fetch :content-type "text/html")))
    (is (null (fetch :content-type nil)))
    (is (null (fetch :body "version: STSv1")))
    (is (null (fetch :body (make-string 70000 :initial-element #\x)))))
  ;; A certificate that does not name mta-sts.example.test.
  (with-mock-dns (r (sts-zone))
    (with-delivery-certificate (:certificate "delivery-other.pem" :key "delivery-other-key.pem")
      (with-mock-server (port s (https-server) :implicit-tls t :timeout 5)
        (let ((d::*mta-sts-port* port))
          (is (null (d:mta-sts-policy "example.test" :resolver r :cache (make-instance 'd:mta-sts-cache)
                                                      :ca-file (fixture "delivery-ca.pem")))))))))

;;; DANE

(test certificate-spki-matches-openssl
  (let* ((spki (d:certificate-spki (pem-der "delivery-server.pem")))
         (pem (uiop:run-program (list "openssl" "x509" "-in" (namestring (fixture "delivery-server.pem"))
                                      "-noout" "-pubkey")
                                :output :string))
         (start (+ 26 (search "-----BEGIN PUBLIC KEY-----" pem)))
         (end (search "-----END PUBLIC KEY-----" pem)))
    (is (equalp (base64-decode (remove-if (lambda (c) (member c '(#\Newline #\Return)))
                                          (subseq pem start end)))
                spki))))

(test tlsa-matching
  (let ((der (pem-der "delivery-server.pem")))
    (is-true (d::tlsa-matches-p (apply #'d:make-tlsa (server-tlsa)) der))
    (is-true (d::tlsa-matches-p (apply #'d:make-tlsa (server-tlsa :selector 0)) der))
    (is-true (d::tlsa-matches-p (d:make-tlsa 3 1 2 (ironclad:digest-sequence :sha512 (d:certificate-spki der)))
                                der))
    (is-true (d::tlsa-matches-p (d:make-tlsa 3 0 0 der) der))
    (is-false (d::tlsa-matches-p (apply #'d:make-tlsa (server-tlsa :fixture "delivery-other.pem")) der))
    (is-false (d::tlsa-usable-p (d:make-tlsa 1 1 1 (sha256 der))))
    (is-false (d::tlsa-usable-p (d:make-tlsa 3 1 1 (subseq (sha256 der) 0 20))))
    (is-false (d::tlsa-usable-p (d:make-tlsa 3 2 1 (sha256 der))))))

;;; Whole deliveries

(test opportunistic-delivery-through-mx
  (with-mock-dns (r (example-zone))
    (with-mock-server (port s (standard-server :extensions '("PIPELINING")))
      (let ((bob (status-of (deliver r (ports :mx1 port)) "bob@example.test")))
        (is (eq :delivered (d:recipient-status-status bob)))
        (is (eq :plaintext (d:recipient-status-security bob)))
        (is (string= "mx1.example.test" (d:recipient-status-host bob))))
      (is (= 1 (length (session-messages s))))
      (is (equal '("bob@example.test") (second (first (session-messages s))))))
    (with-delivery-certificate ()
      (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
        (let ((bob (first (deliver r (ports :mx1 port)))))
          (is (eq :delivered (d:recipient-status-status bob)))
          (is (eq :opportunistic-tls (d:recipient-status-security bob))))
        (is-true (session-tls s))))))

(test falls-back-to-the-next-mx
  (with-mock-dns (r (example-zone))
    ;; mx1 refuses connections.
    (with-mock-server (port s (standard-server))
      (let ((bob (first (deliver r (ports :mx2 port)))))
        (is (eq :delivered (d:recipient-status-status bob)))
        (is (string= "mx2.example.test" (d:recipient-status-host bob)))))
    ;; mx1 answers MAIL with 451.
    (with-mock-server (p1 s1 (standard-server :mail-reply "451 4.3.0 Try later"))
      (with-mock-server (p2 s2 (standard-server))
        (let ((bob (first (deliver r (ports :mx1 p1 :mx2 p2)))))
          (is (eq :delivered (d:recipient-status-status bob)))
          (is (string= "mx2.example.test" (d:recipient-status-host bob))))
        (is (null (session-messages s1)))
        (is (= 1 (length (session-messages s2))))))))

(test recipient-outcomes
  (with-mock-dns (r (example-zone))
    (with-mock-server (port s (standard-server :reject-recipients '("gone@example.test")
                                               :defer-recipients '("busy@example.test")))
      (let ((statuses (d:deliver-message (simple-message :to '("bob@example.test" "gone@example.test"
                                                               "busy@example.test"))
                                         :resolver r :port (ports :mx1 port) :local-name "client.test"
                                         :connect-timeout 5 :timeout 5 :mta-sts nil)))
        (is (eq :delivered (d:recipient-status-status (status-of statuses "bob@example.test"))))
        (is (eq :failed (d:recipient-status-status (status-of statuses "gone@example.test"))))
        (is (= 550 (reply-code (d:recipient-status-reply (status-of statuses "gone@example.test")))))
        ;; Deferred at mx1, and mx2 is unreachable.
        (is (eq :deferred (d:recipient-status-status (status-of statuses "busy@example.test"))))
        (is (= 450 (reply-code (d:recipient-status-reply (status-of statuses "busy@example.test")))))
        (is (search "mx1.example.test: 450" (d:recipient-status-message (status-of statuses "busy@example.test"))))
        (is (equal '("bob@example.test" "gone@example.test" "busy@example.test")
                   (mapcar #'d:recipient-status-recipient statuses)))))
    ;; A permanent refusal of the message is a failure, not a reason to try mx2.
    (with-mock-server (port s (standard-server :data-reply "554 5.7.1 Spam"))
      (is (eq :failed (d:recipient-status-status (first (deliver r (ports :mx1 port)))))))))

(test domain-failures
  (let ((zone (example-zone)))
    (zone-add zone "nullmx.test" :mx '(0 ""))
    (push '("broken.test" . :mx) (zone-failing zone))
    (with-mock-dns (r zone)
      (flet ((status (to)
               (d:recipient-status-status
                (first (d:deliver-message (simple-message :to to) :resolver r :mta-sts nil
                                                                  :local-name "client.test"
                                                                  :connect-timeout 5 :timeout 5)))))
        (is (eq :failed (status "a@nullmx.test")))
        (is (eq :failed (status "a@nowhere.test")))
        (is (eq :deferred (status "a@broken.test")))))))

(defun dane-zone (&rest tlsa-records)
  (let ((zone (example-zone)))
    (when tlsa-records
      (apply #'zone-add zone "_25._tcp.mx1.example.test" :tlsa tlsa-records))
    zone))

(def-tls-test dane-ee-authenticates
  (with-mock-dns (r (dane-zone (server-tlsa)))
    (with-delivery-certificate ()
      (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
        (let ((bob (first (deliver r (ports :mx1 port)))))
          (is (eq :delivered (d:recipient-status-status bob)) "~a" (d:recipient-status-message bob))
          (is (eq :dane (d:recipient-status-security bob))))
        (is-true (session-tls s))))))

(def-tls-test dane-mismatch-is-not-delivered
  ;; The TLSA record is for another key: mx1 is never sent mail.
  (with-mock-dns (r (dane-zone (server-tlsa :fixture "delivery-other.pem")))
    (with-delivery-certificate ()
      (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
        (let ((bob (first (deliver r (ports :mx1 port)))))
          (is (eq :deferred (d:recipient-status-status bob)))
          (is (search "DANE" (d:recipient-status-message bob))))
        (is (null (sent-commands s "MAIL")))))))

(def-tls-test dane-requires-starttls
  (with-mock-dns (r (dane-zone (server-tlsa)))
    (with-mock-server (port s (standard-server :extensions '("PIPELINING")))
      (is (eq :deferred (d:recipient-status-status (first (deliver r (ports :mx1 port))))))
      (is (null (sent-commands s "MAIL"))))))

(def-tls-test dane-ta-checks-chain-and-name
  (let ((ta (list 2 0 1 (sha256 (pem-der "delivery-ca.pem")))))
    (with-mock-dns (r (dane-zone ta))
      (with-delivery-certificate (:certificate "delivery-server-chain.pem" :chain t)
        (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
          (let ((bob (first (deliver r (ports :mx1 port)))))
            (is (eq :delivered (d:recipient-status-status bob)) "~a" (d:recipient-status-message bob))
            (is (eq :dane (d:recipient-status-security bob))))))
      ;; Issued under the anchor, but for another name.
      (with-delivery-certificate (:certificate "delivery-other-chain.pem" :key "delivery-other-key.pem"
                                  :chain t)
        (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
          (is (eq :deferred (d:recipient-status-status (first (deliver r (ports :mx1 port))))))
          (is (null (sent-commands s "MAIL"))))))))

(def-tls-test dane-unusable-records-still-require-tls
  ;; Only a PKIX-EE record: TLS is mandatory but not authenticated.
  (with-mock-dns (r (dane-zone (server-tlsa :usage 1 :fixture "delivery-other.pem")))
    (with-delivery-certificate ()
      (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
        (is (eq :delivered (d:recipient-status-status (first (deliver r (ports :mx1 port))))))
        (is-true (session-tls s))))
    (with-mock-server (port s (standard-server))
      (is (eq :deferred (d:recipient-status-status (first (deliver r (ports :mx1 port)))))))))

(test dane-needs-validated-dns
  (let ((wrong (server-tlsa :fixture "delivery-other.pem")))
    (flet ((delivered-p (zone &rest options)
             (with-delivery-certificate ()
               (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
                 (let ((bob (first (apply #'deliver zone (ports :mx1 port) options))))
                   (and (eq :delivered (d:recipient-status-status bob))
                        (d:recipient-status-security bob)))))))
      ;; An insecure TLSA answer is ignored,
      (let ((zone (dane-zone wrong)))
        (push "_25._tcp.mx1.example.test" (zone-insecure zone))
        (with-mock-dns (r zone)
          (is (eq :opportunistic-tls (delivered-p r)))))
      ;; as is the TLSA record when the MX answer is insecure,
      (let ((zone (dane-zone wrong)))
        (push "example.test" (zone-insecure zone))
        (with-mock-dns (r zone)
          (is (eq :opportunistic-tls (delivered-p r)))))
      ;; or the resolver is not trusted to validate,
      (with-mock-dns (r (dane-zone wrong) :trust-ad nil)
        (is (eq :opportunistic-tls (delivered-p r))))
      ;; or DANE is turned off.
      (with-mock-dns (r (dane-zone wrong))
        (is (eq :opportunistic-tls (delivered-p r :dane nil)))))))

(def-tls-test dane-follows-cnames
  ;; mx1 is an alias: its TLSA records are looked up at the target first.
  (let ((zone (example-zone)))
    (remhash (cons "mx1.example.test" :a) (zone-entries zone))
    (zone-add zone "mx1.example.test" :cname "mx2.example.test")
    (zone-add zone "_25._tcp.mx2.example.test" :tlsa (server-tlsa))
    (with-mock-dns (r zone)
      (with-delivery-certificate ()
        (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
          (let ((bob (first (deliver r (ports :mx1 port)))))
            (is (eq :delivered (d:recipient-status-status bob)) "~a" (d:recipient-status-message bob))
            (is (eq :dane (d:recipient-status-security bob)))))))))

(test address-literal-recipients
  ;; No DNS at all: the address is the server.
  (with-mock-server (port s (standard-server))
    (let ((status (first (d:deliver-message (simple-message :to "bob@[127.0.0.1]")
                                            :resolver (d:make-resolver :nameservers '("127.0.0.1")
                                                                       :port *closed-port* :timeout 0.2)
                                            :port (lambda (host address) (declare (ignore host address)) port)
                                            :local-name "client.test" :connect-timeout 5 :timeout 5))))
      (is (eq :delivered (d:recipient-status-status status)) "~a" (d:recipient-status-message status)))
    (is (equal '("bob@[127.0.0.1]") (second (first (session-messages s)))))))

(test failed-tlsa-lookup-skips-the-host
  (let ((zone (example-zone)))
    (push '("_25._tcp.mx1.example.test" . :tlsa) (zone-failing zone))
    (with-mock-dns (r zone)
      (with-mock-server (p1 s1 (standard-server) :timeout 1)
        (with-mock-server (p2 s2 (standard-server))
          (let ((bob (first (deliver r (ports :mx1 p1 :mx2 p2)))))
            (is (eq :delivered (d:recipient-status-status bob)))
            (is (string= "mx2.example.test" (d:recipient-status-host bob))))
          (is (null (session-commands s1))))))))

(def-tls-test mta-sts-enforced-delivery
  (with-mock-dns (r (sts-zone))
    ;; mx1 is not in the policy and is never contacted; mx2's certificate
    ;; must verify.
    (with-policy-server (:body (policy-text :mx '("mx2.example.test")))
      (with-mock-server (p1 s1 (standard-server :extensions '("STARTTLS")) :timeout 1)
        (with-mock-server (p2 s2 (standard-server :extensions '("STARTTLS")))
          (let ((bob (first (deliver r (ports :mx1 p1 :mx2 p2) :ca-file (fixture "delivery-ca.pem")))))
            (is (eq :delivered (d:recipient-status-status bob)) "~a" (d:recipient-status-message bob))
            (is (eq :mta-sts (d:recipient-status-security bob)))
            (is (string= "mx2.example.test" (d:recipient-status-host bob))))
          (is (null (session-commands s1)))
          (is-true (session-tls s2)))))
    ;; A certificate that does not verify: not delivered.
    (with-policy-server ()
      (with-delivery-certificate (:certificate "delivery-other.pem" :key "delivery-other-key.pem")
        (with-mock-server (p1 s1 (standard-server :extensions '("STARTTLS")))
          (is (eq :deferred (d:recipient-status-status
                             (first (deliver r (ports :mx1 p1) :ca-file (fixture "delivery-ca.pem"))))))
          (is (null (sent-commands s1 "MAIL"))))))
    ;; No STARTTLS: not delivered.
    (with-policy-server ()
      (with-mock-server (p1 s1 (standard-server))
        (is (eq :deferred (d:recipient-status-status
                           (first (deliver r (ports :mx1 p1) :ca-file (fixture "delivery-ca.pem"))))))
        (is (null (sent-commands s1 "MAIL")))))))

(def-tls-test mta-sts-testing-mode-delivers
  (with-mock-dns (r (sts-zone))
    (with-policy-server (:body (policy-text :mode "testing" :mx '("elsewhere.test")))
      (with-mock-server (port s (standard-server))
        (let ((bob (first (deliver r (ports :mx1 port) :ca-file (fixture "delivery-ca.pem")))))
          (is (eq :delivered (d:recipient-status-status bob)))
          (is (eq :plaintext (d:recipient-status-security bob))))))))

(test require-tls-verifies-certificates
  (with-mock-dns (r (example-zone))
    (with-delivery-certificate ()
      (with-mock-server (port s (standard-server :extensions '("STARTTLS")))
        (let ((bob (first (deliver r (ports :mx1 port) :require-tls t :ca-file (fixture "delivery-ca.pem")))))
          (is (eq :delivered (d:recipient-status-status bob)))
          (is (eq :tls (d:recipient-status-security bob))))))
    (with-mock-server (port s (standard-server))
      (is (eq :deferred (d:recipient-status-status (first (deliver r (ports :mx1 port) :require-tls t))))))))

;;; The queue

(defun refused (host address)
  (declare (ignore host address))
  *closed-port*)

(test queue-retries-until-delivered
  (with-mock-dns (r (example-zone))
    (let* ((delivered '()) (deferred 0) (port nil)
           (queue (d:make-delivery-queue :resolver r :local-name "client.test" :timeout 5 :connect-timeout 5
                                         :mta-sts nil
                                         :retry-schedule '(60 120)
                                         :on-delivered (lambda (item statuses)
                                                         (declare (ignore item))
                                                         (setf delivered (append delivered statuses)))
                                         :on-deferred (lambda (item statuses)
                                                        (declare (ignore item statuses))
                                                        (incf deferred))
                                         :port (lambda (host address)
                                                 (if port port (refused host address)))))
           (now 1000000)
           (item (d:enqueue-message queue (simple-message :to "bob@example.test") :now now)))
      ;; Nothing listening: deferred, and due again 60 seconds later.
      (is (= 1 (d:run-delivery-queue queue :now now)))
      (is (= 1 deferred))
      (is (= (+ now 60) (d:queued-message-next-attempt item)))
      (is (= 0 (d:run-delivery-queue queue :now (+ now 30))))
      (with-mock-server (p s (standard-server))
        (setf port p)
        (is (= 1 (d:run-delivery-queue queue :now (+ now 60))))
        (is (= 1 (length (session-messages s)))))
      (is (equal '("bob@example.test") (mapcar #'d:recipient-status-recipient delivered)))
      (is (null (d:delivery-queue-messages queue))))))

(test queue-gives-up
  (with-mock-dns (r (example-zone))
    (let* ((failed '())
           (queue (d:make-delivery-queue :resolver r :local-name "client.test" :mta-sts nil
                                         :timeout 5 :connect-timeout 5
                                         :give-up-after 3600 :port #'refused
                                         :on-failed (lambda (item statuses)
                                                      (declare (ignore item))
                                                      (setf failed statuses)))))
      (d:enqueue-message queue (simple-message :to "bob@example.test") :now 0)
      (d:run-delivery-queue queue :now 0)
      (is (null failed))
      (d:run-delivery-queue queue :now 7200)
      (is (equal '(:failed) (mapcar #'d:recipient-status-status failed)))
      (is (search "Gave up" (d:recipient-status-message (first failed))))
      (is (null (d:delivery-queue-messages queue))))))
