;;; Stress tests for the smtp client: throughput, pool concurrency, connection
;;; churn, 50 MB messages, a hostile server, message-builder fuzzing checked
;;; with Python's email package, DNS response fuzzing, a concurrent delivery
;;; queue, MTA-STS response fuzzing, the queue checked against a model and
;;; address fuzzing. Not part of make test; run with make stress, or from the
;;; checkout:
;;;   sbcl --dynamic-space-size 4096 --non-interactive --load tools/stress.lisp
;;; Sections can be chosen with STRESS=throughput,pool,... (default all).
;;; The fuzzing sections draw from a random seed printed at the start; SEED=n
;;; replays a run.

(asdf:initialize-source-registry
 `(:source-registry (:directory ,(uiop:getcwd)) (:tree ,(merge-pathnames "ocicl/" (uiop:getcwd)))
   :ignore-inherited-configuration))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system :smtp/test))
(in-package #:smtp/test)

(defvar *findings* '())
(defvar *cleanup* '())
(defun finding (fmt &rest args)
  (let ((s (apply #'format nil fmt args)))
    (push s *findings*)
    (format t "~&  FINDING: ~a~%" s)))

(defun now () (/ (get-internal-real-time) internal-time-units-per-second))
(defmacro timed ((label &optional (count 1)) &body body)
  `(let ((start (now)))
     (multiple-value-prog1 (progn ,@body)
       (let ((elapsed (- (now) start)))
         (format t "~&  ~a: ~,2fs~@[, ~,1f/s~]~%" ,label elapsed
                 (and (> ,count 1) (plusp elapsed) (/ ,count elapsed)))))))

(defvar *seed*
  (let ((s (uiop:getenv "SEED")))
    (if (plusp (length s))
        (parse-integer s)
        (random 1000000 (make-random-state t)))))
(format t "~&== Seed ~d (SEED=~:*~d replays this run)~%" *seed*)

(defun fuzz-seed (base i)
  ;; Independent seeds per section and iteration, all derived from *seed*.
  (+ (* *seed* 10000000) base i))

(defun section-p (name)
  (let ((only (uiop:getenv "STRESS")))
    (or (null only) (member name (uiop:split-string only :separator ",") :test #'string=))))

(defun open-fds ()
  (length (directory "/dev/fd/*.*")))

(defun heap-mb ()
  (sb-ext:gc :full t)
  (/ (sb-kernel:dynamic-usage) 1048576.0))

(defun h2 (handler)
  (lambda (s &optional index) (declare (ignore index)) (funcall handler s)))

(defun quiet-server (&rest options)
  ;; A standard server that does not keep the messages it receives.
  (let ((handler (apply #'standard-server options)))
    (lambda (s &optional index)
      (declare (ignore index))
      (funcall handler s)
      (setf (session-commands s) nil))))

;;; 1. Throughput over one connection

(when (section-p "throughput")
  (format t "~&== Throughput: many messages over one connection~%")
  (dolist (mode '(:none :openssl :pure-tls))
    (let ((n (if (eq mode :none) 3000 1000)))
      (with-pool-server (port server (h2 (standard-server :extensions '("STARTTLS" "PIPELINING" "CHUNKING"))))
        (let ((c (if (eq mode :none)
                     (connect port)
                     (open-connection "127.0.0.1" :port port :ca-file (fixture "ca.pem") :tls-hostname "localhost"
                                                  :local-name "client.test" :timeout 10 :tls-backend mode))))
          (timed ((format nil "~a, ~d messages" mode n) n)
            (dotimes (i n)
              (send-message c (simple-message :subject (format nil "message ~d" i)))))
          (close-connection c))
        (let ((got (server-message-count server)))
          (unless (= got n) (finding "throughput ~a: server got ~d of ~d" mode got n)))))))

;;; 2. Pool under concurrency

(when (section-p "pool")
  (format t "~&== Pool: 16 threads x 100 messages, at most 8 connections~%")
  (dolist (tls '(:none :openssl :pure-tls))
    (with-pool-server (port server (h2 (standard-server :extensions '("STARTTLS" "PIPELINING"))))
      (let* ((pool (apply #'make-connection-pool "127.0.0.1" :port port :max-connections 8 :local-name "client.test"
                          :timeout 10 :wait-timeout 60
                          (if (eq tls :none)
                              '(:tls :none)
                              (list :ca-file (fixture "ca.pem") :tls-hostname "localhost" :tls-backend tls))))
             (errors '()) (lock (bt:make-lock)))
        (timed ((format nil "~a pool, 1600 messages" tls) 1600)
          (mapc #'bt:join-thread
                (loop for th below 16
                      collect (let ((th th))
                                (bt:make-thread
                                 (lambda ()
                                   (dotimes (i 100)
                                     (handler-case (pool-send-message pool (simple-message :subject (format nil "~d-~d" th i)))
                                       (error (e) (bt:with-lock-held (lock) (push e errors)))))))))))
        (let ((stats (connection-pool-statistics pool)))
          (format t "~&    stats ~s, server peak ~d connections~%" stats (server-max-active server))
          (close-connection-pool pool)
          (when errors (finding "pool ~a: ~d errors, first: ~a" tls (length errors) (first errors)))
          (unless (= 1600 (server-message-count server))
            (finding "pool ~a: server got ~d of 1600" tls (server-message-count server)))
          (when (> (server-max-active server) 8)
            (finding "pool ~a: ~d simultaneous connections" tls (server-max-active server))))))))

;;; 3. Connection churn: leaks of descriptors or memory

(when (section-p "churn")
  (format t "~&== Churn: connect, send, close, repeatedly~%")
  (dolist (tls '(:none :openssl :pure-tls))
    (let ((n (if (eq tls :none) 1500 400)))
      (with-pool-server (port server (quiet-server :extensions '("STARTTLS")))
        (flet ((once ()
                 (send-mail "127.0.0.1" (simple-message) :port port :local-name "client.test" :timeout 10
                            :tls (if (eq tls :none) :none :starttls) :tls-backend (if (eq tls :none) nil tls)
                            :ca-file (fixture "ca.pem") :tls-hostname "localhost")))
          (dotimes (i 20) (once))
          (sleep 0.5)
          (let ((fds (open-fds)) (heap (heap-mb)))
            (timed ((format nil "~a, ~d connections" tls n) n)
              (dotimes (i n) (once)))
            (sleep 1)
            (let ((fds2 (open-fds)) (heap2 (heap-mb)))
              (format t "~&    descriptors ~d -> ~d, heap ~,1f -> ~,1f MB~%" fds fds2 heap heap2)
              (when (> (- fds2 fds) 10) (finding "churn ~a: ~d descriptors leaked" tls (- fds2 fds)))
              (when (> (- heap2 heap) 50) (finding "churn ~a: heap grew ~,1f MB" tls (- heap2 heap))))))))))

;;; 4. Large messages

(when (section-p "large")
  (format t "~&== Large: 50 MB attachment~%")
  (let ((data (make-array (* 50 1024 1024) :element-type '(unsigned-byte 8))))
    (dotimes (i (length data)) (setf (aref data i) (logand (* i 2654435761) 255)))
    (dolist (case '((:none ("PIPELINING")) (:none ("CHUNKING")) (:openssl ("STARTTLS" "CHUNKING")) (:pure-tls ("STARTTLS"))))
      (destructuring-bind (tls exts) case
        (with-mock-server (port s (standard-server :extensions exts) :timeout 300)
          (let ((heap (heap-mb)))
            (timed ((format nil "~a ~{~a~^+~}" tls exts))
              (send-mail "127.0.0.1" (simple-message :attachments (list (make-attachment data :filename "big.bin")))
                         :port port :local-name "client.test" :timeout 60 :data-timeout 120
                         :tls (if (eq tls :none) :none :starttls) :tls-backend (if (eq tls :none) nil tls)
                         :ca-file (fixture "ca.pem") :tls-hostname "localhost"))
            (format t "~&    heap after ~,1f MB (before ~,1f)~%" (heap-mb) heap))
          (let ((m (first (session-messages s))))
            (if (null m)
                (finding "large ~a: not received" case)
                (let* ((e (parse-entity (text (third m))))
                       (part (second (entity-parts e))))
                  (unless (equalp data (decoded-body part))
                    (finding "large ~a: attachment corrupted" case))))))))))

;;; 5. A hostile server

(defun random-line (rng)
  (let ((len (random-elt rng '(0 1 3 10 80 600 5000 70000))))
    (map 'string (lambda (x) (declare (ignore x))
                   (code-char (random-elt rng (list (+ 32 (random 95 rng)) (random 256 rng) 0 13 9))))
         (make-list len))))

(defun random-elt (rng list) (nth (random (length list) rng) list))

(defun random-reply (rng)
  (let ((code (random-elt rng (list 220 250 334 354 421 451 500 550 554 199 600 999 25 "2x0" "" "abc")))
        (sep (random-elt rng '(" " "-" "" "x" "--"))))
    (format nil "~a~a~a" code sep (random-line rng))))

(defun hostile-handler (seed)
  (lambda (s &optional index)
    (declare (ignore index))
    (let ((rng (sb-ext:seed-random-state (fuzz-seed 0 seed)))
          (stream (session-stream s)))
      (flet ((send (line) (write-sequence (octets line) stream) (write-sequence #(13 10) stream) (force-output stream))
             (raw (n) (write-sequence (let ((v (make-array n :element-type '(unsigned-byte 8))))
                                         (dotimes (i n v) (setf (aref v i) (random 256 rng))))
                                       stream)
               (force-output stream)))
        (let ((script (random 10 rng)) (step 0) (fail-at (random 8 rng)))
          (case script
            (0 (raw (random 5000 rng)))
            (1 (send (random-reply rng)))
            (t
             (send "220 hostile.test ESMTP")
             (loop for line = (srv-read-line s :record nil)
                   while line
                   do (incf step)
                      (cond ((< step fail-at)
                             (let ((verb (%verb line)))
                               (cond ((string= verb "EHLO")
                                      (send "250-hostile.test")
                                      (send (random-elt rng '("250-PIPELINING" "250-STARTTLS" "250-SIZE 10" "250-SIZE x"
                                                              "250-CHUNKING" "250-AUTH PLAIN" "250-8BITMIME")))
                                      (send "250 SMTPUTF8"))
                                     ((string= verb "STARTTLS")
                                      (send "220 go") (raw (random 300 rng)) (return))
                                     ((string= verb "DATA") (send "354 go")
                                      (loop for l = (srv-read-line s :record nil) until (or (null l) (string= l "."))))
                                     ((string= verb "BDAT")
                                      (srv-read-octets s (or (ignore-errors (parse-integer (%arg line) :junk-allowed t)) 0))
                                      (send "250 ok"))
                                     (t (send "250 ok")))))
                            (t (case (random 7 rng)
                                 (0 (return))                    ; close
                                 (1 (sleep 2.5) (return))        ; stall past the client's timeout
                                 (2 (send (random-reply rng)))
                                 (3 (dotimes (i (random 2000 rng)) (send "250-more")) (send "250 done"))
                                 (4 (raw (random 2000 rng)))
                                 (5 (send "421 4.3.2 Shutting down") (return))
                                 (6 (send "250 ok") (send "250 extra") (send "550 surprise")))))))))))))

(when (section-p "hostile")
  (format t "~&== Hostile server: 1500 randomized misbehaving sessions~%")
  (let ((outcomes (make-hash-table :test 'equal)) (slowest 0) (n 1500))
    (timed ("hostile sessions" n)
      (dotimes (seed n)
        (with-mock-server (port s (hostile-handler seed) :timeout 20)
          (let ((start (now)))
            (handler-case
                (sb-sys:with-deadline (:seconds 15)
                  (send-mail "127.0.0.1" (simple-message :attachments (list (make-attachment (make-array 3000 :element-type '(unsigned-byte 8)) :filename "a.bin")))
                             :port port :local-name "client.test" :tls (if (evenp seed) :none :opportunistic)
                             :verify nil :connect-timeout 2 :timeout 1 :data-timeout 2
                             :tls-backend (if (zerop (mod seed 4)) :pure-tls :openssl))
                  (incf (gethash "delivered" outcomes 0)))
              (sb-sys:deadline-timeout ()
                (finding "hostile seed ~d: client hung past 15 s" seed))
              (smtp-error (e) (incf (gethash (string (type-of e)) outcomes 0)))
              (error (e)
                (incf (gethash "NON-SMTP ERROR" outcomes 0))
                (finding "hostile seed ~d: ~a: ~a" seed (type-of e) (let ((m (princ-to-string e))) (subseq m 0 (min 200 (length m)))))))
            (setf slowest (max slowest (- (now) start)))))))
    (format t "~&    outcomes:~{ ~a=~d~}~%    slowest session ~,2fs~%"
            (loop for k being the hash-keys of outcomes using (hash-value v) append (list k v)) slowest)
    (when (> slowest 8) (finding "hostile: a session took ~,1fs with 1 s timeouts" slowest))))

;;; 6. Message building

(defun random-text (rng max)
  (let ((pool (concatenate 'string "abcdefghijklmnopqrstuvwxyz ABC.,;:!?-_=\"'()<>@[]\\/	"
                           "éüßñçøåÆ€£¥©®™—–…“”‘’¿¡" "日本語中文한국어ไทยעבריתالعربيةрусский" "😀🎉👍🏽" "=?UTF-8?B?x?=")))
    (with-output-to-string (o)
      (dotimes (i (random (1+ max) rng))
        (let ((r (random 100 rng)))
          (cond ((< r 3) (write-char #\Newline o))
                ((< r 4) (write-char #\Return o))
                ((< r 5) (format o "~c~c" #\Return #\Newline))
                ((< r 6) (write-string "." o))
                ((< r 7) (write-string (make-string (random 1200 rng) :initial-element #\x) o))
                (t (write-char (char pool (random (length pool) rng)) o))))))))

(defun random-message (rng)
  (let ((clean (lambda (s) (remove-if (lambda (c) (member c '(#\Newline #\Return))) s))))
    (make-message
     :from (make-mailbox "alice@example.com" (funcall clean (random-text rng 40)))
     :to (list (make-mailbox "bob@example.net" (funcall clean (random-text rng 30)))
               (random-elt rng '("carol@bücher.example" "dave@example.org" "éva@example.org")))
     :subject (funcall clean (random-text rng 300))
     :text (and (plusp (random 3 rng)) (random-text rng 3000))
     :html (and (zerop (random 2 rng)) (format nil "<p>~a</p>" (random-text rng 3000)))
     :attachments (loop repeat (random 3 rng)
                        collect (make-attachment (let ((v (make-array (random 5000 rng) :element-type '(unsigned-byte 8))))
                                                   (dotimes (i (length v) v) (setf (aref v i) (random 256 rng))))
                                                 :filename (let ((f (funcall clean (random-text rng 120))))
                                                             (if (zerop (length (string-trim " " f))) "f.bin" f))
                                                 :content-type "application/octet-stream"))
     :headers (and (zerop (random 3 rng)) (list (cons "X-Fuzz" (funcall clean (random-text rng 200))))))))

(when (section-p "messages")
  (format t "~&== Message builder: 3000 random messages~%")
  (let ((dir (uiop:ensure-directory-pathname (format nil "/tmp/smtp-stress-~d/" (random 1000000))))
        (rejected 0) (n 3000) (expectations '()))
    (ensure-directories-exist dir)
    (push dir *cleanup*)
    (timed ("render" n)
      (dotimes (seed n)
        (let ((rng (sb-ext:seed-random-state (fuzz-seed 100000 seed))))
          (handler-case
              (let* ((m (random-message rng))
                     (octets (render-message m)))
                ;; Wire rules: CRLF only, lines of at most 998 octets.
                (let ((col 0))
                  (loop for i below (length octets)
                        for o = (aref octets i)
                        do (cond ((= o 13)
                                  (unless (and (< (1+ i) (length octets)) (= 10 (aref octets (1+ i))))
                                    (finding "message ~d: bare CR" seed) (return))
                                  (setf col 0))
                                 ((= o 10)
                                  (unless (and (plusp i) (= 13 (aref octets (1- i))))
                                    (finding "message ~d: bare LF" seed) (return)))
                                 ((> (incf col) 998) (finding "message ~d: line over 998 octets" seed) (return)))))
                (with-open-file (out (merge-pathnames (format nil "~d.eml" seed) dir) :direction :output
                                                                                 :element-type '(unsigned-byte 8))
                  (write-sequence octets out))
                (push (list seed (message-subject m)
                            (mapcar #'attachment-filename (message-attachments m))
                            (message-text m))
                      expectations))
            (mail-format-error () (incf rejected))
            (error (e) (finding "message ~d: ~a: ~a" seed (type-of e) e))))))
    (format t "~&    rendered ~d, refused (mail-format-error) ~d~%" (length expectations) rejected)
    ;; Python reads every message back: subject, filenames and text body.
    (with-open-file (out (merge-pathnames "expect.json" dir) :direction :output :external-format :utf-8)
      (format out "[~{~a~^,~}]"
              (mapcar (lambda (e)
                        (destructuring-bind (seed subject files text) e
                          (flet ((js (s) (with-output-to-string (o)
                                           (write-char #\" o)
                                           (loop for c across s
                                                 do (case c
                                                      (#\" (write-string "\\\"" o))
                                                      (#\\ (write-string "\\\\" o))
                                                      (t (if (< (char-code c) 32)
                                                             (format o "\\u~4,'0x" (char-code c))
                                                             (if (> (char-code c) #xffff)
                                                                 (let ((v (- (char-code c) #x10000)))
                                                                   (format o "\\u~4,'0x\\u~4,'0x" (+ #xd800 (ash v -10)) (+ #xdc00 (logand v #x3ff))))
                                                                 (write-char c o))))))
                                           (write-char #\" o))))
                            (format nil "[~d,~a,[~{~a~^,~}],~a]" seed (js subject) (mapcar #'js files)
                                    (if text (js text) "null")))))
                      expectations)))
    (let ((report (uiop:run-program
                   (list "python3" "-I" "-c" "
import email, json, sys, os
from email import policy
d = sys.argv[1]
bad = 0
for seed, subject, files, text in json.load(open(os.path.join(d, 'expect.json'), encoding='utf-8')):
    m = email.message_from_binary_file(open(os.path.join(d, f'{seed}.eml'), 'rb'), policy=policy.default)
    problems = []
    if m.defects: problems.append(f'defects {m.defects}')
    # Readers drop a header's leading and trailing whitespace.
    if str(m['Subject']) not in (subject, subject.strip(), ' '.join(subject.split())): problems.append(f'subject {m[\"Subject\"]!r} != {subject!r}')
    got = [p.get_filename() for p in m.walk() if p.get_content_disposition() == 'attachment']
    # Python strips one pair of surrounding double quotes from filenames.
    unq = lambda f: f[1:-1] if len(f) > 1 and f[0] == f[-1] == '\"' else f
    if got != files and got != [unq(f) for f in files]: problems.append(f'files {got!r} != {files!r}')
    if text is not None:
        part = next((p for p in m.walk() if p.get_content_type() == 'text/plain'), None)
        body = part.get_content() if part else None
        want = text.replace('\\r\\n', '\\n').replace('\\r', '\\n')
        if body is None or body.replace('\\r\\n', '\\n').rstrip('\\n') != want.rstrip('\\n'):
            problems.append('text body differs')
    if problems:
        bad += 1
        if bad <= 15: print(seed, '; '.join(problems)[:400])
print('python checked', 'bad', bad)
" (namestring dir))
                   :output :string :error-output :output :ignore-error-status t)))
      (format t "~&    ~a~%" (string-trim '(#\Newline) report))
      (unless (search "bad 0" report) (finding "python round trip problems:~%~a" report)))))

;;; 7. DNS responses

(when (section-p "dns")
  (format t "~&== DNS: 200000 corrupted responses~%")
  (let* ((good (let ((zone (example-zone)))
                 (zone-add zone "example.test" :txt '("a" "b"))
                 (zone-add zone "_25._tcp.mx1.example.test" :tlsa (list 3 1 1 (make-array 32 :element-type '(unsigned-byte 8))))
                 (list (cons :mx (%dns-response zone (smtp/delivery::%make-query 7 "example.test" :mx)))
                       (cons :txt (%dns-response zone (smtp/delivery::%make-query 7 "example.test" :txt)))
                       (cons :tlsa (%dns-response zone (smtp/delivery::%make-query 7 "_25._tcp.mx1.example.test" :tlsa))))))
         (rng (sb-ext:seed-random-state (fuzz-seed 200000 0))) (outcomes (make-hash-table)))
    (timed ("parse" 200000)
      (dotimes (i 200000)
        (destructuring-bind (type . octets) (random-elt rng good)
          (let ((v (copy-seq octets)))
            (dotimes (k (1+ (random 4 rng)))
              (case (random 3 rng)
                (0 (when (plusp (length v)) (setf (aref v (random (length v) rng)) (random 256 rng))))
                (1 (when (plusp (length v)) (setf v (subseq v 0 (random (length v) rng)))))
                (2 (when (> (length v) 2)
                     (let ((p (random (- (length v) 1) rng))) (setf (aref v p) #xc0 (aref v (1+ p)) (random 256 rng)))))))
            (handler-case
                (sb-sys:with-deadline (:seconds 2)
                  (smtp/delivery::%parse-response v 7 (if (eq type :tlsa) "_25._tcp.mx1.example.test" "example.test") type)
                  (incf (gethash :parsed outcomes 0)))
              (smtp/delivery:dns-error () (incf (gethash :dns-error outcomes 0)))
              (sb-sys:deadline-timeout () (finding "dns ~d: parse hung" i))
              (error (e) (incf (gethash :other outcomes 0))
                (when (< (gethash :other outcomes 0) 4) (finding "dns ~d: ~a: ~a" i (type-of e) e))))))))
    (format t "~&    ~{~a=~d~^ ~}~%" (loop for k being the hash-keys of outcomes using (hash-value v) append (list k v)))))

;;; 8. The delivery queue run from several threads

(when (section-p "queue")
  (format t "~&== Delivery queue: 300 messages, 6 threads running the queue at once~%")
  (with-mock-dns (r (example-zone))
    (with-pool-server (port server (h2 (standard-server)))
      (let* ((delivered (make-hash-table :test 'equal)) (lock (bt:make-lock)) (dupes 0)
             (queue (smtp/delivery:make-delivery-queue
                     :resolver r :local-name "client.test" :mta-sts nil :timeout 10 :connect-timeout 5
                     :port (lambda (h a) (declare (ignore a)) (if (search "mx1" h) port 1))
                     :on-delivered (lambda (item statuses)
                                     (declare (ignore statuses))
                                     (bt:with-lock-held (lock)
                                       (when (gethash (smtp/delivery:queued-message-id item) delivered) (incf dupes))
                                       (setf (gethash (smtp/delivery:queued-message-id item) delivered) t))))))
        (dotimes (i 300) (smtp/delivery:enqueue-message queue (simple-message :to "bob@example.test" :subject (format nil "q~d" i))))
        (timed ("queue" 300)
          (mapc #'bt:join-thread
                (loop repeat 6 collect (bt:make-thread (lambda () (loop while (plusp (smtp/delivery:run-delivery-queue queue))))))))
        (format t "~&    delivered ~d, duplicates ~d, server received ~d, left in queue ~d~%"
                (hash-table-count delivered) dupes (server-message-count server)
                (length (smtp/delivery:delivery-queue-messages queue)))
        (unless (and (= 300 (hash-table-count delivered)) (zerop dupes) (= 300 (server-message-count server)))
          (finding "queue: delivered ~d, dupes ~d, server ~d" (hash-table-count delivered) dupes
                   (server-message-count server)))))))

;;; 9. MTA-STS responses and policies

(defparameter *crlf* (coerce '(#\Return #\Linefeed) 'string))

(defclass octet-input (sb-gray:fundamental-binary-input-stream)
  ((octets :initarg :octets) (pos :initform 0)))
(defmethod sb-gray:stream-read-byte ((s octet-input))
  (with-slots (octets pos) s
    (if (< pos (length octets)) (prog1 (aref octets pos) (incf pos)) :eof)))
(defmethod stream-element-type ((s octet-input)) '(unsigned-byte 8))

(defun random-policy (rng)
  "A valid policy's text, and the values PARSE-MTA-STS-POLICY should return."
  (let* ((mode (random-elt rng '(:enforce :testing :none)))
         (mx (loop repeat (if (eq mode :none) (random 3 rng) (1+ (random 3 rng)))
                   collect (format nil "~:[~;*.~]mx~d.example.test" (zerop (random 3 rng)) (random 100 rng))))
         (age (1+ (random 31557600 rng)))
         (eol (random-elt rng (list *crlf* (string #\Newline))))
         (lines (append (list "version: STSv1" (format nil "mode: ~(~a~)" mode))
                        (mapcar (lambda (m) (format nil "mx: ~a" m)) mx)
                        (list (format nil "max_age: ~d" age)))))
    (values (format nil (concatenate 'string "~{~a" eol "~}") lines) (list mode mx age))))

(defun random-http-response (rng body)
  (let* ((octets (smtp::utf8-octets body))
         (framing (random 3 rng))
         (head (format nil "HTTP/1.1 200 OK~aContent-Type: text/plain; charset=utf-8~a~a"
                       *crlf* *crlf*
                       (case framing
                         (0 (format nil "Content-Length: ~d~a" (length octets) *crlf*))
                         (1 (format nil "Transfer-Encoding: chunked~a" *crlf*))
                         (t ""))))
         (out (smtp::make-octet-buffer 1024)))
    (flet ((emit (x) (loop for o across (if (stringp x) (smtp::utf8-octets x) x)
                           do (smtp::buffer-push o out))))
      (emit head) (emit *crlf*)
      (if (= framing 1)
          (loop with start = 0
                while (< start (length octets))
                do (let ((end (min (length octets) (+ start 1 (random 40 rng)))))
                     (emit (format nil "~x~:[~;;ext=1~]~a" (- end start) (zerop (random 4 rng)) *crlf*))
                     (emit (subseq octets start end)) (emit *crlf*)
                     (setf start end))
                finally (emit (format nil "0~a~a" *crlf* *crlf*)))
          (emit octets)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun mutate-octets (rng v)
  (let ((v (copy-seq v)))
    (dotimes (k (1+ (random 4 rng)) v)
      (let ((n (length v)))
        (case (random 6 rng)
          (0 (when (plusp n) (setf (aref v (random n rng)) (random 256 rng))))
          (1 (when (plusp n) (setf v (subseq v 0 (random n rng)))))
          (2 (let ((p (random (1+ n) rng)))
               (setf v (concatenate '(vector (unsigned-byte 8)) (subseq v 0 p)
                                    (smtp::utf8-octets (random-elt rng '("0" "-1" "ffffffffffffffffffff" ":" "\r\n" "\n"
                                                                         "chunked" "99999999999" " ")))
                                    (subseq v p)))))
          (3 (when (plusp n) (let* ((a (random n rng)) (b (min n (+ a 1 (random 20 rng)))))
                               (setf v (concatenate '(vector (unsigned-byte 8)) (subseq v 0 a) (subseq v b))))))
          (4 (when (plusp n) (let* ((a (random n rng)) (b (min n (+ a 1 (random 20 rng)))))
                               (setf v (concatenate '(vector (unsigned-byte 8)) (subseq v 0 b) (subseq v a))))))
          (5 (when (plusp n) (setf (aref v (random n rng)) (random-elt rng (list 10 13 0 58 32 48))))))))))

(defun check-policy (where text expected)
  (multiple-value-bind (mode mx age) (smtp/delivery:parse-mta-sts-policy text)
    (cond (expected
           (unless (equal (list mode mx age) expected)
             (finding "~a: a valid policy parsed as ~s, not ~s" where (list mode mx age) expected)))
          (mode
           (unless (and (member mode '(:enforce :testing :none)) (integerp age) (<= 0 age 31557600)
                        (every #'stringp mx) (or mx (eq mode :none))
                        (every (lambda (m) (and (string= m (string-downcase m))
                                                (not (alexandria:ends-with-subseq "." m))))
                               mx))
             (finding "~a: policy parsed to ~s" where (list mode mx age)))))
    mode))

(when (section-p "mta-sts")
  (format t "~&== MTA-STS: 100000 corrupted policy responses and 100000 TXT records~%")
  (let ((rng (sb-ext:seed-random-state (fuzz-seed 300000 0))) (outcomes (make-hash-table)))
    (timed ("responses" 100000)
      (dotimes (i 100000)
        (multiple-value-bind (policy expected) (random-policy rng)
          (let* ((clean (zerop (random 5 rng)))
                 (response (random-http-response rng policy))
                 (octets (if clean response (mutate-octets rng response))))
            (handler-case
                (sb-sys:with-deadline (:seconds 2)
                  (let ((body (smtp/delivery::%read-http-response
                               (make-instance 'octet-input :octets octets) "mta-sts.example.test")))
                    (unless (stringp body) (finding "mta-sts ~d: body ~s" i body))
                    (incf (gethash (if (check-policy (format nil "mta-sts ~d" i) body (and clean expected))
                                       :policy :invalid)
                                   outcomes 0))))
              (smtp-error ()
                (when clean (finding "mta-sts ~d: a valid response was refused" i))
                (incf (gethash :smtp-error outcomes 0)))
              (sb-sys:deadline-timeout () (finding "mta-sts ~d: reading hung" i))
              (error (e) (incf (gethash :other outcomes 0))
                (when (< (gethash :other outcomes 0) 4) (finding "mta-sts ~d: ~a: ~a" i (type-of e) e))))))))
    (format t "~&    ~{~a=~d~^ ~}~%" (loop for k being the hash-keys of outcomes using (hash-value v) append (list k v)))
    (clrhash outcomes)
    (timed ("TXT records" 100000)
      (dotimes (i 100000)
        (let* ((id (random-text rng 40))
               (good (format nil "v=STSv1; id=~a" id))
               (records (loop repeat (random 3 rng)
                              collect (let ((r (if (zerop (random 2 rng)) good (random-text rng 60))))
                                        (if (zerop (random 3 rng))
                                            (let ((v (copy-seq r)))
                                              (when (plusp (length v))
                                                (setf (char v (random (length v) rng))
                                                      (random-elt rng (coerce ";= vS1" 'list))))
                                              v)
                                            r)))))
          (handler-case
              (let ((result (smtp/delivery::parse-mta-sts-txt records)))
                (incf (gethash (if result :id :none) outcomes 0))
                (when (and result (not (and (stringp result) (<= 1 (length result) 32)
                                            (every (lambda (c) (and (< (char-code c) 128) (alphanumericp c)))
                                                   result))))
                  (finding "mta-sts txt ~d: id ~s from ~s" i result records))
                (when (and (equal records (list good)) (<= 1 (length id) 32)
                           (every (lambda (c) (and (< (char-code c) 128) (alphanumericp c))) id)
                           (not (equal result id)))
                  (finding "mta-sts txt ~d: ~s gave ~s" i records result)))
            (error (e) (finding "mta-sts txt ~d: ~a: ~a" i (type-of e) e))))))
    (format t "~&    ~{~a=~d~^ ~}~%" (loop for k being the hash-keys of outcomes using (hash-value v) append (list k v)))))

;;; 10. The delivery queue against a model

(defun queue-model-run (seed)
  "One randomized queue scenario with a simulated DELIVER-RAW-MESSAGE.
Returns a list of problems."
  (let* ((rng (sb-ext:seed-random-state seed)) (lock (bt:make-lock)) (problems '())
         (sent (make-hash-table :test 'equal))       ; recipient -> times delivered
         (refused (make-hash-table :test 'equal))    ; recipient -> refused for good
         (reported (make-hash-table :test 'equal))   ; recipient -> final statuses reported
         (all '()) (give-up 20000) (threads (1+ (random 4 rng))))
    (labels ((pick (n) (bt:with-lock-held (lock) (random n rng)))
             (problem (fmt &rest args) (bt:with-lock-held (lock) (push (apply #'format nil fmt args) problems)))
             (report (statuses kind)
               (bt:with-lock-held (lock)
                 (dolist (st statuses) (push kind (gethash (smtp/delivery:recipient-status-recipient st) reported))))
               (when (zerop (pick 10)) (error "callback failed")))
             (deliver (octets &key recipients &allow-other-keys)
               (declare (ignore octets))
               (when (zerop (pick 8)) (error "local problem"))
               (loop for r in recipients
                     collect (let ((outcome (case (pick 7) ((0 1 2) :delivered) ((3 4) :deferred) (t :failed))))
                               (bt:with-lock-held (lock)
                                 (case outcome
                                   (:delivered (incf (gethash r sent 0)))
                                   (:failed (setf (gethash r refused) t))))
                               (smtp/delivery::%status r outcome :message "simulated")))))
      (let ((queue (smtp/delivery:make-delivery-queue
                    :retry-schedule '(60 600 3600) :give-up-after give-up
                    :on-delivered (lambda (i s) (declare (ignore i)) (report s :delivered))
                    :on-failed (lambda (i s) (declare (ignore i)) (report s :failed))
                    :on-deferred (lambda (i s) (declare (ignore i s)) (when (zerop (pick 10)) (error "callback failed")))))
            (real (fdefinition 'smtp/delivery:deliver-raw-message))
            (now 0))
        (setf (fdefinition 'smtp/delivery:deliver-raw-message) #'deliver)
        (unwind-protect
             (handler-bind ((warning #'muffle-warning))
               (loop for step from 0
                     do (when (< step 20)
                          (dotimes (m (random 3 rng))
                            (let ((rcpts (loop for j below (1+ (random 5 rng))
                                               collect (format nil "s~dm~dr~d@d~d.test" step m j (random 3 rng)))))
                              (setf all (append all rcpts))
                              (smtp/delivery:enqueue-raw-message queue (smtp::utf8-octets (crlf "Subject: x" "" "x"))
                                                                 :envelope-from "a@example.test" :recipients rcpts
                                                                 :now now))))
                        (mapc #'bt:join-thread
                              (loop repeat threads
                                    collect (let ((at now))
                                              (bt:make-thread (lambda () (smtp/delivery:run-delivery-queue queue :now at))))))
                        (incf now (random 3000 rng))
                     until (or (and (>= step 20) (null (smtp/delivery:delivery-queue-messages queue)))
                               (> now (* 3 give-up)))))
          (setf (fdefinition 'smtp/delivery:deliver-raw-message) real))
        (when (smtp/delivery:delivery-queue-messages queue)
          (problem "~d messages still queued long after giving up" (length (smtp/delivery:delivery-queue-messages queue))))
        (dolist (r all)
          (let ((times (gethash r sent 0)) (kinds (gethash r reported)))
            (when (> times 1) (problem "~a delivered ~d times" r times))
            (unless (= 1 (length kinds)) (problem "~a reported ~s" r kinds))
            (when (and (= times 1) (not (equal kinds '(:delivered)))) (problem "~a delivered but reported ~s" r kinds))
            (when (and (zerop times) (member :delivered kinds)) (problem "~a reported delivered but was not" r))
            (when (and (gethash r refused) (not (equal kinds '(:failed))))
              (problem "~a refused but reported ~s" r kinds))))
        problems))))

(when (section-p "queue-model")
  (format t "~&== Delivery queue model: 300 randomized scenarios~%")
  (let ((n 300) (bad 0))
    (timed ("scenarios" n)
      (dotimes (i n)
        (let ((problems (queue-model-run (fuzz-seed 400000 i))))
          (when problems
            (incf bad)
            (when (<= bad 3)
              (finding "queue model ~d: ~{~a~^; ~}" i (subseq problems 0 (min 5 (length problems)))))))))
    (format t "~&    scenarios with problems: ~d~%" bad)))

;;; 11. Addresses

(defun random-address-string (rng)
  "A string near the shape of a mailbox, often valid, often not."
  (let* ((specials "\"\\<>@,;:()[]. ")
         (local (case (random 4 rng)
                  (0 (random-text rng 12))
                  (1 (format nil "\"~a\"" (random-text rng 12)))
                  (2 (format nil "~a.~a" (random-text rng 6) (random-text rng 6)))
                  (t (random-elt rng '("bob" "a.b" "x+tag" "\"a b\"" "\"a\\\"b\"" "ünï" "o'brien")))))
         (domain (case (random 5 rng)
                   (0 (random-text rng 15))
                   (1 (random-elt rng '("example.test" "bücher.example" "xn--bcher-kva.example" "EXAMPLE.Test."
                                        "[192.0.2.1]" "[IPv6:2001:db8::1]" "[300.1.1.1]" "a" "a..b" "-a.test")))
                   (t (format nil "~a.~a" (random-text rng 8) (random-elt rng '("test" "example" "中国"))))))
         (name (case (random 4 rng)
                 (0 nil)
                 (1 (random-text rng 20))
                 (2 (format nil "\"~a\"" (random-text rng 20)))
                 (t (random-elt rng '("Bob" "Bob Smith" "Smith, Bob" "=?utf-8?q?x?=" "Zoë"))))))
    (let ((s (if name (format nil "~a <~a@~a>" name local domain) (format nil "~a@~a" local domain))))
      (dotimes (k (random 3 rng) s)
        (let ((p (random (1+ (length s)) rng)))
          (setf s (case (random 3 rng)
                    (0 (concatenate 'string (subseq s 0 p) (string (char specials (random (length specials) rng)))
                                    (subseq s p)))
                    (1 (if (< p (length s)) (concatenate 'string (subseq s 0 p) (subseq s (1+ p))) s))
                    (t (concatenate 'string (subseq s 0 p)
                                    (string (random-elt rng (list #\Tab #\Return #\Newline (code-char 0)
                                                                  (code-char #x2028) #\" #\\)))
                                    (subseq s p))))))))))

(defun check-mailbox (where m)
  (let ((address (mailbox-address m)))
    (when (find-if #'smtp::control-char-p address) (finding "~a: control character in ~s" where address))
    (when (> (length (smtp::utf8-octets address)) 254) (finding "~a: ~s is too long" where address))
    (dolist (utf8 '(nil t))
      (let ((text (format-mailbox m :utf8 utf8)))
        (when (find-if #'smtp::control-char-p text) (finding "~a: control character in ~s" where text))
        (handler-case
            (let ((again (parse-mailbox text)))
              (unless (and (smtp::mailbox= m again) (string= address (mailbox-address again))
                           ;; Names are compared unless encoded (RFC 2047), as
                           ;; they are without UTF8 or when a word is too long.
                           (or (search "=?UTF-8?" text)
                               (equal (mailbox-display-name m) (mailbox-display-name again))))
                (finding "~a: ~s formats as ~s, which parses as ~s" where m text again)))
          (error (e) (finding "~a: ~s formats as ~s, which does not parse: ~a" where m text e)))))))

(when (section-p "addresses")
  (format t "~&== Addresses: 200000 random mailboxes and 20000 lists~%")
  (let ((rng (sb-ext:seed-random-state (fuzz-seed 500000 0))) (outcomes (make-hash-table)) (others 0))
    (flet ((other (where e)
             (when (< (incf others) 6) (finding "~a: ~a: ~a" where (type-of e) e))))
      (timed ("mailboxes" 200000)
        (dotimes (i 200000)
          (let ((s (random-address-string rng)))
            (handler-case
                (let ((m (parse-mailbox s)))
                  (incf (gethash :parsed outcomes 0))
                  (check-mailbox (format nil "address ~d ~s" i s) m))
              (invalid-address () (incf (gethash :invalid outcomes 0)))
              (error (e) (other (format nil "address ~d ~s" i s) e))))))
      (format t "~&    ~{~a=~d~^ ~}~%" (loop for k being the hash-keys of outcomes using (hash-value v) append (list k v)))
      (timed ("lists" 20000)
        (dotimes (i 20000)
          (let ((mailboxes (loop repeat (1+ (random 4 rng))
                                 for m = (ignore-errors (parse-mailbox (random-address-string rng)))
                                 when m collect m)))
            (when mailboxes
              (let ((text (format nil "~{~a~^, ~}" (mapcar (lambda (m) (format-mailbox m :utf8 t)) mailboxes))))
                (handler-case
                    (let ((again (parse-mailbox-list text)))
                      (unless (and (= (length again) (length mailboxes)) (every #'smtp::mailbox= mailboxes again))
                        (finding "list ~d: ~s parses as ~s" i text again)))
                  (error (e) (finding "list ~d: ~s does not parse: ~a" i text e)))))))))))

(mapc (lambda (dir) (uiop:delete-directory-tree dir :validate t)) *cleanup*)
(format t "~&~%== ~d finding~:p~%~{  - ~a~%~}" (length *findings*) (reverse *findings*))
(when *findings* (format t "~&  Replay with SEED=~d~%" *seed*))
(uiop:quit (if *findings* 1 0))
