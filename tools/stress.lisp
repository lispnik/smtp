;;; Stress tests for the smtp client: throughput, pool concurrency, connection
;;; churn, 50 MB messages, a hostile server, message-builder fuzzing checked
;;; with Python's email package, DNS response fuzzing and a concurrent delivery
;;; queue. Not part of make test; run with make stress, or from the checkout:
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
    (or (null only) (search name only))))

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

(mapc (lambda (dir) (uiop:delete-directory-tree dir :validate t)) *cleanup*)
(format t "~&~%== ~d finding~:p~%~{  - ~a~%~}" (length *findings*) (reverse *findings*))
(when *findings* (format t "~&  Replay with SEED=~d~%" *seed*))
(uiop:quit (if *findings* 1 0))
