;;; deliver.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; Delivering directly to each recipient domain's mail servers (RFC 5321
;;; section 5): MX lookup with implicit MX and null MX (RFC 7505), the
;;; hosts tried in preference order, and on each one the strongest transport
;;; security the domain asks for: DANE (RFC 7672) when its DNS is signed,
;;; else an enforced MTA-STS policy (RFC 8461), else opportunistic STARTTLS.

(in-package #:smtp/delivery)

(defstruct recipient-status
  "What happened to one recipient. STATUS is :DELIVERED, :DEFERRED (a
temporary failure: try again later) or :FAILED (permanent). REPLY is the
server's reply, if there was one; MESSAGE explains; HOST is the MX host
last tried and SECURITY the protection it got: :DANE, :MTA-STS, :TLS
(verified certificate), :OPPORTUNISTIC-TLS or :PLAINTEXT."
  recipient status reply message host security)

(defun %status (recipient status &key reply message host security)
  (make-recipient-status :recipient recipient :status status :reply reply
                         :message message :host host :security security))

;;; Finding the servers

(define-condition delivery-failed (smtp-error) ()
  (:documentation "Mail for a domain cannot be delivered at all, permanently."))


(defun %null-mx-p (records)
  (and (= 1 (length records)) (equal (second (first records)) "")))

(defun %shuffle (list)
  (let ((v (coerce list 'vector)))
    (loop for i from (1- (length v)) downto 1
          do (rotatef (aref v i) (aref v (random (1+ i)))))
    (coerce v 'list)))

(defun %sort-mx (records)
  "MX hosts by preference, with equal preferences in random order."
  (let ((groups (make-hash-table)))
    (dolist (r records) (push (second r) (gethash (first r) groups)))
    (loop for pref in (sort (alexandria:hash-table-keys groups) #'<)
          append (%shuffle (remove-duplicates (gethash pref groups) :test #'string-equal)))))

(defun mail-exchangers (domain &key (resolver (default-resolver)))
  "The hosts that receive mail for the ASCII DOMAIN, most preferred first,
and whether the MX answer was DNSSEC-validated. Signals DELIVERY-FAILED
for a domain that does not exist or accepts no mail (null MX), DNS-ERROR
when the lookup fails."
  (let ((answer (dns-query domain :mx :resolver resolver)))
    (case (dns-answer-status answer)
      (:nxdomain
       (error 'delivery-failed :message (format nil "The domain ~a does not exist" domain)))
      (:nodata
       ;; Implicit MX: the domain is its own mail server (RFC 5321 5.1).
       (values (list domain) (dns-answer-secure answer)))
      (t
       (let ((records (dns-answer-records answer)))
         (when (%null-mx-p records)
           (error 'delivery-failed :message (format nil "The domain ~a does not accept mail (null MX)"
                                                    domain)))
         (values (%sort-mx (remove "" records :key #'second :test #'string=))
                 (dns-answer-secure answer)))))))

;;; Planning the connection to one host

(defstruct (route (:constructor %make-route))
  host addresses security tls verify tls-hostname reason)

(defun %addresses (host resolver)
  "HOST's addresses (IPv4 first), whether every answer was secure, and the
CNAME-expanded name."
  (let ((addresses '()) (secure t) (canonical nil) (errors 0))
    (dolist (type '(:a :aaaa))
      (handler-case
          (let ((answer (dns-query host type :resolver resolver)))
            (setf addresses (append addresses (dns-answer-records answer)))
            (unless (dns-answer-secure answer) (setf secure nil))
            (when (dns-answer-records answer)
              (setf canonical (or canonical (dns-answer-canonical-name answer)))))
        (dns-error () (incf errors) (setf secure nil))))
    (when (= errors 2)
      (error 'dns-error :name host :message (format nil "Cannot look up the address of ~a" host)))
    (values addresses secure canonical)))

(defun %tlsa-lookup (base resolver port)
  "The secure TLSA records for BASE, :INSECURE, or :NONE. A failed lookup
signals: the host must then be treated as unreachable (RFC 7672 2.1.2)."
  (let ((answer (dns-query (format nil "_~d._tcp.~a" port base) :tlsa :resolver resolver)))
    (cond ((not (dns-answer-secure answer)) :insecure)
          ((dns-answer-records answer)
           (mapcar (lambda (r) (apply #'make-tlsa r)) (dns-answer-records answer)))
          (t :none))))

(defun %plan-route (host domain mx-secure policy resolver &key dane require-tls (tlsa-port 25))
  (multiple-value-bind (addresses secure canonical) (%addresses host resolver)
    (let ((route (%make-route :host host :addresses addresses)))
      (when (null addresses)
        (setf (route-reason route) (format nil "~a has no address" host))
        (return-from %plan-route route))
      ;; DANE: only when the MX and address answers are both validated.
      (when (and dane mx-secure secure)
        (dolist (base (remove-duplicates (remove nil (list canonical host)) :test #'string-equal
                                                                              :from-end t))
          (let ((records (%tlsa-lookup base resolver tlsa-port)))
            (cond ((listp records)
                   (setf (route-security route) :dane
                         (route-tls route) :starttls
                         (route-tls-hostname route) base
                         (route-verify route)
                         (make-dane-verifier records (remove-duplicates (list base domain host)
                                                                        :test #'string-equal)))
                   (return-from %plan-route route))
                  ((eq records :insecure) (return))))))
      (cond ((and policy (eq (mta-sts-policy-mode policy) :enforce))
             (if (mta-sts-policy-allows-p policy host)
                 (setf (route-security route) :mta-sts (route-tls route) :starttls
                       (route-verify route) t (route-tls-hostname route) host)
                 (setf (route-reason route)
                       (format nil "~a is not an MX host in ~a's MTA-STS policy" host domain))))
            (require-tls
             (setf (route-security route) :tls (route-tls route) :starttls
                   (route-verify route) t (route-tls-hostname route) host))
            (t
             (setf (route-security route) :opportunistic-tls (route-tls route) :opportunistic
                   (route-verify route) nil (route-tls-hostname route) host)))
      route)))

;;; Sending

(defun %classify (condition)
  "The status a failed transaction gives its recipients: :FAILED when the
server refused the message for good, else :DEFERRED."
  (typecase condition
    ((or smtp-permanent-error smtp-message-too-large smtp-unsupported-extension mail-format-error)
     :failed)
    (t :deferred)))

(defun %reply-of (condition)
  (and (typep condition 'smtp-reply-error) (smtp-error-reply condition)))

(defun %attempt (route address recipients octets connection-options send-options)
  "Try to deliver to RECIPIENTS through ADDRESS. Returns their statuses;
those still :DEFERRED may be tried at another host."
  (let ((security (route-security route))
        (host (route-host route))
        (connection nil))
    (labels ((all (status condition)
               (mapcar (lambda (r)
                         (%status r status :reply (%reply-of condition) :host host
                                           :security security :message (princ-to-string condition)))
                       recipients))
             (start (tls)
               (apply #'open-connection address :tls tls
                                                :verify (route-verify route)
                                                :tls-hostname (route-tls-hostname route)
                                                connection-options))
             (send ()
               (handler-case
                   (let ((result (handler-case
                                     (apply #'send-raw-message connection octets
                                            :recipients recipients :on-rejected-recipient :skip
                                            send-options)
                                   (smtp-recipients-rejected (e)
                                     (smtp::make-delivery-result
                                      :rejected (smtp-recipients-rejected-rejected e))))))
                     (append
                      (mapcar (lambda (r) (%status r :delivered :reply (delivery-result-reply result)
                                                                :host host :security security))
                              (delivery-result-accepted result))
                      (mapcar (lambda (entry)
                                (destructuring-bind (r . reply) entry
                                  (%status r (if (= (smtp::reply-class reply) 5) :failed :deferred)
                                           :reply reply :host host :security security
                                           :message (format nil "~d ~a" (reply-code reply)
                                                            (reply-text reply)))))
                              (delivery-result-rejected result))))
                 (smtp-error (e) (all (%classify e) e)))))
      (unwind-protect
           (handler-case
               (progn
                 (setf connection
                       (handler-case (start (route-tls route))
                         (smtp-tls-error (e)
                           ;; Opportunistic TLS may fall back to plaintext when
                           ;; the handshake fails (RFC 7435); nothing stronger may.
                           (if (eq (route-tls route) :opportunistic)
                               (start :none)
                               (error e)))))
                 (when (and (eq security :opportunistic-tls) (not (connection-tls-p connection)))
                   (setf security :plaintext))
                 (send))
             ;; Any failure to set up the session (refused, unreachable,
             ;; no STARTTLS where TLS is required, a failed DANE or MTA-STS
             ;; check, a 4xx or 5xx greeting) means trying another host.
             (smtp-error (e) (all :deferred e)))
        (when connection (close-connection connection))))))

(defun %recipient-domain (address)
  (string-downcase (subseq address (1+ (position #\@ address :from-end t)))))

(defun %deliver-to-domain (domain recipients octets &key resolver mta-sts mta-sts-cache dane
                                                         require-tls ca-file tls-backend
                                                         connection-options send-options port)
  (let ((pending recipients) (done '()) (reasons '()) (last-host nil)
        (last (make-hash-table :test 'equalp)))
    (flet ((finish (status message)
             ;; Keep each recipient's latest reply, with every host's reason.
             (append done (mapcar (lambda (r)
                                    (let ((s (gethash r last)))
                                      (%status r status :message message
                                                        :reply (and s (recipient-status-reply s))
                                                        :host (if s (recipient-status-host s) last-host)
                                                        :security (and s (recipient-status-security s)))))
                                  pending))))
      (handler-case
          (multiple-value-bind (hosts mx-secure)
              (if (smtp::%address-literal-p domain)
                  (values (list domain) nil)
                  (mail-exchangers domain :resolver resolver))
            (let ((policy (and mta-sts (not (smtp::%address-literal-p domain))
                               (let ((p (mta-sts-policy domain :resolver resolver :cache mta-sts-cache
                                                               :ca-file ca-file :tls-backend tls-backend)))
                                 (and p (not (eq (mta-sts-policy-mode p) :none)) p)))))
              (dolist (host hosts)
                (setf last-host host)
                (let ((route (handler-case
                                 (if (smtp::%address-literal-p host)
                                     (%make-route :host host :addresses (list (smtp::%normalize-host host))
                                                  :security :opportunistic-tls :tls :opportunistic
                                                  :tls-hostname nil)
                                     (%plan-route host domain mx-secure policy resolver
                                                  :dane dane :require-tls require-tls))
                               (dns-error (e) (%make-route :host host :reason (princ-to-string e))))))
                  (if (route-reason route)
                      (push (route-reason route) reasons)
                      (dolist (address (route-addresses route))
                        (let* ((statuses (%attempt route address pending octets
                                                   (list* :port (if (functionp port)
                                                                    (funcall port host address)
                                                                    port)
                                                          connection-options)
                                                   send-options))
                               (deferred (remove :deferred statuses :key #'recipient-status-status
                                                                    :test-not #'eq)))
                          ;; A server's reply says more than a later failure to connect.
                          (dolist (d deferred)
                            (when (or (recipient-status-reply d)
                                      (null (gethash (recipient-status-recipient d) last)))
                              (setf (gethash (recipient-status-recipient d) last) d)))
                          (setf done (append done (remove :deferred statuses
                                                          :key #'recipient-status-status))
                                pending (mapcar #'recipient-status-recipient deferred)
                                reasons (if deferred
                                            (cons (format nil "~a: ~a" host
                                                          (recipient-status-message (first deferred)))
                                                  reasons)
                                            reasons))
                          (when (null pending)
                            (return-from %deliver-to-domain done))))))))
            (finish :deferred (if reasons
                                  (format nil "~{~a~^; ~}" (reverse reasons))
                                  (format nil "No mail server for ~a could be reached" domain))))
        (delivery-failed (e) (finish :failed (princ-to-string e)))
        (dns-error (e) (finish :deferred (princ-to-string e)))))))

(defun deliver-raw-message (octets &key envelope-from recipients smtputf8
                                     (resolver (default-resolver)) (mta-sts t)
                                     (mta-sts-cache *mta-sts-cache*) (dane t) require-tls
                                     (port 25) local-name ca-file (tls-backend *tls-backend*)
                                     (connect-timeout 30) (timeout 300) (data-timeout 600)
                                     (trace *trace*) dsn-notify dsn-return dsn-envelope-id)
  "Deliver OCTETS, a rendered message, to each recipient's mail servers.
Returns a list of RECIPIENT-STATUS, one per recipient. See DELIVER-MESSAGE."
  (let* ((rcpts (remove-duplicates (mapcar #'mailbox-address (smtp::ensure-mailbox-list recipients))
                                   :test #'string-equal :from-end t))
         (domains (remove-duplicates (mapcar #'%recipient-domain rcpts) :test #'string= :from-end t))
         (tls-backend (smtp::resolve-tls-backend tls-backend))
         (connection-options (list :local-name local-name :connect-timeout connect-timeout
                                   :timeout timeout :data-timeout data-timeout :trace trace
                                   :tls-backend tls-backend :ca-file ca-file))
         (send-options (list :envelope-from envelope-from :smtputf8 smtputf8
                             :dsn-notify dsn-notify :dsn-return dsn-return
                             :dsn-envelope-id dsn-envelope-id)))
    (unless rcpts (error 'mail-format-error :message "No recipients"))
    (unless envelope-from (error 'mail-format-error :message "No envelope sender (:envelope-from)"))
    (sort
     (loop for domain in domains
           append (%deliver-to-domain domain
                                     (remove domain rcpts :key #'%recipient-domain :test-not #'string=)
                                     octets
                                     :resolver resolver :mta-sts mta-sts :mta-sts-cache mta-sts-cache
                                     :dane dane :require-tls require-tls :ca-file ca-file
                                     :tls-backend tls-backend :port port
                                     :connection-options connection-options
                                     :send-options send-options))
     #'< :key (lambda (status)
                (position (recipient-status-recipient status) rcpts :test #'string-equal)))))

(defun deliver-message (message &rest options &key envelope-from recipients dkim &allow-other-keys)
  "Deliver MESSAGE straight to its recipients' mail servers, without a
relay. Returns a list of RECIPIENT-STATUS, one per recipient: :DELIVERED,
:DEFERRED (try again later, for example with a DELIVERY-QUEUE) or :FAILED.

Each domain's MX hosts are tried in order of preference. Transport security
is the strongest the domain supports: DANE when its MX and TLSA records are
DNSSEC-signed and the resolver is trusted to validate (see MAKE-RESOLVER),
otherwise its MTA-STS policy when that is enforced, otherwise STARTTLS when
offered, without certificate checks (RFC 7435). REQUIRE-TLS true insists on
a verified certificate where neither applies. DANE and MTA-STS can be turned
off with :DANE NIL and :MTA-STS NIL.

ENVELOPE-FROM defaults to the Sender, else the From, address; RECIPIENTS to
the To, Cc and Bcc addresses. DKIM signs the message. Other options:
RESOLVER, MTA-STS-CACHE, PORT, LOCAL-NAME (the EHLO name; use this host's
public name, which receiving servers check), CA-FILE, TLS-BACKEND,
CONNECT-TIMEOUT, TIMEOUT, DATA-TIMEOUT, TRACE and the DSN- options of
SEND-RAW-MESSAGE."
  (multiple-value-bind (octets utf8) (render-message message)
    (when dkim (setf octets (smtp:sign-message-octets dkim octets)))
    (apply #'deliver-raw-message octets
           :envelope-from (or envelope-from (smtp::message-sender message) (smtp::message-from message))
           :recipients (or recipients (smtp::message-envelope-recipients message))
           :smtputf8 utf8
           (alexandria:remove-from-plist options :envelope-from :recipients :dkim))))
