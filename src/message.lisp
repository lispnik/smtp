;;; message.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; The message model and its rendering to RFC 5322 / MIME octets. Rendering
;;; always produces CRLF line endings, lines of at most 998 octets and, unless
;;; an address needs SMTPUTF8, pure 7-bit data.

(in-package #:smtp)

;;; Attachments

(defclass attachment ()
  ((source :initarg :source :reader attachment-source
           :documentation "A pathname or an octet vector.")
   (filename :initarg :filename :reader attachment-filename)
   (content-type :initarg :content-type :reader attachment-content-type)
   (inline :initarg :inline :initform nil :reader attachment-inline-p)
   (content-id :initarg :content-id :initform nil :reader attachment-content-id)))

(defmethod print-object ((a attachment) stream)
  (print-unreadable-object (a stream :type t)
    (format stream "~s ~a" (attachment-filename a) (attachment-content-type a))))

(defun %invisible-char-p (char)
  "Whether CHAR changes how a name displays without being seen: the bidi
controls, which can make \"invoice<U+202E>fdp.exe\" display as
\"invoiceexe.pdf\", and the zero-width characters that are not needed to
join letters (U+200C and U+200D are)."
  (let ((code (char-code char)))
    (or (= code #x061C) (= code #x200B) (= code #x200E) (= code #x200F)
        (<= #x202A code #x202E) (= code #x2060) (<= #x2066 code #x2069) (= code #xFEFF))))

(defun %sanitize-filename (name)
  (let* ((base (subseq name (1+ (or (position-if (lambda (c) (find c "/\\")) name :from-end t)
                                    -1))))
         ;; Readers drop surrounding spaces, and Windows trailing dots too.
         (clean (string-right-trim ". " (string-trim '(#\Space #\Tab)
                                                     (remove-if (lambda (c) (or (control-char-p c)
                                                                                (%invisible-char-p c)))
                                                                base)))))
    (if (zerop (length clean)) "attachment" clean)))

(defun %valid-parameters-p (string)
  "Whether STRING is a sequence of \"; token=(token|quoted-string)\"."
  (let ((i 0) (n (length string)))
    (flet ((skip-ws () (loop while (and (< i n) (wsp-char-p (char string i))) do (incf i)))
           (token () (let ((start i))
                       (loop while (and (< i n)
                                        (let ((c (char string i)))
                                          (and (< 32 (char-code c) 127) (not (%tspecial-p c)))))
                             do (incf i))
                       (> i start))))
      (loop
        (skip-ws)
        (when (>= i n) (return t))
        (unless (char= (char string i) #\;) (return nil))
        (incf i)
        (skip-ws)
        (unless (token) (return nil))
        (unless (and (< i n) (char= (char string i) #\=)) (return nil))
        (incf i)
        (cond ((and (< i n) (char= (char string i) #\"))
               (incf i)
               (loop (when (>= i n) (return-from %valid-parameters-p nil))
                     (let ((c (char string i)))
                       (cond ((char= c #\\) (incf i 2))
                             ((char= c #\") (incf i) (return))
                             (t (incf i))))))
              ((not (token)) (return nil)))))))

(defun %check-content-type (type)
  (unless (and (stringp type)
               (ascii-p type)
               (notany #'control-char-p type)
               (let* ((semi (or (position #\; type) (length type)))
                      (base (string-trim " " (subseq type 0 semi)))
                      (slash (position #\/ base)))
                 (and slash
                      (%token-p (subseq base 0 slash))
                      (%token-p (subseq base (1+ slash)))
                      (%valid-parameters-p (subseq type semi))
                      ;; Composite types cannot be base64-encoded (RFC 2045 6.4).
                      (not (member (string-downcase (subseq base 0 slash))
                                   '("multipart" "message") :test #'string=)))))
    (error 'invalid-header :name "Content-Type"
                           :message (format nil "invalid attachment media type ~s" type)))
  type)

(defun %check-id (id what)
  (unless (and (stringp id) (plusp (length id))
               (every (lambda (c) (and (< 32 (char-code c) 127) (not (find c "<>\"\\[]()")))) id))
    (error 'invalid-header :name what :message (format nil "invalid identifier ~s" id)))
  id)

(defun make-attachment (source &key filename content-type inline content-id)
  "An attachment whose content is SOURCE: a pathname or namestring of a file
(read when the message is rendered), or an octet vector.

FILENAME defaults to the file's name (required for octet vectors); it is
stripped of directories. CONTENT-TYPE defaults from FILENAME's extension.
INLINE true makes it a related part of the HTML body, referenced there as
cid:CONTENT-ID (generated if not given)."
  (let ((source (etypecase source
                  ((or pathname string)
                   (let ((path (pathname source)))
                     (unless (probe-file path)
                       (error 'mail-format-error
                              :message (format nil "Attachment file ~a does not exist" path)))
                     path))
                  ((vector (unsigned-byte 8))
                   (unless filename
                     (error 'mail-format-error
                            :message "An attachment made from octets needs a :filename"))
                   (coerce source 'octets)))))
    (let ((name (%sanitize-filename
                 (or filename (file-namestring source)))))
      (make-instance 'attachment
                     :source source
                     :filename name
                     :content-type (%check-content-type
                                    (or content-type (mime-type-for-filename name)))
                     :inline inline
                     :content-id (and inline
                                      (if content-id
                                          (%check-id content-id "Content-ID")
                                          (format nil "~a@inline" (random-token 12))))))))

(defun %attachment-octets (attachment)
  (let ((source (attachment-source attachment)))
    (if (pathnamep source)
        (with-open-file (in source :element-type 'octet)
          (let ((data (make-array (file-length in) :element-type 'octet)))
            (let ((n (read-sequence data in)))
              (if (= n (length data)) data (subseq data 0 n)))))
        source)))

(defun ensure-attachment (designator)
  (etypecase designator
    (attachment designator)
    ((or pathname string) (make-attachment designator))))

;;; Messages

(defclass message ()
  ((from :initarg :from :accessor message-from)
   (sender :initarg :sender :initform nil :accessor message-sender)
   (to :initarg :to :initform '() :accessor message-to)
   (cc :initarg :cc :initform '() :accessor message-cc)
   (bcc :initarg :bcc :initform '() :accessor message-bcc)
   (reply-to :initarg :reply-to :initform '() :accessor message-reply-to)
   (subject :initarg :subject :initform nil :accessor message-subject)
   (text :initarg :text :initform nil :accessor message-text)
   (html :initarg :html :initform nil :accessor message-html)
   (attachments :initarg :attachments :initform '() :accessor message-attachments)
   (headers :initarg :headers :initform '() :accessor message-headers
            :documentation "Extra headers, an alist of (name . value).")
   (date :initarg :date :initform nil :accessor message-date
         :documentation "A universal time, or NIL for the time of rendering.")
   (message-id :initarg :message-id :initform nil :accessor message-id)
   (in-reply-to :initarg :in-reply-to :initform '() :accessor message-in-reply-to)
   (references :initarg :references :initform '() :accessor message-references)
   (list-unsubscribe :initarg :list-unsubscribe :initform '() :accessor message-list-unsubscribe)
   (list-unsubscribe-post :initarg :list-unsubscribe-post :initform nil
                          :accessor message-list-unsubscribe-post)))

(defmethod print-object ((m message) stream)
  (print-unreadable-object (m stream :type t)
    (format stream "~s from ~a" (message-subject m)
            (and (message-from m) (mailbox-address (message-from m))))))

(defparameter +reserved-headers+
  '("Date" "From" "Sender" "To" "Cc" "Bcc" "Reply-To" "Subject" "Message-ID"
    "In-Reply-To" "References" "MIME-Version" "Content-Type"
    "Content-Transfer-Encoding" "Content-Disposition" "Content-ID")
  "Headers the library generates; set them with MAKE-MESSAGE's keywords.")

(defun %check-header-name (name)
  (unless (and (stringp name) (plusp (length name))
               (every (lambda (c) (and (< 32 (char-code c) 127) (char/= c #\:))) name))
    (error 'invalid-header :name name :message "invalid header name"))
  (when (member name +reserved-headers+ :test #'string-equal)
    (error 'invalid-header :name name
                           :message "this header is generated; use the MAKE-MESSAGE keyword"))
  name)

(defun %check-header-value (name value)
  (unless (stringp value)
    (error 'invalid-header :name name :message "the value must be a string"))
  (when (find-if #'control-char-p (remove #\Tab value))
    (error 'invalid-header :name name
                           :message "the value contains a line break or control character"))
  value)

(defun %normalize-msg-id (id what)
  (let* ((s (string-trim '(#\Space) id))
         (inner (if (and (> (length s) 1) (char= (char s 0) #\<)
                         (char= (char s (1- (length s))) #\>))
                    (subseq s 1 (1- (length s)))
                    s))
         (at (position #\@ inner)))
    (unless (and at (plusp at) (< at (1- (length inner))))
      (error 'invalid-header :name what :message (format nil "invalid message id ~s" id)))
    (%check-id (remove #\@ inner :count 1 :start at) what)
    (format nil "<~a>" inner)))

(defun %msg-id-list (designator what)
  (mapcar (lambda (id) (%normalize-msg-id id what))
          (if (listp designator)
              designator
              (remove "" (loop with start = 0
                               for pos = (position #\Space designator :start start)
                               collect (subseq designator start pos)
                               while pos do (setf start (1+ pos)))
                      :test #'string=))))

(defun make-message (&key from sender to cc bcc reply-to subject text html
                       attachments headers date message-id in-reply-to references
                       list-unsubscribe list-unsubscribe-post)
  "Make a message. Addresses may be mailboxes or strings (\"a@example.com\",
\"Name <a@example.com>\"); TO, CC, BCC and REPLY-TO also take lists or
comma-separated strings. TEXT and HTML are the plain and HTML bodies.
ATTACHMENTS is a list of attachments or file pathnames. HEADERS is an alist
of extra (name . value) headers. LIST-UNSUBSCRIBE is a URI or list of URIs;
LIST-UNSUBSCRIBE-POST true adds the RFC 8058 one-click header.

Everything is validated here, so a message that is made can always be
rendered safely; problems signal MAIL-FORMAT-ERROR."
  (unless from (error 'mail-format-error :message "A message needs a :from address"))
  (when subject
    (check-type subject string)
    (when (find-if #'control-char-p (remove #\Tab subject))
      (error 'invalid-header :name "Subject"
                             :message "the subject contains a line break or control character")))
  (when text (check-type text string))
  (when html (check-type html string))
  (when date (check-type date (integer 0)))
  (let ((extra (loop for (name . value) in headers
                     collect (cons (%check-header-name name) (%check-header-value name value))))
        (unsubscribe (and list-unsubscribe
                          (mapcar (lambda (uri)
                                    (unless (and (stringp uri) (plusp (length uri))
                                                 (ascii-p uri)
                                                 (< (length uri) 900)
                                                 (notany (lambda (c) (or (control-char-p c)
                                                                         (find c "<> ")))
                                                         uri))
                                      (error 'invalid-header :name "List-Unsubscribe"
                                                             :message (format nil "invalid URI ~s" uri)))
                                    uri)
                                  (alexandria:ensure-list list-unsubscribe)))))
    (when (and list-unsubscribe-post
               (notany (lambda (u) (string-prefix-p "https:" u)) unsubscribe))
      (error 'invalid-header :name "List-Unsubscribe-Post"
                             :message "one-click unsubscribe needs an https List-Unsubscribe URI"))
    (make-instance 'message
                   :list-unsubscribe unsubscribe
                   :list-unsubscribe-post (and list-unsubscribe-post t)
                   :from (ensure-mailbox from)
                   :sender (and sender (ensure-mailbox sender))
                   :to (ensure-mailbox-list to)
                   :cc (ensure-mailbox-list cc)
                   :bcc (ensure-mailbox-list bcc)
                   :reply-to (ensure-mailbox-list reply-to)
                   :subject subject
                   :text text
                   :html html
                   :attachments (mapcar #'ensure-attachment (alexandria:ensure-list attachments))
                   :headers extra
                   :date date
                   :message-id (and message-id (%normalize-msg-id message-id "Message-ID"))
                   :in-reply-to (and in-reply-to (%msg-id-list in-reply-to "In-Reply-To"))
                   :references (and references (%msg-id-list references "References")))))

(defun message-envelope-recipients (message)
  "The To, Cc and Bcc mailboxes of MESSAGE without duplicates."
  (remove-duplicates (append (message-to message) (message-cc message) (message-bcc message))
                     :test #'mailbox= :from-end t))

(defun message-needs-smtputf8-p (message)
  (some #'mailbox-utf8-p
        (append (list (message-from message))
                (and (message-sender message) (list (message-sender message)))
                (message-to message) (message-cc message) (message-bcc message)
                (message-reply-to message))))

;;; MIME structure

(defstruct (part (:constructor make-part
                     (type &key params encoding disposition disposition-params
                                content-id body children)))
  type params encoding disposition disposition-params content-id body children)

(defun %make-boundary ()
  ;; "=_" cannot occur in quoted-printable or base64 output.
  (format nil "=_~a" (random-token 18)))

(defun %text-part (string subtype)
  (let ((encoding (choose-text-encoding string)))
    (make-part (format nil "text/~a" subtype)
               :params '(("charset" . "utf-8"))
               :encoding encoding
               :body (lambda (buffer) (text-body-to-buffer string encoding buffer)))))

;;; A non-ASCII filename is given once in each header, as Thunderbird does:
;;; RFC 2231 in Content-Disposition, and RFC 2047 encoded-words in the
;;; Content-Type name for older readers. Readers such as Gmail and Python
;;; take the first of two filename parameters, so an ASCII fallback beside
;;; the RFC 2231 value would hide the real name.

(defun %content-type-name (name)
  (if (ascii-p name)
      name
      (let ((words (format nil "~{~a~^ ~}" (encode-header-words name :encoding :b))))
        ;; Too long to stay a quoted string; Content-Disposition still names it.
        (and (<= (length words) 200) words))))

(defun %attachment-part (attachment)
  (let ((name (attachment-filename attachment))
        (type (attachment-content-type attachment)))
    (make-part type
               :params (unless (find #\; type)
                         (list (cons "name" (%content-type-name name))))
               :encoding :base64
               :disposition (if (attachment-inline-p attachment) "inline" "attachment")
               :disposition-params (list (cons "filename" name))
               :content-id (attachment-content-id attachment)
               :body (lambda (buffer)
                       (base64-body-to-buffer (%attachment-octets attachment) buffer)))))

(defun %multipart (subtype children &key type)
  (make-part (format nil "multipart/~a" subtype)
             :params (append (and type (list (cons "type" type)))
                             (list (cons "boundary" (%make-boundary))))
             :children children))

(defun message-mime-structure (message)
  "The root part of MESSAGE's MIME tree."
  (let* ((inline (remove-if-not #'attachment-inline-p (message-attachments message)))
         (html (message-html message))
         (regular (if html
                      (remove-if #'attachment-inline-p (message-attachments message))
                      (message-attachments message)))
         (text-part (and (message-text message) (%text-part (message-text message) "plain")))
         (html-part (and html
                         (if inline
                             (%multipart "related"
                                         (cons (%text-part html "html")
                                               (mapcar #'%attachment-part inline))
                                         :type "text/html")
                             (%text-part html "html"))))
         (body (cond ((and text-part html-part) (%multipart "alternative" (list text-part html-part)))
                     (html-part)
                     (text-part)
                     (t (%text-part "" "plain")))))
    (if regular
        (%multipart "mixed" (cons body (mapcar #'%attachment-part regular)))
        body)))

;;; Rendering

(defun %write-header (buffer name value utf8)
  (let ((line (fold-header name value)))
    (if utf8 (buffer-utf8 buffer line) (buffer-ascii buffer line))
    (buffer-crlf buffer)))

(defun %write-part (part buffer utf8)
  (%write-header buffer "Content-Type" (format-content-header (part-type part) (part-params part)) utf8)
  (when (part-encoding part)
    (%write-header buffer "Content-Transfer-Encoding"
                   (string-downcase (symbol-name (part-encoding part))) utf8))
  (when (part-disposition part)
    (%write-header buffer "Content-Disposition"
                   (format-content-header (part-disposition part) (part-disposition-params part))
                   utf8))
  (when (part-content-id part)
    (%write-header buffer "Content-ID" (format nil "<~a>" (part-content-id part)) utf8))
  (buffer-crlf buffer)
  (if (part-children part)
      (let ((boundary (cdr (assoc "boundary" (part-params part) :test #'string=))))
        (dolist (child (part-children part))
          (buffer-ascii buffer (format nil "--~a" boundary))
          (buffer-crlf buffer)
          (%write-part child buffer utf8)
          (buffer-crlf buffer))
        (buffer-ascii buffer (format nil "--~a--" boundary)))
      (funcall (part-body part) buffer)))

(defun %generate-message-id (from)
  (let ((domain (%ascii-domain (mailbox-domain from))))
    (format nil "<~a@~a>" (random-token 16) domain)))

(defun %address-list (mailboxes utf8)
  (format nil "~{~a~^, ~}" (mapcar (lambda (m) (format-mailbox m :utf8 utf8)) mailboxes)))

(defun %revalidate (message)
  "Re-check slots that may have been changed with the SETF accessors since
MAKE-MESSAGE validated them, so a modified message cannot render unsafely."
  (setf (message-from message) (ensure-mailbox (message-from message))
        (message-sender message) (and (message-sender message)
                                      (ensure-mailbox (message-sender message)))
        (message-to message) (ensure-mailbox-list (message-to message))
        (message-cc message) (ensure-mailbox-list (message-cc message))
        (message-bcc message) (ensure-mailbox-list (message-bcc message))
        (message-reply-to message) (ensure-mailbox-list (message-reply-to message))
        (message-attachments message) (mapcar #'ensure-attachment
                                              (alexandria:ensure-list (message-attachments message))))
  (when (message-subject message)
    (check-type (message-subject message) string))
  (dolist (part (list (message-text message) (message-html message)))
    (when part (check-type part string)))
  (loop for (name . value) in (message-headers message)
        do (%check-header-name name) (%check-header-value name value))
  (when (message-id message)
    (setf (message-id message) (%normalize-msg-id (message-id message) "Message-ID")))
  (setf (message-in-reply-to message) (%msg-id-list (message-in-reply-to message) "In-Reply-To")
        (message-references message) (%msg-id-list (message-references message) "References"))
  (dolist (uri (message-list-unsubscribe message))
    (unless (and (stringp uri) (ascii-p uri)
                 (notany (lambda (c) (or (control-char-p c) (find c "<> "))) uri))
      (error 'invalid-header :name "List-Unsubscribe" :message (format nil "invalid URI ~s" uri)))))

(defun render-message (message &key utf8)
  "Render MESSAGE to an octet vector ready for SMTP DATA (before dot-stuffing).
Returns the octets and, as a second value, whether the message needs
SMTPUTF8 (it contains UTF-8 headers because some address has a non-ASCII
local part, or UTF8 was requested). Bcc recipients are never included.

The Date and Message-ID are fixed on first rendering, so sending the same
message again keeps them."
  (%revalidate message)
  (let* ((utf8 (or utf8 (message-needs-smtputf8-p message)))
         (buffer (make-octet-buffer))
         (date (or (message-date message)
                   (setf (message-date message) (get-universal-time))))
         (id (or (message-id message)
                 (setf (message-id message) (%generate-message-id (message-from message))))))
    (flet ((header (name value) (%write-header buffer name value utf8)))
      (header "Date" (format-rfc5322-date date))
      (header "From" (format-mailbox (message-from message) :utf8 utf8))
      (when (message-sender message)
        (header "Sender" (format-mailbox (message-sender message) :utf8 utf8)))
      (when (message-to message) (header "To" (%address-list (message-to message) utf8)))
      (when (message-cc message) (header "Cc" (%address-list (message-cc message) utf8)))
      (when (message-reply-to message)
        (header "Reply-To" (%address-list (message-reply-to message) utf8)))
      (when (message-subject message)
        (header "Subject" (encode-unstructured (message-subject message) :utf8 utf8 :name "Subject")))
      (header "Message-ID" id)
      (when (message-in-reply-to message)
        (header "In-Reply-To" (format nil "~{~a~^ ~}" (message-in-reply-to message))))
      (when (message-references message)
        (header "References" (format nil "~{~a~^ ~}" (message-references message))))
      (when (message-list-unsubscribe message)
        (header "List-Unsubscribe" (format nil "~{<~a>~^, ~}" (message-list-unsubscribe message)))
        (when (message-list-unsubscribe-post message)
          (header "List-Unsubscribe-Post" "List-Unsubscribe=One-Click")))
      (loop for (name . value) in (message-headers message)
            do (header name (encode-unstructured value :utf8 utf8 :name name)))
      (header "MIME-Version" "1.0"))
    (%write-part (message-mime-structure message) buffer utf8)
    (let ((n (length buffer)))
      (unless (and (>= n 2) (= (aref buffer (- n 2)) 13) (= (aref buffer (- n 1)) 10))
        (buffer-crlf buffer)))
    (values (buffer-octets buffer) utf8)))
