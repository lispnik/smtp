;;; message.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy

(in-package #:smtp/test)

(def-suite :smtp/message :in :smtp :description "Message construction and rendering.")
(in-suite :smtp/message)

;;; A small MIME reader, so that tests check what a recipient would see.

(defstruct entity headers body parts)

(defun %unfold-headers (lines)
  (let ((out '()))
    (dolist (l lines (nreverse out))
      (if (and out (plusp (length l)) (member (char l 0) '(#\Space #\Tab)))
          (setf (car out) (concatenate 'string (car out) l))
          (push l out)))))

(defun header (entity name)
  (cdr (assoc name (entity-headers entity) :test #'string-equal)))

(defun %param (value name)
  (let ((pos (search (format nil "~a=" name) value :test #'char-equal)))
    (when pos
      (let ((start (+ pos (length name) 1)))
        (if (char= (char value start) #\")
            (subseq value (1+ start) (position #\" value :start (1+ start)))
            (subseq value start (or (position #\; value :start start) (length value))))))))

(defun parse-entity (string)
  "Parse STRING (CRLF lines) into an entity tree."
  (let* ((sep (search (crlf "" "" "") string))
         (head (subseq string 0 (or sep (length string))))
         (body (if sep (subseq string (+ sep 4)) ""))
         (headers (mapcar (lambda (l)
                            (let ((colon (position #\: l)))
                              (cons (subseq l 0 colon)
                                    (string-trim " " (subseq l (1+ colon))))))
                          (%unfold-headers (lines-of head))))
         (entity (make-entity :headers headers :body body))
         (type (or (cdr (assoc "Content-Type" headers :test #'string-equal)) "text/plain")))
    (when (string-prefix-p "multipart/" (string-downcase type))
      (let* ((boundary (%param type "boundary"))
             (delimiter (format nil "--~a" boundary))
             (lines (lines-of body))
             (parts '()) (current '()) (in-part nil))
        (dolist (l lines)
          (cond ((string= l (format nil "~a--" delimiter))
                 (when in-part (push (reverse current) parts))
                 (return))
                ((string= l delimiter)
                 (when in-part (push (reverse current) parts))
                 (setf current '() in-part t))
                (in-part (push l current))))
        (setf (entity-parts entity)
              (mapcar (lambda (ls) (parse-entity (format nil "~{~a~^~c~c~}"
                                                         (loop for (l . more) on ls
                                                               collect l
                                                               when more collect #\Return
                                                               and collect #\Linefeed))))
                      (nreverse parts)))))
    entity))

(defun decoded-body (entity)
  "ENTITY's body decoded per its Content-Transfer-Encoding, as octets."
  (let ((cte (string-downcase (or (header entity "Content-Transfer-Encoding") "7bit")))
        (body (entity-body entity)))
    (cond ((string= cte "base64") (base64-decode body))
          ((string= cte "quoted-printable") (quoted-printable-decode body))
          (t (octets body)))))

(defun render (message)
  (text (render-message message)))

(defun parse (message)
  (parse-entity (render message)))

(defun type-of-entity (entity)
  (string-downcase (subseq (header entity "Content-Type") 0
                           (or (position #\; (header entity "Content-Type"))
                               (length (header entity "Content-Type"))))))

(defun body= (expected-text decoded)
  "Whether DECODED is EXPECTED-TEXT's octets, allowing for the CRLF added to
end a message that did not end with one."
  (let ((expected (octets expected-text)))
    (or (equalp expected decoded)
        (equalp (concatenate '(vector (unsigned-byte 8)) expected #(13 10)) decoded))))

;;; Tests

(test rendered-message-is-well-formed
  (let* ((m (make-message :from "Alice <alice@example.com>"
                          :to '("bob@example.net" "Carol <carol@example.org>")
                          :cc "dave@example.com"
                          :bcc "secret@example.com"
                          :subject "Quarterly report"
                          :text (format nil "Hello,~%~%.~%A line.~%")))
         (octets (render-message m))
         (string (text octets))
         (e (parse-entity string)))
    (is (every (lambda (o) (< o 128)) octets))
    (is (every (lambda (l) (<= (length l) 78)) (lines-of string)))
    (is (string= "Alice <alice@example.com>" (header e "From")))
    (is (string= "bob@example.net, Carol <carol@example.org>" (header e "To")))
    (is (string= "dave@example.com" (header e "Cc")))
    (is (null (header e "Bcc")))
    (is (null (search "secret@example.com" string)))
    (is (string= "1.0" (header e "MIME-Version")))
    (is (header e "Date"))
    (is (string-prefix-p "<" (header e "Message-ID")))
    (is (string= "7bit" (header e "Content-Transfer-Encoding")))
    (is (equalp (octets (crlf "Hello," "" "." "A line." "")) (decoded-body e)))
    (is (= 4 (length (message-envelope-recipients m))))))

(test message-id-and-date-are-stable
  (let* ((m (simple-message))
         (first (parse m))
         (second (parse m))
         (other (parse (simple-message))))
    (is (string= (header first "Message-ID") (header second "Message-ID")))
    (is (string= (header first "Date") (header second "Date")))
    (is (string/= (header first "Message-ID") (header other "Message-ID")))
    (is (search "@example.com>" (header first "Message-ID")))))

(test transfer-encoding-choice
  (flet ((cte (text) (header (parse (simple-message :text text)) "Content-Transfer-Encoding")))
    (is (string= "7bit" (cte "plain ascii")))
    (is (string= "quoted-printable" (cte "Grüße aus München")))
    (is (string= "base64" (cte "日本語のメッセージです")))
    (is (string= "quoted-printable" (cte (make-string 2000 :initial-element #\a))))
    (is (string= "quoted-printable" (cte (format nil "nul~cbyte" (code-char 0)))))))

(test long-html-lines-are-wrapped
  (let* ((html (format nil "<p>~{~a~}</p>" (make-list 500 :initial-element "word ")))
         (string (render (simple-message :html html))))
    (is (every (lambda (l) (<= (length l) 78)) (lines-of string)))))

(test text-and-html-alternative
  (let* ((e (parse (simple-message :text "plain" :html "<p>html</p>"))))
    (is (string= "multipart/alternative" (type-of-entity e)))
    (is (equal '("text/plain" "text/html") (mapcar #'type-of-entity (entity-parts e))))
    (is (string= "plain" (text (decoded-body (first (entity-parts e))))))
    (is (string= "<p>html</p>" (text (decoded-body (second (entity-parts e))))))))

(test attachments-and-inline-images
  (let* ((data (coerce (loop for i below 1000 collect (mod (* i 7) 256)) '(vector (unsigned-byte 8))))
         (logo (make-attachment data :filename "logo.png" :inline t :content-id "logo@example"))
         (pdf (make-attachment data :filename "résumé.pdf"))
         (e (parse (simple-message :text "plain" :html "<img src=\"cid:logo@example\">"
                                   :attachments (list logo pdf)))))
    (is (string= "multipart/mixed" (type-of-entity e)))
    (destructuring-bind (body attachment) (entity-parts e)
      (is (string= "multipart/alternative" (type-of-entity body)))
      (let ((related (second (entity-parts body))))
        (is (string= "multipart/related" (type-of-entity related)))
        (let ((image (second (entity-parts related))))
          (is (string= "image/png" (type-of-entity image)))
          (is (string= "<logo@example>" (header image "Content-ID")))
          (is (string-prefix-p "inline" (header image "Content-Disposition")))
          (is (equalp data (decoded-body image)))))
      (is (string= "application/pdf" (type-of-entity attachment)))
      (is (search "filename*=UTF-8''r%C3%A9sum%C3%A9.pdf" (header attachment "Content-Disposition")))
      (is (search "filename=r_sum_.pdf;" (header attachment "Content-Disposition")))
      (is (equalp data (decoded-body attachment))))))

(test attachment-from-file
  (let* ((path (fixture "ca.pem"))
         (e (parse (simple-message :attachments (list path)))))
    (let ((part (second (entity-parts e))))
      (is (search "ca.pem" (header part "Content-Disposition")))
      (is (equalp (alexandria:read-file-into-byte-vector path) (decoded-body part)))))
  (signals mail-format-error (make-attachment #p"/nonexistent/file.pdf"))
  (signals mail-format-error (make-attachment (make-array 3 :element-type '(unsigned-byte 8))))
  (is (string= "passwd" (attachment-filename
                         (make-attachment (make-array 1 :element-type '(unsigned-byte 8))
                                          :filename "../../etc/passwd")))))

(test non-ascii-headers-are-encoded
  (let* ((m (make-message :from (make-mailbox "rene@example.com" "René")
                          :to "bob@bücher.example"
                          :subject "Grüße – a long subject line that will need folding because it goes on and on"
                          :text "x"))
         (octets (render-message m))
         (e (parse-entity (text octets))))
    (is (every (lambda (o) (< o 128)) octets))
    (is (string= "bob@xn--bcher-kva.example" (header e "To")))
    (is (string= "Grüße – a long subject line that will need folding because it goes on and on"
                 (format nil "~{~a~}" (mapcar #'decode-encoded-word
                                              (remove "" (uiop:split-string (header e "Subject") :separator " ")
                                                      :test #'string=)))))))

(test smtputf8-messages-use-utf8-headers
  (multiple-value-bind (octets utf8)
      (render-message (make-message :from "用户@例え.テスト" :to "bob@example.net"
                                     :subject "件名" :text "本文"))
    (is-true utf8)
    (let ((e (parse-entity (text octets))))
      (is (string= "件名" (header e "Subject")))
      (is (string= "用户@xn--r8jz45g.xn--zckzah" (header e "From"))))))

(test header-injection-is-impossible
  (signals invalid-header (simple-message :subject (format nil "Hi~c~cBcc: victim@example.com" #\Return #\Linefeed)))
  (signals invalid-header (simple-message :subject (format nil "Hi~cBcc: victim@example.com" #\Linefeed)))
  (signals invalid-header (simple-message :headers (list (cons "X-Tag" (format nil "a~cb" #\Linefeed)))))
  (signals invalid-header (simple-message :headers '(("X Bad" . "v"))))
  (signals invalid-header (simple-message :headers '(("X-Bad:" . "v"))))
  (signals invalid-header (simple-message :headers '(("bcc" . "victim@example.com"))))
  (signals invalid-header (simple-message :headers '(("Content-Type" . "text/html"))))
  (signals invalid-address (simple-message :reply-to (format nil "a@example.com~cBcc: v@example.com" #\Return)))
  (signals invalid-header (simple-message :message-id "<a b@example.com>"))
  (signals invalid-header (make-attachment (make-array 1 :element-type '(unsigned-byte 8))
                                           :filename "x" :content-type (format nil "text/plain~c~cX: y" #\Return #\Linefeed))))

(test custom-headers-and-threading
  (let ((e (parse (simple-message :headers '(("X-Campaign" . "spring") ("X-Note" . "naïve"))
                                  :message-id "abc@example.com"
                                  :in-reply-to "<parent@example.com>"
                                  :references '("root@example.com" "<parent@example.com>")))))
    (is (string= "spring" (header e "X-Campaign")))
    (is (string-prefix-p "=?UTF-8?" (header e "X-Note")))
    (is (string= "<abc@example.com>" (header e "Message-ID")))
    (is (string= "<parent@example.com>" (header e "In-Reply-To")))
    (is (string= "<root@example.com> <parent@example.com>" (header e "References")))))

(test list-unsubscribe
  (let ((e (parse (simple-message :list-unsubscribe '("https://example.com/u/1" "mailto:u@example.com")
                                  :list-unsubscribe-post t))))
    (is (string= "<https://example.com/u/1>, <mailto:u@example.com>" (header e "List-Unsubscribe")))
    (is (string= "List-Unsubscribe=One-Click" (header e "List-Unsubscribe-Post"))))
  (signals invalid-header (simple-message :list-unsubscribe "mailto:u@example.com" :list-unsubscribe-post t)))

(test message-property-well-formed
  ;; Whatever text goes in, the rendering is 7-bit, CRLF-only, within line
  ;; limits, and the text comes back out.
  (dotimes (i 100)
    (let* ((body (random-string (random 3000)))
           (subject (remove-if (lambda (c) (member c '(#\Return #\Newline #\Tab))) (random-string (random 120))))
           (octets (render-message (simple-message :text body :subject subject)))
           (string (text octets))
           (e (parse-entity string)))
      (is (every (lambda (o) (< o 128)) octets))
      (is (every (lambda (l) (<= (length l) 998)) (lines-of string)))
      (is (body= (canonical body) (decoded-body e))))))

;;; Regressions from review

(test setf-cannot-bypass-validation
  (let ((m (simple-message)))
    (setf (message-headers m) (list (cons (format nil "X-A: 1~c~cBcc" #\Return #\Linefeed) "evil@x.com")))
    (signals invalid-header (render-message m)))
  (let ((m (simple-message)))
    (setf (message-subject m) (format nil "a~cb" (code-char 0)))
    (signals invalid-header (render-message m)))
  (let ((m (simple-message)))
    (setf (message-to m) (format nil "a@example.com~cBcc: x@evil.com" #\Linefeed))
    (signals invalid-address (render-message m)))
  (let ((m (simple-message)))
    (setf (message-headers m) '(("Content-Type" . "text/html")))
    (signals invalid-header (render-message m))))

(test encoded-word-lines-fit
  (dotimes (i 200)
    (let* ((name (remove-if (lambda (c) (member c '(#\Return #\Newline #\Tab))) (random-string (1+ (random 60)))))
           (string (render (simple-message :subject name
                                           :to (list (make-mailbox "a@example.com" name)
                                                     (make-mailbox "b@example.com" name))))))
      (dolist (line (lines-of string))
        (when (search "=?" line)
          (is (<= (length line) 76) "~s" line))))))

(test list-unsubscribe-is-not-encoded
  (let ((e (parse (simple-message :list-unsubscribe "https://x.example/u?a=?b"))))
    (is (string= "<https://x.example/u?a=?b>" (header e "List-Unsubscribe"))))
  (signals invalid-header (simple-message :list-unsubscribe "https://x.example/ü")))

(test attachment-content-types
  (flet ((att (type) (make-attachment (make-array 1 :element-type '(unsigned-byte 8))
                                      :filename "x.bin" :content-type type)))
    (is (att "text/plain; charset=utf-8"))
    (is (att "application/x-thing; name=\"a b\"; v=1"))
    (signals invalid-header (att "text/plain; charset=é"))
    (signals invalid-header (att "text/plain; charset=\"unterminated"))
    (signals invalid-header (att "text/plain; junk"))
    (signals invalid-header (att "multipart/mixed"))
    (signals invalid-header (att "message/rfc822"))))

(test long-ascii-filenames
  (let* ((name (concatenate 'string (make-string 1200 :initial-element #\a) ".txt"))
         (string (render (simple-message :attachments (list (make-attachment (make-array 3 :element-type '(unsigned-byte 8) :initial-element 65) :filename name))))))
    (is (every (lambda (l) (<= (length l) 998)) (lines-of string)))
    (is (search "filename*0=" string))))

(test related-has-type
  (let* ((img (make-attachment (make-array 3 :element-type '(unsigned-byte 8)) :filename "a.png" :inline t))
         (e (parse (simple-message :html "<img src=cid:x>" :attachments (list img)))))
    (is (search "type=\"text/html\"" (header (second (entity-parts e)) "Content-Type")))))
