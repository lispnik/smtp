;;; dane.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Matthew Kennedy
;;;
;;; DANE for SMTP (RFC 7672, 7671, 6698): TLSA records published under
;;; DNSSEC authenticate an MX host's certificate. DANE-EE(3) records pin
;;; the server's own certificate or key, ignoring names and dates; DANE-TA(2)
;;; records name a trust anchor that the server's chain must lead to, with
;;; the certificate matching the TLSA base domain or the next-hop domain.
;;; PKIX-TA(0) and PKIX-EE(1) records are unusable for SMTP.

(in-package #:smtp/delivery)

(defstruct (tlsa (:constructor make-tlsa (usage selector matching-type data)))
  "A TLSA record: USAGE 2 (DANE-TA) or 3 (DANE-EE), SELECTOR 0 (whole
certificate) or 1 (public key), MATCHING-TYPE 0 (exact), 1 (SHA-256) or 2
(SHA-512), and the association DATA."
  usage selector matching-type data)

(defun tlsa-usable-p (record)
  (and (member (tlsa-usage record) '(2 3))
       (member (tlsa-selector record) '(0 1))
       (member (tlsa-matching-type record) '(0 1 2))
       ;; A digest of the wrong length can never match.
       (case (tlsa-matching-type record)
         (1 (= (length (tlsa-data record)) 32))
         (2 (= (length (tlsa-data record)) 64))
         (t (plusp (length (tlsa-data record)))))))

;;; Just enough DER to find a certificate's SubjectPublicKeyInfo.

(defun %der-element (octets pos)
  "The tag at POS, and the start and end of its contents."
  (let ((n (length octets)))
    (when (>= (1+ pos) n) (error 'smtp-tls-error :message "Malformed certificate"))
    (let ((tag (aref octets pos))
          (len (aref octets (1+ pos)))
          (start (+ pos 2)))
      (when (> len #x80)
        (let ((count (- len #x80)))
          (when (or (> count 4) (> (+ start count) n))
            (error 'smtp-tls-error :message "Malformed certificate"))
          (setf len (loop with v = 0 for i from start below (+ start count)
                          do (setf v (+ (ash v 8) (aref octets i)))
                          finally (return v))
                start (+ start count))))
      (when (or (= len #x80) (> (+ start len) n))
        (error 'smtp-tls-error :message "Malformed certificate"))
      (values tag start (+ start len)))))

(defun certificate-spki (der)
  "The DER SubjectPublicKeyInfo of the DER certificate."
  (multiple-value-bind (tag start) (%der-element der 0)
    (unless (= tag #x30) (error 'smtp-tls-error :message "Malformed certificate"))
    (multiple-value-bind (tag tbs) (%der-element der start)
      (unless (= tag #x30) (error 'smtp-tls-error :message "Malformed certificate"))
      (let ((pos tbs))
        ;; [0] version (optional), serial, signature, issuer, validity, subject
        (when (= (aref der pos) #xa0)
          (setf pos (nth-value 2 (%der-element der pos))))
        (dotimes (i 5)
          (setf pos (nth-value 2 (%der-element der pos))))
        (multiple-value-bind (tag start end) (%der-element der pos)
          (declare (ignore start))
          (unless (= tag #x30) (error 'smtp-tls-error :message "Malformed certificate"))
          (subseq der pos end))))))

(defun tlsa-matches-p (record der)
  "Whether the DER certificate matches RECORD's selector and data."
  (let* ((selected (ecase (tlsa-selector record)
                     (0 der)
                     (1 (certificate-spki der))))
         (digest (ecase (tlsa-matching-type record)
                   (0 selected)
                   (1 (ironclad:digest-sequence :sha256 selected))
                   (2 (ironclad:digest-sequence :sha512 selected)))))
    (equalp digest (tlsa-data record))))

(defun make-dane-verifier (records reference-names)
  "A function for OPEN-CONNECTION's :VERIFY that authenticates the server
with the usable TLSA RECORDS. REFERENCE-NAMES are the names a DANE-TA
certificate may match: the TLSA base domain and the next-hop domain. With
no usable records TLS is still required, unauthenticated (RFC 7672 2.2)."
  (let ((usable (remove-if-not #'tlsa-usable-p records)))
    (lambda (backend stream)
      (block verify
       (when usable
        (let ((chain (tls-peer-certificates backend stream))
              (errors '()))
          (unless chain
            (error 'smtp-tls-error :message "The server presented no certificate"))
          (dolist (record usable)
            (handler-case
                (ecase (tlsa-usage record)
                  (3 (when (tlsa-matches-p record (first chain))
                       (return-from verify t)))
                  (2 (let ((anchor
                             (or (find-if (lambda (der) (tlsa-matches-p record der)) (rest chain))
                                 ;; A full certificate in the record is itself the anchor.
                                 (and (= (tlsa-selector record) 0) (= (tlsa-matching-type record) 0)
                                      (tlsa-data record)))))
                       (when anchor
                         (tls-verify-chain backend chain anchor :hostnames reference-names)
                         (return-from verify t)))))
              (smtp-error (e) (push e errors))))
          (error 'smtp-tls-error
                 :message (format nil "DANE authentication failed: no TLSA record matches the ~
                                       server's certificate~@[ (~a)~]"
                                  (first errors)))))))))
