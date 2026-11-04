#lang racket/base

;; SOME/IP message format: the 16 byte header and its payload
;; (AUTOSAR FO, SOME/IP Protocol Specification, chapter 4.1).
;;
;; This module is a pure wire codec. It never touches sockets and never
;; mutates messages, so it is equally usable for online endpoints and
;; offline tooling (log/capture analysis, conformance tests).

(require racket/contract
         racket/format
         "private/bytes.rkt"
         "logging.rkt")

(provide (struct-out exn:fail:someip)
         (struct-out exn:fail:someip:malformed)
         (struct-out someip-message)

         ;; constants
         protocol-version
         sd-service-id
         sd-method-id
         magic-cookie-client-id
         magic-cookie-session-id
         max-udp-payload-size
         tp-max-segment-payload
         (struct-out message-id)
         (struct-out request-id)

         ;; message types
         mt-request mt-request-no-return mt-notification
         mt-response mt-error
         mt-tp-request mt-tp-request-no-return mt-tp-notification
         mt-tp-response mt-tp-error
         message-type-known?
         message-type-has-tp-flag?
         base-message-type
         with-tp-flag
         request-family-message-type?
         response-family-message-type?
         tp-message-type?

         ;; return codes
         rc-e-ok rc-e-not-ok rc-e-unknown-service rc-e-unknown-method
         rc-e-not-ready rc-e-not-reachable rc-e-timeout
         rc-e-wrong-protocol-version rc-e-wrong-interface-version
         rc-e-malformed-message rc-e-wrong-message-type
         rc-e-e2e-repeated rc-e-e2e-wrong-sequence rc-e-e2e
         rc-e-e2e-not-available rc-e-e2e-no-new-data
         return-code-known?

         ;; constructors and predicates
         make-someip-message
         someip-message?
         message-id-value message-id-from-parts
         request-id-value request-id-from-parts
         next-session-id

         ;; codec
         encode-someip-message
         decode-someip-message
         frame-length-at

         ;; magic cookies (TCP stream resync)
         magic-cookie-client->server-bytes
         magic-cookie-server->client-bytes
         magic-cookie-message?)

(module+ test (require rackunit))

;; ------------------------------------------------------------------
;; Errors

(struct exn:fail:someip exn:fail ())
(struct exn:fail:someip:malformed exn:fail:someip ())

(define (malformed fmt . args)
  (raise (exn:fail:someip:malformed (apply format (string-append "someip: " fmt) args)
                                    (current-continuation-marks))))

;; ------------------------------------------------------------------
;; Constants

(define protocol-version 1)

;; SOME/IP-SD rides on the reserved service 0xFFFF (method 0x8100).
(define sd-service-id #xFFFF)
(define sd-method-id  #x8100)

;; Magic cookie Request ID per spec chapter 4.2.1.2.
(define magic-cookie-client-id #xDEAD)
(define magic-cookie-session-id #xBEEF)

;; UDP payloads are limited to 1400 bytes; larger payloads go over TCP or
;; are segmented with SOME/IP-TP, whose aligned segments carry at most
;; 1392 bytes.
(define max-udp-payload-size 1400)
(define tp-max-segment-payload 1392)

;; ------------------------------------------------------------------
;; Message types (Table 4.4) and the TP flag

(define mt-request               #x00)
(define mt-request-no-return     #x01)
(define mt-notification          #x02)
(define mt-response              #x80)
(define mt-error                 #x81)
(define mt-tp-request            #x20)
(define mt-tp-request-no-return  #x21)
(define mt-tp-notification       #x22)
(define mt-tp-response           #xA0)
(define mt-tp-error              #xA1)

(define known-message-types
  (list mt-request mt-request-no-return mt-notification mt-response mt-error
        mt-tp-request mt-tp-request-no-return mt-tp-notification
        mt-tp-response mt-tp-error))

(define (message-type-known? v) (memv v known-message-types))

;; Bit 5 (0x20) marks a SOME/IP-TP segment.
(define tp-flag #x20)

(define (message-type-has-tp-flag? t) (= (bitwise-and t #x20) tp-flag))
(define (tp-message-type? t) (message-type-has-tp-flag? t))

(define (base-message-type t)
  (bitwise-and t (bitwise-not #x20)))

(define (with-tp-flag t)
  (unless (message-type-known? (base-message-type t))
    (raise-argument-error 'with-tp-flag "known message type" t))
  (bitwise-ior t tp-flag))

;; REQUEST/REQUEST_NO_RETURN/NOTIFICATION (0x00/0x01/0x02) vs
;; RESPONSE/ERROR (0x80/0x81).
(define (request-family-message-type? t) (< t #x80))
(define (response-family-message-type? t) (>= t #x80))

;; ------------------------------------------------------------------
;; Return codes (Table 4.11)

(define rc-e-ok                    #x00)
(define rc-e-not-ok                #x01)
(define rc-e-unknown-service       #x02)
(define rc-e-unknown-method        #x03)
(define rc-e-not-ready             #x04)
(define rc-e-not-reachable         #x05)
(define rc-e-timeout               #x06)
(define rc-e-wrong-protocol-version #x07)
(define rc-e-wrong-interface-version #x08)
(define rc-e-malformed-message     #x09)
(define rc-e-wrong-message-type    #x0A)
(define rc-e-e2e-repeated          #x0B)
(define rc-e-e2e-wrong-sequence    #x0C)
(define rc-e-e2e                   #x0D)
(define rc-e-e2e-not-available     #x0E)
(define rc-e-e2e-no-new-data       #x0F)

(define known-return-codes
  (list rc-e-ok rc-e-not-ok rc-e-unknown-service rc-e-unknown-method
        rc-e-not-ready rc-e-not-reachable rc-e-timeout
        rc-e-wrong-protocol-version rc-e-wrong-interface-version
        rc-e-malformed-message rc-e-wrong-message-type
        rc-e-e2e-repeated rc-e-e2e-wrong-sequence rc-e-e2e
        rc-e-e2e-not-available rc-e-e2e-no-new-data))

(define (return-code-known? v) (memv v known-return-codes))

;; ------------------------------------------------------------------
;; Messages

;; `length` is derived from the payload on encode and validated on
;; decode; it counts Request ID + versions + type + return code + payload
;; (i.e. everything after the Length field itself).
(struct someip-message
  (service-id method-id client-id session-id
              protocol-version interface-version
              message-type return-code payload)
  #:transparent
  #:guard
  (lambda (sid mid cid ses pv iv mt rc pl name)
    (unless (exact-nonnegative-integer? sid) (raise-argument-error name "exact-nonnegative-integer?" sid))
    (unless (exact-nonnegative-integer? mid) (raise-argument-error name "exact-nonnegative-integer?" mid))
    (unless (exact-nonnegative-integer? cid) (raise-argument-error name "exact-nonnegative-integer?" cid))
    (unless (exact-nonnegative-integer? ses) (raise-argument-error name "exact-nonnegative-integer?" ses))
    (unless (and (exact-nonnegative-integer? pv) (< pv 256)) (raise-argument-error name "uint8" pv))
    (unless (and (exact-nonnegative-integer? iv) (< iv 256)) (raise-argument-error name "uint8" iv))
    (unless (exact-nonnegative-integer? mt) (raise-argument-error name "exact-nonnegative-integer?" mt))
    (unless (and (exact-nonnegative-integer? rc) (< rc 256)) (raise-argument-error name "uint8" rc))
    (unless (bytes? pl) (raise-argument-error name "bytes" pl))
    (values sid mid cid ses pv iv mt rc pl)))

(define (make-someip-message
         #:service-id service-id
         #:method-id method-id
         #:interface-version interface-version
         #:message-type message-type
         #:client-id [client-id 0]
         #:session-id [session-id 0]
         #:return-code [return-code rc-e-ok]
         #:protocol-version [protocol-version protocol-version]
         #:payload [payload #""])
  (someip-message service-id method-id client-id session-id
                  protocol-version interface-version
                  message-type return-code payload))

(struct message-id (service-id method-id) #:transparent)
(struct request-id (client-id session-id) #:transparent)

(define (message-id-value mid)
  (+ (arithmetic-shift (message-id-service-id mid) 16)
     (message-id-method-id mid)))

(define (message-id-from-parts v)
  (message-id (arithmetic-shift v -16) (bitwise-and v #xFFFF)))

(define (request-id-value rid)
  (+ (arithmetic-shift (request-id-client-id rid) 16)
     (request-id-session-id rid)))

(define (request-id-from-parts v)
  (request-id (arithmetic-shift v -16) (bitwise-and v #xFFFF)))

;; Session IDs live in [0x0001, 0xFFFF] and wrap from 0xFFFF back to 1.
(define (next-session-id sid)
  (let ([n (add1 sid)])
    (if (> n #xFFFF) 1 n)))

;; ------------------------------------------------------------------
;; Encoding

(define message-payload-limit (* 8 (expt 2 32) 4)) ; length field is 32 bit

(define (encode-someip-message m)
  (define pl (someip-message-payload m))
  (define len (+ 8 (bytes-length pl)))
  (when (> len (- (expt 2 32) 1))
    (raise (exn:fail:someip "someip: message exceeds 32 bit length field" (current-continuation-marks))))
  (define c (make-cursor))
  (cur-u32 c (message-id-value
              (message-id (someip-message-service-id m) (someip-message-method-id m))))
  (cur-u32 c len)
  (cur-u32 c (request-id-value
              (request-id (someip-message-client-id m) (someip-message-session-id m))))
  (cur-u8 c (someip-message-protocol-version m))
  (cur-u8 c (someip-message-interface-version m))
  (cur-u8 c (someip-message-message-type m))
  (cur-u8 c (someip-message-return-code m))
  (cur-raw c pl)
  (cursor->bytes c))

;; ------------------------------------------------------------------
;; Decoding

;; Total wire size of the frame starting at `pos`, or #f when fewer than
;; 16 bytes are available (used for TCP stream framing).
(define (frame-length-at bs pos [end (bytes-length bs)])
  (when (> pos end)
    (malformed "frame start ~a beyond end of buffer (~a)" pos end))
  (define avail (- end pos))
  (and (>= avail 16)
       (+ 8 (bytes->u32 bs (+ pos 4)))))

;; Decode one message from `bs` between `start` and `end`. Returns the
;; message and the number of bytes consumed, so callers can decode
;; several packed messages from one datagram or stream chunk.
(define (decode-someip-message bs [start 0] [end (bytes-length bs)])
  (define avail (- end start))
  (when (< avail 16)
    (malformed "need at least 16 bytes for a header, got ~a" avail))
  (define len (bytes->u32 bs (+ start 4)))
  (when (< len 8)
    (malformed "length field ~a is below the header minimum of 8" len))
  (define total (+ 8 len))
  (when (> total avail)
    (malformed "length field ~a exceeds available bytes (~a)" len avail))
  (define sid (bytes->u16 bs start))
  (define mid (bytes->u16 bs (+ start 2)))
  (define cid (bytes->u16 bs (+ start 8)))
  (define ses (bytes->u16 bs (+ start 10)))
  (define pv (bytes-ref bs (+ start 12)))
  (define iv (bytes-ref bs (+ start 13)))
  (define mt (bytes-ref bs (+ start 14)))
  (define rc (bytes-ref bs (+ start 15)))
  (define payload (subbytes bs (+ start 16) (+ start total)))
  (unless (message-type-known? mt)
    (malformed "unknown message type #x~x" mt))
  (values (someip-message sid mid cid ses pv iv mt rc payload)
          total))

;; ------------------------------------------------------------------
;; Magic cookies (may be inserted into TCP streams at regular intervals)

(define (magic-cookie-frame message-type)
  (encode-someip-message
   (make-someip-message
    #:service-id #xFFFF
    #:method-id (if (= message-type mt-request-no-return) #x0000 #x8000)
    #:interface-version 1
    #:message-type message-type
    #:client-id magic-cookie-client-id
    #:session-id magic-cookie-session-id
    #:payload #"")))

;; Wire layout per Figure 4.15: client->server uses message type 0x01,
;; server->client uses 0x02.
(define (magic-cookie-client->server-bytes)
  (magic-cookie-frame mt-request-no-return))

(define (magic-cookie-server->client-bytes)
  (magic-cookie-frame mt-notification))

(define (magic-cookie-message? m)
  (and (= (someip-message-service-id m) #xFFFF)
       (let ([mid (someip-message-method-id m)])
         (or (= mid #x0000) (= mid #x8000)))
       (= (someip-message-client-id m) magic-cookie-client-id)
       (= (someip-message-session-id m) magic-cookie-session-id)
       (= (someip-message-payload-length m) 0)))

(define (someip-message-payload-length m) (bytes-length (someip-message-payload m)))

(provide someip-message-payload-length)

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (check-equal? (encode-someip-message
                 (make-someip-message #:service-id #x0101 #:method-id #x0001
                                      #:interface-version 1
                                      #:message-type mt-request
                                      #:client-id #x0100 #:session-id #x0001
                                      #:payload #"hello"))
                (bytes #x01 #x01 #x00 #x01
                       #x00 #x00 #x00 #x0d
                       #x01 #x00 #x00 #x01
                       #x01 #x01 #x00 #x00
                       104 101 108 108 111))

  (define-values (m n)
    (decode-someip-message
     (encode-someip-message
      (make-someip-message #:service-id #x1234 #:method-id #x8001
                           #:interface-version 2
                           #:message-type mt-notification
                           #:client-id 9 #:session-id 3
                           #:payload (make-bytes 17 7)))))
  (check-equal? n 33)
  (check-equal? (someip-message-service-id m) #x1234)
  (check-equal? (someip-message-method-id m) #x8001)
  (check-equal? (someip-message-client-id m) 9)
  (check-equal? (someip-message-session-id m) 3)
  (check-equal? (someip-message-interface-version m) 2)
  (check-equal? (someip-message-payload m) (make-bytes 17 7))

  ;; several messages packed into one buffer
  (define b1 (encode-someip-message (make-someip-message #:service-id 1 #:method-id 1
                                                         #:interface-version 1 #:message-type mt-request)))
  (define b2 (encode-someip-message (make-someip-message #:service-id 2 #:method-id 2
                                                         #:interface-version 1 #:message-type mt-response)))
  (define packed (bytes-append b1 b2))
  (define-values (m1 n1) (decode-someip-message packed))
  (define-values (m2 n2) (decode-someip-message packed n1))
  (check-equal? (someip-message-service-id m1) 1)
  (check-equal? (someip-message-service-id m2) 2)
  (check-equal? (+ n1 n2) (bytes-length packed))

  ;; malformed: length lies about the remaining bytes
  (define lie (bytes-append (subbytes b1 0 4) (u32->bytes 500) (subbytes b1 8)))
  (check-exn exn:fail:someip:malformed? (lambda () (decode-someip-message lie)))

  ;; malformed: short buffer
  (check-exn exn:fail:someip:malformed? (lambda () (decode-someip-message (make-bytes 5))))

  ;; frame-length-at
  (check-equal? (frame-length-at b1 0) (bytes-length b1))
  (check-false (frame-length-at b1 0 8))
  (check-false (frame-length-at b1 (bytes-length b1)))
  (check-exn exn:fail:someip:malformed?
             (lambda () (frame-length-at b1 (add1 (bytes-length b1)))))

  ;; session wrap
  (check-equal? (next-session-id 1) 2)
  (check-equal? (next-session-id #xFFFF) 1)
  (check-equal? (next-session-id 0) 1)

  ;; TP flag handling
  (check-true (message-type-has-tp-flag? mt-tp-request))
  (check-false (message-type-has-tp-flag? mt-request))
  (check-equal? (base-message-type mt-tp-response) mt-response)
  (check-equal? (with-tp-flag mt-notification) mt-tp-notification)
  (check-exn exn:fail? (lambda () (with-tp-flag #x33)))

  ;; magic cookies per Figure 4.15
  (check-equal? (magic-cookie-client->server-bytes)
                (bytes #xFF #xFF #x00 #x00  #x00 #x00 #x00 #x08
                       #xDE #xAD #xBE #xEF  #x01 #x01 #x01 #x00))
  (check-equal? (magic-cookie-server->client-bytes)
                (bytes #xFF #xFF #x80 #x00  #x00 #x00 #x00 #x08
                       #xDE #xAD #xBE #xEF  #x01 #x01 #x02 #x00)))
