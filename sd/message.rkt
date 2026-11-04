#lang racket/base

;; SOME/IP-SD wire format: SD header (flags), entries and options
;; (AUTOSAR FO, SOME/IP-SD Protocol Specification, chapter 5.1.2).
;;
;; Implemented wire rules:
;;   [00220] SD runs over UDP only
;;   [00251] SD payload: flags (8 bit), reserved (24 bit), entries array
;;           length + array, options array length + array
;;   [00254] flag bit 7 (highest) = Reboot Flag, [00259] bit 6 = Unicast
;;   [00258] reboot detection from (reboot flag, session id) pairs
;;   [00151]-[00164] SD Message ID 0xFFFF8100, type 0x02, return code 0,
;;           client id 0, Session ID starts at 1 and wraps back to 1
;;   [00268] service entries are 16 bytes: type, two option run indexes,
;;           two run lengths, Service ID, Instance ID, Major Version,
;;           TTL, Minor Version
;;   [00270] eventgroup entries are 16 bytes: same head, then
;;           reserved [12 bit], counter [4 bit], Eventgroup ID [16 bit]
;;   [00268]/[00270]/[00386]: entry types 0x00 find, 0x01 offer
;;           (TTL 0 = stop offer), 0x06 subscribe (TTL 0 = stop
;;           subscribe), 0x07 subscribe ack (TTL 0 = nack)
;;   [00273] every option starts with length (16 bit), type (8 bit),
;;           discardable flag (bit 7 of the next byte)
;;   [00276] configuration option: type 0x01, u8-length-prefixed
;;           key=value strings, zero length terminates
;;   [00542] load balancing option: type 0x02, priority + weight
;;   [00305] IPv4 endpoint option: type 0x04
;;   [00314] IPv6 endpoint option: type 0x06
;;   [00323] IPv4 multicast option: type 0x14
;;   [00331] IPv6 multicast option: type 0x16
;;   [00550] IPv4 SD endpoint option: type 0x24
;;   [00557] IPv6 SD endpoint option: type 0x26
;;   option length counts everything except itself and the type byte
;;   [00841] entries of unknown type are ignored on receive
;;   [00343]/[00834] empty option runs are accepted
;;
;; The spec's Table 5.2 lists 0x02/0x03 for subscribe entries, which
;; contradicts the normative field definitions ([00270], [00386]: 0x06 /
;; 0x07) and every deployed stack; 0x06/0x07 is implemented here.

(require racket/contract
         racket/format
         racket/match
         racket/string
         racket/list
         "../message.rkt"
         "../private/bytes.rkt"
         "../logging.rkt")

(provide sd-port
         ttl-infinite
         (struct-out sd-packet)
         (struct-out sd-service-entry)
         (struct-out sd-eventgroup-entry)
         (struct-out sd-config-option)
         (struct-out sd-load-balance-option)
         (struct-out sd-endpoint-option)
         (struct-out sd-raw-option)

         sd-entry-find sd-entry-offer sd-entry-subscribe sd-entry-ack
         entry-type-stop?
         l4-protocol-code l4-protocol-name

         find-service-entry
         offer-service-entry
         stop-offer-service-entry
         subscribe-eventgroup-entry
         stop-subscribe-eventgroup-entry
         subscribe-ack-entry
         subscribe-nack-entry

         encode-sd-packet
         decode-sd-payload
         decode-sd-message
         sd-option-count

         ipv4->bytes bytes->ipv4
         ipv6->bytes bytes->ipv6)

(module+ test (require rackunit racket/list))

;; ------------------------------------------------------------------
;; Constants

;; Default SD port ([00600] SD_PORT).
(define sd-port 30490)

;; TTL value meaning "valid until the next reboot".
(define ttl-infinite #xFFFFFF)

(define sd-entry-find      #x00)
(define sd-entry-offer     #x01)
(define sd-entry-subscribe #x06)
(define sd-entry-ack       #x07)

;; Stop variants share the type code and are signalled by TTL = 0.
(define (entry-type-stop? e)
  (zero? (if (sd-service-entry? e)
             (sd-service-entry-ttl e)
             (sd-eventgroup-entry-ttl e))))

(define (l4-protocol-code p)
  (case p [(udp) #x11] [(tcp) #x06]
    [else (raise-argument-error 'l4-protocol-code "'udp or 'tcp" p)]))

(define (l4-protocol-name c)
  (case c [(#x11) 'udp] [(#x06) 'tcp]
    [else (raise-argument-error 'l4-protocol-name "UDP/TCP code" c)]))

;; ------------------------------------------------------------------
;; Data model

(struct sd-packet (reboot? unicast? entries options) #:transparent)

;; option-runs: (list run1 run2), each a list of options; the encoder
;; assigns indexes into the packet's shared option array.
(struct sd-service-entry (type service-id instance-id
                          major-version minor-version ttl
                          option-runs) #:transparent)
(struct sd-eventgroup-entry (type service-id instance-id
                             major-version ttl counter
                             eventgroup-id
                             option-runs) #:transparent)

(struct sd-config-option (items discardable?) #:transparent)
;; items: list of (cons key (or/c string? #f)); duplicate keys allowed
(struct sd-load-balance-option (priority weight discardable?) #:transparent)
(struct sd-endpoint-option (kind family address port protocol discardable?) #:transparent)
;; kind: 'endpoint 'multicast 'sd-endpoint; family: 'ipv4 'ipv6
(struct sd-raw-option (type bytes) #:transparent)

(define (sd-option? v)
  (or (sd-config-option? v) (sd-load-balance-option? v)
      (sd-endpoint-option? v) (sd-raw-option? v)))

;; ------------------------------------------------------------------
;; Entry constructors (spec section 5.1.2.5 defaults)

;; [00351]: any instance / any version find.
(define (find-service-entry #:service-id service-id
                            #:instance-id [instance-id #xFFFF]
                            #:major-version [major-version #xFF]
                            #:minor-version [minor-version #xFFFFFFFF])
  (sd-service-entry sd-entry-find service-id instance-id
                    major-version minor-version 0 ; TTL ignored for find
                    (list '() '())))

;; [00356]: TTL 0xFFFFFF is valid until the next reboot; [00357]
;; endpoint options signal reachability.
(define (offer-service-entry #:service-id service-id
                             #:instance-id instance-id
                             #:major-version major-version
                             #:minor-version minor-version
                             #:ttl [ttl ttl-infinite]
                             #:udp-endpoint [udp-endpoint #f]
                             #:tcp-endpoint [tcp-endpoint #f]
                             #:extra-options [extra '()])
  (define opts (append (filter values (list udp-endpoint tcp-endpoint)) extra))
  (sd-service-entry sd-entry-offer service-id instance-id
                    major-version minor-version ttl
                    (list opts '())))

;; [00364]: identical fields to the offer, TTL 0; [00840] same options.
(define (stop-offer-service-entry #:service-id service-id
                                  #:instance-id instance-id
                                  #:major-version major-version
                                  #:minor-version minor-version
                                  #:udp-endpoint [udp-endpoint #f]
                                  #:tcp-endpoint [tcp-endpoint #f]
                                  #:extra-options [extra '()])
  (struct-copy sd-service-entry
               (offer-service-entry #:service-id service-id
                                    #:instance-id instance-id
                                    #:major-version major-version
                                    #:minor-version minor-version
                                    #:udp-endpoint udp-endpoint
                                    #:tcp-endpoint tcp-endpoint
                                    #:extra-options extra)
               [ttl 0]))

;; [00386]: subscribe with lifetime; counter differentiates identical
;; subscriptions of the same subscriber; first run = client endpoints,
;; second run = client multicast option + extras.
(define (subscribe-eventgroup-entry #:service-id service-id
                                    #:instance-id instance-id
                                    #:major-version major-version
                                    #:eventgroup-id eventgroup-id
                                    #:ttl [ttl ttl-infinite]
                                    #:counter [counter 0]
                                    #:client-endpoints [endpoints '()]
                                    #:multicast-option [multicast #f]
                                    #:extra-options [extra '()])
  (when (> counter 15)
    (raise-argument-error 'subscribe-eventgroup-entry "4 bit counter" counter))
  (sd-eventgroup-entry sd-entry-subscribe service-id instance-id
                       major-version ttl counter eventgroup-id
                       (list endpoints
                             (append (if multicast (list multicast) '()) extra))))

(define (stop-subscribe-eventgroup-entry #:service-id service-id
                                         #:instance-id instance-id
                                         #:major-version major-version
                                         #:eventgroup-id eventgroup-id
                                         #:counter [counter 0]
                                         #:client-endpoints [endpoints '()]
                                         #:multicast-option [multicast #f]
                                         #:extra-options [extra '()])
  (struct-copy sd-eventgroup-entry
               (subscribe-eventgroup-entry #:service-id service-id
                                           #:instance-id instance-id
                                           #:major-version major-version
                                           #:eventgroup-id eventgroup-id
                                           #:counter counter
                                           #:client-endpoints endpoints
                                           #:multicast-option multicast
                                           #:extra-options extra)
               [ttl 0]))

;; [00487]: the ack may reference up to one multicast option.
(define (subscribe-ack-entry #:service-id service-id
                             #:instance-id instance-id
                             #:major-version major-version
                             #:eventgroup-id eventgroup-id
                             #:ttl [ttl ttl-infinite]
                             #:counter [counter 0]
                             #:multicast-option [multicast #f])
  (when (> counter 15)
    (raise-argument-error 'subscribe-ack-entry "4 bit counter" counter))
  (sd-eventgroup-entry sd-entry-ack service-id instance-id
                       major-version ttl counter eventgroup-id
                       (list '() (if multicast (list multicast) '()))))

(define (subscribe-nack-entry #:service-id service-id
                              #:instance-id instance-id
                              #:major-version major-version
                              #:eventgroup-id eventgroup-id
                              #:counter [counter 0])
  (struct-copy sd-eventgroup-entry
               (subscribe-ack-entry #:service-id service-id
                                    #:instance-id instance-id
                                    #:major-version major-version
                                    #:eventgroup-id eventgroup-id
                                    #:counter counter)
               [ttl 0]))

;; ------------------------------------------------------------------
;; Address helpers

(define (ipv4->bytes s)
  (unless (string? s) (raise-argument-error 'ipv4->bytes "string?" s))
  (define parts (string-split s "."))
  (unless (= (length parts) 4)
    (raise-argument-error 'ipv4->bytes "dotted quad" s))
  (apply
   bytes
   (for/list ([p parts])
     (define v (string->number p))
     (unless (and v (exact-nonnegative-integer? v) (< v 256))
       (raise-argument-error 'ipv4->bytes "dotted quad" s))
     v)))

(define (bytes->ipv4 bs [off 0])
  (string-join (for/list ([i 4]) (~a (bytes-ref bs (+ off i)))) "."))

;; Minimal RFC 4291 parser: groups of 1-4 hex digits, one "::" allowed,
;; optional embedded IPv4 tail.
(define (ipv6->bytes s)
  (unless (string? s) (raise-argument-error 'ipv6->bytes "string?" s))
  (define groups (make-vector 8 0))
  (define (parse-groups str start)
    ;; returns number of groups written
    (define chunks (string-split str ":"))
    (define pos
      (for/fold ([pos start])
                ([i (in-naturals)] [c chunks])
        (cond
          [(string-contains? c ".")
           (unless (<= pos 6)
             (raise-argument-error 'ipv6->bytes "IPv4 tail out of place" s))
           (define b (ipv4->bytes c))
           (vector-set! groups pos (+ (* (bytes-ref b 0) 256) (bytes-ref b 1)))
           (vector-set! groups (add1 pos) (+ (* (bytes-ref b 2) 256) (bytes-ref b 3)))
           (+ pos 2)]
          [else
           (define n (string->number c 16))
           (unless (and n (exact-nonnegative-integer? n) (< n 65536)
                        (<= (string-length c) 4) (positive? (string-length c)))
             (raise-argument-error 'ipv6->bytes "valid IPv6 group" c))
           (vector-set! groups pos n)
           (add1 pos)])))
    (- pos start))
  (define parts (string-split s "::" #:trim? #f))
  (unless (<= (length parts) 2)
    (raise-argument-error 'ipv6->bytes "valid IPv6 address" s))
  (match parts
    ;; no "::": exactly 8 groups
    [(list one)
     (unless (= (parse-groups one 0) 8)
       (raise-argument-error 'ipv6->bytes "expected 8 groups" s))]
    ;; leading "::": tail fills the last groups
    [(list "" tail)
     (define t (count-groups tail))
     (unless (<= 1 t 8)
       (raise-argument-error 'ipv6->bytes "expected groups after ::" s))
     (parse-groups tail (- 8 t))]
    ;; trailing "::": leading groups, rest zero
    [(list head "")
     (define h (parse-groups head 0))
     (unless (< h 8)
       (raise-argument-error 'ipv6->bytes "too many groups before ::" s))]
    ;; "::" in the middle
    [(list head tail)
     (define h (parse-groups head 0))
     (define t (count-groups tail))
     (unless (< (+ h t) 8)
       (raise-argument-error 'ipv6->bytes ":: must compress at least one group" s))
     (parse-groups tail (- 8 t))])
  (apply bytes-append
         (for/list ([g (in-vector groups)])
           (bytes (arithmetic-shift g -8) (bitwise-and g #xFF)))))

(define (count-groups str)
  (for/sum ([c (in-list (string-split str ":"))])
    (if (string-contains? c ".") 2 1)))

;; Decoded addresses are rendered uncompressed but valid: 8 lowercase
;; groups.
(define (bytes->ipv6 bs [off 0])
  (string-join
   (for/list ([i 8])
     (define v (bytes->u16 bs (+ off (* 2 i))))
     (define s (number->string v 16))
     (string-append (make-string (- 4 (string-length s)) #\0) s))
   ":"))

;; ------------------------------------------------------------------
;; Encoding

(define (encode-sd-packet pkt
                          #:session-id [session-id 1]
                          #:client-id [client-id 0])
  (unless (sd-packet? pkt)
    (raise-argument-error 'encode-sd-packet "sd-packet?" pkt))
  (define entries (sd-packet-entries pkt))
  ;; options referenced by entries, plus unreferenced packet options
  ;; (e.g. SD endpoint options, which must not be referenced by entries
  ;; [00548]/[00555]), deduplicated in first-occurrence order
  (define all-options
    (let ([seen (make-hash)])
      (reverse
       (for/fold ([acc '()])
                 ([o (append (collect-options entries) (sd-packet-options pkt))])
         (if (hash-has-key? seen o)
             acc
             (begin (hash-set! seen o #t) (cons o acc)))))))
  (define option-indices (make-hash)) ; option -> index in the array
  (for ([o all-options] [i (in-naturals)])
    (hash-set! option-indices o i))
  (define entries-bytes
    (apply bytes-append
           (for/list ([e entries]) (encode-entry e option-indices))))
  (define options-bytes
    (apply bytes-append
           (for/list ([o all-options])
             (encode-option o))))
  (define c (make-cursor))
  (cur-u8 c (+ (if (sd-packet-reboot? pkt) #x80 0)
               (if (sd-packet-unicast? pkt) #x40 0)))
  (cur-fill c 3) ; reserved
  (cur-u32 c (bytes-length entries-bytes))
  (cur-raw c entries-bytes)
  (cur-u32 c (bytes-length options-bytes))
  (cur-raw c options-bytes)
  (encode-someip-message
   (make-someip-message
    #:service-id sd-service-id
    #:method-id sd-method-id
    #:interface-version 1
    #:message-type mt-notification
    #:client-id client-id
    #:session-id session-id
    #:payload (cursor->bytes c))))

;; Flatten entries' option runs into one array so several entries can
;; share a single option instance.
(define (collect-options entries)
  (define seen (make-hash))
  (reverse
   (for/fold ([acc '()])
             ([e entries])
     (for/fold ([acc acc])
               ([run (entry-runs e)])
       (for/fold ([acc acc])
                 ([o run])
         (if (hash-has-key? seen o)
             acc
             (begin (hash-set! seen o #t)
                    (cons o acc))))))))

(define (entry-runs e)
  (if (sd-service-entry? e)
      (sd-service-entry-option-runs e)
      (sd-eventgroup-entry-option-runs e)))

(define (encode-entry e option-indices)
  (define-values (type opts1 opts2) (values (entry-type e) (car (entry-runs e)) (cadr (entry-runs e))))
  (define run1 (check-run opts1 "first"))
  (define run2 (check-run opts2 "second"))
  ;; [00343] empty runs carry index 0
  (define idx1 (if (null? run1) 0 (option-index (car run1) option-indices)))
  (define idx2 (if (null? run2) 0 (option-index (car run2) option-indices)))
  (check-contiguous run1 option-indices "first")
  (check-contiguous run2 option-indices "second")
  (define c (make-cursor))
  (cur-u8 c type)
  (cur-u8 c idx1)
  (cur-u8 c idx2)
  (cur-u8 c (+ (* 16 (length run1)) (length run2)))
  (cond
    [(sd-service-entry? e)
     (cur-u16 c (sd-service-entry-service-id e))
     (cur-u16 c (sd-service-entry-instance-id e))
     (cur-u8 c (sd-service-entry-major-version e))
     (cur-u24 c (sd-service-entry-ttl e))
     (cur-u32 c (sd-service-entry-minor-version e))]
    [else
     (cur-u16 c (sd-eventgroup-entry-service-id e))
     (cur-u16 c (sd-eventgroup-entry-instance-id e))
     (cur-u8 c (sd-eventgroup-entry-major-version e))
     (cur-u24 c (sd-eventgroup-entry-ttl e))
     ;; 32 bits: reserved [12] | counter [4] | eventgroup id [16]
     (cur-u16 c (bitwise-and (sd-eventgroup-entry-counter e) #xF))
     (cur-u16 c (sd-eventgroup-entry-eventgroup-id e))])
  (cursor->bytes c))

(define (entry-type e)
  (if (sd-service-entry? e)
      (sd-service-entry-type e)
      (sd-eventgroup-entry-type e)))

(define (check-run opts what)
  (when (> (length opts) 15)
    (raise (exn:fail:someip "sd: option run longer than 15 (4 bit field)" (current-continuation-marks))))
  (for ([o opts])
    (unless (sd-option? o)
      (raise-argument-error 'encode-sd-packet "option" o)))
  opts)

(define (option-index o option-indices)
  (hash-ref option-indices o
            (lambda () (error 'encode-sd-packet "internal: option not indexed"))))

(define (check-contiguous run option-indices what)
  (unless (or (null? run) (= (length run) 1))
    (define idxs (map (lambda (o) (option-index o option-indices)) run))
    (unless (equal? idxs (range (car idxs) (+ (car idxs) (length idxs))))
      (raise (exn:fail:someip
              (format "sd: ~a option run is not contiguous in the option array" what)
              (current-continuation-marks))))))

(define (cur-u24 c v)
  (cur-u8 c (bitwise-and (arithmetic-shift v -16) #xFF))
  (cur-u16 c (bitwise-and v #xFFFF)))

;; One option: length (16 bit) + type + flag byte + payload; the length
;; counts everything except itself and the type byte.
(define (encode-option o)
  (define-values (type payload discardable?)
    (cond
      [(sd-config-option? o)
       (values #x01 (encode-config-items (sd-config-option-items o))
               (sd-config-option-discardable? o))]
      [(sd-load-balance-option? o)
       (values #x02 (bytes (arithmetic-shift (sd-load-balance-option-priority o) -8)
                           (bitwise-and (sd-load-balance-option-priority o) #xFF)
                           (arithmetic-shift (sd-load-balance-option-weight o) -8)
                           (bitwise-and (sd-load-balance-option-weight o) #xFF))
               (sd-load-balance-option-discardable? o))]
      [(sd-endpoint-option? o)
       (define kind (sd-endpoint-option-kind o))
       (define family (sd-endpoint-option-family o))
       (define type-code
         (case kind
           [(endpoint) (case family [(ipv4) #x04] [(ipv6) #x06])]
           [(multicast) (case family [(ipv4) #x14] [(ipv6) #x16])]
           [(sd-endpoint) (case family [(ipv4) #x24] [(ipv6) #x26])]
           [else (raise-argument-error 'encode-option "endpoint kind" kind)]))
       (define addr-16? (eq? family 'ipv6))
       (define addr
         (if addr-16?
             (ipv6->bytes (sd-endpoint-option-address o))
             (ipv4->bytes (sd-endpoint-option-address o))))
       (values type-code
               (bytes-append addr
                             (bytes 0) ; reserved
                             (bytes (l4-protocol-code (sd-endpoint-option-protocol o)))
                             (bytes (arithmetic-shift (sd-endpoint-option-port o) -8)
                                    (bitwise-and (sd-endpoint-option-port o) #xFF)))
               (sd-endpoint-option-discardable? o))]
      [(sd-raw-option? o)
       (values (sd-raw-option-type o) (sd-raw-option-bytes o) #f)]))
  (define total (+ 1 (bytes-length payload))) ; type byte + payload
  (when (>= total (arithmetic-shift 1 16))
    (raise (exn:fail:someip "sd: option too large" (current-continuation-marks))))
  (bytes-append
   (bytes (arithmetic-shift total -8) (bitwise-and total #xFF))
   (bytes type)
   (bytes (if discardable? #x80 0))
   payload))

;; [00278]-[00280]: u8-length prefixed items, zero length terminates.
(define (encode-config-items items)
  (define c (make-cursor))
  (for ([item items])
    (match-define (cons key value) item)
    (unless (and (string? key) (non-empty-string? key)
                 (not (string-contains? key "=")))
      (raise-argument-error 'sd-config-option "key without '=' and at least one char" key))
    (define body
      (if value
          (string->bytes/utf-8 (string-append key "=" value))
          (string->bytes/utf-8 key)))
    (when (> (bytes-length body) 255)
      (raise-argument-error 'sd-config-option "item of at most 255 bytes" item))
    (cur-u8 c (bytes-length body))
    (cur-raw c body))
  (cur-u8 c 0)
  (cursor->bytes c))

;; ------------------------------------------------------------------
;; Decoding

;; Decode the SD payload (everything after the 16 byte SOME/IP header).
;; Returns (values sd-packet consumed).
(define (decode-sd-payload bs [start 0] [end (bytes-length bs)])
  (when (< (- end start) 8)
    (raise (exn:fail:someip:malformed
            (format "sd: payload shorter than the fixed SD header part (~a bytes)"
                    (- end start))
            (current-continuation-marks))))
  (define flags (bytes-ref bs start))
  (define r (make-reader bs (+ start 4) end))
  (define entries-len (rd-u32 r))
  (when (> entries-len (rd-remaining r))
    (raise (exn:fail:someip:malformed
            (format "sd: entries array length ~a exceeds the payload" entries-len)
            (current-continuation-marks))))
  (define raw-entries (decode-entries bs (reader-pos r) (+ (reader-pos r) entries-len)))
  (rd-skip r entries-len)
  (define options-len (rd-u32 r))
  (when (> options-len (rd-remaining r))
    (raise (exn:fail:someip:malformed
            (format "sd: options array length ~a exceeds the payload" options-len)
            (current-continuation-marks))))
  (define options (decode-options bs (reader-pos r) (+ (reader-pos r) options-len)))
  (rd-skip r options-len)
  (define entries
    (for/list ([raw raw-entries])
      (define runs (resolve-runs raw options))
      (match (entry-raw-fields raw)
        [(list sid iid major ttl minor)
         (sd-service-entry (entry-raw-type raw) sid iid major minor ttl runs)]
        [(list sid iid major ttl counter egid)
         (sd-eventgroup-entry (entry-raw-type raw) sid iid major ttl counter egid runs)])))
  (values (sd-packet (not (zero? (bitwise-and flags #x80)))
                     (not (zero? (bitwise-and flags #x40)))
                     entries
                     options)
          (- (reader-pos r) start)))

;; Decode a full SOME/IP SD message; verifies Message ID/type and
;; returns (values sd-packet session-id consumed).
(define (decode-sd-message bs [start 0] [end (bytes-length bs)])
  (when (< (- end start) 16)
    (raise (exn:fail:someip:malformed "sd: need a full SOME/IP header"
                                      (current-continuation-marks))))
  (define-values (m consumed) (decode-someip-message bs start end))
  (unless (and (= (someip-message-service-id m) sd-service-id)
               (= (someip-message-method-id m) sd-method-id))
    (raise (exn:fail:someip:malformed "sd: not an SD message (Message ID)"
                                      (current-continuation-marks))))
  (unless (= (someip-message-message-type m) mt-notification)
    (raise (exn:fail:someip:malformed "sd: not an SD message (Message Type)"
                                      (current-continuation-marks))))
  (define-values (pkt rest) (decode-sd-payload (someip-message-payload m)))
  (unless (= rest (bytes-length (someip-message-payload m)))
    (raise (exn:fail:someip:malformed "sd: trailing bytes after the options array"
                                      (current-continuation-marks))))
  (values pkt (someip-message-session-id m) consumed))

(define (sd-option-count pkt)
  (length (sd-packet-options pkt)))

;; First pass over the entries array: field tuples with run index/counts.
(struct entry-raw (type idx1 idx2 num1 num2 fields))

(define (decode-entries bs start end)
  (let loop ([pos start] [acc '()])
    (cond
      [(= pos end) (reverse acc)]
      [(< (- end pos) 16)
       (raise (exn:fail:someip:malformed "sd: trailing bytes in entries array"
                                         (current-continuation-marks)))]
      [else
       (define type (bytes-ref bs pos))
       (define idx1 (bytes-ref bs (+ pos 1)))
       (define idx2 (bytes-ref bs (+ pos 2)))
       (define run-byte (bytes-ref bs (+ pos 3)))
       (define num1 (arithmetic-shift run-byte -4))
       (define num2 (bitwise-and run-byte #xF))
       (define fields
         (case type
           [(#x00 #x01)
            (list (bytes->u16 bs (+ pos 4))   ; service id
                  (bytes->u16 bs (+ pos 6))   ; instance id
                  (bytes-ref bs (+ pos 8))    ; major version
                  (u24-ref bs (+ pos 9))      ; ttl
                  (bytes->u32 bs (+ pos 12)))] ; minor version
           [(#x06 #x07)
            ;; last 32 bits: reserved [12] | counter [4] | eventgroup [16]
            (define w (bytes->u32 bs (+ pos 12)))
            (define reserved (arithmetic-shift w -20))
            (unless (zero? reserved)
              (raise (exn:fail:someip:malformed "sd: eventgroup reserved bits not zero"
                                                (current-continuation-marks))))
            (list (bytes->u16 bs (+ pos 4))   ; service id
                  (bytes->u16 bs (+ pos 6))   ; instance id
                  (bytes-ref bs (+ pos 8))    ; major version
                  (u24-ref bs (+ pos 9))      ; ttl
                  (bitwise-and (arithmetic-shift w -16) #xF) ; counter
                  (bytes->u16 bs (+ pos 14)))] ; eventgroup id
           ;; [00841] unknown entry types are ignored
           [else #f]))
       (loop (+ pos 16)
             (if fields (cons (entry-raw type idx1 idx2 num1 num2 fields) acc) acc))])))

(define (u24-ref bs off)
  (+ (arithmetic-shift (bytes-ref bs off) 16)
     (arithmetic-shift (bytes-ref bs (+ off 1)) 8)
     (bytes-ref bs (+ off 2))))

;; Resolve run placeholders against the decoded option array; empty runs
;; yield '() whatever their index ([00343]/[00834]).
(define (resolve-runs raw options)
  (define (run idx num)
    (when (and (> num 0) (or (< idx 0) (> (+ idx num) (length options))))
      (raise (exn:fail:someip:malformed "sd: option run outside the option array"
                                        (current-continuation-marks))))
    (for/list ([i (in-range num)]) (list-ref options (+ idx i))))
  (list (run (entry-raw-idx1 raw) (entry-raw-num1 raw))
        (run (entry-raw-idx2 raw) (entry-raw-num2 raw))))

(define (decode-options bs start end)
  (let loop ([pos start] [acc '()])
    (cond
      [(= pos end) (reverse acc)]
      [(< (- end pos) 4)
       (raise (exn:fail:someip:malformed "sd: truncated option header"
                                         (current-continuation-marks)))]
      [else
       (define len (bytes->u16 bs pos))
       (unless (>= len 1)
         (raise (exn:fail:someip:malformed "sd: option length below 1"
                                           (current-continuation-marks))))
       (define option-end (+ pos 3 len))
       (when (> option-end end)
         (raise (exn:fail:someip:malformed "sd: option length exceeds the options array"
                                           (current-continuation-marks))))
       (define type (bytes-ref bs (+ pos 2)))
       (define discardable? (not (zero? (bitwise-and (bytes-ref bs (+ pos 3)) #x80))))
       (define payload-start (+ pos 4))
       (define option
         (case type
           [(#x01)
            (sd-config-option
             (decode-config-items bs payload-start option-end)
             discardable?)]
           [(#x02)
            (sd-load-balance-option
             (bytes->u16 bs payload-start)
             (bytes->u16 bs (+ payload-start 2))
             discardable?)]
           [(#x04 #x14 #x24 #x06 #x16 #x26)
            (define addr16? (memv type '(#x06 #x16 #x26)))
            (define addr-len (if addr16? 16 4))
            (when (< (- option-end payload-start) (+ addr-len 4))
              (raise (exn:fail:someip:malformed "sd: truncated endpoint option"
                                                (current-continuation-marks))))
            (define family (if addr16? 'ipv6 'ipv4))
            (define kind
              (case type [(#x04 #x06) 'endpoint]
                [(#x14 #x16) 'multicast] [(#x24 #x26) 'sd-endpoint]))
            (sd-endpoint-option
             kind family
             (if addr16?
                 (bytes->ipv6 bs payload-start)
                 (bytes->ipv4 bs payload-start))
             (bytes->u16 bs (+ payload-start addr-len 2))
             (l4-protocol-name (bytes-ref bs (+ payload-start addr-len 1)))
             discardable?)]
           [else
            (sd-raw-option type (subbytes bs payload-start option-end))]))
       (loop option-end (cons option acc))])))

(define (decode-config-items bs start end)
  (let loop ([pos start] [acc '()])
    (cond
      [(= pos end) (reverse acc)]
      [(> pos end)
       (raise (exn:fail:someip:malformed "sd: configuration item overrun" (current-continuation-marks)))]
      [else
       (define len (bytes-ref bs pos))
       (cond
         [(zero? len)
          (unless (= (+ pos 1) end)
            (raise (exn:fail:someip:malformed "sd: data after configuration terminator"
                                              (current-continuation-marks))))
          (reverse acc)]
         [else
          (define item-end (+ pos 1 len))
          (when (> item-end end)
            (raise (exn:fail:someip:malformed "sd: truncated configuration item"
                                              (current-continuation-marks))))
          (define body (bytes->string/utf-8 (subbytes bs (+ pos 1) item-end)))
          (define eq-pos (index-of (string->list body) #\=))
          (define item
            (if eq-pos
                (cons (substring body 0 eq-pos)
                      (substring body (add1 eq-pos)))
                (cons body #f)))
          (loop item-end (cons item acc))])])))

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (require rackunit
           racket/list)

  ;; ---- address helpers ------------------------------------------
  (check-equal? (ipv4->bytes "192.168.0.1") (bytes 192 168 0 1))
  (check-equal? (bytes->ipv4 (ipv4->bytes "192.168.0.1")) "192.168.0.1")
  (check-exn exn:fail? (lambda () (ipv4->bytes "999.1.1.1")))
  (check-exn exn:fail? (lambda () (ipv4->bytes "1.2.3")))

  (check-equal? (ipv6->bytes "::1")
                (bytes 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1))
  (check-equal? (ipv6->bytes "2001:db8::1")
                (bytes #x20 #x01 #x0d #xb8 0 0 0 0 0 0 0 0 0 0 0 1))
  (check-equal? (ipv6->bytes "fe80::1ff:fe23:4567:890a")
                (bytes #xfe #x80 0 0 0 0 0 0 #x01 #xff #xfe #x23 #x45 #x67 #x89 #x0a))
  (check-equal? (ipv6->bytes "::ffff:192.168.0.1")
                (bytes 0 0 0 0 0 0 0 0 0 0 #xff #xff 192 168 0 1))
  (check-equal? (ipv6->bytes "2001:db8:0:0:0:0:2:1")
                (ipv6->bytes "2001:db8::2:1"))
  ;; decoded addresses render uncompressed: 8 zero-padded hex groups
  (check-equal? (bytes->ipv6 (ipv6->bytes "2001:db8::1"))
                "2001:0db8:0000:0000:0000:0000:0000:0001")
  (check-equal? (bytes->ipv6 (ipv6->bytes "::1"))
                "0000:0000:0000:0000:0000:0000:0000:0001")

  ;; ---- spec example (Figure 5.2) ---------------------------------
  ;; Find + Offer with one IPv4 endpoint option; header checked
  ;; byte-for-byte.
  (define example
    (sd-packet
     #t ; reboot flag 0x80
     #f
     (list (find-service-entry #:service-id #x4711)
           (offer-service-entry #:service-id #x1234
                                #:instance-id 1
                                #:major-version 1
                                #:minor-version #x32
                                #:ttl 3
                                #:udp-endpoint
                                (sd-endpoint-option 'endpoint 'ipv4
                                                    "192.168.0.1" 55555 'udp #f)))
     '()))
  (define example-bytes (encode-sd-packet example #:session-id 1))
  ;; SOME/IP header
  (check-equal? (subbytes example-bytes 0 4) (bytes #xFF #xFF #x81 #x00))
  (check-equal? (bytes-ref example-bytes 14) mt-notification)
  (check-equal? (bytes-ref example-bytes 15) #x00)
  (check-equal? (bytes-ref example-bytes 16) #x80) ; flags: reboot
  (define-values (pkt sid consumed) (decode-sd-message example-bytes))
  (check-equal? sid 1)
  (check-true (sd-packet-reboot? pkt))
  (check-false (sd-packet-unicast? pkt))
  (check-equal? (length (sd-packet-entries pkt)) 2)
  (check-equal? (sd-option-count pkt) 1)

  (define find (first (sd-packet-entries pkt)))
  (check-equal? (sd-service-entry-type find) sd-entry-find)
  (check-equal? (sd-service-entry-service-id find) #x4711)
  (check-equal? (sd-service-entry-instance-id find) #xFFFF)
  (check-equal? (sd-service-entry-minor-version find) #xFFFFFFFF)

  (define offer (second (sd-packet-entries pkt)))
  (check-equal? (sd-service-entry-type offer) sd-entry-offer)
  (check-equal? (sd-service-entry-ttl offer) 3)
  (check-equal? (sd-service-entry-minor-version offer) #x32)
  (define opt (first (sd-packet-options pkt)))
  (check-equal? opt
                (sd-endpoint-option 'endpoint 'ipv4 "192.168.0.1" 55555 'udp #f))
  ;; decoded option runs reference the shared option
  (check-equal? (sd-service-entry-option-runs offer)
                (list (list opt) (list)))

  ;; stop offer: same fields, TTL 0, options preserved [00364]/[00840]
  (define stop
    (stop-offer-service-entry #:service-id #x1234 #:instance-id 1
                              #:major-version 1 #:minor-version #x32
                              #:udp-endpoint
                              (sd-endpoint-option 'endpoint 'ipv4
                                                  "192.168.0.1" 55555 'udp #f)))
  (check-true (entry-type-stop? stop))
  (check-false (entry-type-stop? offer))

  ;; ---- subscribe / ack / nack with counter and multicast ----------
  (define mc (sd-endpoint-option 'multicast 'ipv4 "239.255.1.1" 40901 'udp #f))
  (define sub
    (subscribe-eventgroup-entry #:service-id #x1234 #:instance-id 1
                                #:major-version 1 #:eventgroup-id #x10
                                #:ttl ttl-infinite #:counter 3
                                #:client-endpoints
                                (list (sd-endpoint-option 'endpoint 'ipv4
                                                          "10.0.0.9" 49152 'udp #f))
                                #:multicast-option mc))
  (define ack
    (subscribe-ack-entry #:service-id #x1234 #:instance-id 1
                         #:major-version 1 #:eventgroup-id #x10
                         #:counter 3 #:multicast-option mc))
  (define nack
    (subscribe-nack-entry #:service-id #x1234 #:instance-id 1
                          #:major-version 1 #:eventgroup-id #x10))
  (define-values (pkt2 sid-b consumed2) (decode-sd-message (encode-sd-packet (sd-packet #f #t (list sub ack nack) '()))))
  (check-true (sd-packet-unicast? pkt2))
  (match-define (list sub2 ack2 nack2) (sd-packet-entries pkt2))
  (check-equal? (sd-eventgroup-entry-type sub2) sd-entry-subscribe)
  (check-equal? (sd-eventgroup-entry-counter sub2) 3)
  (check-equal? (sd-eventgroup-entry-ttl sub2) ttl-infinite)
  (check-equal? (sd-eventgroup-entry-eventgroup-id sub2) #x10)
  (check-equal? (length (sd-eventgroup-entry-option-runs sub2)) 2)
  (check-equal? (first (sd-eventgroup-entry-option-runs sub2))
                (list (sd-endpoint-option 'endpoint 'ipv4 "10.0.0.9" 49152 'udp #f)))
  (check-equal? (second (sd-eventgroup-entry-option-runs sub2)) (list mc))
  (check-equal? (sd-eventgroup-entry-type ack2) sd-entry-ack)
  (check-true (entry-type-stop? nack2) "nack carries TTL 0")
  ;; client endpoint + shared multicast, the latter deduplicated
  (check-equal? (sd-option-count pkt2) 2)

  ;; ---- configuration option --------------------------------------
  (define cfg (sd-config-option
               (list (cons "key1" "value1") (cons "flag" #f) (cons "case" "eq=has=signs"))
               #t))
  (define-values (pkt3 sid-c consumed3)
    (decode-sd-message (encode-sd-packet (sd-packet #f #f (list (find-service-entry #:service-id 1)) (list cfg)))))
  (check-equal? (sd-packet-options pkt3) (list cfg))

  ;; ---- load balancing option --------------------------------------
  (define lb (sd-load-balance-option 10 100 #f))
  (define-values (pkt4 sid-d consumed4)
    (decode-sd-message
     (encode-sd-packet
      (sd-packet #f #f
                 (list (offer-service-entry #:service-id 5 #:instance-id 1
                                            #:major-version 1 #:minor-version 0
                                            #:extra-options (list lb)))
                 (list lb)))))
  (check-equal? (sd-packet-options pkt4) (list lb))

  ;; ---- unknown entry types are skipped [00841] --------------------
  ;; hand-built: unknown entry type 0x55 followed by a find entry
  (define hand-built
    (bytes-append
     (bytes #x00) (make-bytes 3 0)      ; flags + reserved
     (bytes 0 0 0 32)                   ; entries array length
     (bytes #x55 0 0 #x00) (make-bytes 12 0) ; ignored unknown entry
     (bytes 0 0 0 0                     ; find: type, idx1, idx2, runs
            0 9 #xFF #xFF               ; service 9, any instance
            #xFF 0 0 0                  ; any major, TTL ignored
            #xFF #xFF #xFF #xFF)        ; any minor
     (bytes 0 0 0 0)))                  ; empty options array
  (define-values (pkt5 sid-e consumed5) (decode-sd-message
                                         (encode-someip-message
                                          (make-someip-message
                                           #:service-id sd-service-id
                                           #:method-id sd-method-id
                                           #:interface-version 1
                                           #:message-type mt-notification
                                           #:payload hand-built))))
  (check-equal? (length (sd-packet-entries pkt5)) 1)
  (check-equal? (sd-service-entry-service-id (first (sd-packet-entries pkt5))) 9)

  ;; ---- unknown option types survive as raw options ----------------
  (define with-raw
    (encode-sd-packet
     (sd-packet #f #f (list (find-service-entry #:service-id 2))
                (list (sd-raw-option #x77 (bytes 1 2 3))))))
  (define-values (pkt6 sid-f consumed6) (decode-sd-message with-raw))
  (check-equal? (sd-packet-options pkt6)
                (list (sd-raw-option #x77 (bytes 1 2 3))))

  ;; ---- malformed framing ------------------------------------------
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-sd-payload (make-bytes 4))))
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-sd-message (make-bytes 15))))
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-sd-message
                         (encode-someip-message
                          (make-someip-message #:service-id 1 #:method-id 2
                                               #:interface-version 1
                                               #:message-type mt-notification)))))

  ;; ---- option run referencing errors ------------------------------
  (check-exn exn:fail:contract?
             (lambda ()
               (encode-sd-packet
                (sd-packet #f #f
                           (list (sd-service-entry sd-entry-offer 1 1 1 0 1
                                                   (list (list (sd-config-option '() #f)
                                                              (find-service-entry #:service-id 1))
                                                         '())))
                           '())))))

