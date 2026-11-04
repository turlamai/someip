#lang racket/base

;; SOME/IP-TP: segmentation of large messages for UDP transport and
;; reassembly on the receiving side (AUTOSAR FO, SOME/IP Protocol
;; Specification, chapter 4.2.1.4).
;;
;; Wire rules implemented here:
;;   [00367] TP flag 0x20 in the Message Type marks segments
;;   [00723] TP header after the header: offset [28 bit], three reserved
;;           flags, More Segments flag [1 bit]
;;   [00724] offset is counted in units of 16 bytes
;;   [00729] all segments but the last are multiples of 16 bytes
;;   [00730] 1392 bytes is the largest aligned segment payload
;;   [00734] all segments with More Segments = 1 have the same size
;;   [00738] reassembly matches Message ID, Protocol Version, Interface
;;           Version and Message Type (without TP flag)
;;   [00740] parallel reassemblies per sender identity
;;   [00741]/[00742] the Session ID selects the next original message; a
;;           segment with a different Session ID restarts the assembly
;;   [00744] only complete reassemblies are delivered
;;   [00745] the Return Code is taken from the last segment
;;   [00746] the TP flag is cleared in the reassembled message
;;   [00752] duplicated/overlapping segments overwrite by last received
;;   [00754] obvious errors are handled gracefully (unaligned non-final
;;           segments are dropped, assemblies never exceed a bound)

(require racket/contract
         racket/format
         "message.rkt"
         "logging.rkt")

(provide segment-someip-message
         tp-segment?
         tp-segment-offset
         tp-segment-more?
         tp-segment-data
         make-tp-reassembler
         tp-feed!
         tp-gc!
         tp-active-count
         (struct-out exn:fail:someip)
         (struct-out exn:fail:someip:malformed))

(module+ test (require rackunit
                      racket/list))

;; ------------------------------------------------------------------
;; Segmentation

;; Default aligned maximum segment payload [00730].
(define default-max-segment-payload 1392)

(define (tp-segment? m)
  (and (someip-message? m) (message-type-has-tp-flag? (someip-message-message-type m))))

;; Split `msg` into SOME/IP-TP segments. Returns the original message
;; unchanged (in a list) when its payload already fits into one segment.
(define (segment-someip-message msg [max-payload default-max-segment-payload])
  (unless (someip-message? msg)
    (raise-argument-error 'segment-someip-message "someip-message?" msg))
  (unless (and (exact-positive-integer? max-payload)
               (<= max-payload default-max-segment-payload)
               (zero? (modulo max-payload 16)))
    (raise-argument-error 'segment-someip-message
                          "segment payload: positive multiple of 16, at most 1392"
                          max-payload))
  (define pl (someip-message-payload msg))
  (define n (bytes-length pl))
  (cond
    [(<= n max-payload) (list msg)]
    [else
     ;; maximal segments [00735]: every non-final segment carries
     ;; max-payload bytes (a multiple of 16 [00729], equal sizes
     ;; [00734]); the last one carries the remainder
     (make-segments msg pl max-payload (ceiling (/ n max-payload)))]))

(define (make-segments msg pl size count)
  (define mt (with-tp-flag (someip-message-message-type msg)))
  (for/list ([i (in-range count)])
    (define start (* i size))
    (define end (min (* (add1 i) size) (bytes-length pl)))
    (define more (< (add1 i) count))
    (make-someip-message
     #:service-id (someip-message-service-id msg)
     #:method-id (someip-message-method-id msg)
     #:interface-version (someip-message-interface-version msg)
     #:message-type mt
     #:client-id (someip-message-client-id msg)
     #:session-id (someip-message-session-id msg)
     #:protocol-version (someip-message-protocol-version msg)
     #:return-code (someip-message-return-code msg)
     #:payload (bytes-append (tp-header (* size i) more) (subbytes pl start end)))))

;; TP header: offset in 16 byte units [28 bit], 3 reserved flags, more
;; segments flag [00723].
(define (tp-header offset-bytes more?)
  (unless (zero? (modulo offset-bytes 16))
    (raise-argument-error 'tp-header "offset in multiples of 16" offset-bytes))
  (bytes (bitwise-and (arithmetic-shift offset-bytes -20) #xFF)
         (bitwise-and (arithmetic-shift offset-bytes -12) #xFF)
         (bitwise-and (arithmetic-shift offset-bytes -4) #xFF)
         (if more? 1 0)))

;; Byte offset of the segment data in the original message (the wire
;; field counts units of 16 bytes [00724]).
(define (tp-segment-offset m)
  (define pl (someip-message-payload m))
  (* 16 (+ (arithmetic-shift (bytes-ref pl 0) 16)
           (arithmetic-shift (bytes-ref pl 1) 8)
           (bytes-ref pl 2))))

(define (tp-segment-more? m)
  (= 1 (bitwise-and (bytes-ref (someip-message-payload m) 3) 1)))

(define (tp-segment-data m)
  (subbytes (someip-message-payload m) 4))

;; ------------------------------------------------------------------
;; Reassembly

;; One in-flight original message. `parts` maps offset ->
;; (cons more? data).
(struct assembly (session client parts first-seen-ms last-seen-ms) #:mutable)

(struct tp-reassembler (lock table max-size idle-timeout-ms))

;; `max-size` guards memory against malicious or broken senders; an
;; assembly exceeding it is dropped entirely. `idle-timeout-ms` is
;; applied by tp-gc!.
(define (make-tp-reassembler
         #:max-size [max-size (* 16 8192)]       ; 128 KiB
         #:idle-timeout-ms [idle-timeout-ms 30000])
  (tp-reassembler (make-semaphore 1) (make-hash) max-size idle-timeout-ms))

(define (tp-feed! r seg [sender #f] [now-ms (current-inexact-milliseconds)])
  (unless (tp-segment? seg)
    (raise-argument-error 'tp-feed! "TP segment message" seg))
  (call-with-semaphore
   (tp-reassembler-lock r)
   (lambda ()
     (let/ec return
       (define table (tp-reassembler-table r))
     ;; Assembly key per [00738] plus the sender identity per [00740].
     (define key (list sender
                       (someip-message-service-id seg)
                       (someip-message-method-id seg)
                       (someip-message-protocol-version seg)
                       (someip-message-interface-version seg)
                       (base-message-type (someip-message-message-type seg))))
     (define session (someip-message-session-id seg))
     (define client (someip-message-client-id seg))
     (define offset (tp-segment-offset seg))
     (define more? (tp-segment-more? seg))
     (define data (tp-segment-data seg))
     (define data-len (bytes-length data))

     ;; [00754] a non-final segment must be a multiple of 16 bytes; the
     ;; whole assembly is cancelled (a sender that violates alignment is
     ;; not going to complete a clean assembly)
     (when (and more? (not (zero? (modulo data-len 16))))
       (someip-log-warning "tp: dropping unaligned non-final segment (~a bytes)" data-len)
       (hash-remove! table key)
       (return #f))

     ;; memory bound: any segment reaching beyond the limit kills the
     ;; assembly [00754]
     (when (> (+ offset data-len) (tp-reassembler-max-size r))
       (someip-log-warning "tp: assembly beyond ~a bytes, dropped"
                           (tp-reassembler-max-size r))
       (hash-remove! table key)
       (return #f))

     ;; [00742] a different Session ID (or Client ID) restarts assembly
     (define current (hash-ref table key #f))
     (define asm
       (if (or (not current)
               (not (= session (assembly-session current)))
               (not (= client (assembly-client current))))
           (assembly session client (make-hash) now-ms now-ms)
           (begin
             (set-assembly-last-seen-ms! current now-ms)
             current)))
     (define parts (assembly-parts asm))

       ;; [00752] place/overwrite the segment by offset
       (hash-set! parts offset (cons more? data))
       (hash-set! table key asm)
       (define completed (try-complete seg asm))
       (when completed
         ;; the original message is delivered; the entry is consumed
         (hash-remove! table key))
       completed))))

;; A reassembly is complete when the parts, walked in ascending offset
;; order, tile the range [0, end) without gaps and the highest segment
;; carries More Segments = 0.
(define (try-complete seg asm)
  (define parts (assembly-parts asm))
  (define offsets (sort (hash-keys parts) <))
  (let walk ([remaining offsets] [expected 0] [last-more #t])
    (cond
      [(null? remaining) #f]
      [(not (= (car remaining) expected)) #f] ; gap: keep waiting [00749]
      [else
       (define part (hash-ref parts (car remaining)))
       (define data (cdr part))
       (define next-expected (+ (car remaining) (bytes-length data)))
       (define more (car part))
       (if (null? (cdr remaining))
           ;; final part on the wire
           (and (not more)
                (make-someip-message
                 #:service-id (someip-message-service-id seg)
                 #:method-id (someip-message-method-id seg)
                 #:interface-version (someip-message-interface-version seg)
                 #:message-type (base-message-type (someip-message-message-type seg))
                 #:client-id (assembly-client asm)
                 #:session-id (assembly-session asm)
                 #:protocol-version (someip-message-protocol-version seg)
                 #:return-code (someip-message-return-code seg) ; [00745]
                 #:payload (assemble-payload parts offsets)))
           (walk (cdr remaining) next-expected more))])))

(define (assemble-payload parts offsets)
  (apply bytes-append
         (for/list ([o offsets])
           (cdr (hash-ref parts o)))))

;; Drop assemblies idle for longer than the configured timeout.
(define (tp-gc! r [now-ms (current-inexact-milliseconds)])
  (call-with-semaphore
   (tp-reassembler-lock r)
   (lambda ()
     (define table (tp-reassembler-table r))
     (define timeout (tp-reassembler-idle-timeout-ms r))
     (for ([(key asm) (in-hash table)]
           #:when (> (- now-ms (assembly-last-seen-ms asm)) timeout))
       (someip-log-debug "tp: dropping idle assembly")
       (hash-remove! table key)))))

(define (tp-active-count r)
  (call-with-semaphore (tp-reassembler-lock r)
                       (lambda () (hash-count (tp-reassembler-table r)))))

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (require rackunit)

  ;; spec example: 5880 bytes payload in 5 segments (Figure 4.17-4.20)
  (define big
    (make-someip-message #:service-id #x0101 #:method-id #x0009
                         #:interface-version 1
                         #:message-type mt-request
                         #:client-id #x0001 #:session-id #x0005
                         #:payload (list->bytes (for/list ([i (in-range 5880)]) (modulo i 256)))))
  (define segs (segment-someip-message big))
  (check-equal? (length segs) 5)
  (for ([s segs] [i 5])
    (check-true (tp-segment? s) "TP flag set")
    (check-equal? (tp-segment-offset s) (* 1392 i)))
  (check-true (tp-segment-more? (car segs)))
  (check-false (tp-segment-more? (last segs)))
  (for ([s (drop-right segs 1)])
    (check-equal? (bytes-length (tp-segment-data s)) 1392))
  (check-equal? (bytes-length (tp-segment-data (last segs))) 312)
  ;; segment length field = 8 + 4 + payload size
  (check-equal? (someip-message-length-payload-size (car segs)) 1404)

  ;; round trip
  (define r (make-tp-reassembler))
  (define done
    (for/fold ([acc #f]) ([s segs])
      (or acc (tp-feed! r s))))
  (check-equal? (someip-message-payload done) (someip-message-payload big))
  (check-false (message-type-has-tp-flag? (someip-message-message-type done)))
  (check-equal? (tp-active-count r) 0 "assembly consumed")

  ;; short messages are not segmented
  (define small
    (make-someip-message #:service-id 1 #:method-id 1
                         #:interface-version 1 #:message-type mt-request
                         #:payload (make-bytes 100)))
  (check-equal? (segment-someip-message small) (list small))

  ;; invalid max-payload values
  (check-exn exn:fail? (lambda () (segment-someip-message big 100)))
  (check-exn exn:fail? (lambda () (segment-someip-message big 1393)))

  ;; out-of-order delivery still completes ([00747])
  (define r2 (make-tp-reassembler))
  (define shuffled (list (fourth segs) (second segs) (fifth segs) (car segs) (third segs)))
  (define done2
    (for/fold ([acc #f]) ([s shuffled])
      (or acc (tp-feed! r2 s))))
  (check-equal? (someip-message-payload done2) (someip-message-payload big))

  ;; duplicates are harmless ([00752])
  (define r3 (make-tp-reassembler))
  (check-false (tp-feed! r3 (car segs)))
  (check-false (tp-feed! r3 (car segs)))
  (check-equal? (tp-active-count r3) 1)

  ;; a segment with a different Session ID restarts ([00742])
  (define other-session
    (make-someip-message
     #:service-id (someip-message-service-id (car segs))
     #:method-id (someip-message-method-id (car segs))
     #:interface-version 1
     #:message-type (someip-message-message-type (car segs))
     #:client-id (someip-message-client-id (car segs))
     #:session-id 6
     #:protocol-version 1
     #:payload (someip-message-payload (car segs))))
  (check-false (tp-feed! r3 other-session))
  (check-false (tp-feed! r3 (second segs)) "old session restarted by new")
  (check-equal? (tp-active-count r3) 1)
  (define done3
    (for/fold ([acc #f]) ([s segs])
      (or acc (tp-feed! r3 s))))
  (check-true (someip-message? done3) "session 5 reassembles again after restart")
  (check-equal? (someip-message-session-id done3) 5)

  ;; parallel assemblies per sender identity ([00740])
  (define r4 (make-tp-reassembler))
  (check-false (tp-feed! r4 (car segs) 'sender-a))
  (check-false (tp-feed! r4 (car segs) 'sender-b))
  (check-equal? (tp-active-count r4) 2)

  ;; unaligned non-final segment cancels gracefully ([00754])
  (define r5 (make-tp-reassembler))
  (check-false (tp-feed! r5 (car segs)))
  (define bad
    (make-someip-message
     #:service-id (someip-message-service-id (second segs))
     #:method-id (someip-message-method-id (second segs))
     #:interface-version 1
     #:message-type (someip-message-message-type (second segs))
     #:client-id (someip-message-client-id (second segs))
     #:session-id (someip-message-session-id (second segs))
     #:protocol-version 1
     #:payload (bytes-append (tp-header 1392 #t) (make-bytes 10))))
  (check-false (tp-feed! r5 bad))
  (check-equal? (tp-active-count r5) 0)

  ;; size bound drops oversized assemblies
  (define r6 (make-tp-reassembler #:max-size 2048))
  (check-false (tp-feed! r6 (car segs)))
  (check-equal? (tp-active-count r6) 1)
  (check-false (tp-feed! r6 (second segs)) "second segment exceeds the bound")
  (check-equal? (tp-active-count r6) 0)

  ;; idle timeout
  (define r7 (make-tp-reassembler #:idle-timeout-ms 1000))
  (tp-feed! r7 (car segs) #f 1000.0)
  (check-equal? (tp-active-count r7) 1)
  (tp-gc! r7 1500.0)
  (check-equal? (tp-active-count r7) 1)
  (tp-gc! r7 2500.0)
  (check-equal? (tp-active-count r7) 0))

;; Length helper used in tests (payload = everything after the length
;; field).
(define (someip-message-length-payload-size m)
  (+ 8 (bytes-length (someip-message-payload m))))
