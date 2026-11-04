#lang racket/base

;; Byte-stream primitives shared by all wire-format modules.
;;
;; Encoding writes into an opaque cursor (growable byte buffer); decoding
;; reads from a byte string with an explicit end bound so a single buffer
;; can contain several packed messages.

(require racket/contract
         racket/flonum)

(provide cursor?
         make-cursor
         cursor-size
         cursor-buf
         cursor->bytes
         cur-u8 cur-u16 cur-u32 cur-u64
         cur-i8 cur-i16 cur-i32 cur-i64
         cur-f32 cur-f64
         cur-raw
         cur-fill
         cur-patch-u16 cur-patch-u32
         reader?
         make-reader
         reader-bs
         reader-end
         set-reader-end!
         reader-pos
         set-reader-pos!
         rd-remaining
         rd-eof?
         rd-u8 rd-u16 rd-u32 rd-u64
         rd-i8 rd-i16 rd-i32 rd-i64
         rd-f32 rd-f64
         rd-raw
         rd-skip
         u16->bytes u32->bytes u64->bytes
         bytes->u16 bytes->u32 bytes->u64
         signed-value-in-range?)

(struct cursor (buf pos) #:mutable)
(struct reader (bs end pos) #:mutable)

(define (make-cursor)
  (cursor (make-vector 64 0) 0))

(define (cursor-size c) (cursor-pos c))

(define (cursor-reserve! c n)
  (define b (cursor-buf c))
  (define need (+ (cursor-pos c) n))
  (when (> need (vector-length b))
    (let grow ([cap (vector-length b)])
      (if (>= cap need)
          (let ([nb (make-vector cap 0)])
            (vector-copy! nb 0 b)
            (set-cursor-buf! c nb))
          (grow (* cap 2))))))

(define (cursor-put-u8! c v)
  (cursor-reserve! c 1)
  (vector-set! (cursor-buf c) (cursor-pos c) (bitwise-and v #xFF))
  (set-cursor-pos! c (+ (cursor-pos c) 1)))

(define (cursor-put-int! c v n)
  (let loop ([i (sub1 n)] [v v])
    (when (>= i 0)
      (cursor-put-u8! c (bitwise-and (arithmetic-shift v (* -8 i)) #xFF))
      (loop (sub1 i) v))))

(define (cursor-put-signed! c v n)
  (unless (signed-value-in-range? v n)
    (raise-argument-error 'cur-i "value in range" v))
  (cursor-put-int! c (if (< v 0) (+ v (arithmetic-shift 1 (* 8 n))) v) n))

(define (signed-value-in-range? v n)
  (define lim (arithmetic-shift 1 (sub1 (* 8 n))))
  (and (exact-integer? v) (>= v (- lim)) (< v lim)))

(define-syntax-rule (define-int-cursor cur-i n)
  (define (cur-i c v) (cursor-put-signed! c v n)))

(define (cur-u8 c v)
  (unless (and (exact-nonnegative-integer? v) (< v 256))
    (raise-argument-error 'cur-u8 "uint8" v))
  (cursor-put-u8! c v))

(define (cur-u16 c v) (cursor-put-int! c v 2))
(define (cur-u32 c v) (cursor-put-int! c v 4))
(define (cur-u64 c v) (cursor-put-int! c v 8))
(define-int-cursor cur-i8 1)
(define-int-cursor cur-i16 2)
(define-int-cursor cur-i32 4)
(define-int-cursor cur-i64 8)

(define (cur-f32 c v)
  (define b (real->floating-point-bytes (exact->inexact v) 4 #t))
  (cur-raw c b))

(define (cur-f64 c v)
  (define b (real->floating-point-bytes (exact->inexact v) 8 #t))
  (cur-raw c b))

(define (cur-raw c bs)
  (cursor-reserve! c (bytes-length bs))
  (let loop ([i 0])
    (when (< i (bytes-length bs))
      (vector-set! (cursor-buf c) (+ (cursor-pos c) i) (bytes-ref bs i))
      (loop (add1 i))))
  (set-cursor-pos! c (+ (cursor-pos c) (bytes-length bs))))

(define (cur-fill c n [byte 0])
  (let loop ([i 0])
    (when (< i n)
      (cursor-put-u8! c byte)
      (loop (add1 i)))))

(define (cursor->bytes c)
  (define n (cursor-pos c))
  (define bs (make-bytes n))
  (let loop ([i 0])
    (when (< i n)
      (bytes-set! bs i (vector-ref (cursor-buf c) i))
      (loop (add1 i))))
  bs)

;; Patching lets serializers write a length field before the covered
;; bytes are known. Positions are recorded by the caller.
(define (check-patch c pos n)
  (unless (and (exact-nonnegative-integer? pos)
               (>= (cursor-pos c) (+ pos n)))
    (raise-argument-error 'cur-patch "reserved position inside buffer" pos)))

(define (cur-patch-u16 c pos v)
  (check-patch c pos 2)
  (define b (cursor-buf c))
  (vector-set! b pos (bitwise-and (arithmetic-shift v -8) #xFF))
  (vector-set! b (add1 pos) (bitwise-and v #xFF)))

(define (cur-patch-u32 c pos v)
  (check-patch c pos 4)
  (define b (cursor-buf c))
  (for ([i (in-range 4)])
    (vector-set! b (+ pos i)
                 (bitwise-and (arithmetic-shift v (* -8 (- 3 i))) #xFF))))

;; ------------------------------------------------------------------
;; Decoding

(define (make-reader bs [start 0] [end (bytes-length bs)])
  (unless (<= 0 start end (bytes-length bs))
    (raise-argument-error 'make-reader "start/end inside byte string" start))
  (reader bs end start))

(define (rd-check r n who)
  (when (> (+ (reader-pos r) n) (reader-end r))
    (raise
     (exn:fail (format "someip: premature end of data in ~a (need ~a byte(s), have ~a)"
                       who n (rd-remaining r))
               (current-continuation-marks)))))

(define (rd-int r n who)
  (rd-check r n who)
  (let loop ([i 0] [v 0])
    (if (= i n)
        (begin (set-reader-pos! r (+ (reader-pos r) n)) v)
        (loop (add1 i)
              (+ (arithmetic-shift v 8) (bytes-ref (reader-bs r) (+ (reader-pos r) i)))))))

(define (rd-u8 r) (rd-int r 1 "rd-u8"))
(define (rd-u16 r) (rd-int r 2 "rd-u16"))
(define (rd-u32 r) (rd-int r 4 "rd-u32"))
(define (rd-u64 r) (rd-int r 8 "rd-u64"))

(define (rd-signed r n who)
  (define v (rd-int r n who))
  (define half (arithmetic-shift 1 (sub1 (* 8 n))))
  (if (>= v half) (- v (arithmetic-shift 1 (* 8 n))) v))

(define (rd-i8 r) (rd-signed r 1 "rd-i8"))
(define (rd-i16 r) (rd-signed r 2 "rd-i16"))
(define (rd-i32 r) (rd-signed r 4 "rd-i32"))
(define (rd-i64 r) (rd-signed r 8 "rd-i64"))

(define (rd-f32 r)
  (rd-check r 4 "rd-f32")
  (begin0 (floating-point-bytes->real (reader-bs r) #t (reader-pos r) (+ (reader-pos r) 4))
    (set-reader-pos! r (+ (reader-pos r) 4))))

(define (rd-f64 r)
  (rd-check r 8 "rd-f64")
  (begin0 (floating-point-bytes->real (reader-bs r) #t (reader-pos r) (+ (reader-pos r) 8))
    (set-reader-pos! r (+ (reader-pos r) 8))))

(define (rd-raw r n)
  (rd-check r n "rd-raw")
  (begin0 (subbytes (reader-bs r) (reader-pos r) (+ (reader-pos r) n))
    (set-reader-pos! r (+ (reader-pos r) n))))

(define (rd-skip r n)
  (rd-check r n "rd-skip")
  (set-reader-pos! r (+ (reader-pos r) n)))

(define (rd-remaining r) (- (reader-end r) (reader-pos r)))
(define (rd-eof? r) (>= (reader-pos r) (reader-end r)))

;; ------------------------------------------------------------------
;; Standalone converters (big endian)

(define (u16->bytes v)
  (bytes (bitwise-and (arithmetic-shift v -8) #xFF) (bitwise-and v #xFF)))

(define (u32->bytes v)
  (bytes (bitwise-and (arithmetic-shift v -24) #xFF)
         (bitwise-and (arithmetic-shift v -16) #xFF)
         (bitwise-and (arithmetic-shift v -8) #xFF)
         (bitwise-and v #xFF)))

(define (u64->bytes v)
  (bytes (bitwise-and (arithmetic-shift v -56) #xFF)
         (bitwise-and (arithmetic-shift v -48) #xFF)
         (bitwise-and (arithmetic-shift v -40) #xFF)
         (bitwise-and (arithmetic-shift v -32) #xFF)
         (bitwise-and (arithmetic-shift v -24) #xFF)
         (bitwise-and (arithmetic-shift v -16) #xFF)
         (bitwise-and (arithmetic-shift v -8) #xFF)
         (bitwise-and v #xFF)))

(define (bytes->u16 bs [off 0])
  (+ (arithmetic-shift (bytes-ref bs off) 8) (bytes-ref bs (+ off 1))))

(define (bytes->u32 bs [off 0])
  (+ (arithmetic-shift (bytes-ref bs off) 24)
     (arithmetic-shift (bytes-ref bs (+ off 1)) 16)
     (arithmetic-shift (bytes-ref bs (+ off 2)) 8)
     (bytes-ref bs (+ off 3))))

(define (bytes->u64 bs [off 0])
  (for/fold ([v 0]) ([i (in-range 8)])
    (+ (arithmetic-shift v 8) (bytes-ref bs (+ off i)))))
