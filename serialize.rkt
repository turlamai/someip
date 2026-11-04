#lang racket/base

;; SOME/IP payload serialization framework (AUTOSAR FO, SOME/IP Protocol
;; Specification, chapter 4.1.3/4.1.4).
;;
;; Codecs are first-class values describing one payload type. They are
;; composed into strings, arrays, structs and unions and driven by a
;; `serialization` configuration that captures everything the wire format
;; leaves open: payload byte order, alignment, default length-field size,
;; and TLV (tag/length/value) mode.
;;
;; Wire rules implemented here (requirement IDs from the specification):
;;   [00368] header is always big endian; [00369] payload order per config
;;   [00569] alignment is measured from the start of the serialized area
;;   [00611] padding after variable-size data when followed by more data
;;   [00612] no padding behind fixed-size data
;;   [00613] alignment behind variable data is 8..256 bits, per config
;;   [00615] boolean: only the lowest bit is interpreted
;;   [00370] struct length field covers the struct bytes on the wire
;;   [00095] string/array length fields do not count themselves
;;   [00090] string length field is placed before the BOM and includes it
;;   [00087] every string starts with a BOM, [00948]/[00084] zero terminated
;;   [00377] dynamic array length excludes the length field itself
;;   [00119] union = length field + type selector + data (+ padding)
;;   [00126] union length covers data and padding, not length/type fields
;;   [00907] union type 0 is reserved for NULL
;;   [00201..00244] TLV: 2 byte tags, wire types, skip unknown members

(require racket/contract
         racket/dict
         racket/format
         racket/list
         racket/match
         "private/bytes.rkt"
         "logging.rkt")

(provide (struct-out serialization)
         (struct-out exn:fail:someip:malformed)
         (struct-out someip-union)
         codec?

         serialization-config
         current-serialization

         uint8-c sint8-c uint16-c sint16-c uint32-c sint32-c
         uint64-c sint64-c
         float32-c float64-c boolean-c

         string-c
         dyn-string
         utf-8-string utf-16be-string utf-16le-string
         fixed-string

         fixed-array
         dyn-array

         member struct-member-name struct-member-codec
         struct-c

         union-c

         members-c

         encode-payload
         decode-payload
         decode-payload*)

(module+ test (require rackunit))

(struct exn:fail:someip:malformed exn:fail ())

(define (malformed fmt . args)
  (raise (exn:fail:someip:malformed (apply format (string-append "someip-serialize: " fmt) args)
                                    (current-continuation-marks))))

;; ------------------------------------------------------------------
;; Configuration

;; big-endian?: payload byte order; the header is always big endian
;; [00368], payload order is a configuration property [00369].
;; aligned?: insert padding after variable-size data [00611].
;; variable-alignment-bytes: that padding's boundary in bytes (1..32).
;; length-field-bytes: default length-field size in bytes for dynamic
;;   constructs (1/2/4); individual codecs may override.
;; tlv?: tagged serialization; alignment behind variable data becomes
;;   8 bits [00222].
(struct serialization
  (big-endian? aligned? variable-alignment-bytes length-field-bytes tlv?)
  #:transparent)

(define (serialization-config
         #:big-endian? [big-endian? #t]
         #:aligned? [aligned? #t]
         #:variable-alignment-bytes [variable-alignment-bytes 8]
         #:length-field-bytes [length-field-bytes 4]
         #:tlv? [tlv? #f])
  (unless (memv variable-alignment-bytes '(1 2 4 8 16 32))
    (raise-argument-error 'serialization-config
                          "alignment of 8/16/32/64/128/256 bits" variable-alignment-bytes))
  (unless (memv length-field-bytes '(1 2 4))
    (raise-argument-error 'serialization-config "length field of 8/16/32 bits" length-field-bytes))
  (serialization big-endian? aligned? variable-alignment-bytes length-field-bytes tlv?))

(define current-serialization
  (make-parameter (serialization-config)))

;; ------------------------------------------------------------------
;; Codec plumbing

;; A codec knows how to write a value into a cursor and read one back
;; from a reader, under a serialization config. `fixed-size` is the wire
;; size in bytes for fixed-layout codecs, or #f for variable ones.
(struct codec (enc dec fixed-size)
  #:property prop:procedure
  (lambda (c v [cfg (current-serialization)])
    (encode-payload c v cfg)))

;; Apply a codec's encoder/decoder (the struct fields are accessors).
(define (encode-with c v cur cfg) ((codec-enc c) v cur cfg))
(define (decode-with c r cfg) ((codec-dec c) r cfg))

(define (resolve-length-bytes v who)
  (cond
    [(eq? v 'default) #f] ; resolved against the config at use time
    [(memv v '(1 2 4)) v]
    [else (raise-argument-error who "length field of 0/8/16/32 bits" v)]))

;; ---- ints ---------------------------------------------------------

(define (int-limit n)
  (arithmetic-shift 1 (* 8 n)))

(define (check-uint v n who)
  (unless (and (exact-nonnegative-integer? v) (< v (int-limit n)))
    (raise-argument-error who (format "uint~a" (* 8 n)) v)))

(define (check-sint v n who)
  (unless (and (exact-integer? v)
               (>= v (- (/ (int-limit n) 2)))
               (< v (/ (int-limit n) 2)))
    (raise-argument-error who (format "sint~a" (* 8 n)) v)))

;; Payload order per config [00369].
(define (put-int c v n cfg)
  (if (serialization-big-endian? cfg)
      (let loop ([i (sub1 n)] [v v])
        (unless (< i 0)
          (cur-u8 c (bitwise-and (arithmetic-shift v (* -8 i)) #xFF))
          (loop (sub1 i) v)))
      (let loop ([i 0] [v v])
        (unless (>= i n)
          (cur-u8 c (bitwise-and v #xFF))
          (loop (add1 i) (arithmetic-shift v -8))))))

(define (get-int r n cfg)
  (let loop ([i 0] [v 0])
    (if (= i n)
        v
        (loop (add1 i)
              (if (serialization-big-endian? cfg)
                  (+ (arithmetic-shift v 8) (rd-u8 r))
                  (+ v (arithmetic-shift (rd-u8 r) (* 8 i))))))))

(define (get-signed r n cfg)
  (define v (get-int r n cfg))
  (define half (arithmetic-shift 1 (sub1 (* 8 n))))
  (if (>= v half) (- v (arithmetic-shift 1 (* 8 n))) v))

(define (make-int-codes n signed?)
  (define who (string->symbol (format "~a~a-c" (if signed? "sint" "uint") (* 8 n))))
  (codec
   (lambda (v c cfg)
     (if signed?
         (begin (check-sint v n who)
                (put-int c (if (< v 0) (+ v (int-limit n)) v) n cfg))
         (begin (check-uint v n who)
                (put-int c v n cfg))))
   (lambda (r cfg) (if signed? (get-signed r n cfg) (get-int r n cfg)))
   n))

(define uint8-c  (make-int-codes 1 #f))
(define uint16-c (make-int-codes 2 #f))
(define uint32-c (make-int-codes 4 #f))
(define uint64-c (make-int-codes 8 #f))
(define sint8-c  (make-int-codes 1 #t))
(define sint16-c (make-int-codes 2 #t))
(define sint32-c (make-int-codes 4 #t))
(define sint64-c (make-int-codes 8 #t))

;; IEEE 754 binary32/binary64.
(define float32-c
  (codec (lambda (v c cfg)
           (unless (real? v) (raise-argument-error 'float32-c "real?" v))
           (cur-raw c (real->floating-point-bytes (exact->inexact v) 4 (serialization-big-endian? cfg))))
         (lambda (r cfg)
           (when (< (rd-remaining r) 4) (malformed "premature end in float32"))
           (begin0 (floating-point-bytes->real (reader-bs r) (serialization-big-endian? cfg)
                                               (reader-pos r) (+ (reader-pos r) 4))
             (rd-skip r 4)))
         4))

(define float64-c
  (codec (lambda (v c cfg)
           (unless (real? v) (raise-argument-error 'float64-c "real?" v))
           (cur-raw c (real->floating-point-bytes (exact->inexact v) 8 (serialization-big-endian? cfg))))
         (lambda (r cfg)
           (when (< (rd-remaining r) 8) (malformed "premature end in float64"))
           (begin0 (floating-point-bytes->real (reader-bs r) (serialization-big-endian? cfg)
                                               (reader-pos r) (+ (reader-pos r) 8))
             (rd-skip r 8)))
         8))

;; BOOLEAN: one byte, only the lowest bit is interpreted [00615].
(define boolean-c
  (codec (lambda (v c cfg)
           (unless (boolean? v) (raise-argument-error 'boolean-c "boolean?" v))
           (cur-u8 c (if v 1 0)))
         (lambda (r cfg) (not (zero? (bitwise-and (rd-u8 r) 1))))
         1))

;; ------------------------------------------------------------------
;; Alignment

(define (effective-alignment cfg)
  ;; no padding in unaligned mode or in TLV mode ([00222])
  (if (and (serialization-aligned? cfg) (not (serialization-tlv? cfg)))
      (serialization-variable-alignment-bytes cfg)
      1))

(define (align-write c cfg)
  (define a (effective-alignment cfg))
  (when (> a 1)
    (define pad (modulo (- a (modulo (cursor-size c) a)) a))
    (cur-fill c pad)))

(define (align-read r cfg)
  (define a (effective-alignment cfg))
  (when (> a 1)
    (define pad (modulo (- a (modulo (reader-pos r) a)) a))
    (when (> pad (rd-remaining r)) (malformed "truncated alignment padding"))
    (rd-skip r pad)))

;; Padding after a variable-size element that is not the last element of
;; its container [00611]; skipped entirely in TLV mode [00222].
(define (pad-after-element c variable? more-follow? cfg)
  (when (and variable? more-follow?) (align-write c cfg)))

(define (skip-after-element r variable? more-follow? cfg)
  (when (and variable? more-follow?) (align-read r cfg)))

;; ------------------------------------------------------------------
;; Strings
;;
;; Every string starts with a BOM and ends with a zero termination
;; [00087][00948][00084]. Dynamic strings carry a length field that
;; includes BOM and termination but not the length field itself
;; [00090][00095]. Fixed strings occupy exactly their wire size; shorter
;; content is accepted when correctly terminated [00912], longer content
;; is rejected [00911][00914].

(struct string-impl (utf16? big-endian? length-bytes fixed-bytes))

(define (bom-bytes si)
  (if (string-impl-utf16? si)
      (if (string-impl-big-endian? si) #"\xFE\xFF" #"\xFF\xFE")
      #"\xEF\xBB\xBF"))

;; UTF-16 code units with surrogate pairs (strings are sequences of code
;; points, some beyond the BMP).
(define (string->utf16-units s)
  (apply
   append
   (for/list ([ch (in-string s)])
     (define cp (char->integer ch))
     (if (< cp #x10000)
         (list cp)
         (list (+ #xD800 (arithmetic-shift (- cp #x10000) -10))
               (+ #xDC00 (bitwise-and (- cp #x10000) #x3FF)))))))

(define (encode-string-body s si)
  (define bom (bom-bytes si))
  (define body
    (if (string-impl-utf16? si)
        (let* ([units (string->utf16-units s)]
               [data
                (apply bytes-append
                       (for/list ([u units])
                         (if (string-impl-big-endian? si)
                             (bytes (arithmetic-shift u -8) (bitwise-and u #xFF))
                             (bytes (bitwise-and u #xFF) (arithmetic-shift u -8)))))])
          (bytes-append bom data (bytes 0 0)))
        (bytes-append bom (string->bytes/utf-8 s) (bytes 0))))
  (define fixed (string-impl-fixed-bytes si))
  (when fixed
    (when (> (bytes-length body) fixed)
      (malformed "string content of ~a bytes exceeds the fixed size of ~a"
                 (bytes-length body) fixed))
    (set! body (bytes-append body (make-bytes (- fixed (bytes-length body)) 0))))
  body)

;; `strict-end?` = dynamic strings (termination must sit at the end);
;; fixed strings accept termination anywhere, the remainder must be
;; padding.
(define (decode-string-body body si strict-end?)
  (define bom (bom-bytes si))
  (unless (>= (bytes-length body) (bytes-length bom))
    (malformed "string body shorter than its BOM"))
  (unless (equal? (subbytes body 0 (bytes-length bom)) bom)
    (malformed "missing byte order mark at string start"))
  (define rest (subbytes body (bytes-length bom)))
  (if (string-impl-utf16? si)
      (decode-utf16 rest si strict-end?)
      (decode-utf8 rest strict-end?)))

(define (decode-utf8 rest strict-end?)
  (unless (>= (bytes-length rest) 1)
    (malformed "UTF-8 string missing zero termination"))
  (define term-pos (for/first ([i (in-range (bytes-length rest))]
                               #:when (zero? (bytes-ref rest i)))
                     i))
  (unless term-pos (malformed "UTF-8 string not zero terminated"))
  (when strict-end?
    (unless (= term-pos (sub1 (bytes-length rest)))
      (malformed "UTF-8 string termination not at end of length")))
  (bytes->string/utf-8 (subbytes rest 0 term-pos)))

(define (decode-utf16 rest si strict-end?)
  (unless (even? (bytes-length rest))
    (malformed "UTF-16 string has odd length; last byte ignored is not accepted here"))
  (unless (>= (bytes-length rest) 2)
    (malformed "UTF-16 string missing zero termination"))
  (define big? (string-impl-big-endian? si))
  (define n-units (/ (bytes-length rest) 2))
  (define units
    (for/vector ([i (in-range n-units)])
      (define b0 (bytes-ref rest (* 2 i)))
      (define b1 (bytes-ref rest (+ (* 2 i) 1)))
      (if big? (+ (arithmetic-shift b0 8) b1) (+ (arithmetic-shift b1 8) b0))))
  (define term-pos
    (for/first ([i (in-range n-units)] #:when (zero? (vector-ref units i))) i))
  (unless term-pos (malformed "UTF-16 string not zero terminated"))
  (when strict-end?
    (unless (= term-pos (sub1 n-units))
      (malformed "UTF-16 string termination not at end of length")))
  ;; padding after the termination must be zero
  (for ([i (in-range (add1 term-pos) n-units)])
    (unless (zero? (vector-ref units i))
      (malformed "non-zero padding after string termination")))
  ;; combine surrogate pairs
  (let loop ([i 0] [chars '()])
    (cond
      [(= i term-pos) (list->string (reverse chars))]
      [else
       (define u (vector-ref units i))
       (cond
         [(<= #xD800 u #xDBFF)
          (unless (< (add1 i) term-pos)
            (malformed "unpaired high surrogate in UTF-16 string"))
          (define lo (vector-ref units (add1 i)))
          (unless (<= #xDC00 lo #xDFFF)
            (malformed "unpaired high surrogate in UTF-16 string"))
          (loop (+ i 2)
                (cons (integer->char (+ #x10000
                                        (arithmetic-shift (- u #xD800) 10)
                                        (- lo #xDC00)))
                      chars))]
         [(<= #xDC00 u #xDFFF)
          (malformed "unpaired low surrogate in UTF-16 string")]
         [else (loop (add1 i) (cons (integer->char u) chars))])])))

(define (make-string-codec si)
  (codec
   (lambda (v c cfg)
     (unless (string? v) (raise-argument-error 'string-c "string?" v))
     (define body (encode-string-body v si))
     (define lenb (cond
                    [(string-impl-fixed-bytes si) #f]
                    [(string-impl-length-bytes si)]
                    [else (serialization-length-field-bytes cfg)]))
     (cond
       [lenb
        (when (>= (bytes-length body) (arithmetic-shift 1 (* 8 lenb)))
          (malformed "string longer than the ~a-bit length field" (* 8 lenb)))
        (put-int c (bytes-length body) lenb cfg)
        (cur-raw c body)]
       [else (cur-raw c body)]))
   (lambda (r cfg)
     (define lenb (cond
                    [(string-impl-fixed-bytes si) #f]
                    [(string-impl-length-bytes si)]
                    [else (serialization-length-field-bytes cfg)]))
     (define body
       (cond
         [lenb
          (define n0 (get-int r lenb cfg))
          (when (> n0 (rd-remaining r)) (malformed "string length ~a exceeds remaining bytes" n0))
          (rd-raw r n0)]
         [(string-impl-fixed-bytes si) (rd-raw r (string-impl-fixed-bytes si))]
         [else (malformed "internal: string without length field or fixed size")]))
     (decode-string-body body si (and (not (string-impl-fixed-bytes si)) #t)))
   #f))

;; Dynamic string with an explicit or configured length field.
(define (string-c [encoding 'utf-8] [length-bytes 'default])
  (unless (memq encoding '(utf-8 utf-16be utf-16le))
    (raise-argument-error 'string-c "'utf-8, 'utf-16be or 'utf-16le" encoding))
  (make-string-codec
   (string-impl (not (eq? encoding 'utf-8)) (eq? encoding 'utf-16be)
                (resolve-length-bytes length-bytes 'string-c)
                #f)))

(define dyn-string string-c)

(define utf-8-string (string-c 'utf-8 'default))
(define utf-16be-string (string-c 'utf-16be 'default))
(define utf-16le-string (string-c 'utf-16le 'default))

;; Fixed size string: exactly `n` wire bytes including BOM and zero
;; termination.
(define (fixed-string n [encoding 'utf-8])
  (unless (exact-positive-integer? n)
    (raise-argument-error 'fixed-string "exact-positive-integer?" n))
  (unless (memq encoding '(utf-8 utf-16be utf-16le))
    (raise-argument-error 'fixed-string "'utf-8, 'utf-16be or 'utf-16le" encoding))
  (make-string-codec
   (string-impl (not (eq? encoding 'utf-8)) (eq? encoding 'utf-16be)
                #f n)))

;; ------------------------------------------------------------------
;; Arrays

(define (encode-elements vals element-c c cfg)
  (let loop ([vals vals])
    (when (pair? vals)
      (encode-with element-c (car vals) c cfg)
      (pad-after-element c (not (codec-fixed-size element-c)) (pair? (cdr vals)) cfg)
      (loop (cdr vals)))))

;; n elements; an optional length field may precede the elements
;; ([00944], length covers the elements only [00377]).
(define (fixed-array n element-c [length-bytes 'default])
  (unless (exact-nonnegative-integer? n)
    (raise-argument-error 'fixed-array "exact-nonnegative-integer?" n))
  (define lb (resolve-length-bytes length-bytes 'fixed-array))
  (define elem-fixed (codec-fixed-size element-c))
  (codec
   (lambda (v c cfg)
     (unless (list? v) (raise-argument-error 'fixed-array "list?" v))
     (unless (= (length v) n)
       (raise-argument-error 'fixed-array (format "list of ~a elements" n) v))
     (cond
       [lb
        (define pos (cursor-size c))
        (put-int c 0 lb cfg) ; placeholder
        (encode-elements v element-c c cfg)
        (patch-int c pos (- (cursor-size c) pos lb) lb cfg)]
       [else (encode-elements v element-c c cfg)]))
   (lambda (r cfg)
     (define limit
       (cond
         [lb
          (define n0 (get-int r lb cfg))
          (when (> n0 (rd-remaining r)) (malformed "array length ~a exceeds remaining bytes" n0))
          (+ (reader-pos r) n0)]
         [else (reader-end r)]))
     (define saved-end (reader-end r))
     (set-reader-end! r limit)
     (define vals
       (let loop ([acc '()])
         (cond
           [(= (length acc) n) (reverse acc)]
           [(>= (reader-pos r) limit)
            (malformed "fixed array truncated: ~a of ~a elements" (length acc) n)]
           [(and (pair? acc) (not (codec-fixed-size element-c)))
            (align-read r cfg)
            (loop (cons (decode-with element-c r cfg) acc))]
           [else (loop (cons (decode-with element-c r cfg) acc))])))
     (set-reader-end! r saved-end)
     (when lb (set-reader-pos! r limit))
     vals)
   (and elem-fixed (not lb) (* n elem-fixed))))

;; Dynamic length array: length field excludes itself [00377].
(define (dyn-array element-c [length-bytes 'default])
  (define lb (resolve-length-bytes length-bytes 'dyn-array))
  (codec
   (lambda (v c cfg)
     (unless (list? v) (raise-argument-error 'dyn-array "list?" v))
     (define lenb (or lb (serialization-length-field-bytes cfg)))
     (define pos (cursor-size c))
     (put-int c 0 lenb cfg) ; placeholder
     (encode-elements v element-c c cfg)
     (patch-int c pos (- (cursor-size c) pos lenb) lenb cfg))
   (lambda (r cfg)
     (define lenb (or lb (serialization-length-field-bytes cfg)))
     (define n0 (get-int r lenb cfg))
     (when (> n0 (rd-remaining r)) (malformed "array length ~a exceeds remaining bytes" n0))
     (define limit (+ (reader-pos r) n0))
     (define saved-end (reader-end r))
     (set-reader-end! r limit)
     (define vals
       (let loop ([acc '()])
         (cond
           [(>= (reader-pos r) limit) (reverse acc)]
           [(and (pair? acc) (not (codec-fixed-size element-c)))
            (align-read r cfg)
            (loop (cons (decode-with element-c r cfg) acc))]
           [else (loop (cons (decode-with element-c r cfg) acc))])))
     (set-reader-end! r saved-end)
     (set-reader-pos! r limit)
     vals)
   #f))

;; Patch a length field previously written at `pos` (cfg byte order).
(define (patch-int c pos v n cfg)
  (define tmp (make-cursor))
  (put-int tmp v n cfg)
  (define enc-bytes (cursor->bytes tmp))
  (unless (>= (cursor-size c) (+ pos n))
    (malformed "internal: length field patch position outside buffer"))
  (for ([i (in-range n)])
    (vector-set! (cursor-buf c) (+ pos i) (bytes-ref enc-bytes i))))

;; ------------------------------------------------------------------
;; Structs and member lists

(struct struct-member (name codec data-id optional?))

(define (member name codec [data-id #f] #:optional [optional? #f])
  (unless (symbol? name) (raise-argument-error 'member "symbol?" name))
  (unless (codec? codec) (raise-argument-error 'member "codec?" codec))
  (unless (or (not data-id) (and (exact-nonnegative-integer? data-id) (< data-id 4096)))
    (raise-argument-error 'member "12 bit data-id" data-id))
  (struct-member name codec data-id optional?))

(define (check-member-level members who)
  (define ids (map struct-member-data-id members))
  (unless (or (andmap not ids) (andmap values ids))
    (raise-argument-error who
                          "data-ids defined for all members of a level or none"
                          members)))

;; Serializes a member sequence against a dict mapping member names to
;; values. Used as struct bodies and method payloads. In TLV mode,
;; members carrying a data-id are prefixed by their tag; unknown tags
;; are skipped via the wire type [00217]; missing required members abort
;; parsing [00218]; absent optional members are ignored [00223] and
;; decode to 'absent.
(define (members-c members)
  (unless (and (list? members) (pair? members) (andmap struct-member? members))
    (raise-argument-error 'members-c "non-empty list of members" members))
  (check-member-level members 'members-c)
  (codec
   (lambda (v c cfg)
     (unless (dict? v) (raise-argument-error 'members-c "dict of member values" v))
     (for ([m members] [i (in-naturals)])
       (define val (dict-ref v (struct-member-name m) 'absent))
       (cond
         [(serialization-tlv? cfg)
          (when (eq? val 'absent)
            (unless (struct-member-optional? m)
              (malformed "required member ~a absent" (struct-member-name m))))
          (unless (eq? val 'absent)
            (write-tag c (struct-member-data-id m) (wire-type (struct-member-codec m) cfg))
            (write-tagged-member (struct-member-codec m) val c cfg))]
         [else
          (when (eq? val 'absent)
            (unless (struct-member-optional? m)
              (malformed "required member ~a absent" (struct-member-name m))))
          (unless (eq? val 'absent)
            (encode-with (struct-member-codec m) val c cfg)
            (pad-after-element c (not (codec-fixed-size (struct-member-codec m)))
                               (< (add1 i) (length members)) cfg))])))
   (lambda (r cfg)
     (if (serialization-tlv? cfg)
         (decode-tagged-members members r cfg)
         (let ([acc (make-hasheq)])
           (for ([m members] [i (in-naturals)])
             (hash-set! acc (struct-member-name m) (decode-with (struct-member-codec m) r cfg))
             (skip-after-element r (not (codec-fixed-size (struct-member-codec m)))
                                 (< (add1 i) (length members)) cfg))
           ;; expose immutable hashes to callers (equal?-comparable)
           (for/hasheq ([(k v) (in-hash acc)]) (values k v)))))
   #f))

;; A struct with an optional length field covering its body [00370]; in
;; TLV mode the length field is required [00241].
(define (struct-c members [length-bytes 'default])
  (unless (and (list? members) (pair? members) (andmap struct-member? members))
    (raise-argument-error 'struct-c "non-empty list of members" members))
  (check-member-level members 'struct-c)
  (define lb (resolve-length-bytes length-bytes 'struct-c))
  (define body (members-c members))
  (codec
   (lambda (v c cfg)
     (define lenb (or lb (serialization-length-field-bytes cfg)))
     (when (serialization-tlv? cfg)
       (unless lenb
         (raise-argument-error 'struct-c "TLV requires a struct length field > 0" length-bytes)))
     (define pos (cursor-size c))
     (put-int c 0 lenb cfg)
     (encode-with body v c cfg)
     (patch-int c pos (- (cursor-size c) pos lenb) lenb cfg))
   (lambda (r cfg)
     (define lenb (or lb (serialization-length-field-bytes cfg)))
     (define n0 (get-int r lenb cfg))
     (when (> n0 (rd-remaining r)) (malformed "struct length ~a exceeds remaining bytes" n0))
     (define limit (+ (reader-pos r) n0))
     (define saved-end (reader-end r))
     (set-reader-end! r limit)
     (begin0 (decode-with body r cfg)
       (set-reader-end! r saved-end)
       (set-reader-pos! r limit)))
   #f))

;; ------------------------------------------------------------------
;; TLV helpers

;; Tag [00203]: 2 bytes; bit 7 reserved, bits 6-4 wire type, bits 3-0 the
;; high nibble of the 12 bit data id, second byte the low byte.
(define (write-tag c data-id wire-type)
  (cur-u8 c (+ (arithmetic-shift wire-type 4) (bitwise-and (arithmetic-shift data-id -8) #xF)))
  (cur-u8 c (bitwise-and data-id #xFF)))

(define (read-tag r)
  (define b0 (rd-u8 r))
  (define b1 (rd-u8 r))
  (values (arithmetic-shift b0 -4)
          (+ (arithmetic-shift (bitwise-and b0 #xF) 8) b1)))

(define (wire-type c cfg)
  (define fs (codec-fixed-size c))
  (cond
    [fs (case fs [(1) 0] [(2) 1] [(4) 2] [(8) 3] [else 4])]
    [else (case (serialization-length-field-bytes cfg) [(1) 5] [(2) 6] [(4) 4])]))

(define (write-tagged-member codec v c cfg)
  (cond
    [(codec-fixed-size codec) (encode-with codec v c cfg)]
    [else
     (define wt (wire-type codec cfg))
     (define lenb (case wt [(5) 1] [(6) 2] [(4) (serialization-length-field-bytes cfg)]))
     (define pos (cursor-size c))
     (put-int c 0 lenb cfg)
     (encode-with codec v c cfg)
     (patch-int c pos (- (cursor-size c) pos lenb) lenb cfg)]))

(define (read-tagged-member codec wt r cfg)
  (cond
    [(codec-fixed-size codec) (decode-with codec r cfg)]
    [else
     (define lenb (case wt [(5) 1] [(6) 2] [(4) (serialization-length-field-bytes cfg)]))
     (define n0 (get-int r lenb cfg))
     (when (> n0 (rd-remaining r)) (malformed "member length ~a exceeds remaining bytes" n0))
     (define limit (+ (reader-pos r) n0))
     (define saved-end (reader-end r))
     (set-reader-end! r limit)
     (begin0 (decode-with codec r cfg)
       (set-reader-end! r saved-end)
       (set-reader-pos! r limit))]))

(define (skip-tagged-member wt r cfg)
  (cond
    [(memv wt '(0 1 2 3)) (rd-skip r (case wt [(0) 1] [(1) 2] [(2) 4] [(3) 8]))]
    [else
     (define lenb (case wt [(5) 1] [(6) 2] [(4) (serialization-length-field-bytes cfg)]))
     (define n0 (get-int r lenb cfg))
     (when (> n0 (rd-remaining r)) (malformed "unknown member length ~a exceeds remaining bytes" n0))
     (rd-skip r n0)]))

(define (decode-tagged-members members r cfg)
  (define acc (make-hasheq))
  (let loop ([remaining members])
    (cond
      ;; wire exhausted: only optional members may remain absent [00223]
      [(rd-eof? r)
       (for ([m remaining])
         (if (struct-member-optional? m)
             (hash-set! acc (struct-member-name m) 'absent)
             (malformed "required member ~a absent" (struct-member-name m))))]
      [else
       (define-values (wt data-id) (read-tag r))
       (define m (findf (lambda (m) (equal? (struct-member-data-id m) data-id)) remaining))
       (cond
         [m
          (unless (= wt (wire-type (struct-member-codec m) cfg))
            (malformed "wire type ~a does not match member ~a" wt (struct-member-name m)))
          (hash-set! acc (struct-member-name m) (read-tagged-member (struct-member-codec m) wt r cfg))
          (loop (remq m remaining))]
         [else
          (skip-tagged-member wt r cfg)
          (loop remaining)])]))
    (for/hasheq ([(k v) (in-hash acc)]) (values k v)))

;; ------------------------------------------------------------------
;; Unions / variants
;;
;; Wire layout (Table 4.8): length field, type selector, data with
;; padding. Length covers data + padding only [00126]; type value 0 is
;; reserved for NULL [00907]. Data padding aligns to
;; `padding-alignment-bytes` (the spec's examples pad to 32 bit).

(struct someip-union (type value) #:transparent)

(define (union-c cases
                 #:type-field-bytes [type-field-bytes 'default]
                 #:length-field-bytes [length-field-bytes 'default]
                 #:padding-alignment-bytes [padding-alignment-bytes 4]
                 #:null-allowed? [null-allowed? #f])
  (unless (and (list? cases) (pair? cases))
    (raise-argument-error 'union-c "non-empty list of (list type-value codec) cases" cases))
  (define valid-cases
    (for/list ([kase cases])
      (match kase
        [(list (? exact-nonnegative-integer? tv) (? codec? c)) (cons tv c)]
        [_ (raise-argument-error 'union-c "(list type-value codec) case" kase)])))
  (when (assv 0 valid-cases)
    (raise-argument-error 'union-c "type value 0 is reserved for NULL" cases))
  (define dups (check-duplicates (map car valid-cases)))
  (when dups
    (raise-argument-error 'union-c "duplicate type values" dups))
  (unless (memv padding-alignment-bytes '(1 2 4 8 16 32))
    (raise-argument-error 'union-c "padding alignment of 8..256 bits" padding-alignment-bytes))
  (codec
   (lambda (v c cfg)
     (define tfb (if (eq? type-field-bytes 'default) (serialization-length-field-bytes cfg) type-field-bytes))
     (define lfb (if (eq? length-field-bytes 'default) (serialization-length-field-bytes cfg) length-field-bytes))
     (define pos (cursor-size c))
     (put-int c 0 lfb cfg) ; length placeholder
     (put-int c (if (and v (someip-union? v)) (someip-union-type v) 0) tfb cfg)
     (cond
       [(not v)
        (unless null-allowed?
          (raise-argument-error 'union-c "NULL union not allowed by configuration" v))]
       [else
        (unless (someip-union? v) (raise-argument-error 'union-c "someip-union?" v))
        (define kase (assv (someip-union-type v) valid-cases))
        (unless kase
          (raise-argument-error 'union-c "union type not in case list" (someip-union-type v)))
        (encode-with (cdr kase) (someip-union-value v) c cfg)
        (define pad (modulo (- padding-alignment-bytes
                              (modulo (cursor-size c) padding-alignment-bytes))
                            padding-alignment-bytes))
        (cur-fill c pad)])
     ;; length covers data + padding only [00126]
     (patch-int c pos (- (cursor-size c) pos lfb tfb) lfb cfg))
   (lambda (r cfg)
     (define tfb (if (eq? type-field-bytes 'default) (serialization-length-field-bytes cfg) type-field-bytes))
     (define lfb (if (eq? length-field-bytes 'default) (serialization-length-field-bytes cfg) length-field-bytes))
     (define n0 (get-int r lfb cfg))
     ;; the covered block is length field + type field + data/padding
     (define limit (+ (reader-pos r) n0 tfb))
     (when (> limit (+ (reader-pos r) (rd-remaining r)))
       (malformed "union length ~a exceeds remaining bytes" n0))
     (define saved-end (reader-end r))
     (set-reader-end! r limit)
     (define tv (get-int r tfb cfg))
     (define result
       (cond
         [(zero? tv)
          (unless null-allowed? (malformed "NULL union not allowed by configuration"))
          (someip-union 0 #f)]
         [else
          (define kase (assv tv valid-cases))
          (unless kase (malformed "union type ~a not in case list" tv))
          (someip-union tv (decode-with (cdr kase) r cfg))]))
     (set-reader-end! r saved-end)
     (set-reader-pos! r limit)
     result)
   #f))

;; ------------------------------------------------------------------
;; Top level entry points

(define (encode-payload c v [cfg (current-serialization)])
  (unless (codec? c) (raise-argument-error 'encode-payload "codec?" c))
  (define cur (make-cursor))
  (encode-with c v cur cfg)
  (cursor->bytes cur))

;; Decode a single value; bytes left over in `bs` are ignored.
(define (decode-payload c bs [cfg (current-serialization)])
  (define-values (v consumed) (decode-payload* c bs cfg))
  v)

;; Returns the decoded value and the number of bytes consumed.
(define (decode-payload* c bs [cfg (current-serialization)])
  (unless (codec? c) (raise-argument-error 'decode-payload* "codec?" c))
  (unless (bytes? bs) (raise-argument-error 'decode-payload* "bytes?" bs))
  (define r (make-reader bs))
  (values (decode-with c r cfg) (reader-pos r)))

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (require rackunit)

  (define be (serialization-config))
  (define le (serialization-config #:big-endian? #f))

  ;; ---- primitives ----------------------------------------------

  (check-equal? (encode-payload uint16-c #x1234 be) (bytes #x12 #x34))
  (check-equal? (encode-payload uint16-c #x1234 le) (bytes #x34 #x12))
  (check-equal? (encode-payload uint32-c #xDEADBEEF be) (bytes #xDE #xAD #xBE #xEF))
  (check-equal? (encode-payload uint64-c 1 be)
                (bytes 0 0 0 0 0 0 0 1))
  (check-equal? (encode-payload sint16-c -2 be) (bytes #xFF #xFE))
  (check-equal? (encode-payload sint8-c -128 be) (bytes #x80))
  (check-equal? (encode-payload float32-c 1.0 be) (bytes #x3F #x80 #x00 #x00))
  (check-equal? (encode-payload float64-c 1.0 be)
                (bytes #x3F #xF0 0 0 0 0 0 0))

  (define round-trips
    (list (cons uint8-c  '(0 1 254))
          (cons sint8-c  '(0 1 127 -128 -1))
          (cons uint16-c '(0 1 65534 300))
          (cons sint16-c '(0 -1 -300 32767 -32768))
          (cons uint32-c '(0 4294967294 70000))
          (cons sint32-c '(0 -70000 2147483647 -2147483648))
          (cons uint64-c '(0 12345678901234 4294967296))
          (cons sint64-c '(0 -12345678901234))
          (cons float32-c '(1.5 -0.25 0.0))
          (cons float64-c '(1.5 -0.25 123456789.125))
          (cons boolean-c '(#t #f))))
  (for ([rt round-trips])
    (define c (car rt))
    (for ([v (cdr rt)])
      (define bs (encode-payload c v be))
      (define-values (v2 used) (decode-payload* c bs be))
      (check-equal? v2 v (format "~a round trip" v))
      (check-equal? used (bytes-length bs))))

  ;; range checks
  (check-exn exn:fail? (lambda () (encode-payload uint16-c 70000 be)))
  (check-exn exn:fail? (lambda () (encode-payload sint16-c 40000 be)))
  (check-exn exn:fail? (lambda () (encode-payload uint8-c -1 be)))

  ;; boolean: only the lowest bit is interpreted [00615]
  (check-false (decode-payload boolean-c (bytes 2) be))
  (check-true (decode-payload boolean-c (bytes 255) be))

  ;; ---- strings -------------------------------------------------

  ;; "a" UTF-8: length 5 = BOM(3) + 'a' + termination
  (check-equal? (encode-payload utf-8-string "a" be)
                (bytes 0 0 0 5 #xEF #xBB #xBF 97 0))
  ;; "a" UTF-16BE: length 6 = BOM(2) + unit(2) + termination(2)
  (check-equal? (encode-payload utf-16be-string "a" be)
                (bytes 0 0 0 6 #xFE #xFF 0 97 0 0))
  (check-equal? (encode-payload utf-16le-string "a" be)
                (bytes 0 0 0 6 #xFF #xFE 97 0 0 0))
  ;; empty string: BOM + termination
  (check-equal? (encode-payload utf-8-string "" be)
                (bytes 0 0 0 4 #xEF #xBB #xBF 0))
  (check-equal? (encode-payload utf-16be-string "" be)
                (bytes 0 0 0 4 #xFE #xFF 0 0))

  ;; 16 bit length field
  (check-equal? (encode-payload (dyn-string 'utf-8 2) "a" be)
                (bytes 0 5 #xEF #xBB #xBF 97 0))

  ;; astral plane char round trip via surrogate pairs
  (define rocket "🚀 rocket")
  (for ([enc (list 'utf-8 'utf-16be 'utf-16le)])
    (define bs (encode-payload (dyn-string enc) rocket be))
    (check-equal? (decode-payload (dyn-string enc) bs) rocket))

  ;; fixed string: short content accepted, padded
  (check-equal? (encode-payload (fixed-string 6 'utf-8) "hi" be)
                (bytes #xEF #xBB #xBF 104 105 0))
  (check-equal? (decode-payload (fixed-string 6 'utf-8)
                                (bytes #xEF #xBB #xBF 104 105 0) be)
                "hi")
  (check-exn exn:fail:someip:malformed?
             (lambda () (encode-payload (fixed-string 3 'utf-8) "abc" be)))
  ;; no BOM / no termination / embedded NUL
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-payload utf-8-string (bytes 0 0 0 2 97 0) be)))
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-payload utf-8-string (bytes 0 0 0 2 #xEF #xBB) be)))
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-payload utf-8-string (bytes 0 0 0 5 #xEF #xBB #xBF 0 97) be)))

  ;; ---- arrays ---------------------------------------------------

  (check-equal? (encode-payload (fixed-array 3 uint16-c) '(1 2 3) be)
                (bytes 0 1 0 2 0 3))
  ;; with length field: length covers elements only
  (check-equal? (encode-payload (fixed-array 3 uint16-c 4) '(1 2 3) be)
                (bytes 0 0 0 6 0 1 0 2 0 3))
  (check-equal? (encode-payload (dyn-array uint8-c) (list 1 2 3 4) be)
                (bytes 0 0 0 4 1 2 3 4))
  (check-equal? (encode-payload (dyn-array uint8-c) '() be)
                (bytes 0 0 0 0))

  ;; variable-size elements get alignment padding between them [00611]
  (define str-arr (dyn-array utf-8-string))
  (define arr-bytes (encode-payload str-arr (list "a" "b") be))
  ;; "a" is 9 bytes, pad to the next 8-byte boundary (3), "b" 9 -> 21
  (check-equal? (subbytes arr-bytes 0 4) (bytes 0 0 0 21))
  (check-equal? (decode-payload str-arr arr-bytes be) (list "a" "b"))

  ;; unaligned mode packs elements back to back
  (define no-align (serialization-config #:aligned? #f))
  (define arr2 (encode-payload str-arr (list "a" "b") no-align))
  (check-equal? (subbytes arr2 0 4) (bytes 0 0 0 18))
  (check-equal? (decode-payload str-arr arr2 no-align) (list "a" "b"))

  ;; declared length longer than elements: extra bytes skipped [00917]
  (define padded-arr
    (bytes 0 0 0 8 0 1 0 2 0 0 0 0))
  (check-equal? (decode-payload (fixed-array 2 uint16-c 4) padded-arr be)
                (list 1 2))

  ;; ---- struct with length field [00370] --------------------------

  (define point-c
    (struct-c (list (member 'x float32-c)
                    (member 'y float32-c))))
  (define point-bytes (encode-payload point-c (hasheq 'x 1.0 'y 2.0) be))
  (check-equal? point-bytes
                (bytes 0 0 0 8 #x3F #x80 0 0 #x40 0 0 0))
  (check-equal? (decode-payload point-c point-bytes be)
                (hasheq 'x 1.0 'y 2.0))

  ;; Figure 4.3 shape: uint16 + dynamic array + uint32 + uint64; padding
  ;; is inserted after the variable array before the next member.
  (define fig-c
    (members-c (list (member 'm1 uint16-c)
                     (member 'm2 (dyn-array uint8-c))
                     (member 'm3 uint32-c)
                     (member 'm4 uint64-c))))
  (define fig-bytes
    (encode-payload fig-c (hasheq 'm1 1 'm2 (list 9 9 9) 'm3 2 'm4 3) be))
  ;; 2 + (4+3) + pad(to 8-byte boundary: 7) + 4 + 8 = 28 bytes
  (check-equal? (bytes-length fig-bytes) 28)
  (check-equal? (bytes->u32 fig-bytes 16) 2)      ; uint32 after padding
  (check-equal? (decode-payload fig-c fig-bytes be)
                (hasheq 'm1 1 'm2 (list 9 9 9) 'm3 2 'm4 3))

  ;; ---- TLV ------------------------------------------------------

  (define tlv-cfg (serialization-config #:tlv? #f))
  (define tagged
    (members-c (list (member 'id uint16-c 1)
                     (member 'name (dyn-string 'utf-8) 2)
                     (member 'score uint32-c 3 #:optional #t))))
  (define tagged-cfg (serialization-config #:tlv? #t))
  (define tagged-bytes
    (encode-payload tagged (hasheq 'id 7 'name "ab") tagged-cfg))
  ;; tag layout [00203]: bits 6-4 wire type, bits 3-0 high nibble of the
  ;; data id. id=1 wire=1 -> #x10 #x01; id=2 wire=4 -> #x40 #x02. The
  ;; string member has an outer TLV length of 10 (its own length field 4
  ;; plus its body 6, BOM 3 + "ab" 2 + termination 1).
  (check-equal? (subbytes tagged-bytes 0 2) (bytes #x10 #x01))
  (check-equal? (subbytes tagged-bytes 4 6) (bytes #x40 #x02))
  ;; TLV length covers the member content: the string's own length field
  ;; (4) plus its body (6) => 10; the inner string length is 6.
  (check-equal? (bytes->u32 tagged-bytes 6) 10)
  (check-equal? (bytes->u32 tagged-bytes 10) 6)
  (check-equal? (decode-payload tagged tagged-bytes tagged-cfg)
                (hasheq 'id 7 'name "ab" 'score 'absent))
  ;; missing required member
  (check-exn exn:fail:someip:malformed?
             (lambda () (decode-payload tagged (subbytes tagged-bytes 0 4) tagged-cfg)))
  ;; unknown member skipped via wire type [00217]: tag id=9 wire=0 (1 byte)
  (define with-unknown
    (bytes-append (bytes #x09 #x90) ; reserved bit high nibble 9? wire 0 id #x090
                  (bytes #xFF)
                  tagged-bytes))
  (check-equal? (decode-payload tagged with-unknown tagged-cfg)
                (hasheq 'id 7 'name "ab" 'score 'absent))
  ;; optional member present
  (define tagged-full
    (encode-payload tagged (hasheq 'id 7 'name "ab" 'score 99) tagged-cfg))
  (check-equal? (decode-payload tagged tagged-full tagged-cfg)
                (hasheq 'id 7 'name "ab" 'score 99))

  ;; ---- unions ---------------------------------------------------

  (define u8 (union-c (list (list 1 uint8-c) (list 2 utf-8-string))))
  ;; uint8 case: length 4 (data+pad to 32 bit), type 4 bytes, data+pad
  (define u-bytes (encode-payload u8 (someip-union 1 7) be))
  (check-equal? u-bytes
                (bytes 0 0 0 4  0 0 0 1  7 0 0 0))
  (check-equal? (decode-payload u8 u-bytes be) (someip-union 1 7))
  ;; string case
  (define us-bytes (encode-payload u8 (someip-union 2 "a") be))
  (check-equal? (decode-payload u8 us-bytes be) (someip-union 2 "a"))
  ;; NULL
  (define unull (union-c (list (list 1 uint8-c)) #:null-allowed? #t))
  (check-equal? (decode-payload unull (encode-payload unull #f be) be)
                (someip-union 0 #f))
  (check-exn exn:fail? (lambda () (encode-payload u8 #f be)))
  ;; unknown type on the wire
  (check-exn exn:fail:someip:malformed?
             (lambda ()
               (decode-payload u8 (bytes 0 0 0 4 0 0 0 9 1 0 0 0) be)))
  ;; compact union: 1 byte length + 1 byte type
  (define ucompact (union-c (list (list 1 uint8-c))
                            #:type-field-bytes 1 #:length-field-bytes 1
                            #:padding-alignment-bytes 1))
  (check-equal? (encode-payload ucompact (someip-union 1 7) be)
                (bytes 1 1 7))
  (check-equal? (decode-payload ucompact (bytes 1 1 7) be) (someip-union 1 7))

  ;; codec values are applicable directly
  (check-equal? (uint16-c 5 be) (bytes 0 5))
  )
