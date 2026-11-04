#lang racket/base

;; UDP/TCP transport endpoints for SOME/IP (AUTOSAR FO, SOME/IP Protocol
;; Specification, chapter 4.2.1).
;;
;; Wire rules implemented here:
;;   [00140] several SOME/IP messages may share one datagram / TCP
;;           segment; the receiver splits them using the length field
;;   [00141] every message carries its own header
;;   [00142] unaligned (packed) messages are accepted
;;   [00720]-[00754] large UDP payloads are segmented with SOME/IP-TP on
;;           send and reassembled on receive
;;   [00707] one TCP connection per peer per endpoint; a broken
;;           connection is dropped so the next send re-establishes it
;;           [00706]
;;   SD specifics (SOME/IP-SD specification): SD runs over UDP only
;;   [00220] on SD_PORT 30490; the endpoint can join multicast groups so
;;   unicast and multicast SD datagrams arrive on one socket.
;;
;; The endpoint owns one custodian; closing it tears down every thread
;; and socket. Received messages are dispatched to a single handler
;; callback with the sender identity; protocol machines and the
;; provider/consumer layer do their own routing on top.

(require racket/contract
         racket/format
         racket/match
         racket/tcp
         racket/udp
         "message.rkt"
         "tp.rkt"
         "logging.rkt")

(provide (struct-out sender)
         (struct-out someip-endpoint)
         make-someip-endpoint
         endpoint-closed?
         endpoint-send-udp!
         endpoint-send-multicast!
         endpoint-send-tcp!
         endpoint-close!
         endpoint-udp-port
         endpoint-tcp-port)

(module+ test (require rackunit racket/list))

;; Sender identity of a received message: host and port for UDP
;; datagrams.
(struct sender (host port) #:transparent)

(struct someip-endpoint
  (custodian
   udp-sock
   udp-port
   tcp-listener      ; #f when no TCP
   tcp-port
   message-handler   ; (-> someip-message? sender any/c)
   tcp-connections   ; box: hash "host:port" -> (cons input-port output-port)
   tcp-lock
   reassembler       ; TP reassembly for inbound UDP segments
   closed?)
  #:mutable)

;; Build an endpoint. `message-handler` receives every fully decoded
;; SOME/IP message; for UDP datagrams carrying SOME/IP-TP segments the
;; handler sees the reassembled original message.
(define (make-someip-endpoint
         #:udp-port [udp-port #f]
         #:tcp-port [tcp-port #f]
         #:multicast-groups [multicast-groups '()] ; (list group-address)
         #:reuse-address? [reuse-address? #f]
         #:message-handler message-handler
         #:tp-max-size [tp-max-size (* 16 8192)])
  (unless (procedure? message-handler)
    (raise-argument-error 'make-someip-endpoint "procedure?" message-handler))
  (define cust (make-custodian))
  (parameterize ([current-custodian cust])
    ;; note: this Racket version has no SO_REUSEADDR for UDP sockets;
    ;; `reuse-address?` applies to the TCP listener only
    (define sock (udp-open-socket #f))
    (udp-bind! sock #f (or udp-port 0))
    (define-values (_lh bound-port _rh _rp)
      (udp-addresses sock #t))
    (for ([group-address multicast-groups])
      (udp-multicast-join-group! sock group-address)
      (udp-multicast-set-loopback! sock #f))
    ;; UDP reader thread
    (define reassembler (make-tp-reassembler #:max-size tp-max-size))
    (define buffer (make-bytes 65536))
    (thread
     (lambda ()
       (let loop ()
         (define-values (n host port)
           (with-handlers ([exn:fail? (lambda (_) (values eof #f #f))])
             (udp-receive! sock buffer)))
         (unless (eof-object? n)
           (when (positive? n)
             (with-handlers ([exn:fail? (lambda (e)
                                          (someip-log-warning
                                           "transport: dropped UDP datagram: ~a"
                                           (exn-message e)))])
               (dispatch-datagram message-handler
                                  reassembler
                                  buffer 0 n host port)))
           (loop)))))
    ;; TCP listener
    ;; tcp-port 0 would leave the listener port unknowable (Racket has
    ;; no listener-port query), so pick an ephemeral port ourselves
    (define chosen-tcp-port
      (cond
        [(not tcp-port) #f]
        [(exact-positive-integer? tcp-port) tcp-port]
        [else
         (define probe (udp-open-socket #f))
         (udp-bind! probe #f 0)
         (define-values (_lh p _rh _rp) (udp-addresses probe #t))
         (udp-close probe)
         p]))
    (define listener
      (and chosen-tcp-port
           (tcp-listen chosen-tcp-port 128 reuse-address?)))
    (when listener
      (thread
       (lambda ()
         (let accept-loop ()
           (define-values (in out) (tcp-accept listener))
           (thread (lambda () (tcp-reader-loop message-handler in out)))
           (accept-loop)))))
    (someip-endpoint cust sock bound-port listener chosen-tcp-port message-handler
                     (box (make-hash)) (make-semaphore 1)
                     reassembler
                     #f)))

;; UDP port the endpoint is bound to (SD messages must originate from
;; SD_PORT [00601]; binds make that possible).
(define (endpoint-udp-port ep)
  (someip-endpoint-udp-port ep))

(define (endpoint-tcp-port ep)
  (someip-endpoint-tcp-port ep))

(define (endpoint-closed? ep)
  (someip-endpoint-closed? ep))

;; Split one datagram into messages and dispatch each [00140]. TP
;; segments go into the reassembler; completed originals are dispatched
;; with the same sender identity.
(define (dispatch-datagram handler reassembler bs start end host port)
  (let loop ([pos start])
    (when (< pos end)
      (define frame (frame-length-at bs pos end))
      (cond
        [(not frame)
         (someip-log-warning "transport: trailing ~a bytes are not a SOME/IP frame"
                             (- end pos))]
        [(> frame (- end pos))
         (someip-log-warning "transport: declared frame length exceeds the datagram")]
        [else
         (define-values (m consumed) (decode-someip-message bs pos end))
         (cond
           [(tp-segment? m)
            (define completed (tp-feed! reassembler m (list host port)))
            (when completed
              (handler completed (sender host port)))]
           [else
            (handler m (sender host port))])
         (loop (+ pos consumed))]))))

;; TCP stream reader: buffers bytes, extracts and dispatches complete
;; frames.
(define (tcp-reader-loop handler in out)
  (let loop ([acc #""])
    (define chunk (make-bytes 65536))
    (define n
      (with-handlers ([exn:fail? (lambda (_) eof)])
        (read-bytes-avail! chunk in)))
    (cond
      [(eof-object? n)
       (with-handlers ([exn:fail? void]) (close-input-port in))
       (with-handlers ([exn:fail? void]) (close-output-port out))]
      [else
       (define acc2 (bytes-append acc (subbytes chunk 0 n)))
       (loop (dispatch-tcp-frames handler acc2))])))

;; Extract and dispatch all complete messages; returns the remainder.
(define (dispatch-tcp-frames handler bs)
  (let loop ([pos 0])
    (define total (bytes-length bs))
    (define frame (frame-length-at bs pos total))
    (cond
      [(not frame) (subbytes bs pos)]
      [(> frame (- total pos)) (subbytes bs pos)]
      [else
       (define-values (m consumed) (decode-someip-message bs pos total))
       (with-handlers ([exn:fail? (lambda (e)
                                    (someip-log-warning
                                     "transport: dropped TCP message: ~a"
                                     (exn-message e)))])
         (handler m (sender "tcp-peer" 0)))
       (loop (+ pos consumed))])))

;; Send one message over UDP; payloads beyond the UDP limit are
;; segmented with SOME/IP-TP [00720].
(define (endpoint-send-udp! ep host port msg)
  (when (someip-endpoint-closed? ep)
    (raise (exn:fail:someip "transport: endpoint is closed" (current-continuation-marks))))
  (for ([seg (segment-someip-message msg)])
    (udp-send-to (someip-endpoint-udp-sock ep) host port
                 (encode-someip-message seg))))

(define (endpoint-send-multicast! ep group-address port msg)
  (endpoint-send-udp! ep group-address port msg))

;; Send one message over TCP, reusing (or establishing) the connection
;; to host:port. A broken connection is dropped so the next send
;; re-establishes it [00706].
(define (endpoint-send-tcp! ep host port msg)
  (when (someip-endpoint-closed? ep)
    (raise (exn:fail:someip "transport: endpoint is closed" (current-continuation-marks))))
  (define key (format "~a:~a" host port))
  (define out
    (call-with-semaphore (someip-endpoint-tcp-lock ep)
                         (lambda ()
                           (define conn (hash-ref (unbox (someip-endpoint-tcp-connections ep))
                                                  key #f))
                           (and conn (cdr conn)))))
  (define out2
    (or out
        (let ()
          (define-values (in o) (tcp-connect host port))
          (call-with-semaphore (someip-endpoint-tcp-lock ep)
                               (lambda ()
                                 (hash-set! (unbox (someip-endpoint-tcp-connections ep))
                                            key (cons in o))))
          o)))
  (with-handlers ([exn:fail?
                   (lambda (e)
                     (drop-tcp-connection! ep key)
                     (raise e))])
    (write-bytes (encode-someip-message msg) out2)
    (flush-output out2)))

(define (drop-tcp-connection! ep key)
  (call-with-semaphore (someip-endpoint-tcp-lock ep)
                       (lambda ()
                         (define conn (hash-ref (unbox (someip-endpoint-tcp-connections ep))
                                                key #f))
                         (when conn
                           (with-handlers ([exn:fail? void]) (close-input-port (car conn)))
                           (with-handlers ([exn:fail? void]) (close-output-port (cdr conn)))
                           (hash-remove! (unbox (someip-endpoint-tcp-connections ep)) key)))))

;; Tear down the endpoint: closes sockets and kills all threads.
(define (endpoint-close! ep)
  (unless (someip-endpoint-closed? ep)
    (set-someip-endpoint-closed?! ep #t)
    (when (someip-endpoint-tcp-listener ep)
      (with-handlers ([exn:fail? void])
        (tcp-close (someip-endpoint-tcp-listener ep))))
    (for ([conn (in-hash-values (unbox (someip-endpoint-tcp-connections ep)))])
      (with-handlers ([exn:fail? void]) (close-input-port (car conn)))
      (with-handlers ([exn:fail? void]) (close-output-port (cdr conn))))
    (with-handlers ([exn:fail? void])
      (udp-close (someip-endpoint-udp-sock ep)))
    (custodian-shutdown-all (someip-endpoint-custodian ep))))

;; ------------------------------------------------------------------
;; Tests (loopback)

(module+ test
  (require rackunit
           racket/list)

  (define received '())
  (define (collect m sender)
    (set! received (cons (cons m (sender->list sender)) received)))
  (define (sender->list s) (list (sender-host s) (sender-port s)))
  (define (reset!) (set! received '()))
  (define (wait-for n [timeout-ms 5000])
    (let loop ([deadline (+ (current-inexact-milliseconds) timeout-ms)])
      (cond
        [(>= (length received) n) (reverse received)]
        [(> (current-inexact-milliseconds) deadline)
         (error (format "transport test: timeout waiting for ~a messages (have ~a)" n (length received)))]
        [else (sleep 0.01) (loop deadline)])))

  ;; ---- UDP round trip + packed messages ---------------------------
  (define ep-a (make-someip-endpoint #:message-handler collect))
  (define ep-b (make-someip-endpoint #:message-handler collect))
  (define m1 (make-someip-message #:service-id 1 #:method-id 1
                                  #:interface-version 1 #:message-type mt-request
                                  #:payload #"ping"))
  (endpoint-send-udp! ep-a "127.0.0.1" (endpoint-udp-port ep-b) m1)
  (define got (wait-for 1))
  (check-equal? (someip-message-service-id (car (car got))) 1)
  (check-equal? (first (cdr (car got))) "127.0.0.1")
  (check-true (exact-positive-integer? (second (cdr (car got)))))

  ;; two messages in one datagram [00140]
  (reset!)
  (define m2 (make-someip-message #:service-id 2 #:method-id 2
                                  #:interface-version 1 #:message-type mt-request))
  (define packed (bytes-append (encode-someip-message m1) (encode-someip-message m2)))
  (udp-send-to (someip-endpoint-udp-sock ep-a) "127.0.0.1"
               (endpoint-udp-port ep-b) packed)
  (check-equal? (length (wait-for 2)) 2)
  (check-equal? (someip-message-service-id (car (car (reverse received)))) 1)
  (check-equal? (someip-message-service-id (car (car received))) 2)

  ;; ---- TP over UDP: a 5880-byte payload reassembles ----------------
  (reset!)
  (define big (make-someip-message #:service-id 7 #:method-id 1
                                   #:interface-version 1 #:message-type mt-request
                                   #:payload (list->bytes
                                              (for/list ([i (in-range 5880)]) (modulo i 256)))))
  (endpoint-send-udp! ep-a "127.0.0.1" (endpoint-udp-port ep-b) big)
  (define got-big (wait-for 1))
  (check-equal? (someip-message-service-id (car (car got-big))) 7)
  (check-equal? (bytes-length (someip-message-payload (car (car got-big)))) 5880)

  ;; ---- TCP round trip ----------------------------------------------
  (reset!)
  (define ep-c (make-someip-endpoint #:tcp-port 0 #:message-handler collect))
  (define tcp-port (endpoint-tcp-port ep-c))
  (check-true (exact-positive-integer? tcp-port))
  (endpoint-send-tcp! ep-a "127.0.0.1" tcp-port m1)
  (endpoint-send-tcp! ep-a "127.0.0.1" tcp-port m2)
  (wait-for 2)
  (check-true (>= (length received) 2) "both TCP messages arrived")

  ;; ---- cleanup ------------------------------------------------------
  (endpoint-close! ep-a)
  (endpoint-close! ep-b)
  (endpoint-close! ep-c)
  (check-true (endpoint-closed? ep-a))
  (check-exn exn:fail:someip?
             (lambda () (endpoint-send-udp! ep-a "127.0.0.1" 40000 m1)))
)
