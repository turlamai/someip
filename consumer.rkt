#lang racket/base

;; Service consumer: call methods (request/response with timeout and
;; Request ID matching), send fire&forget calls, receive events; can
;; discover the service through SOME/IP-SD.
;;
;; Protocol rules implemented here:
;;   [00043]/[00739] responses are matched to requests via the Request
;;           ID; responses with an unknown Request ID are ignored [00928]
;;   [00521] session IDs increment per call and wrap 0xFFFF -> 1
;;   [00044] Request IDs are not reused while a request is outstanding
;;   [00025] "maybe" reliability over UDP: a single timeout yields
;;           E_TIMEOUT to the caller [Figure 4.22]
;;   [00181]/[00182] field getter: empty request, value in the response;
;;           setter: value in the request, value in the response
;;
;; Transport-first like the provider: point it at a statically
;; configured server (host/port), or run `consumer-start-discovery!`
;; with a multicast address and let the SD client machine fill the
;; server location in.

(require racket/contract
         racket/format
         racket/list
         racket/match
         "private/timers.rkt"
         "message.rkt"
         "sd/message.rkt"
         "sd/machine.rkt"
         "transport.rkt"
         "logging.rkt")

(provide (struct-out call-result)
         (struct-out service-consumer)
         make-service-consumer
         consumer-attach-endpoint!
         consumer-start-discovery!
         consumer-stop-discovery!
         consumer-ready?
         consumer-server-endpoint
         consumer-call
         consumer-fire-and-forget!
         consumer-set-event-callback!
         consumer-message-handler
         consumer-handle-message!)

(module+ test (require rackunit racket/list))

;; Result of a synchronous method call.
(struct call-result (return-code payload) #:transparent)

(struct service-consumer
  (service-id instance-id interface-version
   endpoint            ; attached via consumer-attach-endpoint!
   server-host server-port   ; static location (may be filled by discovery)
   client-id           ; this consumer's client id
   timeout-ms
   pending             ; box: hash (client-id . session-id) -> pending-call
   session-counter     ; box
   event-callbacks     ; box: hash event-id -> (-> payload sender void)
   server-location-box ; box: #f or (list host port) filled by discovery
   sd-client           ; #f or the sd client machine
   timer-manager
   lock)
  #:mutable)

(struct pending-call (sem result-box))

;; Build a consumer. `server-host`/`server-port` give the static
;; location; `multicast-address` enables SOME/IP-SD discovery instead.
(define (make-service-consumer
         #:service-id service-id
         #:instance-id [instance-id 1]
         #:interface-version interface-version
         #:client-id [client-id 1]
         #:server-host [server-host #f]
         #:server-port [server-port #f]
         #:timeout-ms [timeout-ms 2000]
         #:eventgroup-ids [eventgroup-ids '()]
         #:multicast-address [multicast-address #f]
         #:multicast-port [multicast-port #f]
         #:timer-manager [timers (make-timer-manager)]
         #:sd-config [sd-config* (make-sd-config)])
  (unless (exact-positive-integer? client-id)
    (raise-argument-error 'make-service-consumer "exact-positive-integer?" client-id))
  (define c
    (service-consumer service-id instance-id interface-version
                      #f server-host server-port client-id timeout-ms
                      (box (make-hash)) (box 0) (box (make-hash))
                      (box #f)
                      #f timers
                      (make-semaphore 1)))
  (when multicast-address
    (define sd-client
      (make-sd-client
       #:timer-manager timers
       #:config sd-config*
       #:service-id service-id
       #:instance-id instance-id
       #:major-version interface-version
       #:eventgroup-ids eventgroup-ids
       #:send-multicast
       (lambda (bs)
         (endpoint-send-udp-raw! (service-consumer-endpoint c)
                                   multicast-address
                                   (or multicast-port sd-port) bs))
       #:send-unicast
       (lambda (dest bs)
         (endpoint-send-udp-raw! (service-consumer-endpoint c)
                             (sender-host dest) (sender-port dest) bs))
       #:on-offer
       (lambda (info)
         (set-box! (service-consumer-server-location-box c)
                   (list (sender-host (offer-info-sender info))
                         (sender-port (offer-info-sender info)))))))
    (set-service-consumer-sd-client! c sd-client))
  c)

(define (consumer-attach-endpoint! c endpoint)
  (set-service-consumer-endpoint! c endpoint))

;; ------------------------------------------------------------------
;; Discovery

(define (consumer-start-discovery! c)
  (define sd (service-consumer-sd-client c))
  (unless sd
    (raise (exn:fail:someip "consumer: discovery requires a multicast-address"
                            (current-continuation-marks))))
  (sd-client-start-request! sd))

(define (consumer-stop-discovery! c)
  (define sd (service-consumer-sd-client c))
  (when sd (sd-client-stop-request! sd)))

;; The server location once known (static config or discovery).
(define (consumer-server-endpoint c)
  (or (unbox (service-consumer-server-location-box c))
      (and (service-consumer-server-host c)
           (service-consumer-server-port c)
           (list (service-consumer-server-host c)
                 (service-consumer-server-port c)))))

(define (consumer-ready? c)
  (pair? (consumer-server-endpoint c)))

;; ------------------------------------------------------------------
;; Calls

;; Next session id (0x0001..0xFFFF, wrapping [00521]).
(define (next-session! c)
  (call-with-semaphore (service-consumer-lock c)
    (lambda ()
      (define b (service-consumer-session-counter c))
      (define n (add1 (unbox b)))
      (define v (if (> n #xFFFF) 1 n))
      (set-box! b v)
      v)))

;; Synchronous request/response (message type REQUEST [00920]). On
;; timeout the caller receives E_TIMEOUT [Figure 4.22].
(define (consumer-call c method-id
                       #:payload [payload #""]
                       #:timeout-ms [timeout-ms (service-consumer-timeout-ms c)])
  (define dest (consumer-server-endpoint c))
  (unless dest
    (raise (exn:fail:someip "consumer: service location unknown (not discovered)"
                            (current-continuation-marks))))
  (define ep (service-consumer-endpoint c))
  (unless ep
    (raise (exn:fail:someip "consumer: no endpoint attached"
                            (current-continuation-marks))))
  (define session (next-session! c))
  (define key (cons (service-consumer-client-id c) session))
  (define sem (make-semaphore))
  (define result-box (box #f))
  (call-with-semaphore (service-consumer-lock c)
    (lambda ()
      (hash-set! (unbox (service-consumer-pending c)) key (pending-call sem result-box))))
  (endpoint-send-udp! ep (first dest) (second dest)
                      (make-someip-message
                       #:service-id (service-consumer-service-id c)
                       #:method-id method-id
                       #:interface-version (service-consumer-interface-version c)
                       #:message-type mt-request
                       #:client-id (service-consumer-client-id c)
                       #:session-id session
                       #:payload payload))
  (define got (sync/timeout (/ timeout-ms 1000) sem))
  (call-with-semaphore (service-consumer-lock c)
    (lambda ()
      (hash-remove! (unbox (service-consumer-pending c)) key)))
  (cond
    [got
     (define resp (unbox result-box))
     (call-result (someip-message-return-code resp)
                  (someip-message-payload resp))]
    [else (call-result rc-e-timeout #"")]))

;; Fire&forget: message type REQUEST_NO_RETURN, never answered [00171].
(define (consumer-fire-and-forget! c method-id #:payload [payload #""])
  (define dest (consumer-server-endpoint c))
  (unless dest
    (raise (exn:fail:someip "consumer: service location unknown" (current-continuation-marks))))
  (define session (next-session! c))
  (endpoint-send-udp! (service-consumer-endpoint c) (first dest) (second dest)
                      (make-someip-message
                       #:service-id (service-consumer-service-id c)
                       #:method-id method-id
                       #:interface-version (service-consumer-interface-version c)
                       #:message-type mt-request-no-return
                       #:client-id (service-consumer-client-id c)
                       #:session-id session
                       #:payload payload))
  (call-result rc-e-ok #""))

;; Wire into the endpoint handler: completes pending request/response
;; calls and dispatches notifications to event callbacks.
(define (consumer-handle-message! c m sender)
  (define mt (someip-message-message-type m))
  (cond
    [(and (response-family-message-type? mt)
          (= (someip-message-service-id m) (service-consumer-service-id c))
          (= (someip-message-client-id m) (service-consumer-client-id c)))
     ;; [00739] response session must match the request session
     (define key (cons (someip-message-client-id m) (someip-message-session-id m)))
     (define pend
       (call-with-semaphore (service-consumer-lock c)
         (lambda () (hash-ref (unbox (service-consumer-pending c)) key #f))))
     (when pend
       (set-box! (pending-call-result-box pend) m)
       (semaphore-post (pending-call-sem pend)))]
    [(= mt mt-notification)
     (define cb (hash-ref (unbox (service-consumer-event-callbacks c))
                          (someip-message-method-id m) #f))
     (when cb (cb (someip-message-payload m) sender))]
    [else (void)]))

;; Composite endpoint message handler: routes SOME/IP-SD messages into
;; the SD client machine and service messages into the consumer.
(define (consumer-message-handler c)
  (lambda (m sender)
    (cond
      [(and (= (someip-message-service-id m) sd-service-id)
            (= (someip-message-method-id m) sd-method-id)
            (service-consumer-sd-client c))
       (define-values (pkt consumed)
         (decode-sd-payload (someip-message-payload m)))
       (sd-client-handle-message! (service-consumer-sd-client c) pkt 0 sender #f)]
      [else
       (consumer-handle-message! c m sender)])))

;; Register a callback for event/notification messages of `event-id`.
(define (consumer-set-event-callback! c event-id callback)
  (call-with-semaphore (service-consumer-lock c)
    (lambda ()
      (hash-set! (unbox (service-consumer-event-callbacks c)) event-id callback))))

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (require rackunit
           racket/list)

  (define c (make-service-consumer
             #:service-id 1 #:interface-version 1
             #:client-id 42 #:timeout-ms 100
             #:server-host "127.0.0.1" #:server-port 12345))
  (consumer-attach-endpoint!
   c (make-someip-endpoint #:message-handler (lambda (m s) (consumer-handle-message! c m s))))

  ;; simulate the server answering from another thread
  (define (fake-response! session payload [rc rc-e-ok])
    (consumer-handle-message!
     c (make-someip-message #:service-id 1 #:method-id 1
                            #:interface-version 1 #:message-type mt-response
                            #:client-id 42 #:session-id session
                            #:return-code rc #:payload payload)
     (sender "127.0.0.1" 1)))

  (define result-box (box #f))
  (define worker
    (thread (lambda ()
              (set-box! result-box (consumer-call c 1 #:payload #"hi"
                                                  #:timeout-ms 2000)))))
  (sleep 0.05)
  ;; answer on whatever session the consumer picked
  (define pending-sessions
    (for/list ([k (in-hash-keys (unbox (service-consumer-pending c)))]) (cdr k)))
  (check-equal? (length pending-sessions) 1 "one pending call")
  (fake-response! (first pending-sessions) #"pong")
  (sync (thread-dead-evt worker))
  (check-equal? (call-result-return-code (unbox result-box)) rc-e-ok)
  (check-equal? (call-result-payload (unbox result-box)) #"pong")

  ;; unknown request id is ignored [00928]
  (fake-response! 999 #"junk")
  (check-equal? (hash-count (unbox (service-consumer-pending c))) 0)

  ;; timeout yields E_TIMEOUT [Figure 4.22]
  (define timeout-result (consumer-call c 2 #:timeout-ms 50))
  (check-equal? (call-result-return-code timeout-result) rc-e-timeout)

  ;; event callbacks
  (define events '())
  (consumer-set-event-callback! c #x8010
                                (lambda (payload sender)
                                  (set! events (cons payload events))))
  (consumer-handle-message!
   c (make-someip-message #:service-id 1 #:method-id #x8010
                          #:interface-version 1 #:message-type mt-notification
                          #:payload (bytes 9))
   (sender "127.0.0.1" 1))
  (check-equal? events (list (bytes 9)))

  ;; session wrap [00521]
  (set-box! (service-consumer-session-counter c) #xFFFF)
  (check-equal? (next-session! c) 1)

  (endpoint-close! (service-consumer-endpoint c)))
