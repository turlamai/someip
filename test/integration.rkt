#lang racket/base

;; End-to-end loopback integration.
;;
;; Scenario 1 (SD): a provider offers a service via SOME/IP-SD on the
;; multicast group, a consumer discovers it, subscribes, calls a method
;; and receives an event. CI cloud runners commonly block multicast, so
;; this scenario probes first and skips when the environment cannot
;; deliver multicast.
;;
;; Scenario 2 (static): the same protocol flow over plain unicast with
;; a statically configured server location - runs everywhere.

(require racket/list
         racket/match
         rackunit
         "../message.rkt"
         "../sd/message.rkt"
         "../sd/machine.rkt"
         "../private/timers.rkt"
         "../transport.rkt"
         "../provider.rkt"
         "../consumer.rkt")

(define (wait-until pred [timeout-ms 15000] [step 0.05])
  (let loop ([deadline (+ (current-inexact-milliseconds) timeout-ms)])
    (cond
      [(pred) #t]
      [(> (current-inexact-milliseconds) deadline) #f]
      [else (sleep step) (loop deadline)])))

(define sd-multicast "239.255.1.100")
(define fast-sd
  (make-sd-config #:initial-delay-min-ms 50
                  #:initial-delay-max-ms 50
                  #:repetitions-base-delay-ms 100
                  #:repetitions-max 2
                  #:request-response-delay-min-ms 0
                  #:request-response-delay-max-ms 20
                  #:cyclic-offer-delay-ms 2000
                  #:subscribe-retry-delay-ms 200))

;; ====================================================================
;; Scenario 1: SD discovery (skipped when multicast is unavailable)
;; ====================================================================

(define provider-endpoint
  (make-someip-endpoint
   #:udp-port 30490
   #:multicast-groups (list sd-multicast)
   #:message-handler void))

(define consumer-events '())

(define provider
  (make-service-provider
   #:endpoint provider-endpoint
   #:service-id #x4321
   #:instance-id 1
   #:interface-version 3
   #:methods
   (list (method #x0001
                 (lambda (payload sender)
                   (bytes (add1 (bytes-ref payload 0))))))
   #:events
   (list (event #x8010 #x1))
   #:multicast-address sd-multicast
   #:timer-manager (make-timer-manager)
   #:sd-config fast-sd))

(set-someip-endpoint-message-handler!
 provider-endpoint (provider-message-handler provider))
(provider-start! provider)

(define consumer-endpoint
  (make-someip-endpoint
   #:udp-port 0
   #:multicast-groups (list sd-multicast)
   #:message-handler void))

(define consumer
  (make-service-consumer
   #:service-id #x4321
   #:instance-id 1
   #:interface-version 3
   #:client-id 42
   #:eventgroup-ids '(#x1)
   #:multicast-address sd-multicast
   #:timer-manager (make-timer-manager)
   #:sd-config fast-sd))

(consumer-attach-endpoint! consumer consumer-endpoint)
(set-someip-endpoint-message-handler!
 consumer-endpoint (consumer-message-handler consumer))
(consumer-set-event-callback!
 consumer #x8010 (lambda (payload sender)
                   (set! consumer-events (cons payload consumer-events))))

;; probe: CI cloud runners commonly block multicast
(consumer-start-discovery! consumer)
(define multicast-ok? (wait-until (lambda () (consumer-ready? consumer)) 3000))
(unless multicast-ok?
  (eprintf "integration: multicast unavailable here; skipping the SD scenario\n")
  (consumer-stop-discovery! consumer))

(when multicast-ok?
  (check-true (consumer-ready? consumer) "consumer discovered the service")

  ;; subscription handshake completes (retry loop until ack)
  (check-true
   (wait-until (lambda ()
                 (pair? (hash-ref (unbox (service-provider-subscribers provider))
                                  #x1 '())))
               10000)
   "subscription recorded by the provider")

  ;; ---- method call ----
  (define result (consumer-call consumer #x0001
                                #:payload (bytes 20) #:timeout-ms 3000))
  (check-equal? (call-result-return-code result) rc-e-ok)
  (check-equal? (call-result-payload result) (bytes 21))

  ;; ---- event ----
  (provider-notify! provider #x8010 (bytes 1 2 3))
  (check-true (wait-until (lambda () (pair? consumer-events)) 5000)
              "event received")
  (check-equal? (first consumer-events) (bytes 1 2 3)))

(consumer-stop-discovery! consumer)
(provider-stop! provider)
(endpoint-close! provider-endpoint)
(endpoint-close! consumer-endpoint)

;; ====================================================================
;; Scenario 2: static configuration (always runs; unicast only)
;; ====================================================================

(define static-provider-endpoint
  (make-someip-endpoint
   #:udp-port 0
   #:message-handler void))

(define static-provider
  (make-service-provider
   #:endpoint static-provider-endpoint
   #:service-id #x4321
   #:instance-id 1
   #:interface-version 3
   #:methods
   (list (method #x0001
                 (lambda (payload sender)
                   (bytes (add1 (bytes-ref payload 0))))))
   #:events
   (list (event #x8010 #x1))))

(set-someip-endpoint-message-handler!
 static-provider-endpoint (provider-message-handler static-provider))

(define static-events '())
(define static-consumer-endpoint
  (make-someip-endpoint #:udp-port 0 #:message-handler void))

(define static-consumer
  (make-service-consumer
   #:service-id #x4321
   #:instance-id 1
   #:interface-version 3
   #:client-id 7
   #:server-host "127.0.0.1"
   #:server-port (endpoint-udp-port static-provider-endpoint)
   #:timeout-ms 2000))

(consumer-attach-endpoint! static-consumer static-consumer-endpoint)
(set-someip-endpoint-message-handler!
 static-consumer-endpoint (consumer-message-handler static-consumer))
(consumer-set-event-callback!
 static-consumer #x8010 (lambda (payload sender)
                          (set! static-events (cons payload static-events))))

;; static setup: record the subscription directly (no SD)
(provider-subscribe! static-provider #x1
                     (list "127.0.0.1" (endpoint-udp-port static-consumer-endpoint)))

(define static-result
  (consumer-call static-consumer #x0001 #:payload (bytes 20) #:timeout-ms 3000))
(check-equal? (call-result-return-code static-result) rc-e-ok)
(check-equal? (call-result-payload static-result) (bytes 21))

(provider-notify! static-provider #x8010 (bytes 7 8))
(check-true (wait-until (lambda () (pair? static-events)) 5000) "event received")
(check-equal? (first static-events) (bytes 7 8))

(endpoint-close! static-provider-endpoint)
(endpoint-close! static-consumer-endpoint)
