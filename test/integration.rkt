#lang racket/base

;; End-to-end loopback integration: a provider offers a service over
;; SOME/IP-SD on the SD port, a consumer discovers it via the multicast
;; group, subscribes, calls a method and receives an event.

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

;; ---- configuration ---------------------------------------------------

;; NOTE: on a real vehicle network the provider binds SD_PORT 30490 for
;; SD traffic ([00600]/[00601]); two endpoints on one host cannot both
;; bind it, so the consumer here uses an ephemeral port (its unicast
;; sends still reach the provider, which answers to the datagram's
;; source address).
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

;; ---- provider ----------------------------------------------------------

(define provider-endpoint
  (make-someip-endpoint
   #:udp-port 30490
   #:multicast-groups (list sd-multicast)
   #:message-handler (lambda (m s) (eprintf "P<- ~a/~a sid=~a mt=~a
"
                                            (sender-host s) (sender-port s)
                                            (someip-message-service-id m)
                                            (someip-message-message-type m)))))

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

;; route SD and service traffic through the composite handler
(set-someip-endpoint-message-handler!
 provider-endpoint (provider-message-handler provider))

(provider-start! provider)

;; ---- consumer ----------------------------------------------------------

(define consumer-events '())
(define consumer-endpoint
  (make-someip-endpoint
   #:udp-port 0
   #:multicast-groups (list sd-multicast)
   #:message-handler (lambda (m s) (eprintf "C<- ~a/~a sid=~a mt=~a
"
                                            (sender-host s) (sender-port s)
                                            (someip-message-service-id m)
                                            (someip-message-message-type m)))))

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

;; wait until a predicate holds, polling
(define (wait-until pred [timeout-ms 15000] [step 0.05])
  (let loop ([deadline (+ (current-inexact-milliseconds) timeout-ms)])
    (cond
      [(pred) #t]
      [(> (current-inexact-milliseconds) deadline) #f]
      [else (sleep step) (loop deadline)])))

;; ---- discovery + subscribe ----------------------------------------------

(consumer-start-discovery! consumer)
(check-true (wait-until (lambda () (consumer-ready? consumer)))
            "consumer discovered the service")

;; subscription handshake completes (retry loop until ack)
(check-true
 (wait-until (lambda ()
               (pair? (hash-ref (unbox (service-provider-subscribers provider))
                                #x1 '())))
             10000)
 "subscription recorded by the provider")

;; ---- method call ---------------------------------------------------------

(define result (consumer-call consumer #x0001 #:payload (bytes 20) #:timeout-ms 3000))
(check-equal? (call-result-return-code result) rc-e-ok)
(check-equal? (call-result-payload result) (bytes 21))

;; ---- event ----------------------------------------------------------------

(provider-notify! provider #x8010 (bytes 1 2 3))
(check-true (wait-until (lambda () (pair? consumer-events)) 5000)
            "event received")
(check-equal? (first consumer-events) (bytes 1 2 3))

;; ---- shutdown ---------------------------------------------------------------

(consumer-stop-discovery! consumer)
(provider-stop! provider)
(endpoint-close! provider-endpoint)
(endpoint-close! consumer-endpoint)
