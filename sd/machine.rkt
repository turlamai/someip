#lang racket/base

;; SOME/IP-SD service discovery state machines: server (offer/subscribe)
;; and client (find/subscribe), following the communication behavior of
;; AUTOSAR FO, SOME/IP-SD Protocol Specification, chapter 5.1.4.
;;
;; Both machines are synchronous stateful objects with no threads of
;; their own: all timing is driven by an injected timer manager (the
;; real one from private/timers, or a virtual clock in tests), all wire
;; output goes through injected send callbacks, and incoming messages
;; are pushed in via handle-message!. That keeps the protocol logic
;; fully deterministic and testable, and lets the transport layer own
;; sockets and dispatch.
;;
;; Behavior implemented here:
;;   [00395] three phases per service instance: Initial Wait, Repetition,
;;           Main
;;   [00399]-[00401] random INITIAL_DELAY in [min, max]
;;   [00405]-[00407] repetition delays 2^run x base, up to REPETITIONS_MAX
;;   [00408] finds stop once an offer is received
;;   [00411]-[00413] cyclic offers in the Main Phase
;;   [00415] no cyclic finds in the Main Phase
;;   [00417]-[00421] REQUEST_RESPONSE_DELAY for answers to entries
;;           received via multicast; immediate unicast answers otherwise
;;   [00422] finds are answered with a unicast Offer (basic behavior)
;;   [00427] stopping sends StopOffer entries
;;   [00428] StopSubscribe is answered (ack with TTL 0)
;;   [00429]/[00430] a StopOffer clears subscriptions on the client,
;;           which then waits for the next offer instead of finding
;;   [00431] releasing a client sends StopSubscribe entries
;;   [00386]/[00388] subscribe with TTL, retried until ack/nack
;;   [00157]-[00161] Session IDs start at 1, wrap to 1, per relation
;;   [00250]-[00256] Reboot flag until the session wraps, kept per
;;           relation; [00258] reboot detection on receive
;;   [00540] unicast flag set on all sent SD messages
;;   [00270] the subscribe counter distinguishes refresh/retries
;;
;; Simplifications (documented deviations for this release):
;;   - the server answers every find with a unicast offer (the basic
;;     behavior [00422]); the multicast-answer optimization [00423] is
;;     not implemented
;;   - the client restarts its find cycle when an offer's TTL expires
;;     (the spec returns to "searching" for a still-requested service)

(require racket/contract
         racket/format
         racket/match
         "../message.rkt"
         "message.rkt"
         "../private/timers.rkt"
         "../logging.rkt")

(provide sd-config
         make-sd-config
         (struct-out offered-eventgroup)

         (struct-out sd-server)
         (struct-out sd-client)
         make-sd-server
         sd-server-start!
         sd-server-stop!
         sd-server-handle-message!
         sd-server-active?
         sd-server-subscribers

         (struct-out sd-client)
         (struct-out offer-info)
         make-sd-client
         sd-client-start-request!
         sd-client-stop-request!
         sd-client-handle-message!
         sd-client-offer-info)

(module+ test (require rackunit racket/list))

;; ------------------------------------------------------------------
;; Configuration

;; All timings in milliseconds unless named *-seconds. The defaults are
;; a sane starting point for in-vehicle networks; tune per deployment.
(struct sd-config
  (initial-delay-min-ms
   initial-delay-max-ms
   repetitions-base-delay-ms
   repetitions-max
   request-response-delay-min-ms
   request-response-delay-max-ms
   cyclic-offer-delay-ms
   stop-offer-repetitions
   stop-offer-repetition-delay-ms
   subscribe-retry-delay-ms
   subscribe-retry-max            ; #f = retry forever
   ttl-refresh-ratio              ; re-subscribe at ratio x acknowledged TTL
   )
  #:transparent)

(define (make-sd-config
         #:initial-delay-min-ms [initial-delay-min-ms 200]
         #:initial-delay-max-ms [initial-delay-max-ms 1500]
         #:repetitions-base-delay-ms [repetitions-base-delay-ms 500]
         #:repetitions-max [repetitions-max 3]
         #:request-response-delay-min-ms [request-response-delay-min-ms 0]
         #:request-response-delay-max-ms [request-response-delay-max-ms 100]
         #:cyclic-offer-delay-ms [cyclic-offer-delay-ms 10000]
         #:stop-offer-repetitions [stop-offer-repetitions 3]
         #:stop-offer-repetition-delay-ms [stop-offer-repetition-delay-ms 250]
         #:subscribe-retry-delay-ms [subscribe-retry-delay-ms 2000]
         #:subscribe-retry-max [subscribe-retry-max #f]
         #:ttl-refresh-ratio [ttl-refresh-ratio 3/4])
  (unless (<= initial-delay-min-ms initial-delay-max-ms)
    (raise-argument-error 'make-sd-config "initial-delay-min-ms <= max" initial-delay-min-ms))
  (unless (<= request-response-delay-min-ms request-response-delay-max-ms)
    (raise-argument-error 'make-sd-config "request-response-delay-min-ms <= max"
                          request-response-delay-min-ms))
  (unless (<= 0 ttl-refresh-ratio 1)
    (raise-argument-error 'make-sd-config "ttl-refresh-ratio in [0, 1]" ttl-refresh-ratio))
  (sd-config initial-delay-min-ms initial-delay-max-ms
             repetitions-base-delay-ms repetitions-max
             request-response-delay-min-ms request-response-delay-max-ms
             cyclic-offer-delay-ms
             stop-offer-repetitions stop-offer-repetition-delay-ms
             subscribe-retry-delay-ms subscribe-retry-max
             ttl-refresh-ratio))

;; One eventgroup a server offers.
(struct offered-eventgroup (id multicast-option) #:transparent)

;; random integer in [lo, hi]; machines take a random procedure so tests
;; can pin values
(define (random-between random-proc lo hi)
  (if (= lo hi) lo (+ lo ((or random-proc default-random) (- hi lo)))))

(define (default-random span) (random (add1 span)))

;; ------------------------------------------------------------------
;; Session bookkeeping (per communication relation [00160]/[00256])

;; `reboot` stays set until the session wraps [00255].
(struct session-state (counter reboot?) #:mutable)

(define (make-session-state) (session-state 0 #t))

;; Returns (values new-session new-reboot-flag) for the next message of
;; a relation.
(define (next-session! st)
  (define next (+ (session-state-counter st) 1))
  (cond
    [(> next #xFFFF)
     (set-session-state-counter! st 1)
     (set-session-state-reboot?! st #f)
     (values 1 #f)]
    [else
     (set-session-state-counter! st next)
     (values next (session-state-reboot? st))]))

;; Detect a reboot of the peer [00258]: old.reboot=0 and new.reboot=1,
;; or both set with old.session >= new.session.
(define (reboot-detected? old-session old-reboot new-session new-reboot)
  (or (and (not old-reboot) new-reboot)
      (and old-reboot new-reboot (>= old-session new-session))))

;; Entry matching: Service ID always exact; Instance ID and Major
;; Version may be "any" (0xFFFF / 0xFF) on the FIND side.
(define (service-entry-matches? our-sid our-iid our-major sid iid major)
  (and (= sid our-sid)
       (or (= iid our-iid) (= iid #xFFFF))
       (or (= major our-major) (= major #xFF))))

;; ------------------------------------------------------------------
;; Server machine

(struct subscriber (sender counter eventgroup-id ttl-expiry-ms) #:transparent)

(struct sd-server
  (lock timers config random
   service-id instance-id major-version minor-version ttl-seconds
   udp-endpoint tcp-endpoint
   eventgroups                     ; hash: id -> multicast-option or #f
   send-multicast send-unicast     ; (-> bytes void) / (-> dest bytes void)
   on-subscribe                    ; (-> sid iid egid ttl endpoints) -> 'ack | 'nack
   state)
  #:transparent)

(struct server-state
  (phase                            ; 'stopped 'initial-wait 'repetition 'main 'down
   phase-timer
   run
   sessions-multicast               ; session-state
   sessions-unicast                 ; hash sender -> session-state
   subscribers)                     ; hash eventgroup-id -> (listof subscriber)
  #:mutable
  #:transparent)

(define (make-sd-server
         #:timer-manager timers
         #:service-id service-id
         #:instance-id instance-id
         #:major-version major-version
         #:minor-version minor-version
         #:ttl-seconds [ttl-seconds 30]
         #:udp-endpoint [udp-endpoint #f]
         #:tcp-endpoint [tcp-endpoint #f]
         #:eventgroups [eventgroups '()]
         #:send-multicast send-multicast
         #:send-unicast send-unicast
         #:on-subscribe [on-subscribe (lambda (sid iid egid ttl endpoints) 'ack)]
         #:config [config (make-sd-config)]
         #:random [random #f])
  (unless (> ttl-seconds 0)
    (raise-argument-error 'make-sd-server "positive TTL in seconds" ttl-seconds))
  (unless (<= ttl-seconds ttl-infinite)
    (raise-argument-error 'make-sd-server (format "TTL of at most ~a seconds" ttl-infinite)
                          ttl-seconds))
  (for ([eg eventgroups])
    (unless (offered-eventgroup? eg)
      (raise-argument-error 'make-sd-server "offered-eventgroup" eg)))
  (sd-server (make-semaphore 1) timers config random
             service-id instance-id major-version minor-version ttl-seconds
             udp-endpoint tcp-endpoint
             (for/hash ([eg eventgroups])
               (values (offered-eventgroup-id eg)
                       (offered-eventgroup-multicast-option eg)))
             send-multicast send-unicast on-subscribe
             (server-state 'stopped #f 0 (make-session-state) (make-hash) (make-hash))))

(define (with-server-lock srv thunk)
  (call-with-semaphore (sd-server-lock srv) thunk))

;; TTL is carried in seconds in the 24 bit entry field [00356].
(define (server-ttl-field srv)
  (inexact->exact (round (sd-server-ttl-seconds srv))))

(define (server-session-for! srv sender)
  (hash-ref! (server-state-sessions-unicast (sd-server-state srv)) sender make-session-state))

(define (send-sd srv dest pkt session)
  (define bs (encode-sd-packet pkt #:session-id session))
  (if dest
      ((sd-server-send-unicast srv) dest bs)
      ((sd-server-send-multicast srv) bs)))

(define (server-send-offer srv dest reboot session)
  (define entry
    (offer-service-entry #:service-id (sd-server-service-id srv)
                         #:instance-id (sd-server-instance-id srv)
                         #:major-version (sd-server-major-version srv)
                         #:minor-version (sd-server-minor-version srv)
                         #:ttl (server-ttl-field srv)
                         #:udp-endpoint (sd-server-udp-endpoint srv)
                         #:tcp-endpoint (sd-server-tcp-endpoint srv)))
  (send-sd srv dest (sd-packet reboot #t (list entry) '()) session))

(define (server-send-stop-offer srv dest reboot session)
  (define entry
    (stop-offer-service-entry #:service-id (sd-server-service-id srv)
                              #:instance-id (sd-server-instance-id srv)
                              #:major-version (sd-server-major-version srv)
                              #:minor-version (sd-server-minor-version srv)
                              #:udp-endpoint (sd-server-udp-endpoint srv)
                              #:tcp-endpoint (sd-server-tcp-endpoint srv)))
  (send-sd srv dest (sd-packet reboot #t (list entry) '()) session))

(define (schedule-server-phase-timer! srv delay proc)
  (define st (sd-server-state srv))
  (when (server-state-phase-timer st)
    (timer-cancel! (sd-server-timers srv) (server-state-phase-timer st)))
  (define t (timer-schedule! (sd-server-timers srv) delay proc))
  (set-server-state-phase-timer! st t)
  t)

(define (server-cancel-phase-timer! srv)
  (define st (sd-server-state srv))
  (when (server-state-phase-timer st)
    (timer-cancel! (sd-server-timers srv) (server-state-phase-timer st))
    (set-server-state-phase-timer! st #f)))

(define (sd-server-start! srv)
  (with-server-lock srv
    (lambda ()
      (define st (sd-server-state srv))
      (unless (eq? (server-state-phase st) 'stopped)
        (raise (exn:fail:someip "sd-server: already started" (current-continuation-marks))))
      (set-server-state-phase! st 'initial-wait)
      (set-server-state-run! st 0)
      (set-server-state-sessions-multicast! st (make-session-state))
      (schedule-server-phase-timer!
       srv (random-between (sd-server-random srv)
                           (sd-config-initial-delay-min-ms (sd-server-config srv))
                           (sd-config-initial-delay-max-ms (sd-server-config srv)))
       (lambda () (server-initial-tick! srv))))))

(define (send-multicast-offer! srv)
  (define st (sd-server-state srv))
  (define-values (session reboot) (next-session! (server-state-sessions-multicast st)))
  (server-send-offer srv #f reboot session))

(define (server-initial-tick! srv)
  (with-server-lock srv
    (lambda ()
      (define st (sd-server-state srv))
      (when (eq? (server-state-phase st) 'initial-wait)
        (send-multicast-offer! srv)
        (cond
          [(> (sd-config-repetitions-max (sd-server-config srv)) 0)
           (set-server-state-phase! st 'repetition)
           (set-server-state-run! st 0)
           (schedule-server-phase-timer!
            srv (sd-config-repetitions-base-delay-ms (sd-server-config srv))
            (lambda () (server-repetition-tick! srv)))]
          [else (enter-server-main-phase! srv)])))))

(define (server-repetition-tick! srv)
  (with-server-lock srv
    (lambda ()
      (define st (sd-server-state srv))
      (when (eq? (server-state-phase st) 'repetition)
        (send-multicast-offer! srv)
        (set-server-state-run! st (add1 (server-state-run st)))
        (cond
          [(< (server-state-run st) (sd-config-repetitions-max (sd-server-config srv)))
           (schedule-server-phase-timer!
            srv (* (expt 2 (server-state-run st))
                   (sd-config-repetitions-base-delay-ms (sd-server-config srv)))
            (lambda () (server-repetition-tick! srv)))]
          [else (enter-server-main-phase! srv)])))))

(define (enter-server-main-phase! srv)
  (define st (sd-server-state srv))
  (set-server-state-phase! st 'main)
  (schedule-server-phase-timer! srv (sd-config-cyclic-offer-delay-ms (sd-server-config srv))
                                (lambda () (server-main-tick! srv))))

(define (server-main-tick! srv)
  (with-server-lock srv
    (lambda ()
      (when (eq? (server-state-phase (sd-server-state srv)) 'main)
        (send-multicast-offer! srv)
        (schedule-server-phase-timer!
         srv (sd-config-cyclic-offer-delay-ms (sd-server-config srv))
         (lambda () (server-main-tick! srv)))))))

(define (sd-server-stop! srv)
  (with-server-lock srv
    (lambda ()
      (define st (sd-server-state srv))
      (when (eq? (server-state-phase st) 'stopped)
        (void)
        (void))
      (unless (eq? (server-state-phase st) 'stopped)
        (server-cancel-phase-timer! srv)
        (set-server-state-phase! st 'down)
        (set-server-state-subscribers! st (make-hash))
        ;; StopOffer repetitions (multicast)
        (define n (sd-config-stop-offer-repetitions (sd-server-config srv)))
        (let send-stops ([remaining n])
          (when (> remaining 0)
            (define-values (session reboot)
              (next-session! (server-state-sessions-multicast st)))
            (server-send-stop-offer srv #f reboot session)
            (when (> remaining 1)
              (timer-schedule! (sd-server-timers srv)
                               (sd-config-stop-offer-repetition-delay-ms (sd-server-config srv))
                               (lambda () (send-stops (sub1 remaining)))))))))))

;; Feed a decoded SD packet received from `sender`. `from-multicast?`
;; drives the REQUEST_RESPONSE_DELAY [00417].
(define (sd-server-handle-message! srv pkt session-id sender
                                   [from-multicast? #f]
                                   [now-ms (current-inexact-milliseconds)])
  (unless (sd-packet? pkt)
    (raise-argument-error 'sd-server-handle-message! "sd-packet?" pkt))
  (with-server-lock srv
    (lambda ()
      (define st (sd-server-state srv))
      (when (memq (server-state-phase st) '(repetition main))
        (for ([entry (sd-packet-entries pkt)])
          (cond
            [(sd-service-entry? entry)
             (define type (sd-service-entry-type entry))
             (define sid (sd-service-entry-service-id entry))
             (define iid (sd-service-entry-instance-id entry))
             (define major (sd-service-entry-major-version entry))
             (cond
               ;; FindService [00350]: answer with a unicast offer
               [(and (= type sd-entry-find)
                     (service-entry-matches?
                      (sd-server-service-id srv) (sd-server-instance-id srv)
                      (sd-server-major-version srv)
                      sid iid major)
                     ;; [00843] entries with the unicast flag cleared are
                     ;; not answered
                     (sd-packet-unicast? pkt))
                (answer-find srv sender from-multicast?)]
               [else (void)])]
            [(sd-eventgroup-entry? entry)
             (define type (sd-eventgroup-entry-type entry))
             (define sid (sd-eventgroup-entry-service-id entry))
             (define iid (sd-eventgroup-entry-instance-id entry))
             (define major (sd-eventgroup-entry-major-version entry))
             (define egid (sd-eventgroup-entry-eventgroup-id entry))
             (define endpoints (car (sd-eventgroup-entry-option-runs entry)))
             (cond
               [(and (memv type (list sd-entry-subscribe))
                     (= sid (sd-server-service-id srv))
                     (or (= iid (sd-server-instance-id srv)) (= iid #xFFFF))
                     (or (= major (sd-server-major-version srv)) (= major #xFF))
                     (hash-has-key? (sd-server-eventgroups srv) egid)
                     (sd-packet-unicast? pkt))
                (handle-subscribe srv entry sender endpoints now-ms)]
               [(and (memv type (list sd-entry-subscribe))
                     (= sid (sd-server-service-id srv))
                     (or (= iid (sd-server-instance-id srv)) (= iid #xFFFF))
                     (or (= major (sd-server-major-version srv)) (= major #xFF))
                     (sd-packet-unicast? pkt))
                ;; our service, but an unknown eventgroup: nack [5.1.4.6]
                (send-subscribe-reply srv 'nack entry sender)]
               [else (void)])]
            [else (void)]))))))

(define (answer-find srv sender from-multicast?)
  ;; caller holds the server lock
  (define cfg (sd-server-config srv))
  (define delay
    (if from-multicast?
        (random-between (sd-server-random srv)
                        (sd-config-request-response-delay-min-ms cfg)
                        (sd-config-request-response-delay-max-ms cfg))
        0))
  (if (> delay 0)
      (timer-schedule! (sd-server-timers srv) delay
                       (lambda () (answer-find-locked srv sender)))
      ;; delay 0: the caller already holds the server lock
      (server-answer-now srv sender)))

;; lock-acquiring variant for timer callbacks
(define (answer-find-locked srv sender)
  (with-server-lock srv (lambda () (server-answer-now srv sender))))

;; caller must hold the server lock
(define (server-answer-now srv sender)
  (define st (sd-server-state srv))
  (unless (memq (server-state-phase st) '(stopped down))
    (define session-st (server-session-for! srv sender))
    (define-values (session reboot) (next-session! session-st))
    (server-send-offer srv sender reboot session)))

(define (handle-subscribe srv entry sender endpoints now-ms)
  (define st (sd-server-state srv))
  (define egid (sd-eventgroup-entry-eventgroup-id entry))
  (define ttl (sd-eventgroup-entry-ttl entry))
  (define counter (sd-eventgroup-entry-counter entry))
  (define verdict
    ((sd-server-on-subscribe srv)
     (sd-server-service-id srv) (sd-server-instance-id srv)
     egid ttl endpoints))
  (if (eq? verdict 'nack)
      (send-subscribe-reply srv 'nack entry sender)
      (let ()
        (define subs (server-state-subscribers st))
        (define others
          (filter (lambda (s) (not (equal? (subscriber-sender s) sender)))
                  (hash-ref subs egid '())))
        (hash-set! subs egid
                   (cons (subscriber sender counter egid
                                     (if (= ttl ttl-infinite) #f (+ now-ms (* ttl 1000))))
                         others))
        (send-subscribe-reply srv 'ack entry sender))))

;; ack/nack unicast answer; the ack references the eventgroup's
;; multicast option when one is configured [00487]
(define (send-subscribe-reply srv kind entry sender)
  (define egid (sd-eventgroup-entry-eventgroup-id entry))
  (define ttl (if (eq? kind 'ack) (sd-eventgroup-entry-ttl entry) 0))
  (define reply
    (if (eq? kind 'ack)
        (subscribe-ack-entry
         #:service-id (sd-server-service-id srv)
         #:instance-id (sd-server-instance-id srv)
         #:major-version (sd-server-major-version srv)
         #:eventgroup-id egid
         #:ttl ttl
         #:counter (sd-eventgroup-entry-counter entry)
         #:multicast-option (hash-ref (sd-server-eventgroups srv) egid #f))
        (subscribe-nack-entry
         #:service-id (sd-server-service-id srv)
         #:instance-id (sd-server-instance-id srv)
         #:major-version (sd-server-major-version srv)
         #:eventgroup-id egid
         #:counter (sd-eventgroup-entry-counter entry))))
  (define session-st (server-session-for! srv sender))
  (define-values (session reboot) (next-session! session-st))
  (send-sd srv sender (sd-packet reboot #t (list reply) '()) session))

(define (sd-server-active? srv)
  (with-server-lock srv
    (lambda ()
      (memq (server-state-phase (sd-server-state srv))
            '(initial-wait repetition main)))))

(define (sd-server-subscribers srv)
  (with-server-lock srv
    (lambda ()
      (for/hash ([(k v) (in-hash (server-state-subscribers (sd-server-state srv)))])
        (values k v)))))

;; ------------------------------------------------------------------
;; Client machine

(struct offer-info (sender endpoints ttl-expiry-ms multicast-options) #:transparent)

(struct subscription (phase                        ; 'idle 'subscribing 'subscribed
                      counter retry-timer refresh-timer
                      server-sender
                      multicast-options)
  #:mutable
  #:transparent)

(struct client-state
  (phase                                            ; 'idle 'initial-wait 'repetition 'main
   find-timer run
   offer                                            ; offer-info or #f
   offer-timer
   sessions-multicast sessions-unicast
   subscriptions)                                   ; hash eventgroup-id -> subscription
  #:mutable
  #:transparent)

(struct sd-client
  (lock timers config random
   service-id instance-id major-version minor-version
   eventgroup-ids                    ; list of eventgroup ids to subscribe
   client-udp-endpoint client-tcp-endpoint
   send-multicast send-unicast
   on-offer on-stop on-subscribe-ack on-subscribe-nack on-reboot
   state)
  #:transparent)

(define (make-sd-client
         #:timer-manager timers
         #:service-id service-id
         #:instance-id [instance-id #xFFFF]
         #:major-version [major-version 1]
         #:minor-version [minor-version #xFFFFFFFF]
         #:eventgroup-ids [eventgroup-ids '()]
         #:client-udp-endpoint [client-udp-endpoint #f]
         #:client-tcp-endpoint [client-tcp-endpoint #f]
         #:send-multicast send-multicast
         #:send-unicast send-unicast
         #:on-offer [on-offer (lambda (info) (void))]
         #:on-stop [on-stop (lambda () (void))]
         #:on-subscribe-ack [on-subscribe-ack (lambda (egid multicast-options) (void))]
         #:on-subscribe-nack [on-subscribe-nack (lambda (egid) (void))]
         #:on-reboot [on-reboot (lambda () (void))]
         #:config [config (make-sd-config)]
         #:random [random #f])
  (sd-client (make-semaphore 1) timers config random
             service-id instance-id major-version minor-version
             eventgroup-ids client-udp-endpoint client-tcp-endpoint
             send-multicast send-unicast
             on-offer on-stop on-subscribe-ack on-subscribe-nack on-reboot
             (client-state 'idle #f 0 #f #f (make-session-state) (make-hash) (make-hash))))

(define (with-client-lock c thunk)
  (call-with-semaphore (sd-client-lock c) thunk))

(define (client-session-for! c sender)
  (hash-ref! (client-state-sessions-unicast (sd-client-state c)) sender make-session-state))

(define (send-sd-client c dest pkt session)
  (define bs (encode-sd-packet pkt #:session-id session))
  (if dest
      ((sd-client-send-unicast c) dest bs)
      ((sd-client-send-multicast c) bs)))

(define (schedule-client-find-timer! c delay proc)
  (define st (sd-client-state c))
  (when (client-state-find-timer st)
    (timer-cancel! (sd-client-timers c) (client-state-find-timer st)))
  (define t (timer-schedule! (sd-client-timers c) delay proc))
  (set-client-state-find-timer! st t)
  t)

(define (client-cancel-find-timer! c)
  (define st (sd-client-state c))
  (when (client-state-find-timer st)
    (timer-cancel! (sd-client-timers c) (client-state-find-timer st))
    (set-client-state-find-timer! st #f)))

(define (sd-client-start-request! c)
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (unless (eq? (client-state-phase st) 'idle)
        (raise (exn:fail:someip "sd-client: already requesting" (current-continuation-marks))))
      (set-client-state-phase! st 'initial-wait)
      (schedule-client-find-timer!
       c (random-between (sd-client-random c)
                         (sd-config-initial-delay-min-ms (sd-client-config c))
                         (sd-config-initial-delay-max-ms (sd-client-config c)))
       (lambda () (client-find-initial-tick! c))))))

(define (client-send-find! c)
  (define st (sd-client-state c))
  (define entry
    (find-service-entry #:service-id (sd-client-service-id c)
                        #:instance-id (sd-client-instance-id c)
                        #:major-version (sd-client-major-version c)
                        #:minor-version (sd-client-minor-version c)))
  (define-values (session reboot) (next-session! (client-state-sessions-multicast st)))
  (send-sd-client c #f (sd-packet reboot #t (list entry) '()) session))

(define (client-find-initial-tick! c)
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (when (eq? (client-state-phase st) 'initial-wait)
        (client-send-find! c)
        (cond
          [(> (sd-config-repetitions-max (sd-client-config c)) 0)
           (set-client-state-phase! st 'repetition)
           (set-client-state-run! st 0)
           (schedule-client-find-timer!
            c (sd-config-repetitions-base-delay-ms (sd-client-config c))
            (lambda () (client-find-repetition-tick! c)))]
          [else (set-client-state-phase! st 'main)])))))

(define (client-find-repetition-tick! c)
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (when (eq? (client-state-phase st) 'repetition)
        (client-send-find! c)
        (set-client-state-run! st (add1 (client-state-run st)))
        (cond
          [(< (client-state-run st) (sd-config-repetitions-max (sd-client-config c)))
           (schedule-client-find-timer!
            c (* (expt 2 (client-state-run st))
                 (sd-config-repetitions-base-delay-ms (sd-client-config c)))
            (lambda () (client-find-repetition-tick! c)))]
          [else
           ;; [00415] no cyclic finds in the main phase
           (set-client-state-phase! st 'main)])))))

(define (client-endpoint-options c)
  (filter values (list (sd-client-client-udp-endpoint c) (sd-client-client-tcp-endpoint c))))

(define (client-send-subscribe! c egid sender counter)
  (define entry
    (subscribe-eventgroup-entry #:service-id (sd-client-service-id c)
                                #:instance-id (sd-client-instance-id c)
                                #:major-version (sd-client-major-version c)
                                #:eventgroup-id egid
                                #:ttl ttl-infinite
                                #:counter counter
                                #:client-endpoints (client-endpoint-options c)))
  (define session-st (client-session-for! c sender))
  (define-values (session reboot) (next-session! session-st))
  (send-sd-client c sender (sd-packet reboot #t (list entry) '()) session))

(define (client-stop-subscribe! c egid sender sub)
  (define entry
    (stop-subscribe-eventgroup-entry #:service-id (sd-client-service-id c)
                                     #:instance-id (sd-client-instance-id c)
                                     #:major-version (sd-client-major-version c)
                                     #:eventgroup-id egid
                                     #:counter (subscription-counter sub)
                                     #:client-endpoints (client-endpoint-options c)))
  (define session-st (client-session-for! c sender))
  (define-values (session reboot) (next-session! session-st))
  (send-sd-client c sender (sd-packet reboot #t (list entry) '()) session))

(define (sd-client-stop-request! c)
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (unless (eq? (client-state-phase st) 'idle)
        (client-cancel-find-timer! c)
        (when (client-state-offer-timer st)
          (timer-cancel! (sd-client-timers c) (client-state-offer-timer st))
          (set-client-state-offer-timer! st #f))
        ;; [00431] StopSubscribe entries for all active subscriptions
        (for ([(egid sub) (in-hash (client-state-subscriptions st))]
              #:when (and (not (eq? (subscription-phase sub) 'idle))
                          (subscription-server-sender sub)))
          (client-stop-subscribe! c egid (subscription-server-sender sub) sub))
        (set-client-state-subscriptions! st (make-hash))
        (set-client-state-offer! st #f)
        (set-client-state-phase! st 'idle)))))

;; Entry point from the transport: a decoded SD packet from `sender`.
(define (sd-client-handle-message! c pkt session-id sender
                                   [from-multicast? #f]
                                   [now-ms (current-inexact-milliseconds)])
  (unless (sd-packet? pkt)
    (raise-argument-error 'sd-client-handle-message! "sd-packet?" pkt))
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (when (memq (client-state-phase st) '(initial-wait repetition main))
        (for ([entry (sd-packet-entries pkt)])
          (cond
            [(sd-service-entry? entry)
             (define type (sd-service-entry-type entry))
             (define sid (sd-service-entry-service-id entry))
             (define iid (sd-service-entry-instance-id entry))
             (define major (sd-service-entry-major-version entry))
             (define minor (sd-service-entry-minor-version entry))
             (define ttl (sd-service-entry-ttl entry))
             (unless (= sid (sd-client-service-id c)) (void))
             (cond
               [(and (= type sd-entry-offer) (zero? ttl))
                ;; [00429]/[00430] stop offer: clear, wait for offers
                (client-handle-stop-offer! c)]
               [(and (= type sd-entry-offer)
                     (client-offer-matches? c iid major minor))
                (client-handle-offer! c entry sender session-id
                                      (sd-packet-reboot? pkt) now-ms)]
               [else (void)])]
            [(sd-eventgroup-entry? entry)
             (when (= (sd-eventgroup-entry-type entry) sd-entry-ack)
               (client-handle-subscribe-ack! c entry sender now-ms))]
            [else (void)]))))))

;; the client matches offers per its configured any/exact rules [00826]
(define (client-offer-matches? c iid major minor)
  (and (or (= (sd-client-instance-id c) #xFFFF)
           (= (sd-client-instance-id c) iid))
       (or (= (sd-client-major-version c) #xFF)
           (= (sd-client-major-version c) major))
       (or (= (sd-client-minor-version c) #xFFFFFFFF)
           (= (sd-client-minor-version c) minor))))

(define (client-handle-offer! c entry sender session-id reboot-flag now-ms)
  (define st (sd-client-state c))
  (define sessions (client-state-sessions-unicast st))
  (define old (hash-ref sessions sender #f))
  (define old-session (if old (session-state-counter old) 0))
  (define old-reboot (if old (session-state-reboot? old) #f))
  ;; remember the peer relation for future reboot detection [00256]
  (hash-set! sessions sender (session-state session-id reboot-flag))
  (when (and old (reboot-detected? old-session old-reboot session-id reboot-flag))
    ;; [00258] peer rebooted: re-subscribe everything active
    (someip-log-info "sd-client: peer reboot detected, re-subscribing")
    ((sd-client-on-reboot c))
    (for ([(egid sub) (in-hash (client-state-subscriptions st))]
          #:when (not (eq? (subscription-phase sub) 'idle)))
      (set-subscription-phase! sub 'subscribing)
      (set-subscription-server-sender! sub sender)
      (schedule-subscribe-retry! c egid)))
  ;; the find cycle stops once an offer arrives [00408]
  (client-cancel-find-timer! c)
  (set-client-state-phase! st 'main)
  (define endpoints (car (sd-service-entry-option-runs entry)))
  (define ttl (sd-service-entry-ttl entry))
  (define ttl-expiry (if (= ttl ttl-infinite) #f (+ now-ms (* ttl 1000))))
  (define mc-options
    (filter (lambda (o) (and (sd-endpoint-option? o)
                             (eq? (sd-endpoint-option-kind o) 'multicast)))
            (cadr (sd-service-entry-option-runs entry))))
  (define info (offer-info sender endpoints ttl-expiry mc-options))
  (set-client-state-offer! st info)
  (when (client-state-offer-timer st)
    (timer-cancel! (sd-client-timers c) (client-state-offer-timer st)))
  (when ttl-expiry
    (set-client-state-offer-timer!
     st (timer-schedule! (sd-client-timers c) (inexact->exact (- ttl-expiry now-ms))
                         (lambda () (client-offer-expired! c)))))
  ((sd-client-on-offer c) info)
  ;; subscribe to all requested eventgroups that are not yet subscribed
  (for ([egid (sd-client-eventgroup-ids c)])
    (define subs (client-state-subscriptions st))
    (define sub (hash-ref subs egid #f))
    (unless sub
      (set! sub (subscription 'idle 0 #f #f #f #f))
      (hash-set! subs egid sub))
    (when (eq? (subscription-phase sub) 'idle)
      (begin-subscription! c egid sender 0))))

(define (begin-subscription! c egid sender counter)
  (define st (sd-client-state c))
  (define sub (hash-ref (client-state-subscriptions st) egid))
  (set-subscription-phase! sub 'subscribing)
  (set-subscription-counter! sub counter)
  (set-subscription-server-sender! sub sender)
  (client-send-subscribe! c egid sender counter)
  (schedule-subscribe-retry! c egid))

(define (schedule-subscribe-retry! c egid)
  (define st (sd-client-state c))
  (define sub (hash-ref (client-state-subscriptions st) egid))
  (when (subscription-retry-timer sub)
    (timer-cancel! (sd-client-timers c) (subscription-retry-timer sub)))
  (set-subscription-retry-timer!
   sub
   (timer-schedule! (sd-client-timers c)
                    (sd-config-subscribe-retry-delay-ms (sd-client-config c))
                    (lambda () (client-subscribe-retry-tick! c egid)))))

(define (client-subscribe-retry-tick! c egid)
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (define sub (hash-ref (client-state-subscriptions st) egid #f))
      (when (and sub (eq? (subscription-phase sub) 'subscribing)
                 (subscription-server-sender sub))
        (define retry-max (sd-config-subscribe-retry-max (sd-client-config c)))
        (cond
          [(and retry-max (>= (subscription-counter sub) retry-max))
           ((sd-client-on-subscribe-nack c) egid)
           (set-subscription-phase! sub 'idle)]
          [else
           (define next-counter (modulo (add1 (subscription-counter sub)) 16))
           (set-subscription-counter! sub next-counter)
           (client-send-subscribe! c egid (subscription-server-sender sub) next-counter)
           (schedule-subscribe-retry! c egid)])))))

(define (client-handle-subscribe-ack! c entry sender now-ms)
  (define st (sd-client-state c))
  (define egid (sd-eventgroup-entry-eventgroup-id entry))
  (define sub (hash-ref (client-state-subscriptions st) egid #f))
  (when (and sub (eq? (subscription-phase sub) 'subscribing))
    (define ttl (sd-eventgroup-entry-ttl entry))
    (when (subscription-retry-timer sub)
      (timer-cancel! (sd-client-timers c) (subscription-retry-timer sub))
      (set-subscription-retry-timer! sub #f))
    (set-subscription-phase! sub 'subscribed)
    (define mc-options
      (filter (lambda (o) (and (sd-endpoint-option? o)
                               (eq? (sd-endpoint-option-kind o) 'multicast)))
              (cadr (sd-eventgroup-entry-option-runs entry))))
    (set-subscription-multicast-options! sub mc-options)
    ((sd-client-on-subscribe-ack c) egid mc-options)
    ;; TTL refresh: re-subscribe before the subscription expires
    (define refresh-ms
      (inexact->exact
       (floor (* (sd-config-ttl-refresh-ratio (sd-client-config c)) (* ttl 1000)))))
    (when (and (> refresh-ms 0) (not (= ttl ttl-infinite)))
      (set-subscription-refresh-timer!
       sub (timer-schedule! (sd-client-timers c) refresh-ms
                            (lambda () (client-subscription-refresh-tick! c egid)))))))

(define (client-subscription-refresh-tick! c egid)
  (with-client-lock c
    (lambda ()
      (define sub (hash-ref (client-state-subscriptions (sd-client-state c)) egid #f))
      (when (and sub (eq? (subscription-phase sub) 'subscribed))
        ;; the counter distinguishes the refresh from the initial
        ;; subscribe [00270]
        (define next-counter (modulo (add1 (subscription-counter sub)) 16))
        (set-subscription-counter! sub next-counter)
        (client-send-subscribe! c egid (subscription-server-sender sub) next-counter)
        (schedule-subscribe-retry! c egid)))))

(define (client-handle-stop-offer! c)
  (define st (sd-client-state c))
  (set-client-state-offer! st #f)
  (when (client-state-offer-timer st)
    (timer-cancel! (sd-client-timers c) (client-state-offer-timer st))
    (set-client-state-offer-timer! st #f))
  (for ([(egid sub) (in-hash (client-state-subscriptions st))])
    (when (subscription-retry-timer sub)
      (timer-cancel! (sd-client-timers c) (subscription-retry-timer sub))
      (set-subscription-retry-timer! sub #f))
    (when (subscription-refresh-timer sub)
      (timer-cancel! (sd-client-timers c) (subscription-refresh-timer sub))
      (set-subscription-refresh-timer! sub #f))
    (set-subscription-phase! sub 'idle))
  ((sd-client-on-stop c)))

(define (client-offer-expired! c)
  (with-client-lock c
    (lambda ()
      (define st (sd-client-state c))
      (set-client-state-offer! st #f)
      (for ([(egid sub) (in-hash (client-state-subscriptions st))])
        (when (subscription-retry-timer sub)
          (timer-cancel! (sd-client-timers c) (subscription-retry-timer sub))
          (set-subscription-retry-timer! sub #f))
        (when (subscription-refresh-timer sub)
          (timer-cancel! (sd-client-timers c) (subscription-refresh-timer sub))
          (set-subscription-refresh-timer! sub #f))
        (set-subscription-phase! sub 'idle))
      ((sd-client-on-stop c))
      ;; restart the find cycle for the still-requested service
      (set-client-state-phase! st 'initial-wait)
      (schedule-client-find-timer!
       c (random-between (sd-client-random c)
                         (sd-config-initial-delay-min-ms (sd-client-config c))
                         (sd-config-initial-delay-max-ms (sd-client-config c)))
       (lambda () (client-find-initial-tick! c))))))

(define (sd-client-offer-info c)
  (with-client-lock c
    (lambda () (client-state-offer (sd-client-state c)))))

;; ------------------------------------------------------------------
;; Tests (deterministic: virtual clock, pinned random, captured sends)

(module+ test
  (require rackunit
           racket/list)

  (define config
    (make-sd-config #:initial-delay-min-ms 100
                    #:initial-delay-max-ms 100
                    #:repetitions-base-delay-ms 200
                    #:repetitions-max 2
                    #:request-response-delay-min-ms 50
                    #:request-response-delay-max-ms 50
                    #:cyclic-offer-delay-ms 1000
                    #:subscribe-retry-delay-ms 300))

  ;; captured send log: (list 'multicast bytes) | (list 'unicast dest bytes)
  (define log '())
  (define (record kind dest bs) (set! log (cons (list kind dest bs) log)))
  (define (reset-log!) (set! log '()))
  (define (multicasts)
    (reverse (for/list ([e log] #:when (eq? (car e) 'multicast)) (caddr e))))
  (define (unicasts-to dest)
    (reverse (for/list ([e log] #:when (and (eq? (car e) 'unicast) (equal? (cadr e) dest)))
               (caddr e))))

  (define vm (make-virtual-timer-manager))
  (define sender-a 'sender-a)

  ;; ---- server lifecycle ------------------------------------------

  (define random-zero (lambda (span) 0))
  (define server
    (make-sd-server
     #:timer-manager vm
     #:random random-zero
     #:config config
     #:service-id #x1234
     #:instance-id 1
     #:major-version 1
     #:minor-version 5
     #:ttl-seconds 30
     #:udp-endpoint (sd-endpoint-option 'endpoint 'ipv4 "10.0.0.1" 40001 'udp #f)
     #:eventgroups (list (offered-eventgroup #x10
                                             (sd-endpoint-option 'multicast 'ipv4
                                                                 "239.1.1.1" 41001 'udp #f)))
     #:send-multicast (lambda (bs) (record 'multicast #f bs))
     #:send-unicast (lambda (dest bs) (record 'unicast dest bs))))

  (sd-server-start! server)
  (check-equal? (multicasts) '() "no offer before the initial delay")
  (virtual-advance! vm 100)
  ;; initial offer: session 1, reboot flag set
  (define-values (offer1 sid1 _) (decode-sd-message (first (multicasts))))
  (check-true (sd-packet-reboot? offer1))
  (check-true (sd-packet-unicast? offer1))
  (check-equal? sid1 1)
  (define e1 (first (sd-packet-entries offer1)))
  (check-equal? (sd-service-entry-type e1) sd-entry-offer)
  (check-equal? (sd-service-entry-service-id e1) #x1234)
  (check-equal? (sd-service-entry-ttl e1) 30)
  (check-equal? (length (sd-packet-options offer1)) 1 "udp endpoint option")
  ;; repetition: offers at 200, 400; then main phase at +1000 cycles
  (virtual-advance! vm 200)
  (check-equal? (length (multicasts)) 2)
  (define-values (_offer2 sid2 _c2) (decode-sd-message (second (multicasts))))
  (check-equal? sid2 2 "session increments per relation")
  (virtual-advance! vm 400)
  (check-equal? (length (multicasts)) 3)
  (virtual-advance! vm 999)
  (check-equal? (length (multicasts)) 3 "main phase waits the cyclic delay")
  (virtual-advance! vm 1)
  (check-equal? (length (multicasts)) 4 "first cyclic offer")
  (check-not-false (sd-server-active? server))

  ;; ---- find handling ----------------------------------------------

  (reset-log!)
  (define find-pkt
    (sd-packet #f #t
               (list (find-service-entry #:service-id #x1234
                                         #:instance-id 1
                                         #:major-version 1))
               '()))
  ;; [00843] unicast flag cleared: not answered
  (define find-no-unicast (struct-copy sd-packet find-pkt [unicast? #f]))
  (sd-server-handle-message! server find-no-unicast 7 sender-a #t)
  (check-equal? log '())
  ;; multicast find with unicast flag: answered unicast after the
  ;; request-response delay (50 ms in this config)
  (sd-server-handle-message! server find-pkt 7 sender-a #t)
  (check-equal? (length (unicasts-to sender-a)) 0 "answer delayed")
  (virtual-advance! vm 50)
  (check-equal? (length (unicasts-to sender-a)) 1)
  (define-values (offer-a sid-a _c3) (decode-sd-message (first (unicasts-to sender-a))))
  (check-equal? sid-a 1 "per-peer session starts at 1")
  (check-true (sd-packet-reboot? offer-a))

  ;; ---- subscribe handling -----------------------------------------

  (reset-log!)
  (define acks '())
  (define subscribe
    (subscribe-eventgroup-entry #:service-id #x1234 #:instance-id 1
                                #:major-version 1 #:eventgroup-id #x10
                                #:counter 0
                                #:client-endpoints
                                (list (sd-endpoint-option 'endpoint 'ipv4
                                                          "10.0.0.9" 49152 'udp #f))))
  (sd-server-handle-message! server (sd-packet #f #t (list subscribe) '()) 9 sender-a #f)
  (define-values (ack sid-ack _c4) (decode-sd-message (first (unicasts-to sender-a))))
  (check-equal? (sd-eventgroup-entry-type (first (sd-packet-entries ack))) sd-entry-ack)
  (check-equal? (sd-eventgroup-entry-ttl (first (sd-packet-entries ack))) ttl-infinite)
  ;; ack references the multicast option [00487]
  (define ack-mc (second (sd-eventgroup-entry-option-runs (first (sd-packet-entries ack)))))
  (check-equal? ack-mc
                (list (sd-endpoint-option 'multicast 'ipv4 "239.1.1.1" 41001 'udp #f)))
  (check-equal? (sd-server-subscribers server)
                (hash #x10 (list (subscriber sender-a 0 #x10 #f))))

  ;; unknown eventgroup -> nack
  (reset-log!)
  (define subscribe-bad
    (subscribe-eventgroup-entry #:service-id #x1234 #:instance-id 1
                                #:major-version 1 #:eventgroup-id #x99))
  (sd-server-handle-message! server (sd-packet #f #t (list subscribe-bad) '()) 10 sender-a #f)
  (define-values (nack _n1 _c5) (decode-sd-message (first (unicasts-to sender-a))))
  (check-equal? (sd-eventgroup-entry-type (first (sd-packet-entries nack))) sd-entry-ack)
  (check-equal? (sd-eventgroup-entry-ttl (first (sd-packet-entries nack))) 0)

  ;; application-driven nack
  (reset-log!)
  (define server2
    (make-sd-server
     #:timer-manager vm
     #:random random-zero
     #:config config
     #:service-id #x1234 #:instance-id 1 #:major-version 1 #:minor-version 5
     #:eventgroups (list (offered-eventgroup #x10 #f))
     #:send-multicast (lambda (bs) (void))
     #:send-unicast (lambda (dest bs) (record 'unicast dest bs))
     #:on-subscribe (lambda (sid iid egid ttl endpoints) 'nack)))
  (sd-server-start! server2)
  (virtual-advance! vm 100)
  (reset-log!)
  (sd-server-handle-message! server2 (sd-packet #f #t (list subscribe) '()) 1 sender-a #f)
  (define-values (nack2 _n2 _c6) (decode-sd-message (first (unicasts-to sender-a))))
  (check-equal? (sd-eventgroup-entry-type (first (sd-packet-entries nack2))) sd-entry-ack)
  (check-equal? (sd-eventgroup-entry-ttl (first (sd-packet-entries nack2))) 0)
  ;; stop server2 so its cyclic offers no longer reach the multicast log
  (sd-server-stop! server2)

  ;; ---- stop: three stop offers -------------------------------------

  (reset-log!)
  (sd-server-stop! server)

  (virtual-advance! vm 1000)

  (check-equal? (length (multicasts)) 3)
  (define-values (stop1 _s4 _c11) (decode-sd-message (first (multicasts))))
  (check-true (entry-type-stop? (first (sd-packet-entries stop1))))
  (check-false (sd-server-active? server))

  ;; ---- client: find, subscribe, retry, refresh ----------------------

  (reset-log!)
  (define client-events '())
  (define client
    (make-sd-client
     #:timer-manager vm
     #:random random-zero
     #:config config
     #:service-id #x1234 #:instance-id 1 #:major-version 1
     #:eventgroup-ids '(#x10)
     #:client-udp-endpoint (sd-endpoint-option 'endpoint 'ipv4 "10.0.0.9" 49152 'udp #f)
     #:send-multicast (lambda (bs) (record 'multicast #f bs))
     #:send-unicast (lambda (dest bs) (record 'unicast dest bs))
     #:on-offer (lambda (info) (set! client-events (cons 'offer client-events)))
     #:on-subscribe-ack (lambda (egid mc) (set! client-events (cons 'ack client-events)))
     #:on-stop (lambda () (set! client-events (cons 'stop client-events)))
     #:on-reboot (lambda () (set! client-events (cons 'reboot client-events)))))

  (sd-client-start-request! client)
  (virtual-advance! vm 100)
  ;; initial find + repetition finds at 200, 400
  (check-equal? (length (multicasts)) 1)
  (define-values (find1 find-sid _c7) (decode-sd-message (first (multicasts))))
  (check-equal? find-sid 1)
  (check-equal? (sd-service-entry-type (first (sd-packet-entries find1))) sd-entry-find)
  (virtual-advance! vm 200)
  (check-equal? (length (multicasts)) 2)
  (virtual-advance! vm 400)
  (check-equal? (length (multicasts)) 3)
  (virtual-advance! vm 10000)
  (check-equal? (length (multicasts)) 3 "no cyclic finds [00415]")

  ;; an offer stops the find cycle and triggers the subscribe
  (define server-offer (first (multicasts)))
  (reset-log!)
  (define offer-entry
    (offer-service-entry #:service-id #x1234 #:instance-id 1
                         #:major-version 1 #:minor-version 5
                         #:ttl 30
                         #:udp-endpoint (sd-endpoint-option 'endpoint 'ipv4
                                                            "10.0.0.1" 40001 'udp #f)))
  (sd-client-handle-message! client
                             (sd-packet #t #t (list offer-entry) '())
                             1 sender-a #t)
  (check-equal? (reverse client-events) '(offer))
  (check-equal? (length (unicasts-to sender-a)) 1)
  (define-values (sub1 _s1 _c8) (decode-sd-message (first (unicasts-to sender-a))))
  (define sub1-entry (first (sd-packet-entries sub1)))
  (check-equal? (sd-eventgroup-entry-type sub1-entry) sd-entry-subscribe)
  (check-equal? (sd-eventgroup-entry-counter sub1-entry) 0)
  (check-equal? (first (sd-eventgroup-entry-option-runs sub1-entry))
                (list (sd-endpoint-option 'endpoint 'ipv4 "10.0.0.9" 49152 'udp #f)))

  ;; no ack yet: retries with an incremented counter
  (reset-log!)
  (virtual-advance! vm 300)
  (define-values (sub2 _s2 _c9) (decode-sd-message (first (unicasts-to sender-a))))
  (check-equal? (sd-eventgroup-entry-counter (first (sd-packet-entries sub2))) 1)

  ;; ack arrives: refresh timer is scheduled at ttl * 3/4 = 22500 ms
  (reset-log!)
  (define ack-entry
    (subscribe-ack-entry #:service-id #x1234 #:instance-id 1
                         #:major-version 1 #:eventgroup-id #x10
                         #:ttl 30
                         #:counter 1
                         #:multicast-option (sd-endpoint-option 'multicast 'ipv4
                                                                "239.1.1.1" 41001 'udp #f)))
  (sd-client-handle-message! client (sd-packet #t #t (list ack-entry) '()) 2 sender-a #f)
  (check-equal? (reverse client-events) '(offer ack))
  (reset-log!)
  (virtual-advance! vm 22499)
  (check-equal? (unicasts-to sender-a) '() "refresh not yet due")
  (virtual-advance! vm 2)
  (define-values (refresh _s3 _c10) (decode-sd-message (first (unicasts-to sender-a))))
  (check-equal? (sd-eventgroup-entry-counter (first (sd-packet-entries refresh))) 2)

  ;; peer reboot detection: sessions go backwards with the flag set
  (reset-log!)
  ;; the client recorded session 2 from the offer; a new offer with a
  ;; lower session and the reboot flag signals a reboot [00258]
  (sd-client-handle-message! client
                             (sd-packet #t #t (list offer-entry) '())
                             1 sender-a #t)
  (check-not-false (memq 'reboot (reverse client-events)))
  ;; after the reboot the subscription re-subscribes (retry delay 300)
  (virtual-advance! vm 300)
  (check-equal? (length (unicasts-to sender-a)) 1)

  ;; stop offer clears everything
  (reset-log!)
  (set! client-events '())
  (define stop-entry
    (stop-offer-service-entry #:service-id #x1234 #:instance-id 1
                              #:major-version 1 #:minor-version 5))
  (sd-client-handle-message! client (sd-packet #f #t (list stop-entry) '()) 5 sender-a #t)
  (check-equal? (reverse client-events) '(stop))
  (check-false (sd-client-offer-info client))

  ;; release: stop-request sends StopSubscribe while subscribed
  ;; (re-subscribe first)
  (reset-log!)
  (sd-client-handle-message! client
                             (sd-packet #t #t (list offer-entry) '())
                             3 sender-a #t)
  (set! client-events '())
  (reset-log!)
  (sd-client-stop-request! client)
  (check-equal? (length (unicasts-to sender-a)) 1 "stop subscribe sent")
  (define-values (stop-sub _s5 _c12) (decode-sd-message (first (unicasts-to sender-a))))
  (check-true (entry-type-stop? (first (sd-packet-entries stop-sub)))))
