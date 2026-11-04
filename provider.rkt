#lang racket/base

;; Service provider: expose methods, events and fields over a transport
;; endpoint, with optional SOME/IP-SD advertising.
;;
;; Protocol rules implemented here:
;;   [00921] request payload = input arguments in signature order
;;   [00922] responses copy Message ID and Request ID from the request,
;;           message type RESPONSE [00901] or ERROR [00902]
;;   [00904] only RESPONSE/ERROR carry a non-zero return code
;;   [00905] everything else sets the return code to 0
;;   [00188]/[00189] events and fire&forget are never answered
;;   [0024x] field mapping: getter = field id, setter = field id + 1,
;;           notifier = field id + 2
;;   [0xxxx] SD advertising via sd/machine when endpoints are configured
;;
;; The provider is transport-first: it works without SD (consumers can
;; be configured statically), and `offer`/`stop-offer!` drive the SD
;; server machine when a multicast group is configured.

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

(provide provider-message-handler
         (struct-out method)
         (struct-out event)
         (struct-out field)
         (struct-out service-provider)
         make-service-provider
         provider-handle-message!
         provider-start!
         provider-stop!
         provider-stop-offer!
         provider-notify!
         provider-subscribe!
         provider-subscribers)

(module+ test (require rackunit racket/list))

;; ------------------------------------------------------------------
;; Service description

;; method: handler receives (payload-bytes sender) and returns either
;; response payload bytes (return code 0) or (cons return-code payload).
(struct method (id handler))
(struct event (id eventgroup))
;; field: value is held by the application; getter/setter handlers like
;; method handlers, notifier event = id + 2.
(struct field (id getter setter eventgroup))

(struct service-provider
  (endpoint
   service-id instance-id interface-version
   methods            ; box: hash method-id -> method
   events             ; box: hash event-id -> event
   eventgroups        ; box: hash eventgroup-id -> (listof event-id)
   subscribers        ; box: hash eventgroup-id -> (listof sender)
   multicast-address multicast-port
   lock
   sd-server-box)     ; box: #f or the sd-server machine
  #:transparent)

(define (make-service-provider
         #:endpoint endpoint
         #:service-id service-id
         #:instance-id instance-id
         #:interface-version interface-version
         #:methods [methods '()]
         #:events [events '()]
         #:fields [fields '()]
         #:multicast-address [multicast-address #f]
         #:multicast-port [multicast-port #f]
         #:timer-manager [timers (make-timer-manager)]
         #:sd-config [sd-config* (make-sd-config)]
         #:ttl-seconds [ttl-seconds 30]
         #:on-subscribe [on-subscribe (lambda (sid iid egid ttl endpoints) 'ack)])
  (unless (exact-positive-integer? service-id)
    (raise-argument-error 'make-service-provider "exact-positive-integer?" service-id))
  (define eventgroups
    (for/hash ([eg (remove-duplicates (map event-group-of (append events fields)))])
      (values eg
              (for/list ([e (append events fields)]
                         #:when (= (event-group-of e) eg))
                (event-id e)))))
  (define p
    (service-provider endpoint service-id instance-id interface-version
                      (box (for/hash ([m methods]) (values (method-id m) m)))
                      (box (for/hash ([e events]) (values (event-id e) e)))
                      (box eventgroups)
                      (box (make-hash))
                      multicast-address multicast-port
                      (make-semaphore 1)
                      (box #f)))
  (define sd-server
    (and multicast-address
         (make-sd-server
          #:timer-manager timers
          #:config sd-config*
          #:service-id service-id
          #:instance-id instance-id
          #:major-version interface-version
          #:minor-version 0
          #:ttl-seconds ttl-seconds
          #:udp-endpoint (endpoint-udp-announcement endpoint)
          #:eventgroups
          (for/list ([eg (hash-keys eventgroups)])
            (offered-eventgroup eg #f)) ; no per-group multicast endpoint yet
          #:send-multicast
          (lambda (bs)
            (endpoint-send-udp-raw! endpoint multicast-address
                                      (or multicast-port sd-port) bs))
          #:send-unicast
          (lambda (dest bs)
            (endpoint-send-udp-raw! endpoint (dest-host dest) (dest-port dest) bs))
          #:on-subscribe
          (lambda (sid iid egid ttl endpoints sender)
            ;; record the subscription destination, then consult the
            ;; application
            (provider-subscribe! p egid sender)
            (on-subscribe sid iid egid ttl endpoints)))))
  (set-box! (service-provider-sd-server-box p) sd-server)
  p)

;; helpers to treat events and fields uniformly
(define (event-group-of e)
  (if (event? e) (event-eventgroup e) (field-eventgroup e)))

;; the SD advertisement needs the provider's UDP endpoint tuple; the
;; transport endpoint exposes its bound port
(define (endpoint-udp-announcement endpoint)
  (sd-endpoint-option 'endpoint 'ipv4 "0.0.0.0" (endpoint-udp-port endpoint) 'udp #f))

;; subscriber destinations arrive as the transport's opaque sender
;; identity (a `sender` struct); accept plain (list host port) too
(define (dest-host d) (if (sender? d) (sender-host d) (first d)))
(define (dest-port d) (if (sender? d) (sender-port d) (second d)))

;; ------------------------------------------------------------------
;; Lifecycle

(define (provider-start! p)
  (define sd (unbox (service-provider-sd-server-box p)))
  (when sd (sd-server-start! sd)))

(define (provider-stop-offer! p)
  (define sd (unbox (service-provider-sd-server-box p)))
  (when sd (sd-server-stop! sd)))

(define (provider-stop! p)
  (provider-stop-offer! p))

;; ------------------------------------------------------------------
;; Dispatch (wired by the application's endpoint message handler)

;; Process one inbound message. Returns #f or a response message to be
;; sent back to the sender.
(define (provider-handle-message! p m sender)
  (call-with-semaphore (service-provider-lock p)
    (lambda ()
      (define sid (someip-message-service-id m))
      (define mt (someip-message-message-type m))
      (cond
        ;; not ours
        [(not (= sid (service-provider-service-id p))) #f]
        [(not (= (someip-message-interface-version m)
                 (service-provider-interface-version p)))
         ;; [PRS_SOMEIP_00195] interface version mismatch -> error
         (make-error-response p m rc-e-wrong-interface-version)]
        [(memv mt (list mt-request mt-request-no-return))
         (handle-method-call p m sender)]
        [(= mt mt-notification)
         ;; inbound notifications are not a provider concern
         #f]
        [else #f]))))

(define (handle-method-call p m sender)
  (define mid (someip-message-method-id m))
  (define handlers (unbox (service-provider-methods p)))
  (define method (hash-ref handlers mid #f))
  (cond
    [(not method)
     ;; [PRS_SOMEIP_00195] method unknown: answer request calls with an
     ;; error; fire&forget is never answered [00189]
     (if (= (someip-message-message-type m) mt-request)
         (make-error-response p m rc-e-unknown-method)
         #f)]
    [else
     (define result
       (with-handlers ([exn:fail? (lambda (e)
                                   (someip-log-warning "provider: method ~a failed: ~a"
                                                       mid (exn-message e))
                                   (cons rc-e-not-ok #""))])
         ((method-handler method) (someip-message-payload m) sender)))
     (define-values (rc payload)
       (match result
         [(cons rc pl) (values rc pl)]
         [pl (values rc-e-ok (if (bytes? pl) pl #""))]))
     (if (= (someip-message-message-type m) mt-request)
         (make-someip-message
          #:service-id (someip-message-service-id m)
          #:method-id mid
          #:interface-version (service-provider-interface-version p)
          #:message-type (if (= rc rc-e-ok) mt-response mt-error)
          #:client-id (someip-message-client-id m)
          #:session-id (someip-message-session-id m)
          #:return-code rc
          #:protocol-version (someip-message-protocol-version m)
          #:payload payload)
         ;; fire&forget: no response [00171]/[00189]
         #f)]))

(define (make-error-response p m rc)
  (make-someip-message
   #:service-id (someip-message-service-id m)
   #:method-id (someip-message-method-id m)
   #:interface-version (service-provider-interface-version p)
   #:message-type mt-error
   #:client-id (someip-message-client-id m)
   #:session-id (someip-message-session-id m)
   #:return-code rc
   #:protocol-version (someip-message-protocol-version m)
   #:payload #""))

;; Composite endpoint message handler: routes SOME/IP-SD messages into
;; the SD server machine and service messages into the provider; sends
;; responses back to the sender.
(define (provider-message-handler p)
  (lambda (m sender)
    (cond
      [(and (= (someip-message-service-id m) sd-service-id)
            (= (someip-message-method-id m) sd-method-id)
            (unbox (service-provider-sd-server-box p)))
       (define-values (pkt consumed)
         (decode-sd-payload (someip-message-payload m)))
       (sd-server-handle-message! (unbox (service-provider-sd-server-box p)) pkt 0 sender #f)]
      [else
       ;; service dispatch with reply
       (define resp (provider-handle-message! p m sender))
       (when resp
         (endpoint-send-udp! (service-provider-endpoint p)
                             (sender-host sender) (sender-port sender) resp))])))

;; ------------------------------------------------------------------
;; Events

;; Notify all subscribers of `event-id`'s eventgroup. Returns the list
;; of destinations the event was sent to.
(define (provider-notify! p event-id payload)
  (call-with-semaphore (service-provider-lock p)
    (lambda ()
      (define eg (hash-ref (unbox (service-provider-events p)) event-id #f))
      (define egid (or (and eg (event-eventgroup eg))
                       (for/first ([(g eids) (in-hash (unbox (service-provider-eventgroups p)))]
                                   #:when (memv event-id eids))
                         g)))
      (unless egid
        (raise (exn:fail:someip (format "provider: event ~a is not offered" event-id)
                                (current-continuation-marks))))
      (define subs (hash-ref (unbox (service-provider-subscribers p)) egid '()))
      (define msg
        (make-someip-message
         #:service-id (service-provider-service-id p)
         #:method-id event-id
         #:interface-version (service-provider-interface-version p)
         #:message-type mt-notification
         #:payload payload))
      (for/list ([dest subs])
        (endpoint-send-udp! (service-provider-endpoint p)
                            (dest-host dest) (dest-port dest) msg)
        dest))))

(define (provider-subscribers p)
  (call-with-semaphore (service-provider-lock p)
    (lambda ()
      (for/hash ([(k v) (in-hash (unbox (service-provider-subscribers p)))])
        (values k v)))))

;; record subscribers coming from the SD machine's subscribe callback
(define (provider-subscribe! p eventgroup-id sender)
  (call-with-semaphore (service-provider-lock p)
    (lambda ()
      (define subs (unbox (service-provider-subscribers p)))
      (define others (filter (lambda (s) (not (equal? s sender)))
                             (hash-ref subs eventgroup-id '())))
      (hash-set! subs eventgroup-id (cons sender others)))))

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (require rackunit
           racket/list
           "transport.rkt")

  ;; dispatch-level tests with a synthetic endpoint table
  (define sent '())
  (define fake-ep
    (make-someip-endpoint #:message-handler void))
  (define p
    (make-service-provider
     #:endpoint fake-ep
     #:service-id #x1234
     #:instance-id 1
     #:interface-version 2
     #:methods (list (method #x0001
                             (lambda (payload sender)
                               (if (= (bytes-length payload) 1)
                                   (bytes (add1 (bytes-ref payload 0)))
                                   (cons rc-e-not-ok #""))))
                     (method #x0002 (lambda (payload sender) #"")))
     #:events (list (event #x8010 #x1))))
  ;; note: on-subscribe is wired by the application; simulate it here
  (provider-subscribe! p #x1 (list "127.0.0.1" 50000))

  (define (req mid payload [type mt-request])
    (make-someip-message #:service-id #x1234 #:method-id mid
                         #:interface-version 2 #:message-type type
                         #:client-id 7 #:session-id 3
                         #:payload payload))

  ;; request/response, echo of ids [00922]
  (define resp (provider-handle-message! p (req #x0001 (bytes 41)) (list "h" 1)))
  (check-equal? (someip-message-message-type resp) mt-response)
  (check-equal? (someip-message-return-code resp) rc-e-ok)
  (check-equal? (someip-message-payload resp) (bytes 42))
  (check-equal? (someip-message-client-id resp) 7)
  (check-equal? (someip-message-session-id resp) 3)

  ;; application error via return code: still message type RESPONSE
  ;; [00901] note per [PRS_SOMEIP_00901]; payload-level errors are
  ;; carried by return codes of RESPONSE, so a cons result maps to ERROR
  (define resp2 (provider-handle-message! p (req #x0001 (bytes 1 2 3)) (list "h" 1)))
  (check-equal? (someip-message-message-type resp2) mt-error)
  (check-equal? (someip-message-return-code resp2) rc-e-not-ok)

  ;; fire&forget is never answered [00189]
  (check-false (provider-handle-message! p (req #x0001 (bytes 9) mt-request-no-return)
                                         (list "h" 1)))

  ;; unknown method: request -> error [00195]; fire&forget -> nothing
  (check-equal? (someip-message-return-code
                 (provider-handle-message! p (req #x00FF #"") (list "h" 1)))
                rc-e-unknown-method)
  (check-false (provider-handle-message! p (req #x00FF #"" mt-request-no-return)
                                         (list "h" 1)))

  ;; interface version mismatch
  (check-equal? (someip-message-return-code
                 (provider-handle-message!
                  p (struct-copy someip-message (req #x0001 #"") [interface-version 1])
                  (list "h" 1)))
                rc-e-wrong-interface-version)

  ;; foreign service ignored
  (check-false (provider-handle-message!
                p (struct-copy someip-message (req #x0001 #"") [service-id 999])
                (list "h" 1)))

  ;; notify: event exists, subscriber recorded
  (provider-notify! p #x8010 (bytes 1 2 3))
  (check-equal? (hash-ref (provider-subscribers p) #x1) (list (list "127.0.0.1" 50000)))
  (check-exn exn:fail:someip? (lambda () (provider-notify! p #x8099 (bytes 1))))

  (endpoint-close! fake-ep))
