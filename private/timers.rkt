#lang racket/base

;; Minimal one-shot timer facility used by the SD state machines.
;;
;; `make-timer-manager` runs one background thread that fires scheduled
;; closures close to their due time. `sd/machine` can inject a different
;; implementation (e.g. the virtual clock below in tests), so the
;; machines themselves never touch threads or the wall clock.

(require racket/async-channel
         racket/contract
         "../logging.rkt")

(provide (struct-out entry) (struct-out timer-manager) timer-manager?
         make-timer-manager
         timer-schedule!
         timer-cancel!
         timer-manager-stop!
         timer-id?

         make-virtual-timer-manager
         (struct-out virtual-manager)
         virtual-manager-heap
         virtual-now
         virtual-schedule!
         virtual-cancel!
         virtual-advance!)

;; opaque id returned by timer-schedule!
(struct timer-id (gen) #:transparent)
(struct real-timer-manager (thread control))
(struct timer-manager (kind handle))
;; one scheduled entry
(struct entry (id due proc))

;; ---- real manager ---------------------------------------------------

(define (make-timer-manager)
  (define control (make-async-channel))
  (define (run)
    (let loop ([pending '()]) ; sorted by due time
      (define next-due (and (pair? pending) (entry-due (car pending))))
      (define fire-evt
        (if next-due
            (handle-evt (alarm-evt (max 0.0 (- next-due (current-inexact-milliseconds))))
                        (lambda (_) 'fire))
            never-evt))
      (define v (sync fire-evt (handle-evt control values)))
      (cond
        [(eq? v 'fire)
         (define now (current-inexact-milliseconds))
         (for ([e (take-due pending now)])
           (with-handlers ([exn:fail? (lambda (x)
                                        (someip-log-error "timers: ~a" (exn-message x)))])
             ((entry-proc e))))
         (loop (drop-due pending now))]
        [(cancel-message? v)
         (loop (remove-id pending (cdr v)))]
        [(schedule-message? v)
         (loop (insert-entry pending
                             (entry (cadr v)
                                    (+ (current-inexact-milliseconds) (caddr v))
                                    (cadddr v))))]
        [(eq? v 'stop) (void)]
        [else (loop pending)])))
  (timer-manager 'real (real-timer-manager (thread run) control)))

(define (timer-manager-control mgr)
  (case (timer-manager-kind mgr)
    [(real) (real-timer-manager-control (timer-manager-handle mgr))]
    [(virtual) (error 'timer-manager-control "virtual manager has no control channel")]))

(define (cancel-message? v) (and (pair? v) (eq? (car v) 'cancel)))
(define (schedule-message? v) (and (pair? v) (eq? (car v) 'schedule)))

(define next-id (let ([c (box 0)]) (lambda () (set-box! c (add1 (unbox c))) (unbox c))))

;; Schedule `proc` to run after `delay-ms`. Returns an id for
;; timer-cancel!.
(define (timer-schedule! mgr delay-ms proc)
  (unless (timer-manager? mgr)
    (raise-argument-error 'timer-schedule! "timer-manager?" mgr))
  (unless (exact-nonnegative-integer? delay-ms)
    (raise-argument-error 'timer-schedule! "exact-nonnegative-integer? delay-ms" delay-ms))
  (unless (procedure? proc)
    (raise-argument-error 'timer-schedule! "procedure?" proc))
  (define id (timer-id (next-id)))
  (case (timer-manager-kind mgr)
    [(real)
     (async-channel-put (timer-manager-control mgr)
                        (list 'schedule id delay-ms proc))]
    [(virtual)
     (define handle (timer-manager-handle mgr))
     (define gen (add1 (unbox (virtual-manager-counter-box handle))))
     (set-box! (virtual-manager-counter-box handle) gen)
     (set-box! (virtual-manager-heap-box handle)
               (insert-entry (unbox (virtual-manager-heap-box handle))
                             (entry id (+ (virtual-now mgr) delay-ms) proc)))])
  id)

(define (timer-cancel! mgr id)
  (unless (timer-manager? mgr)
    (raise-argument-error 'timer-cancel! "timer-manager?" mgr))
  (case (timer-manager-kind mgr)
    [(real)
     (async-channel-put (timer-manager-control mgr) (cons 'cancel id))]
    [(virtual)
     (define handle (timer-manager-handle mgr))
     (set-box! (virtual-manager-heap-box handle)
               (remove-id (unbox (virtual-manager-heap-box handle)) id))]))

(define (timer-manager-stop! mgr)
  (unless (timer-manager? mgr)
    (raise-argument-error 'timer-manager-stop! "timer-manager?" mgr))
  (async-channel-put (timer-manager-control mgr) 'stop))

;; ---- pending list helpers ------------------------------------------

(define (insert-entry pending e)
  (cond
    [(null? pending) (list e)]
    [(<= (entry-due e) (entry-due (car pending)))
     (cons e pending)]
    [else (cons (car pending) (insert-entry (cdr pending) e))]))

(define (take-due pending now)
  (let loop ([pending pending] [acc '()])
    (cond
      [(null? pending) (reverse acc)]
      [(<= (entry-due (car pending)) now)
       (loop (cdr pending) (cons (car pending) acc))]
      [else (reverse acc)])))

(define (drop-due pending now)
  (cond
    [(null? pending) '()]
    [(<= (entry-due (car pending)) now) (drop-due (cdr pending) now)]
    [else pending]))

(define (remove-id pending id)
  (filter (lambda (e) (not (equal? (entry-id e) id))) pending))

;; ---- virtual manager (deterministic tests) --------------------------

(struct virtual-manager (heap-box now-box counter-box))

(define (make-virtual-timer-manager [start-ms 0.0])
  (timer-manager 'virtual (virtual-manager (box '()) (box start-ms) (box 0))))

(define (virtual-manager-heap mgr) (virtual-manager-heap-box (timer-manager-handle mgr)))
(define (virtual-manager-now mgr) (virtual-manager-now-box (timer-manager-handle mgr)))
(define (virtual-manager-counter mgr) (virtual-manager-counter-box (timer-manager-handle mgr)))

(define (virtual-now mgr) (unbox (virtual-manager-now mgr)))

(define (virtual-schedule! mgr delay-ms proc)
  (define gen (add1 (unbox (virtual-manager-counter mgr))))
  (set-box! (virtual-manager-counter mgr) gen)
  (define id (timer-id gen))
  (set-box! (virtual-manager-heap mgr)
            (insert-entry (unbox (virtual-manager-heap mgr))
                          (entry id (+ (virtual-now mgr) delay-ms) proc)))
  id)
(define (virtual-set-heap! mgr v) (set-box! (virtual-manager-heap mgr) v))

(define (virtual-cancel! mgr id)
  (virtual-set-heap! mgr (remove-id (unbox (virtual-manager-heap mgr)) id)))

;; Advance the virtual clock by `ms`, firing every timer that becomes
;; due. The clock takes each event's exact due time before it fires, so
;; timers scheduled from within a callback get their delay relative to
;; the moment of that callback - just like real timers.
(define (virtual-advance! mgr ms)
  (define handle (timer-manager-handle mgr))
  (define target (+ (virtual-now mgr) ms))
  (let loop ()
    (define heap (unbox (virtual-manager-heap-box handle)))
    (cond
      [(and (pair? heap) (<= (entry-due (car heap)) target))
       (set-box! (virtual-manager-now-box handle) (entry-due (car heap)))
       (set-box! (virtual-manager-heap-box handle) (cdr heap))
       ((entry-proc (car heap)))
       (loop)]
      [else
       (set-box! (virtual-manager-now-box handle) target)])))

;; ------------------------------------------------------------------
;; Tests

(module+ test
  (require rackunit)

  ;; real manager (generous margins: CI machines are slow and loaded)
  (define mgr (make-timer-manager))
  (define sem (make-semaphore))
  (timer-schedule! mgr 300 (lambda () (semaphore-post sem)))
  (check-not-false (sync/timeout 10 sem) "fired after delay")
  (timer-schedule! mgr 100 (lambda () (error "must be cancelled")))
  (define id (timer-schedule! mgr 500 (lambda () (semaphore-post sem))))
  (timer-cancel! mgr id)
  (check-false (sync/timeout 1 sem) "cancelled timer does not fire")
  (timer-manager-stop! mgr)

  ;; virtual manager
  (define vm (make-virtual-timer-manager))
  (define log '())
  (virtual-schedule! vm 100 (lambda () (set! log (cons 'a log))))
  (virtual-schedule! vm 50 (lambda () (set! log (cons 'b log))))
  (virtual-advance! vm 60)
  (check-equal? log '(b))
  (virtual-advance! vm 40)
  (check-equal? log '(a b))
  (define cancelled (virtual-schedule! vm 10 (lambda () (set! log (cons 'x log)))))
  (virtual-cancel! vm cancelled)
  (virtual-advance! vm 10)
  (check-equal? log '(a b)))
