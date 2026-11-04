#lang racket/base

;; Pluggable logging for the someip package.
;;
;; All modules log through the "someip" logger topic, so applications can
;; route, filter or silence the stack with Racket's standard logger
;; facilities. Library code must never print directly.

(require racket/contract
         racket/format)

(provide current-someip-logger
         someip-log-debug
         someip-log-info
         someip-log-warning
         someip-log-error)

(define someip-logger
  (make-logger 'someip #f))

;; Parameter controlling which logger receives someip diagnostics.
;; Applications may replace it (e.g. with their application logger) to
;; aggregate stack logs.
(define current-someip-logger
  (make-parameter someip-logger (lambda (v) (or (logger? v) (eq? v #f)))))

(define (someip-log level fmt . args)
  (define lg (current-someip-logger))
  (when lg
    (log-message lg level
                 (string->symbol (format "~a" (logger-name lg)))
                 (apply format fmt args) #f)))

(define (someip-log-debug fmt . args) (apply someip-log 'debug fmt args))
(define (someip-log-info fmt . args) (apply someip-log 'info fmt args))
(define (someip-log-warning fmt . args) (apply someip-log 'warning fmt args))
(define (someip-log-error fmt . args) (apply someip-log 'error fmt args))
