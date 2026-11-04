#lang racket/base

;; `someip` facade: the whole stack from one require.
;;
;; Layers, bottom to top:
;;   (someip message)     SOME/IP header codec, message types, return codes
;;   (someip serialize)   payload serialization framework (TLV, BOM, unions)
;;   (someip tp)          SOME/IP-TP segmentation / reassembly
;;   (someip sd message)  SOME/IP-SD wire format
;;   (someip sd machine)  SOME/IP-SD server/client state machines
;;   (someip transport)   UDP/TCP endpoints with multicast
;;   (someip provider)    service provider (methods, events, fields, SD)
;;   (someip consumer)    service consumer (calls, events, discovery)

(require "message.rkt"
         "serialize.rkt"
         "tp.rkt"
         "transport.rkt"
         "sd/message.rkt"
         "sd/machine.rkt"
         "provider.rkt"
         "consumer.rkt"
         "logging.rkt")

(provide (all-from-out "message.rkt")
         (all-from-out "serialize.rkt")
         (all-from-out "tp.rkt")
         (all-from-out "transport.rkt")
         (all-from-out "sd/message.rkt")
         (all-from-out "sd/machine.rkt")
         (all-from-out "provider.rkt")
         (all-from-out "consumer.rkt")
         (all-from-out "logging.rkt"))
