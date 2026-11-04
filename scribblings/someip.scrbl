#lang scribble/doc
@(require scribble/manual
          scribble/core
          (for-label racket/base
                     racket/contract
                     (file "../main.rkt")))

@title[#:tag "top"]{someip: a SOME/IP protocol stack in pure Racket}

@author{turlamai}

@defmodule[someip]

This package implements the AUTOSAR @deftech{SOME/IP} family of
protocols --- the message format, SOME/IP-TP segmentation, SOME/IP-SD
service discovery, UDP/TCP transport, and provider/consumer APIs ---
in pure Racket on the standard distribution.

The implementation follows the AUTOSAR Foundation specifications
(SOME/IP Protocol and SOME/IP-SD, release R22-11) and is validated
byte-for-byte against the specification's own examples in the test
suite.

@section[#:tag "concepts"]{Layering}

@itemlist[
 @item{@tt{(someip message)} --- the 16-byte header codec, message
   types, return codes, session id handling, TCP magic cookies.}
 @item{@tt{(someip serialize)} --- payload serialization: primitives,
   BOM-carrying strings, arrays, structs, unions, TLV.}
 @item{@tt{(someip tp)} --- SOME/IP-TP segmentation and reassembly.}
 @item{@tt{(someip sd/message)} --- SOME/IP-SD entries and options.}
 @item{@tt{(someip sd/machine)} --- SD server and client state
   machines, driven by injectable timers.}
 @item{@tt{(someip transport)} --- UDP/TCP endpoints, multicast,
   packed-message splitting.}
 @item{@tt{(someip provider)} --- methods, events, fields, SD offer.}
 @item{@tt{(someip consumer)} --- calls with request/response matching,
   event callbacks, SD discovery.}]

@section[#:tag "quickstart"]{Quick start}

@subsection{Provider}

@racketblock[
(require someip)
(define ep (make-someip-endpoint
            #:udp-port 30490
            #:multicast-groups '("239.255.1.100")
            #:message-handler void))
(define provider
  (make-service-provider
   #:endpoint ep
   #:service-id #x4321
   #:instance-id 1
   #:interface-version 1
   #:methods
   (list (method #x0001
                 (lambda (payload sender)
                   (bytes (add1 (bytes-ref payload 0))))))
   #:events (list (event #x8010 #x1))
   #:multicast-address "239.255.1.100"))
(provider-start! provider)
]

Inbound traffic is routed by composing the provider's handler with the
endpoint's @racket[message-handler] argument; see
@racket[provider-message-handler].

@subsection{Consumer}

@racketblock[
(require someip)
(define ep (make-someip-endpoint
            #:multicast-groups '("239.255.1.100")
            #:message-handler void))
(define consumer
  (make-service-consumer
   #:service-id #x4321
   #:interface-version 1
   #:eventgroup-ids '(#x1)
   #:multicast-address "239.255.1.100"))
(consumer-attach-endpoint! ep consumer)
(consumer-start-discovery! consumer)
(define result (consumer-call consumer #x0001 #:payload (bytes 20)))
]

@section[#:tag "conformance"]{Wire conformance and deviations}

The stack is validated against the specification's own worked
examples: the 5880-byte SOME/IP-TP segmentation walkthrough, the SD
example PDU (Figure 5.2 of the SD specification) and the TCP magic
cookie layouts.

Known spec-text conflicts are resolved and documented in the source:
the SD entry types for subscribe/ack are @tt{0x06}/@tt{0x07} per the
normative field definitions (the summary table's @tt{0x02}/@tt{0x03}
is a specification typo); stop-offer / stop-subscribe / nack are the
offer/subscribe/ack types with TTL 0.

Documented simplifications: the SD server answers every find with a
unicast offer (the specification's basic behavior; the multicast-answer
optimization is not implemented), and the consumer restarts its find
cycle when an offer's TTL expires.

@section[#:tag "testing"]{Deterministic testing}

The SD machines take injectable timer managers, random sources and
send callbacks, so the whole discovery lifecycle is tested
deterministically with a virtual clock (see @tt{private/timers}). The
transport layer is tested over the loopback interface, including an
end-to-end discovery → subscribe → call → event scenario.
