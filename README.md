# someip

A SOME/IP protocol stack in pure Racket.

`someip` implements the AUTOSAR **SOME/IP** (Scalable service-Oriented
MiddlewarE over IP) family of protocols on top of the standard Racket
distribution — no foreign libraries, no FFI:

- **SOME/IP message codec** — the 16-byte header with strict validation,
  message types, return codes, TCP magic cookies, packed-message
  decoding.
- **Payload serialization framework** — configurable byte order,
  alignment and length-field sizes; primitives, BOM-carrying
  UTF-8/UTF-16 strings, fixed/dynamic arrays, structs with length
  fields, unions, and TLV tagging with unknown-member skipping.
- **SOME/IP-TP** — segmentation of large payloads for UDP transport and
  loss-tolerant reassembly (out-of-order, duplicates, gap detection).
- **SOME/IP-SD** — the full wire format (entries, options, IPv4/IPv6
  endpoint/multicast/SD-endpoint options) plus deterministic server and
  client state machines: Initial Wait / Repetition / Main phases,
  find/offer/subscribe lifecycles, TTL refresh, peer reboot detection.
- **Transport** — UDP endpoints with multicast groups, TCP with framing
  and connection reuse; several SOME/IP messages per datagram or TCP
  segment are split automatically.
- **Provider/consumer APIs** — methods, events, fields and publish/
  subscribe over UDP or TCP, with optional service discovery.

The design target is embeddable testing and tooling: a complete,
deterministic protocol stack for talking to (and testing against)
automotive ECUs from Racket, whether you are building diagnostics,
device simulation, replay tools or vehicle data services.

## Installation

```
raco pkg install someip
```

or, from a Git checkout:

```
raco pkg install --link ./someip
```

## Quick start

Server side:

```racket
#lang racket/base
(require someip)

(define ep
  (make-someip-endpoint
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
                   ;; request payload in, response payload out
                   (bytes (add1 (bytes-ref payload 0))))))
   #:events
   (list (event #x8010 #x1))
   #:multicast-address "239.255.1.100"))

;; route inbound SD and service messages, answering requests
(define handler (provider-message-handler provider))
(void
 (thread
  (lambda ()
    (let loop ()
      (sleep 0.1)
      (loop)))))

(provider-start! provider)              ; SD offer lifecycle
(provider-notify! provider #x8010 #"hello subscribers")
```

Consumer side:

```racket
#lang racket/base
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
(void
 (thread
  (lambda ()
    (let loop ()
      (sleep 0.1)
      (loop)))))

(consumer-set-event-callback!
 consumer #x8010 (lambda (payload sender) (printf "event: ~a\n" payload)))

(consumer-start-discovery! consumer)    ; SD find/subscribe lifecycle

(define result (consumer-call consumer #x0001 #:payload (bytes 20)))
(call-result-payload result)            ; => #"\x15"
```

For static topologies without SD, pass `#:server-host`/`#:server-port`
to the consumer and skip discovery.

The transport endpoints own their threads through a custodian; call
`endpoint-close!` to tear everything down deterministically.

## Wire conformance

The implementation follows the AUTOSAR Foundation specifications
(SOME/IP Protocol, SOME/IP-SD, release R22-11) and is validated against
them at the byte level in the test suite, including the specification's
own worked examples (the 5880-byte TP segmentation example, the SD
example PDU, the TCP magic cookies). Known, documented deviations and
spec-typo resolutions are noted in the module documentation.

## Platform notes

UDP multicast behaves the same on macOS, Linux and Windows; endpoints
pick ephemeral ports explicitly because Racket does not expose a
listener-port query. The package is pure `#lang racket/base` +
`racket/tcp`/`racket/udp` and runs anywhere Racket CS runs.

## Documentation

Full module documentation is rendered from `scribblings/`:

```
raco docs someip
```

## Development

```
raco test .
raco setup --check-pkg-deps someip
```

## License

[Apache-2.0](LICENSE)

中文说明见 [README.zh-CN.md](README.zh-CN.md)。
