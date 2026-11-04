#lang info

(define collection "someip")

(define version "0.1.0")

;; Runtime depends only on the base distribution: pure Racket, no foreign
;; libraries. Everything (codec, transport, discovery) is implemented on
;; top of racket/base, racket/udp and racket/tcp.
(define deps '("base" "rackunit-lib"))

(define build-deps '("base" "scribble-lib" "racket-doc" "rackunit-doc" "rackunit-lib"))

(define scribblings '(("scribblings/someip.scrbl" ())))

(define pkg-desc
  "SOME/IP protocol stack: wire codec, SOME/IP-TP segmentation, SOME/IP-SD service discovery, UDP/TCP endpoints, and RPC/event/field APIs. Pure Racket.")

(define pkg-authors '(turlamai))

(define license 'Apache-2.0)
