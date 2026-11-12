#lang info

(define name "someip")

(define collection "someip")

(define version "0.1")

;; The shipped collection depends on base alone: pure Racket, no foreign
;; libraries. rackunit-lib stays a runtime dep because test/ ships inside
;; this package and raco setup --check-pkg-deps classifies its requires
;; as run-mode (glaze/foreman precedent).
(define deps '("base" "rackunit-lib"))

(define build-deps '("base" "scribble-lib" "racket-doc" "rackunit-doc" "rackunit-lib"))

(define scribblings '(("scribblings/someip.scrbl" ())))

(define pkg-desc
  "SOME/IP protocol stack: wire codec, SOME/IP-TP segmentation, SOME/IP-SD service discovery, UDP/TCP endpoints, and RPC/event/field APIs. Pure Racket.")

(define pkg-authors '(turlamai))

(define license 'Apache-2.0)

;; `test/` runs under raco test; keep it out of setup compilation.
(define test-omit-paths '("test"))
