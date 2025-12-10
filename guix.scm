;; RRecord-Verity - Guix Package Definition
;; Run: guix shell -D -f guix.scm

(use-modules (guix packages)
             (guix gexp)
             (guix git-download)
             (guix build-system node)
             ((guix licenses) #:prefix license:)
             (gnu packages base))

(define-public rrecord_verity
  (package
    (name "RRecord-Verity")
    (version "0.1.0")
    (source (local-file "." "RRecord-Verity-checkout"
                        #:recursive? #t
                        #:select? (git-predicate ".")))
    (build-system node-build-system)
    (synopsis "JavaScript/Node.js application")
    (description "JavaScript/Node.js application - part of the RSR ecosystem.")
    (home-page "https://github.com/hyperpolymath/RRecord-Verity")
    (license license:agpl3+)))

;; Return package for guix shell
rrecord_verity
