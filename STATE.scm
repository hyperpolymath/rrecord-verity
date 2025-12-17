;;; STATE.scm — rrecord-verity
;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell

(define metadata
  '((version . "0.1.0") (updated . "2025-12-17") (project . "rrecord-verity")))

(define current-position
  '((phase . "v0.2 - Infrastructure Hardening")
    (overall-completion . 35)
    (components
     ((rsr-compliance ((status . "complete") (completion . 100)))
      (scm-files ((status . "complete") (completion . 100)))
      (security-review ((status . "complete") (completion . 100)))
      (nix-flake ((status . "complete") (completion . 100)))
      (guix-package ((status . "complete") (completion . 100)))
      (rescript-conversion ((status . "not-started") (completion . 0)))
      (wasm-modules ((status . "not-started") (completion . 0)))))))

(define blockers-and-issues
  '((critical ())
    (high-priority
     (("ReScript conversion required per RSR policy" . "migration")))))

(define critical-next-actions
  '((immediate
     (("ReScript migration planning" . high)
      ("Unit test expansion" . medium)))
    (this-week
     (("Verify CI/CD with new flake.nix" . high)
      ("Document ReScript migration path" . medium)))))

(define session-history
  '((snapshots
     ((date . "2025-12-15") (session . "initial") (notes . "SCM files added"))
     ((date . "2025-12-17") (session . "security-review")
      (notes . "Security audit, flake.nix added, HTTP URLs fixed, security.txt updated")))))

(define state-summary
  '((project . "rrecord-verity") (completion . 35) (blockers . 1) (updated . "2025-12-17")))
