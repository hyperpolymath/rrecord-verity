;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;; ECOSYSTEM.scm — rrecord-verity

(ecosystem
  (version "1.0.0")
  (name "rrecord-verity")
  (type "project")
  (purpose "Comprehensive email security suite for Mozilla Thunderbird with DKIM, SPF, DMARC verification, phishing detection, and advanced threat analysis.")

  (position-in-ecosystem
    "Part of hyperpolymath ecosystem. Follows RSR guidelines.")

  (related-projects
    (project (name "rhodium-standard-repositories")
             (url "https://github.com/hyperpolymath/rhodium-standard-repositories")
             (relationship "standard")))

  (what-this-is "Comprehensive email security suite for Mozilla Thunderbird with DKIM, SPF, DMARC verification, phishing detection, and advanced threat analysis.")
  (what-this-is-not "- NOT exempt from RSR compliance"))
