<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-02-19 -->

# RRecord Verity — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              THUNDERBIRD USER           │
                        │        (Email Interface / Security HUD) │
                        └───────────────────┬─────────────────────┘
                                            │
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           EXTENSION UI LAYER            │
                        │  ┌───────────┐  ┌───────────────────┐  │
                        │  │ Content   │  │  Options / Config │  │
                        │  │ Pages     │  │  (Localization)   │  │
                        │  └─────┬─────┘  └────────┬──────────┘  │
                        └────────│─────────────────│──────────────┘
                                 │                 │
                                 ▼                 ▼
                        ┌─────────────────────────────────────────┐
                        │           BACKGROUND ENGINE (JS)        │
                        │    (Message Analysis, DNS Resolver)     │
                        └──────────┬───────────────────┬──────────┘
                                   │                   │
                                   ▼                   ▼
                        ┌───────────────────────┐  ┌────────────────────────────────┐
                        │ VERIFICATION MODULES  │  │ THREAT ANALYSIS                │
                        │ - DKIM (RFC 6376)     │  │ - Phishing Detection           │
                        │ - SPF (RFC 7208)      │  │ - Header Analysis              │
                        │ - DMARC Policy        │  │ - DNSBL Checking               │
                        └──────────┬────────────┘  └──────────┬─────────────────────┘
                                   │                          │
                                   └────────────┬─────────────┘
                                                ▼
                        ┌─────────────────────────────────────────┐
                        │           EXTERNAL SERVICES             │
                        │  ┌───────────┐  ┌───────────┐  ┌───────┐│
                        │  │ DNS (LOC) │  │ VirusTotal│  │ Spam  ││
                        │  │ (Verified)│  │ (Optional)│  │ Lists ││
                        │  └───────────┘  └───────────┘  └───────┘│
                        └─────────────────────────────────────────┘

                        ┌─────────────────────────────────────────┐
                        │          REPO INFRASTRUCTURE            │
                        │  Justfile Automation  .machine_readable/  │
                        │  Deno / Node (Pack)   0-AI-MANIFEST.a2ml  │
                        └─────────────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE VERIFICATION
  DKIM Implementation               ██████████ 100%    RFC 6376 compliant stable
  SPF / DMARC                       ██████████ 100%    Policy enforcement active
  DNS Resolver (dns.js)             ██████████ 100%    Local verification verified
  Header Analysis                   ██████████ 100%    Security scoring active

THREAT & PHISHING
  Phishing Detection                ██████████ 100%    v7.0 multi-heuristic stable
  DNSBL Checking                    ██████████ 100%    15+ blacklists verified
  Bayesian Spam Filter              ████████░░  80%    Adaptive learning active
  VirusTotal Integration            ██████████ 100%    Optional API support

REPO INFRASTRUCTURE
  Justfile Automation               ██████████ 100%    Standard build/pack tasks
  .machine_readable/                ██████████ 100%    STATE tracking active
  Extension Packaging (.xpi)        ██████████ 100%    Production format verified

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            █████████░  ~95%   Security suite stable & production
```

## Key Dependencies

```
Email Header ────► DNS Resolver ─────► DKIM/SPF/DMARC ──► Trust HUD
     │                 │                   │                 │
     ▼                 ▼                   ▼                 ▼
Content Page ───► Phishing Heur ────► DNSBL Check ──────► Warning
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
