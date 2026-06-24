<!--
SPDX-License-Identifier: CC-BY-SA-4.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# Cryptographic Hash Policy

## Current Status
This repo uses MD5 or SHA1 in some files.

## Policy
- **NEVER** use MD5/SHA1 for security purposes (passwords, signatures, integrity)
- MD5/SHA1 is acceptable ONLY for:
  - Cache key generation (non-security)
  - Legacy format compatibility
  - File checksums (when not security-critical)

## Migration
Replace security-critical usage:
- `md5(password)` → `argon2` or `bcrypt`
- `sha1(signature)` → `sha256` or `sha384`
- `md5(integrity)` → `sha256`

## Files to Review
Check files flagged by CI for MD5/SHA1 usage.
