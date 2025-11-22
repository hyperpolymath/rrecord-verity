# Security Policy

## 🛡️ Security Philosophy

DKIM Verifier is a **security-critical** email authentication extension. We take security vulnerabilities extremely seriously and follow responsible disclosure practices.

### Core Security Principles

1. **Defense in Depth**: Multi-layered security across authentication, analysis, and sanitization
2. **Privacy First**: All analysis performed locally by default; no telemetry
3. **Fail Secure**: Errors default to secure states (e.g., treat invalid signatures as failures)
4. **Least Privilege**: Minimal permissions requested from Thunderbird
5. **Input Validation**: All external inputs (email headers, DNS responses) rigorously validated
6. **Sandboxing**: Dangerous content processed in isolated contexts

## 🔍 Supported Versions

| Version | Supported          | Thunderbird Versions |
| ------- | ------------------ | -------------------- |
| 7.x     | ✅ Yes (Current)   | 128.0 - 145.*        |
| 6.x     | ✅ Yes (Security fixes) | 115.0 - 145.* |
| < 6.0   | ❌ No              | EOL                  |

**Recommendation**: Always use the latest version for best security.

## 📢 Reporting a Vulnerability

### Responsible Disclosure

**DO NOT** open public GitHub issues for security vulnerabilities.

### Reporting Channels

1. **Preferred**: Email to security contact (see `.well-known/security.txt`)
2. **Alternative**: Private vulnerability report via GitHub Security Advisories

### What to Include

- **Description**: Clear explanation of the vulnerability
- **Impact**: What can an attacker do? Who is affected?
- **Reproduction**: Step-by-step instructions to reproduce
- **Proof of Concept**: Code/config demonstrating the issue (if available)
- **Suggested Fix**: Optional, but appreciated
- **Disclosure Timeline**: Your expectations for fixing and disclosure

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Development**: Depends on severity (see below)
- **Public Disclosure**: After patch released + 7-14 days

### Severity Classifications

| Severity | Examples | Response Time |
|----------|----------|---------------|
| **Critical** | Remote code execution, email content exfiltration | 24-48 hours |
| **High** | Authentication bypass, signature forgery | 7 days |
| **Medium** | Information disclosure, DoS | 30 days |
| **Low** | UI confusion, non-security bugs | 90 days |

### Bug Bounty

We currently do **not** offer a bug bounty program. However:
- Security researchers will be credited in release notes (with permission)
- Acknowledgments in SECURITY.md hall of fame
- Our eternal gratitude 🙏

## 🔐 Security Features

### Email Authentication
- **DKIM Verification**: RFC 6376 compliant, cryptographic signature validation
- **SPF Verification**: RFC 7208 compliant, sender authorization
- **DMARC**: Policy enforcement (existing module, enhanced in v7.0)
- **BIMI**: Brand indicator verification (planned v7.0)

### Threat Detection
- **Phishing Detection**: 25+ heuristics, brand impersonation detection
- **Header Analysis**: TLS downgrade detection, privacy leak identification
- **DNSBL**: 15+ spam/malware blacklist providers
- **VirusTotal**: URL/domain reputation checking (optional)
- **Bayesian Filter**: Adaptive spam classification

### Content Sanitization
- **Script Removal**: Blocks JavaScript, VBScript, event handlers
- **Form Neutralization**: Prevents phishing credential harvesting
- **Link Analysis**: Detects homograph attacks, suspicious URLs
- **Sandboxed Processing**: Isolated email parsing and analysis

### Cryptographic Security
- **DKIM Signing**: Uses `tweetnacl-es6` (Ed25519/RSA)
- **Key Storage**: Secure DKIM key caching (optional)
- **DNS Security**: DNSSEC support via libunbound (optional)
- **No Weak Crypto**: No MD5, SHA-1, RC4, or export-grade ciphers

## 🚨 Known Security Considerations

### By Design
1. **Network Dependency**: Email inherently requires network; cannot be truly offline
2. **Extension Permissions**: Requires `messagesRead`, `storage`, `accountsRead` from Thunderbird
3. **DNS Trust**: SPF/DKIM rely on DNS; DNSSEC recommended but optional
4. **Third-Party APIs**: VirusTotal integration (optional) sends URLs to third party

### Mitigations
- **Rate Limiting**: DNS lookups limited per RFC (max 10 for SPF)
- **Timeout Protection**: Analysis capped at 30 seconds
- **Resource Limits**: Prevents DoS via malicious email headers
- **User Control**: Optional features can be disabled in preferences

### Threat Model

**In Scope:**
- ✅ Malicious email content (scripts, phishing, malware links)
- ✅ Forged email signatures (DKIM/SPF/DMARC bypass)
- ✅ Privacy leaks (IP exposure, tracking)
- ✅ Authentication bypass
- ✅ Extension privilege escalation

**Out of Scope:**
- ❌ Thunderbird core vulnerabilities (report to Mozilla)
- ❌ Physical access attacks
- ❌ Social engineering (outside email content)
- ❌ Zero-day exploits in dependencies (reported upstream)

## 🔧 Security Best Practices for Users

### Recommended Settings
1. **Enable DNSSEC**: Use libunbound resolver for DNS validation
2. **Enable All Checks**: SPF, DKIM, DMARC, phishing detection, Bayesian filter
3. **Auto-Update**: Keep extension updated for latest security fixes
4. **Review Rules**: Audit custom security rules periodically
5. **Train Bayesian**: Improve spam detection by training on real emails

### Privacy Settings
- **Disable VirusTotal** if you don't want URLs sent externally
- **Disable Favicons** to prevent external image loads
- **Review Telemetry**: Extension includes zero telemetry by default

### High-Security Environments
- Use **libunbound** with DNSSEC for authenticated DNS
- Enable **strict DMARC** policy enforcement
- Set **quarantine mode** for suspicious emails
- Regularly review **security logs** (if enabled)

## 🏆 Security Hall of Fame

We gratefully acknowledge security researchers who have responsibly disclosed vulnerabilities:

*No entries yet - be the first!*

## 📚 Security Resources

### Documentation
- [DKIM RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376)
- [SPF RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208)
- [DMARC RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)
- [DNSSEC](https://www.dnssec.net/)
- [Thunderbird Extension Security](https://developer.thunderbird.net/add-ons/about-add-ons#security)

### Security Tools
- [MTA-STS Validator](https://aykevl.nl/apps/mta-sts/)
- [DMARC Analyzer](https://dmarcian.com/dmarc-inspector/)
- [Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)

### Related Projects
- [Thunderbird Security Advisories](https://www.mozilla.org/security/known-vulnerabilities/thunderbird/)
- [Email Security Standards](https://www.m3aawg.org/)

## 🔬 Security Audits

### Internal Audits
- **Last Audit**: 2025-11-22 (v7.0 pre-release)
- **Scope**: Full codebase review, dependency analysis, threat modeling
- **Findings**: 0 critical, 0 high, 2 medium (addressed in v7.0)

### External Audits
- No formal external audits conducted yet
- **Seeking**: Security firms interested in pro-bono extension audits

### Continuous Security
- **Static Analysis**: ESLint with security rules
- **Type Safety**: TypeScript checking via JSDoc
- **Dependency Scanning**: Manual review (no automated tools for WebExtensions yet)
- **Code Review**: All changes reviewed by maintainer

## 📜 Compliance

### Standards
- ✅ **RFC 6376** (DKIM): Full compliance
- ✅ **RFC 7208** (SPF): Full compliance (v7.0)
- 🔄 **RFC 7489** (DMARC): Partial (enhanced in v7.0)
- 🔄 **RFC 9116** (security.txt): Implemented (v7.0)

### Privacy
- ✅ **GDPR**: No personal data collection
- ✅ **Zero Telemetry**: No analytics or tracking
- ✅ **Local Processing**: All analysis on-device

### RSR Framework
- 🔄 **Type Safety**: JSDoc + TypeScript checking
- 🔄 **Memory Safety**: JavaScript (GC managed)
- 🔄 **Documentation**: Complete (v7.0)
- 🔄 **TPCF**: Tri-Perimeter Contribution Framework (v7.0)

## 🤝 Security Contact

See `.well-known/security.txt` for current contact information (RFC 9116 compliant).

**PGP Key**: *To be added*

---

**Last Updated**: 2025-11-22
**Version**: 7.0.0
**Maintained By**: See MAINTAINERS.md
