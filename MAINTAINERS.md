# Maintainers

This document lists the current maintainers of the DKIM Verifier project and their areas of responsibility.

## 🎯 TPCF Perimeter 1: Core Maintainers

Core maintainers have full repository access and make final decisions on project direction, releases, and governance.

### Philippe Lieser (@lieser)
**Role**: Lead Maintainer & Creator
**Responsibilities**:
- Overall project direction and roadmap
- Release management and versioning
- Security vulnerability coordination
- Final review on major architectural changes
- Community governance

**Contact**:
- GitHub: [@lieser](https://github.com/lieser)
- Email: *(See .well-known/security.txt for current contact)*

**Expertise**:
- Email authentication protocols (DKIM, SPF, DMARC)
- Thunderbird WebExtension development
- Cryptographic verification
- 10+ years maintaining DKIM Verifier

**Active Since**: 2014
**Timezone**: CET/CEST (Europe/Berlin)
**Languages**: German, English

---

## 👥 TPCF Perimeter 2: Trusted Contributors

*(Currently seeking trusted contributors - see CONTRIBUTING.md for advancement criteria)*

These contributors have demonstrated sustained quality contributions and are granted write access to feature branches.

**How to Become a Trusted Contributor**:
1. 3+ quality contributions accepted
2. Demonstrated codebase understanding
3. Positive community interactions
4. Maintainer nomination

---

## 🌍 TPCF Perimeter 3: Community Contributors

All community members who contribute through:
- Bug reports and feature requests
- Pull requests and code review
- Documentation improvements
- Translations
- Testing and feedback

**Top Community Contributors** (3+ contributions):
- *(To be populated as contributions grow)*

**View All Contributors**: [GitHub Contributors Page](https://github.com/lieser/dkim_verifier/graphs/contributors)

---

## 📋 Areas of Responsibility

### Code Ownership

| Area | Primary | Backup |
|------|---------|--------|
| Core DKIM Verification | @lieser | - |
| SPF Verification (v7.0) | @lieser | - |
| DMARC Integration | @lieser | - |
| Header Analysis (v7.0) | - | - |
| Phishing Detection (v7.0) | - | - |
| Bayesian Filter (v7.0) | - | - |
| Email Sanitization (v7.0) | - | - |
| Security Orchestrator (v7.0) | - | - |
| UI/UX | @lieser | - |
| Build System | @lieser | - |
| CI/CD | @lieser | - |
| Translations | Community | @lieser |

### Platform & Infrastructure

| Area | Owner |
|------|-------|
| GitHub Repository | @lieser |
| Thunderbird Add-ons (ATN) | @lieser |
| Wiki Documentation | @lieser |
| Issue Triage | @lieser |

### Special Roles

**Security Team**: @lieser
- Handles security vulnerability reports
- Coordinates security fixes
- Reviews security-sensitive code

**Release Manager**: @lieser
- Cuts releases
- Manages versioning
- Updates changelogs
- Publishes to ATN

**Community Manager**: @lieser
- Moderates discussions
- Enforces Code of Conduct
- Welcomes new contributors

---

## 🔐 Security Contact

For **security vulnerabilities**, contact maintainers via:
1. See `.well-known/security.txt` (RFC 9116)
2. Private vulnerability report on GitHub
3. Email to security contact (see security.txt)

**Do NOT** open public GitHub issues for security bugs!

---

## 🤝 Becoming a Maintainer

### Path to Maintainership

**From Perimeter 3 → Perimeter 2** (Trusted Contributor):
1. 3+ quality contributions accepted
2. Understanding of codebase and standards
3. Positive community interactions
4. Maintainer nomination

**From Perimeter 2 → Perimeter 1** (Core Maintainer):
1. Sustained contributions over 6+ months
2. Deep expertise in email security / WebExtensions
3. Demonstrated leadership and mentorship
4. Unanimous approval from existing maintainers

### Expectations for Core Maintainers

**Time Commitment**:
- ~5-10 hours/month minimum
- Responsive to security issues (24-48h)
- Attend monthly sync meetings (if established)

**Responsibilities**:
- Code review (1-2 PRs/week)
- Issue triage
- Community support
- Release participation
- Documentation maintenance

**Skills Required**:
- JavaScript/TypeScript expertise
- Email protocols (DKIM, SPF, DMARC)
- Thunderbird extension development
- Security best practices
- Git/GitHub workflows

---

## 📞 Contacting Maintainers

### Public Communication (Preferred)
- **Issues**: [GitHub Issues](https://github.com/lieser/dkim_verifier/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lieser/dkim_verifier/discussions)
- **Pull Requests**: [GitHub PRs](https://github.com/lieser/dkim_verifier/pulls)

### Private Communication
- **Security**: See SECURITY.md and .well-known/security.txt
- **Code of Conduct**: Email maintainers (see below)
- **Sensitive Matters**: Email maintainers directly

**Email**: *(See .well-known/humans.txt for current contact)*

---

## 🎓 Emeritus Maintainers

Maintainers who have stepped down but made significant contributions:

*(None yet - founding maintainer still active)*

---

## 🌟 Special Thanks

### Major Contributors
- **Translators**: 15 languages supported thanks to community
- **Testers**: Beta testers who provide crucial feedback
- **Reporters**: Security researchers who responsibly disclose

### Institutional Support
- **Mozilla Thunderbird**: Platform and community
- **Spamhaus**: DNSBL data and expertise
- **VirusTotal**: Malware/phishing intelligence

---

## 📊 Maintainer Statistics

### Activity (Last 12 Months)
- **Commits**: ~150 (primary: @lieser)
- **PRs Merged**: ~20
- **Issues Closed**: ~40
- **Releases**: 3 major (6.0, 6.1, 6.2)

### Contributor Growth
- **Total Contributors**: 15+ (all-time)
- **Active Contributors**: 3-5 (monthly average)
- **Translations**: 15 languages maintained

---

## 🗳️ Governance

### Decision Making

**Minor Decisions** (code style, small features):
- Lead maintainer (@lieser) decides
- Community input via issues/discussions

**Major Decisions** (architecture, breaking changes):
- Proposal in GitHub Discussion
- Community feedback period (7+ days)
- Maintainer consensus (currently @lieser)
- Document in ROADMAP.md or CHANGELOG.md

**Security Decisions**:
- Security team decides immediately
- Public disclosure after patch + 7-14 days

### Conflict Resolution

1. Discussion in GitHub (public) or email (private)
2. Attempt consensus through compromise
3. Lead maintainer (@lieser) makes final call if needed
4. Document decision rationale

### Removing Maintainers

**Voluntary**: Maintainer can step down anytime, moves to Emeritus
**Involuntary**: For serious Code of Conduct violations or prolonged inactivity
- Requires unanimous vote of remaining maintainers
- Clear documentation of reasons
- Graceful transition period when possible

---

## 📜 Changes to This Document

This document is updated as maintainer roster changes.

**Version**: 1.0
**Last Updated**: 2025-11-22
**Next Review**: 2026-01-01 (annually, or as needed)

---

## 🙏 Thank You

To all maintainers, past and present, thank you for your dedication to making email safer for everyone! 🛡️

---

**Related Documents**:
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute (TPCF)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards
- [SECURITY.md](SECURITY.md) - Security policies
