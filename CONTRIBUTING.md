# Contributing to DKIM Verifier

Thank you for your interest in contributing to DKIM Verifier! This document outlines our **Tri-Perimeter Contribution Framework (TPCF)** and how to get involved.

## 🎯 Tri-Perimeter Contribution Framework (TPCF)

We use a graduated trust model with three perimeters:

### Perimeter 3: Community Sandbox (🌍 Public)
**Anyone can contribute here without special permissions**

- **Bug Reports**: Open issues for bugs, feature requests
- **Discussions**: Participate in GitHub Discussions
- **Documentation**: Suggest improvements via issues
- **Translations**: Submit translation updates
- **Testing**: Test beta versions and provide feedback
- **Code Review**: Comment on pull requests

**Access**: Public, no approval needed
**Scope**: Read-only access, issue creation, discussions
**Review**: Maintainers review all contributions

### Perimeter 2: Trusted Contributors (🤝 Vetted)
**Contributors who have demonstrated sustained, quality contributions**

- **Pull Requests**: Direct PR submissions
- **Code Changes**: Implement features, fix bugs
- **Test Development**: Add unit/integration tests
- **Documentation Editing**: Direct doc improvements
- **Triage**: Help triage and label issues

**How to Advance**:
1. 3+ quality contributions accepted from Perimeter 3
2. Demonstrated understanding of codebase and standards
3. Positive community interactions
4. Maintainer nomination

**Access**: Write access to feature branches, PR creation
**Scope**: All repos, except main/release branches
**Review**: Maintainer approval required for merge

### Perimeter 1: Maintainer Core (⚡ Core Team)
**Core maintainers with full repository access**

- **Release Management**: Cut releases, manage versions
- **Merge to Main**: Approve and merge PRs
- **Security Response**: Handle security vulnerabilities
- **Governance**: Make project decisions
- **Infrastructure**: Manage CI/CD, hosting

**Current Maintainers**: See MAINTAINERS.md

**How to Advance**:
1. Sustained contributions over 6+ months
2. Deep expertise in email security / WebExtensions
3. Unanimous approval from existing maintainers
4. Demonstrated leadership and mentorship

**Access**: Full repository access, release permissions
**Scope**: All operations including security-sensitive
**Review**: Peer review from other maintainers

## 📋 Contribution Guidelines

### Code Contributions

#### Before You Start
1. **Check Issues**: See if someone is already working on it
2. **Open Discussion**: For large features, discuss first
3. **Read CLAUDE.md**: Understand project architecture
4. **Review Roadmap**: See ROADMAP.md for planned features

#### Code Standards
- **Language**: JavaScript ES2024, TypeScript checking via JSDoc
- **Style**: Follow existing conventions (enforced by ESLint)
- **Types**: Add comprehensive JSDoc type annotations
- **Tests**: Add tests for new functionality
- **Docs**: Update documentation for user-facing changes

#### Development Workflow

1. **Fork & Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/dkim_verifier.git
   cd dkim_verifier
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Follow code conventions (see CLAUDE.md)
   - Add `// @ts-check` to new .mjs.js files
   - Use tabs (4 spaces width) for indentation
   - Double quotes for strings
   - Semicolons required

4. **Run Checks**
   ```bash
   npm run lint        # ESLint (zero warnings required)
   npm run checkJs     # TypeScript type checking
   npm run test        # Unit tests
   ```

5. **Commit**
   ```bash
   git add .
   git commit -m "Brief description of changes"
   ```
   - Use clear, descriptive commit messages
   - Reference issue numbers: `Fixes #123`

6. **Push & PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   - Open Pull Request on GitHub
   - Fill out PR template completely
   - Link related issues

#### Pull Request Requirements

**Must Have**:
- ✅ All CI checks passing (lint, type check, tests)
- ✅ Descriptive title and description
- ✅ Tests for new code (aim for >80% coverage)
- ✅ Documentation updates if user-facing
- ✅ No merge conflicts with main branch

**Nice to Have**:
- 📝 Screenshots/GIFs for UI changes
- 📝 Performance benchmarks for optimizations
- 📝 Migration guide for breaking changes

### Bug Reports

**Use the Bug Report Template**

Include:
- **Thunderbird Version**: From Help → About
- **Extension Version**: From Add-ons Manager
- **Steps to Reproduce**: Detailed, numbered steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Error Console**: Any errors from Tools → Error Console
- **Sample Email**: If possible, provide .eml file (redact sensitive info)

### Feature Requests

**Use the Feature Request Template**

Include:
- **Problem Statement**: What problem does this solve?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Use Case**: Real-world scenario
- **Impact**: Who benefits? How many users?

### Translation Contributions

See `_locales/Readme.md` for details.

1. **Check Existing**: See if your language already exists
2. **Reference Locale**: Use `_locales/en_US/messages.json`
3. **Submit PR**: Add/update `_locales/YOUR_LOCALE/messages.json`
4. **Test**: Load extension in Thunderbird with your locale

**Current Languages**: 15 supported
**Priority Languages**: German, French, Spanish, Japanese, Chinese

### Documentation Improvements

All documentation lives in:
- `README.md` - Project overview
- `CLAUDE.md` - AI assistant / developer guide
- `ROADMAP.md` - Feature roadmap
- `test/Readme.md`, `_locales/Readme.md` - Component docs
- [Wiki](https://github.com/lieser/dkim_verifier/wiki) - User guide

**Small Fixes**: Direct PR
**Large Changes**: Open issue first for discussion

## 🧪 Testing

### Unit Tests
```bash
npm run test           # Run in Node.js
npm run test:ci        # CI mode with JSON output
```

**Browser Testing**:
```bash
npx http-server . -c-1
# Open: http://localhost:8080/test/unittest/SpecRunner.html
```

### Manual Testing
1. Load extension in Thunderbird (see CLAUDE.md)
2. Test with real emails (use test accounts)
3. Check error console for warnings/errors
4. Verify all features still work

### Test Coverage
- **Target**: >80% line coverage
- **Current**: ~70% (v6.2)
- **Framework**: Mocha + Chai + Sinon

## 🏗️ Development Environment

### Prerequisites
- **Node.js**: >= 22.0.0
- **Git**: In PATH
- **Thunderbird**: 128.0 or later

### Setup
```bash
npm install
```

### Useful Commands
```bash
npm run lint              # ESLint
npm run lint:ci           # CI mode (no warnings)
npm run checkJs           # Type checking
npm run test              # Unit tests
npm run pack              # Package extension
npm run update-thirdparty # Update dependencies
```

### IDE Setup

**VS Code** (Recommended):
- Extensions: ESLint, TypeScript
- Settings already in `.vscode/settings.json`

**Other Editors**:
- Ensure EditorConfig support (.editorconfig)
- Configure for tabs (4-width), LF line endings

## 📚 Learning Resources

### Email Security
- [DKIM RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376)
- [SPF RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208)
- [DMARC RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)

### Thunderbird Development
- [Thunderbird Extension API](https://webextension-api.thunderbird.net/)
- [WebExtension Docs](https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions)
- [Experiment APIs](https://thunderbird-webextensions.readthedocs.io)

### Project Architecture
- **CLAUDE.md**: Comprehensive developer guide
- **ROADMAP.md**: Feature plans and architecture
- Module documentation in source files

## 🎓 First-Time Contributors

### Good First Issues
Look for issues labeled:
- `good first issue` - Beginner-friendly
- `documentation` - Docs improvements
- `translation` - Localization help
- `help wanted` - Community assistance needed

### Mentorship
- Ask questions in GitHub Discussions
- Tag `@maintainers` for guidance
- Join discussion on complex issues

## 🤝 Code of Conduct

We follow our [Code of Conduct](CODE_OF_CONDUCT.md). Summary:

- **Be Respectful**: Treat everyone with respect
- **Be Inclusive**: Welcome diverse perspectives
- **Be Collaborative**: Work together constructively
- **Be Professional**: Focus on technical merit

**Violations**: Report to maintainers privately

## 🔒 Security Contributions

See [SECURITY.md](SECURITY.md) for:
- Responsible disclosure process
- Security vulnerability reporting
- Bug bounty (if applicable)

**Do NOT** open public issues for security bugs!

## 📄 License

By contributing, you agree that your contributions will be licensed under the **MIT License** (see LICENSE.txt).

**Note**: We are considering dual-licensing with **Palimpsest License v0.8** for future versions. Contributors will be consulted before any license changes.

### Third-Party Code
If submitting code from other sources:
- Ensure compatible license (MIT, BSD, Apache 2.0)
- Add attribution to `THIRDPARTY_LICENSE.txt`
- Document in commit message

## 🚀 Release Process (Maintainers Only)

1. Update `CHANGELOG.md` with version and date
2. Update `manifest.json` version
3. Run full test suite: `npm run lint && npm run checkJs && npm run test`
4. Tag release: `git tag v7.0.0`
5. Push tags: `git push origin v7.0.0`
6. Run `npm run pack`
7. Upload to addons.thunderbird.net
8. Create GitHub Release with changelog

## 📊 Contribution Statistics

We value all contributions! Stats tracked:
- Code commits
- Issues opened/commented
- PRs submitted/reviewed
- Documentation improvements
- Community support

**Top Contributors**: See GitHub Insights

## 🙏 Recognition

Contributors are recognized in:
- Release notes (CHANGELOG.md)
- GitHub contributors page
- Special thanks in major releases

**Want to be listed?**: Make 3+ quality contributions!

## 📞 Getting Help

- **GitHub Discussions**: General questions, ideas
- **GitHub Issues**: Bug reports, feature requests
- **Email**: See MAINTAINERS.md for contact
- **Wiki**: [User documentation](https://github.com/lieser/dkim_verifier/wiki)

## 🗺️ Roadmap Alignment

See [ROADMAP.md](ROADMAP.md) for:
- Planned features (v7.0 - v8.0)
- Architecture vision
- Priority areas

**Want to work on roadmap items?** Open an issue to claim it!

---

**Thank you for contributing to email security! Together, we make email safer for everyone.** 🛡️

**Last Updated**: 2025-11-22
**TPCF Version**: 1.0
**Maintained By**: See MAINTAINERS.md
