<!--
SPDX-License-Identifier: CC-BY-SA-4.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# CLAUDE.md - AI Assistant Guide for DKIM Verifier

This guide helps AI assistants understand and work effectively with the DKIM Verifier codebase.

## Project Overview

**DKIM Verifier** is a Mozilla Thunderbird WebExtension that verifies DKIM (DomainKeys Identified Mail) signatures in email messages according to RFC 6376.

- **Type**: Thunderbird WebExtension (Manifest v2)
- **Language**: JavaScript (ES2024) with TypeScript type checking via JSDoc
- **Platform**: Thunderbird 128.0 - 145.*
- **License**: MIT
- **No Build Step**: Files are used directly; only packaging is needed

## Project Structure

```
dkim_verifier/
├── _locales/           # i18n translations (15 languages)
├── content/            # UI pages (HTML/CSS/JS)
├── modules/            # Core business logic (ES modules)
│   └── dkim/          # DKIM-specific modules
├── experiments/        # Thunderbird privileged API extensions
├── data/              # Static data (signer rules, favicons)
├── thirdparty/        # Third-party libraries
├── scripts/           # Development scripts
├── test/              # Mocha unit tests
│   ├── unittest/      # Test specs (*Spec.mjs.js)
│   ├── helpers/       # Test utilities and mocks
│   └── data/          # Email samples (.eml files)
└── manifest.json      # Extension manifest
```

### Key Directories

- **`modules/`**: Core logic using ES modules (`.mjs.js` extension)
  - Main modules: `authVerifier.mjs.js`, `msgParser.mjs.js`, `dkim/verifier.mjs.js`
  - All modules use `// @ts-check` for TypeScript checking

- **`experiments/`**: Privileged APIs for Thunderbird access
  - `dkimHeader.js`, `jsdns.js`, `libunbound.js`, `mailUtils.js`
  - Each has `-schema.json` and `.d.ts` files

- **`test/`**: Comprehensive test suite
  - Run with: `npm run test` (Node) or browser (SpecRunner.html)
  - Test files: `*Spec.mjs.js`

## Development Workflow

### Prerequisites

- Node.js >= 22.0.0
- Git (in PATH)
- Thunderbird (for manual testing)

### Setup

```bash
npm install
```

### Before Making Changes

**Always run these checks before committing:**

```bash
npm run lint        # ESLint (zero warnings required)
npm run checkJs     # TypeScript type checking
npm run test        # Unit tests
```

### Testing Your Changes

**In Node.js:**
```bash
npm run test
```

**In Browser:**
```bash
npx http-server . -c-1
# Open: http://localhost:8080/test/unittest/SpecRunner.html
```

**In Thunderbird:**
1. Open Thunderbird
2. Tools → Developer Tools → Debug Add-ons
3. Load Temporary Add-on
4. Select `manifest.json` from project root

## Code Conventions

### File Extensions

- **`.mjs.js`**: ES modules that need TypeScript tooling
  - Provides IntelliSense while being recognized as ES modules
  - Use `import/export` syntax
  - ALWAYS include `// @ts-check` at the top

- **`*Spec.mjs.js`**: Unit test files
- **`.d.ts`**: TypeScript definition files

### Code Style

**Enforced by ESLint:**
- Indentation: **Tabs** (4 spaces width), except HTML/MD/SVG (2 spaces)
- Quotes: **Double quotes**
- Semicolons: **Required**
- Brace style: **1TBS** (one true brace style)
- Line endings: **LF** (Unix style)
- Naming: **camelCase** for files and variables
- Target: **ES2024**

### TypeScript via JSDoc

All JavaScript files use TypeScript checking:

```javascript
// @ts-check
// Always at the top of .mjs.js files

/**
 * @typedef {object} MyType
 * @property {string} name
 * @property {number} value
 */

/**
 * @param {MyType} obj
 * @returns {string}
 */
function example(obj) {
    return obj.name;
}
```

**Type Definition Files:**
- Check `RuntimeMessage.d.ts` for message types
- Check `WebExtensions.d.ts` for WebExtension API extensions
- Each module may have a corresponding `.d.ts` file

## Common Tasks

### Adding a New Module

1. Create file in `modules/` with `.mjs.js` extension
2. Add `// @ts-check` at the top
3. Create corresponding `.d.ts` file for type exports
4. Use ES module syntax (`import`/`export`)
5. Add JSDoc type annotations
6. Create test file: `test/unittest/yourModuleSpec.mjs.js`

### Modifying DKIM Verification Logic

**Key files:**
- `modules/dkim/verifier.mjs.js`: Core verification logic
- `modules/dkim/crypto.mjs.js`: Cryptographic operations
- `modules/dkim/signRules.mjs.js`: Signer rules
- `modules/authVerifier.mjs.js`: Overall auth verification

### Working with Preferences

- `modules/preferences.mjs.js`: Preference management
- Settings stored via WebExtension storage API
- See `Preferences` namespace in type definitions

### Adding/Updating Tests

1. Create/edit `test/unittest/*Spec.mjs.js`
2. Use Mocha/Chai/Sinon:
   ```javascript
   // @ts-check
   import { expect } from "../helpers/chaiUtils.mjs.js";
   import { describe, it } from "../helpers/mochaUtils.mjs.js";

   describe("MyModule", () => {
       it("should do something", () => {
           expect(true).to.be.true;
       });
   });
   ```
3. Test data goes in `test/data/` (`.eml` files for emails)
4. Use helpers from `test/helpers/` for mocks

### Updating Translations

1. Edit `_locales/en_US/messages.json` (reference locale)
2. Update other locales in `_locales/*/messages.json`
3. Format: WebExtension i18n standard
4. See `_locales/Readme.md` for details

### Packaging for Release

```bash
npm run pack
```

Creates: `dkim_verifier-{version}.xpi` (clean) or with git hash (dev)

## Important Gotchas

### Module Globals

Different directories have different global objects:
- `content/`: Browser + WebExtension APIs
- `experiments/`: Mozilla privileged APIs
- `modules/`: Shared Node/Browser + WebExtension APIs
- `scripts/`: Node.js APIs
- `test/`: Mocha + test helpers

**Don't assume browser APIs are available in all contexts!**

### Experiment APIs

Experiment APIs provide privileged access:
- Defined in `experiments/*-schema.json`
- Registered in `manifest.json`
- Access via `browser.{apiName}`

**Don't modify experiment APIs without understanding Thunderbird's API system.**

### No Build Step

This project doesn't use bundlers or transpilers:
- Files are loaded directly by Thunderbird
- ES modules work natively
- No webpack, rollup, babel, etc.
- Only packaging (ZIP into XPI) is needed

**Don't introduce build-time transformations.**

### Type Checking

TypeScript checking happens via JSDoc:
- Run `npm run checkJs` to check types
- Strict checking enabled in `jsconfig.json`
- Must pass for CI

**Always add type annotations to new code.**

### Testing Requirements

All three CI checks must pass:
1. ESLint (zero warnings)
2. Type checking
3. Unit tests

**Run all checks before committing.**

## DNS Resolution

Two methods supported:
1. **JSDNS** (`experiments/jsdns.js`): JavaScript DNS library
2. **libunbound** (`experiments/libunbound.js`): Native library

**Don't break compatibility with either method.**

## Useful References

- **DKIM Standard**: RFC 6376
- **WebExtension API**: https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions
- **Thunderbird API**: https://webextension-api.thunderbird.net/
- **Project Wiki**: https://github.com/lieser/dkim_verifier/wiki
- **Issues**: https://github.com/lieser/dkim_verifier/issues

## Version Information

- **Node.js**: >= 22.0.0
- **Thunderbird**: 128.0 - 145.*
- **JavaScript**: ES2024
- **Manifest**: v2

## Quick Command Reference

```bash
# Install dependencies
npm install

# Linting
npm run lint
npm run lint:ci         # CI mode (no warnings allowed)

# Type checking
npm run checkJs

# Testing
npm run test            # Node
npm run test:ci         # CI mode

# Packaging
npm run pack

# Update third-party libs
npm run update-thirdparty

# Generate ATN changelog
npm run atnChangelog
```

## When Working on Issues

1. **Understand the issue**: Read the issue description carefully
2. **Find relevant code**: Use grep/search to locate related files
3. **Check tests**: Look for existing tests in `test/unittest/`
4. **Make changes**: Follow code conventions
5. **Add tests**: Add test cases for new functionality
6. **Run checks**: `npm run lint && npm run checkJs && npm run test`
7. **Test manually**: Load in Thunderbird if UI-related
8. **Commit**: Use clear, descriptive commit messages
9. **Push**: To the designated branch

## Architecture Notes

### Message Flow

1. Email arrives in Thunderbird
2. `authVerifier.mjs.js` coordinates verification
3. `msgParser.mjs.js` parses the email
4. `dkim/verifier.mjs.js` verifies DKIM signatures
5. Results displayed via content scripts in UI

### Storage

- **Preferences**: WebExtension storage API
- **Signer Rules**: JSON file + user overrides
- **Key Store**: Optional caching of DKIM keys

### Security Considerations

- DKIM verification is security-sensitive
- Cryptographic operations use `tweetnacl`
- DNS queries may be cached
- Be careful with untrusted email content

**Always consider security implications of changes.**

---

**Last Updated**: 2025-11-21
**Maintainer**: https://github.com/lieser/dkim_verifier
