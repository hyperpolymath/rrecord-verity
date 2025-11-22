# DKIM Verifier

Comprehensive email security suite for Mozilla Thunderbird with DKIM, SPF, DMARC verification, phishing detection, and advanced threat analysis.

## Features

- ✅ **DKIM Verification**: RFC 6376 compliant signature validation
- ✅ **SPF Verification**: RFC 7208 sender authorization (v7.0)
- ✅ **DMARC**: Policy enforcement
- ✅ **Phishing Detection**: Multi-heuristic threat analysis (v7.0)
- ✅ **Header Analysis**: Security scoring and privacy leak detection (v7.0)
- ✅ **DNSBL Checking**: 15+ spam/malware blacklists (v7.0)
- ✅ **Bayesian Spam Filter**: Adaptive learning (v7.0)
- ✅ **Email Sanitization**: Content neutering for safety (v7.0)
- ✅ **Rules Engine**: Declarative security automation (v7.0)
- 🔄 **VirusTotal** (Optional): URL/domain reputation checking (v7.0)

**All analysis performed locally**. Optional external services (VirusTotal) can be disabled in preferences.

Usage information can be found in the wiki at <https://github.com/lieser/dkim_verifier/wiki>.

## Packing the Add-on

This Add-on does not require any extra build steps.
All files in the repository are already in the format required by Thunderbird.
It only needs to be packed into an extension file.

Thunderbird extensions are packed as normal zip files.
Often the file extension `.xpi` is used,
but this is not a requirement.

### Manually

You can simply use your favorite zip tool to pack the content of the extension.

The required files are listed below under *Code structure*,
but for simplicity you can also pack the complete folder.
Just make sure the content is directly in the zip file and not in an extra root directory.

### Using Node.js

Requirements:

- [Node.js](https://nodejs.org)
- [Git](https://git-scm.com/) (must be in the path environment variable)

Run the following command to pack the extension:

```bash
npm run pack
```

## Code structure

The root of the repository can be directly loaded as a temporary Add-on in Thunderbird.

The following directories and files are included in the packed extension:

- `_locales/`: Localize strings.
  More details in the included [readme](_locales/Readme.md).
  Only `.json` files are included in the packed extension.
- `content/`: The background page and various content pages.
  Also contains some shared modules for working with the DOM.
  Only `.html`, `.css` and `.js` files are included in the packed extension.
- `data/`: Data of the included signers rules and favicons.
- `experiments/`: Experiment APIs. Only `.js`, and `.json` files are included in the packed extension.
- `modules/`: Internal JavaScript modules (ECMAScript Modules (ESM) / ES6 Modules).
  Contains most of the business logic.
  Only `.js` files are included in the packed extension.
- `thirdparty`: Most of the included third-party libraries.
- `CHANGELOG.md`: Changelog of user visible changes.
- `icon.svg`: Icon of the extension.
- `LICENSE.txt`: Licensing information for the extension.
- `manifest.json`: Manifest file containing basic metadata about the extension.
- `README.md`: This readme.
- `THIRDPARTY_LICENSE.txt`: Licensing information for included third party
software components.

Other directories and files are used only for development. This includes:

- `scripts`: Node.js scripts used during development.
- `test`: Automated tests.
  More details in the included [readme](test/Readme.md).
- `icon-black-64.png`: Icon of the extension used on ATN, generated from `icon-black.svg`.

## Included third-party Libraries

- Joshua Tauberer's DNS Library (part of Thunderbird Sender Verification Extension) (<https://github.com/tauberer/thunderbird-spf>)
  - dns.js - DNS Library
- [Tabulator](https://tabulator.info)
- ES6 version of the [tweetnacl-js](https://github.com/dchest/tweetnacl-js) `nacl-fast.js` (<https://github.com/hakanols/tweetnacl-es6>)
