# Security Policy

## Supported versions
Security fixes are provided for the latest v1.x release.

## Reporting vulnerabilities
Please do not publish exploitable vulnerability details in a public issue. Contact the maintainer through https://www.taheramine.org with a concise reproduction, impact, affected version, and suggested remediation if known.

## Security boundaries
LogFable generates synthetic representations only. Generation performs no network requests. Explicit `knowledge update` commands are the only built-in operations intended to access the network. Plugins are trusted Python code and are not sandboxed.

The project rejects unsafe bundled indicators, uses `yaml.safe_load`, performs atomic dataset creation, verifies checksums, avoids shell execution/eval/untrusted deserialization, and keeps student packages separate from ground truth.
