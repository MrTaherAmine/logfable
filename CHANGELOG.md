# Changelog

All notable changes follow Semantic Versioning.

## [1.0.0]

### Mac static/release gate follow-up (2026-08-24)

- Real MacBook Pro run: **74 tests passed** on Python 3.14.7.
- Strict mypy: PASS with no issues in 21 source files.
- Bandit: PASS with no reported findings.
- pip-audit: no known dependency vulnerabilities; the unpublished local `logfable` package is correctly skipped as not yet present on PyPI.
- Wheel and sdist build: PASS; Twine validation: PASS for both artifacts.
- Ruff findings from the first branded Mac candidate were formatting/style/static-quality findings; R2 applies the reported formatter changes, import cleanup, modern `datetime.UTC`, Typer annotation cleanup, and reviewed S310 annotation without changing incident-generation semantics.

### Mac-readiness hardening (2026-08-24)
- Refuse symlink and non-LogFable overwrite targets; preserve atomic dataset assembly.
- Neutralize CSV spreadsheet-formula prefixes and sanitize line-oriented syslog/CEF/LEEF fields.
- Use each scenario's declared duration, noise, and environment preset as CLI defaults unless explicitly overridden.
- Refuse cross-host redirects during explicit knowledge updates.
- Return clean exit-code-2 errors for common missing scenario/dataset inputs.
- Add a correlated container-runtime observation to the Kubernetes service-account scenario so all bundled scenarios include multi-source suspicious evidence.

### Added
- Deterministic scenario-as-code engine and versioned YAML schema.
- **28 built-in cross-source defensive training scenarios** spanning identity/MFA, email, ransomware, cloud, SaaS, insider activity, web/API, mobile/MDM, Kubernetes, CI/CD, DLP/removable media, DNS anomaly investigation, remote access, backup control planes, hybrid identity, and passive IT/OT investigations.
- Deterministic environment/entity graph with six presets.
- Canonical event envelope, benign-noise generation, and deterministic telemetry impairments.
- Synthetic `mdm` and `dlp` telemetry families in addition to endpoint, identity/SaaS, network, cloud, application, email, container/CI/CD, and passive OT/ICS sources.
- JSON/JSONL/NDJSON, CSV, RFC5424-style syslog, CEF, LEEF, ECS 9.4.0, OCSF 1.8.0, OpenTelemetry Logs, Splunk HEC-file, Elasticsearch bulk-file, and optional Parquet exports.
- ATT&CK 19.2 and D3FEND 1.5.0 pinned mapping support with provenance.
- Strict ATT&CK object-type validation that distinguishes Techniques from Detection Strategies, Analytics, and Data Components.
- Student/instructor archive separation, offline reports, validation, diffing, benchmarking, replay-to-stdout, Sigma-subset validation, and plugin discovery.
- Security threat model, CI, contributor workflow, SBOM/checksum release process, and sample datasets.
- Expanded deterministic tests covering failure paths, safety boundaries, update errors, CLI recovery, validator corruption, impairments, optional branches, and scenario semantics.

### Quality
- 28/28 bundled scenarios pass structural and semantic validation.
- The current readiness audit passes 73 tests; one property-test module skips only because Hypothesis is unavailable in the audit sandbox.
- Readiness coverage measured **96.50% statement coverage**, **93.26% branch coverage**, and **95.77% combined line/branch coverage**.

### Release-readiness branding and quality hardening

- Added `logfable about` with creator, maintainer, copyright, website, repository, and license metadata.
- Added persistent generator provenance to dataset manifests, reports, student briefs, and summaries.
- Tightened strict typing and reviewed Bandit findings for deterministic simulation RNG and pinned HTTPS knowledge updates.
- Added PyYAML type stubs to the development environment and explicit optional-PyArrow mypy handling.
