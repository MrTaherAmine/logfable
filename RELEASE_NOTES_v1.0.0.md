# LogFable v1.0.0 — Pre-publication Mac Validation Candidate

**Generate complete cyber incidents without launching a single attack.**

LogFable v1.0.0 is the intended initial public release of a local-first scenario-as-code engine for deterministic, causally coherent, multi-source synthetic cybersecurity telemetry. This package is the pre-publication candidate for real macOS validation; public release remains contingent on that runtime test and hosted quality/security gates.

## Highlights
- **28 built-in incident scenarios** spanning identity/MFA, email, ransomware, cloud, SaaS, insider activity, web/API, mobile/MDM, Kubernetes, CI/CD, DLP/removable media, DNS anomaly investigation, remote access, backup controls, hybrid identity, and passive IT/OT investigations.
- Six deterministic organization/environment presets with stable identities, hosts, cloud resources, Kubernetes entities, and segmented IT/OT relationships.
- Benign activity as a first-class signal with approximate noise percentages and false-positive lookalikes.
- Deterministic clock skew, ingestion delay, missing-event, and duplicate-event impairments.
- Canonical event envelope plus JSON/JSONL/NDJSON, CSV, syslog, CEF, LEEF, ECS, OCSF, OpenTelemetry, HEC-file, Elasticsearch bulk-file, and optional Parquet export profiles.
- Synthetic MDM and DLP telemetry families in addition to the broader endpoint, identity, network, cloud, application, email, container/CI/CD, and passive OT/ICS source set.
- MITRE ATT&CK 19.2 mapping baseline and MITRE D3FEND 1.5.0 defensive-opportunity baseline with provenance and qualified claims.
- Stricter ATT&CK validation distinguishing Techniques, Detection Strategies, Analytics, and Data Components.
- Student-safe and instructor packages with strict ground-truth separation.
- Offline self-contained HTML reports, checksums, manifest, quality validation, dataset diffing, and detection benchmark metrics.
- Plugin entry-point SDK, original Sigma examples, GitHub Action, configured multi-OS CI/security/SBOM workflows, and contributor governance.
- Real MacBook Pro validation on Python 3.14.7 reaches **74 passing tests** with Hypothesis enabled. Strict `mypy src/` passes with no issues, Bandit completes cleanly, `pip-audit` reports no known dependency vulnerabilities, `python -m build` succeeds, and `twine check dist/*` passes for both wheel and sdist. Ruff was the only failing Mac gate on the previous candidate; the R2 source addresses all findings reported in that run and awaits final Ruff confirmation on macOS. The optional Parquet exporter remains separately dependent on PyArrow.

## Safety
LogFable generates representations only. It contains no malware, exploit, credential-stealing routine, destructive command, phishing kit, operational persistence payload, or OT control command. Generation performs no outbound network access.

## Known v1.0 boundaries
The source profiles are compatibility-oriented synthetic representations carried in canonical JSONL source-family partitions, not native vendor wire schemas or byte-perfect proprietary emulations. The scenario model exposes `state_changes`, `actor`, and `target`, but v1.0 does not yet enforce a general mutable world-state/precondition engine or rich entity-selector resolution. Parquet requires the optional PyArrow extra. Text exporters stream, but the current engine still retains the canonical event collection in memory during assembly, so v1.0 does not claim bounded-memory multi-million-event generation. The built-in benchmark matcher supports event IDs, correlation IDs, scenario steps, techniques, and basic user/host time windows. Plugins are trusted Python code and are not sandboxed.

Maintainer: Taher Amine ELHOUARI · https://www.taheramine.org
