# Scenario Authoring Guide

Create a starter:
```bash
logfable scenarios scaffold my-exercise --output ./scenarios
```

A scenario is a versioned DAG of defensive-observation steps. Every step declares predecessors, deterministic delay range, optional probability, ATT&CK evidence rationale, D3FEND opportunities, telemetry evidence, benign lookalikes, and expected detections.

## Compatibility policy
- `schema_version` follows semantic versioning.
- Patch versions may clarify validation without changing valid semantics.
- Minor versions may add optional fields.
- Major versions may change required fields or interpretation.
- A scenario declares its own semantic `version` independently from schema version.
- Reproducibility is scoped to the same engine/scenario/knowledge/configuration/seed/concurrency combination.

## Safety checklist
Use only RFC1918, RFC5737, RFC3849, loopback, and `.example` names. Evidence descriptions must be inert. Never put a working exploit, credential, token, malware hash sourced from a real sample, control-system command, or executable payload in a bundled scenario.
