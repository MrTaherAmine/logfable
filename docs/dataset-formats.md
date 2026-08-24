# Dataset Formats

All formats derive from the canonical event envelope. LogFable never silently claims lossless conversion.

| Format | v1.0 profile | Loss policy |
|---|---|---|
| Canonical JSON / JSONL / NDJSON | LogFable envelope | Lossless for analyst-visible fields |
| CSV | Flat core fields | Nested fields omitted and declared lossy |
| RFC5424 syslog | Compatibility-oriented line format | Core subset in structured data |
| CEF / LEEF | Compatibility-oriented | Core subset only; declared lossy |
| ECS | ECS 9.4.0 field profile | Unmapped canonical values preserved under `logfable.unmapped` selectively |
| OCSF | OCSF 1.8.0 generic activity profile | Unmapped values preserved under `unmapped` |
| OpenTelemetry Logs | Log record + Attributes | Canonical context becomes attributes |
| Splunk HEC file | HEC-compatible JSON objects | File only; never transmitted |
| Elasticsearch bulk | Bulk NDJSON action/doc pairs | File only; never transmitted |
| Parquet | Optional PyArrow | Same analyst-visible object rows |

## Source-family files

`telemetry/source/<family>/events.jsonl` partitions the canonical analyst-visible envelope by synthetic source family. These files are useful for correlation exercises and downstream adapters, but they are **not native vendor wire schemas**. For example, a `windows-security` partition is Windows Security-style synthetic evidence carried in the LogFable canonical envelope, not EVTX/XML; a `cloudtrail` partition is synthetic CloudTrail-style evidence, not a byte-for-byte AWS CloudTrail record.
