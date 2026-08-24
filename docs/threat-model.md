# Threat Model

| Threat | Control in v1.0 | Residual risk |
|---|---|---|
| Malicious YAML | `yaml.safe_load`, Pydantic schema, semantic validation | Resource-heavy but syntactically valid files still require OS limits |
| Path traversal | Generated paths are fixed; workspace helper validates child paths | Trusted plugins can still write arbitrary paths |
| Symlink/archive traversal | Output symlinks are refused before overwrite; archives are created only from internally generated trees | External archives are not imported by core v1.0 |
| Resource exhaustion | Size/volume validation, bounded knowledge downloads | Very large requested datasets can consume disk/time |
| Regex denial of service | Simple bounded regexes only | Future complex detectors require review |
| Template injection | Report is constructed with HTML escaping; no untrusted template evaluation | Custom trusted report plugins can alter behavior |
| Terminal/log-line injection | User-facing error/path text is sanitized; syslog/CEF/LEEF records are forced to a single line; JSON serialization escapes controls | Rich/third-party plugin output remains trusted |
| Untrusted plugins | Entry-point listing does not import plugin code | Executing plugins is trusted-code only; no sandbox |
| Malicious knowledge download | HTTPS/TLS, pinned source hosts, cross-host redirect refusal, size limits, JSON/version validation, checksums | Upstream compromise is still a supply-chain risk |
| Dependency compromise | Minimal dependencies, Dependabot, dependency review, pip-audit CI | PyPI ecosystem risk remains |
| Ground-truth leakage | Analyst envelope strips `internal`; student ZIP deletes scenario/mappings/instructor and rewrites manifest/report | Custom plugins/exporters must preserve contract |
| Accidental transmission | No automatic sinks beyond stdout; generation has no network path | Users can manually transmit files |
| Overwrite/data loss | Existing paths are refused by default; `--overwrite` only replaces a recognized LogFable dataset and refuses symlink/dangerous targets; assembly is atomic | A user can still intentionally delete a recognized LogFable dataset by requesting overwrite |
