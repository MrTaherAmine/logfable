# Compatibility and Deprecation Policy

LogFable follows Semantic Versioning.

- Dataset reproducibility is guaranteed only within the same engine version, scenario version, knowledge versions, configuration, seed, and concurrency mode.
- Public schema fields are not removed in a minor release without prior deprecation.
- Deprecations remain documented for at least one minor release when practical.
- Export-format schema version bumps are recorded in the manifest and may intentionally change normalized output.
- Plugin API compatibility is versioned independently (`API_VERSION=1` in v1.0).
