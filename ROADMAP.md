# Roadmap

LogFable v1.0.0 launches with 28 bundled scenarios and the expanded validation/test surface originally explored during pre-release development. The items below are intentionally **post-v1.0** priorities.

## v1.1 priorities

1. Replace the in-memory canonical event list with deterministic partitioned streaming for materially lower memory use on million-event datasets.
2. Add richer benchmark matchers and documented custom matcher plugins.
3. Expand impairment profiles: longer source outages, dropped fields, parser failures, delayed cloud logs, NAT/VPN reuse, DHCP reuse, hostname changes, and enrichment failures.
4. Deepen environment state transitions so identity/device/cloud/Kubernetes/OT state mutations constrain later evidence more explicitly.
5. Add broader current-schema conformance fixtures and additional source-specific validation profiles.
6. Deepen the existing 28 scenarios with more partial-success/failure branches, alternate benign explanations, source outages, and visibility gaps rather than simply multiplying scenario count.
7. Improve canonical-event memory behavior while preserving deterministic output across worker scheduling.
8. Expand plugin metadata discovery without importing plugin code where platform metadata permits it.
9. Consider optional encrypted instructor bundles using standard authenticated encryption and a standard password-based KDF.
10. Expand community-maintained scenario packs and environment presets under the compatibility and safety policies.

## Later

- Additional schema-version compatibility profiles.
- Larger-scale research benchmark corpora that remain safe, local-first, and license-clean.
- More sophisticated report visualizations that remain fully self-contained and offline.
