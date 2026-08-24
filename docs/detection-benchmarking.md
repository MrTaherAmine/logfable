# Detection benchmarking

LogFable benchmarks imported alert exports against instructor-only ground truth. Results apply only to the generated synthetic dataset, configuration, and alert set; they are not proof of universal detection coverage.

## Alert formats

JSON, JSONL/NDJSON, and CSV are supported. An alert can match ground truth through one or more of:

- `event_id` or `event_ids`
- `correlation_id` or `correlation_ids`
- `scenario_step` or `scenario_steps`
- `technique`, `technique_id`, or `techniques`
- `user`/`user_id` and/or `host`/`host_id`, optionally constrained with `start_time`/`window_start` and `end_time`/`window_end`

Times use ISO 8601. Unsupported or malformed matching fields simply do not create a ground-truth match; normal input/JSON errors fail loudly.

## Metrics

The benchmark reports true positives, false positives, false negatives, precision, recall, F1, mean/median time to detect when `alert_time` is supplied, ATT&CK technique coverage, scenario-step coverage, source coverage, and false positives against the dataset's instructor-only benign-lookalike index.

```bash
logfable benchmark --dataset ./lab --alerts ./alerts.json
```

The command writes machine-readable `reports/benchmark.json` and human-readable `reports/benchmark.md` in addition to terminal output.

## v1.0 boundaries

Custom matcher plugins, arbitrary query-language adapters, and automatic paired comparison of impaired versus unimpaired datasets are not part of the v1.0 built-in matcher. Generate deterministic paired datasets and compare their benchmark reports when evaluating impairment sensitivity.
