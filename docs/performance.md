# Performance

LogFable v1.0.0 is designed for interactive training and validation datasets. Performance claims are measured, not extrapolated.

## Measured readiness smoke

On the current readiness-audit environment (Linux, CPython 3.13.5), the v1.0.0 100k-event smoke used:

```bash
logfable generate ransomware-enterprise \
  --duration 6h --users 500 --noise 98 \
  --target-events 100000 --seed 2026 \
  --formats generic-jsonl --output ./perf-100k
```

The run emitted 100,022 events after deterministic duplicate-event impairment, completed in 20.61 seconds, and reached approximately 678 MiB peak resident memory in this environment. Hardware and filesystem characteristics affect these values.

## v1.0 limitation

Text exporters stream their output, but the core engine still retains the canonical event collection in memory while a run is being assembled. v1.0 therefore does **not** claim bounded-memory multi-million-event generation. Partitioned canonical streaming is a v1.1 priority.
