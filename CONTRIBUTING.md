# Contributing

Contributions are welcome for scenarios, source profiles, exporters, framework mappings, validators, reports, tests, and documentation.

## Development
```bash
python -m pip install -e ".[dev]"
pytest --cov=logfable --cov-branch
ruff check .
mypy src/
```

## Scenario contributions
Every scenario must include attribution and license, `safety.synthetic_only: true`, only reserved/private indicators, deterministic seeds, at least one benign lookalike, ATT&CK rationale, D3FEND rationale or explicit `unmapped`, investigation questions, scoring, and tests. Do not include live malicious infrastructure, secrets, malware, exploits, or ready-to-run intrusion commands.

Run `logfable scenarios validate PATH` before opening a pull request.

## Mapping review
Mappings are evidence-backed assertions, not equivalence claims. Record version, rationale, evidence source, confidence, provenance, and review state. D3FEND inferred relationships must remain qualified as inferred/experimental when used.

## Pull requests
Keep changes focused, add tests, update docs/changelog when behavior changes, and preserve deterministic output unless the change intentionally bumps a compatibility boundary.
