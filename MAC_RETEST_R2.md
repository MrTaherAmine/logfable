# LogFable v1.0.0 — Mac R2 Retest

This R2 source incorporates the Ruff findings from the first branded Mac candidate.

Verified previously on the real MacBook Pro:

- 74 tests passed
- strict mypy passed
- Bandit passed
- pip-audit found no known dependency vulnerabilities
- wheel/sdist build passed
- Twine checks passed

The remaining purpose of R2 is to confirm Ruff on the corrected source and rerun the release gates after those style-only changes.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'

logfable about
logfable doctor
ruff format --check .
ruff check .
mypy src/
bandit -q -r src/logfable
pip-audit
pytest -ra
pytest --cov=logfable --cov-branch --cov-report=term-missing
python -m build
twine check dist/*
```

Do not publish externally until the R2 run is confirmed clean.
