# LogFable v1.0.0 — Mac Retest R3

R3 contains one non-functional formatting correction after the R2 Mac check:

- `src/logfable/cli.py`: `APP_HELP` is formatted exactly as Ruff expects.

The R2 Mac run already established that `ruff check .` passes. R3 is intended to close the remaining `ruff format --check .` finding.

Run:

```bash
ruff format --check .
ruff check .
mypy src/
bandit -q -r src/logfable
pip-audit
pytest -ra
python -m build
twine check dist/*
```
