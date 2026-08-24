# macOS Local Testing Guide

This guide tests the extracted LogFable v1.0.0 repository locally on a MacBook Pro before any public GitHub or PyPI publication.

## 1. Open Terminal and enter the extracted repository

```bash
cd ~/Downloads/logfable-v1.0.0
```

If the folder is elsewhere, type `cd ` and drag the extracted folder from Finder into Terminal.

## 2. Confirm Python

```bash
python3 --version
```

Use Python 3.11 through 3.14. If needed and Homebrew is installed:

```bash
brew install python@3.13
```

## 3. Create and activate a clean virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

## 4. Install LogFable and its test tools

```bash
python -m pip install -e '.[dev]'
```

Optional Parquet support:

```bash
python -m pip install -e '.[dev,parquet]'
```

## 5. Basic health checks

```bash
logfable version
logfable doctor
logfable --help
logfable scenarios list
logfable scenarios validate scenarios/
logfable knowledge verify
```

Expected version: `1.0.0`. The scenario list should contain 28 built-in scenarios.

## 6. Generate a small first dataset

```bash
logfable generate password-spray-account-takeover \
  --duration 15m \
  --users 20 \
  --noise 90 \
  --seed 2026 \
  --formats generic-jsonl,ecs \
  --output ./mac-smoke-simple

logfable validate ./mac-smoke-simple
logfable inspect ./mac-smoke-simple --report
open ./mac-smoke-simple/reports/report.html
```

Do not reuse an existing non-LogFable directory as `--output`. LogFable refuses accidental overwrite by default.

## 7. Generate a multi-source training dataset

```bash
logfable generate ransomware-enterprise \
  --duration 30m \
  --users 50 \
  --noise 95 \
  --seed 2026 \
  --formats generic-jsonl,ecs,ocsf,cef \
  --student-package \
  --instructor-package \
  --output ./mac-smoke-ransomware

logfable validate ./mac-smoke-ransomware
logfable inspect ./mac-smoke-ransomware --report
open ./mac-smoke-ransomware/reports/report.html
```

Confirm that the sibling student ZIP does not contain `instructor/`, `mappings/`, or `scenario/` paths.

## 8. Confirm reproducibility

```bash
logfable generate mfa-fatigue-session-takeover --seed 777 --target-events 60 --output ./mac-seed-a
logfable generate mfa-fatigue-session-takeover --seed 777 --target-events 60 --output ./mac-seed-b
logfable diff ./mac-seed-a ./mac-seed-b
```

The diff should report identical output for the same release, scenario, configuration, and seed.

## 9. Run the automated quality suite

```bash
pytest
pytest --cov=logfable --cov-branch --cov-report=term-missing
ruff format --check .
ruff check .
mypy src/
bandit -q -r src/logfable
pip-audit
python -m build
twine check dist/*
```

The current pre-Mac audit baseline is 73 passing tests with one skipped property-test module only because Hypothesis was unavailable in the audit sandbox. Installing `.[dev]` on the Mac should install Hypothesis, so that module should execute there instead of skipping.

## 10. Test the built wheel in a second clean environment

After `python -m build` succeeds:

```bash
deactivate
cd ..
python3 -m venv logfable-wheel-test
source logfable-wheel-test/bin/activate
python -m pip install ./logfable-v1.0.0/dist/logfable-1.0.0-py3-none-any.whl
logfable version
logfable doctor
logfable generate kubernetes-service-account --target-events 40 --seed 2026 --output ./wheel-smoke-k8s
logfable validate ./wheel-smoke-k8s
```

If the extracted repository folder has another name/path, update the wheel path accordingly.

## What to send back if something fails

Paste the complete command and Terminal output, or send a screenshot. Do not delete the generated dataset that failed validation; it can help reproduce the problem.
