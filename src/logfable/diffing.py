from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast


def digest_dataset(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in {"report.html", "checksums.sha256"}:
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _manifest(root: Path) -> dict[str, Any]:
    raw: object = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("dataset manifest must be a JSON object")
    return cast(dict[str, Any], raw)


def diff(a: Path, b: Path) -> dict[str, Any]:
    manifest_a = _manifest(a)
    manifest_b = _manifest(b)
    keys = ["engine_version", "scenario_version", "seed", "configuration", "knowledge"]
    changes = {
        key: {"a": manifest_a.get(key), "b": manifest_b.get(key)}
        for key in keys
        if manifest_a.get(key) != manifest_b.get(key)
    }
    digest_a = digest_dataset(a)
    digest_b = digest_dataset(b)
    return {
        "identical": digest_a == digest_b,
        "digest_a": digest_a,
        "digest_b": digest_b,
        "expected_change_dimensions": changes,
    }
