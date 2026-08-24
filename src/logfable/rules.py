from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml


def validate_sigma(path: Path) -> dict[str, Any]:
    paths = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    results: list[dict[str, Any]] = []
    for candidate in paths:
        try:
            raw: object = yaml.safe_load(candidate.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("Sigma document must be a YAML mapping")
            document = cast(dict[str, Any], raw)
            errors: list[str] = []
            for key in ["title", "id", "status", "logsource", "detection"]:
                if key not in document:
                    errors.append(f"missing:{key}")
            detection = document.get("detection", {})
            condition = ""
            if isinstance(detection, dict):
                condition = str(detection.get("condition", ""))
            if any(token in condition for token in ["near ", " | ", "1 of them"]):
                errors.append("unsupported-condition-construct")
            results.append({"path": str(candidate), "valid": not errors, "errors": errors})
        except Exception as exc:
            results.append({"path": str(candidate), "valid": False, "errors": [str(exc)]})
    return {
        "valid": all(item["valid"] for item in results),
        "supported_subset": "simple selections with boolean condition names",
        "results": results,
    }
