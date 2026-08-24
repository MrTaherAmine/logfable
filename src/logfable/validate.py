from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .knowledge import validate_attack, validate_d3fend
from .safety import unsafe_indicators

HEX_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def _safe_dataset_path(root: Path, rel: str) -> tuple[Path | None, str | None]:
    """Resolve a dataset-relative path without following data outside the dataset."""
    pure = PurePosixPath(rel)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        return None, f"unsafe-dataset-path:{rel}"
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            return None, f"unsafe-dataset-symlink:{rel}"
    try:
        current.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return None, f"unsafe-dataset-path:{rel}"
    return current, None


def validate_dataset(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    root = root.resolve()

    def safe_file(rel: str, *, required: bool = False) -> Path | None:
        path, unsafe = _safe_dataset_path(root, rel)
        if unsafe:
            errors.append(unsafe)
            return None
        if path is None or not path.is_file():
            if required:
                errors.append(f"missing:{rel}")
            return None
        return path

    required = [
        "manifest.json",
        "environment/entities.json",
        "telemetry/canonical/events.jsonl",
        "training/questions.json",
        "reports/quality.json",
        "checksums.sha256",
    ]
    required_paths = {rel: safe_file(rel, required=True) for rel in required}

    manifest: dict[str, Any] = {}
    manifest_path = required_paths["manifest.json"]
    if manifest_path is not None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"invalid-manifest:{exc}")

    event_ids: set[str] = set()
    counts = 0
    canonical_path = required_paths["telemetry/canonical/events.jsonl"]
    if canonical_path is not None:
        prev: str | None = None
        for lineno, line in enumerate(canonical_path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"invalid-jsonl-line:{lineno}")
                continue
            counts += 1
            event_id = record.get("event_id")
            if not event_id:
                errors.append(f"missing-event-id:{lineno}")
            elif event_id in event_ids:
                errors.append(f"duplicate-event-id:{event_id}")
            else:
                event_ids.add(event_id)
            if "internal" in record:
                errors.append(f"ground-truth-leak:internal:{lineno}")
            if "labels" in record and not manifest.get("configuration", {}).get("labeled"):
                errors.append(f"ground-truth-leak:labels:{lineno}")
            for value in [
                record.get("source_ip"),
                record.get("destination_ip"),
                record.get("message"),
            ]:
                if isinstance(value, str):
                    errors.extend(f"event-{lineno}:{item}" for item in unsafe_indicators(value))
            observed = record.get("observed_time")
            if prev and observed and observed < prev:
                warnings.append("out-of-order-observed-time")
            if observed:
                prev = observed

    if manifest and counts != manifest.get("event_count"):
        errors.append("manifest-event-count-mismatch")

    attack_path = safe_file("mappings/attack.json")
    if attack_path is not None:
        try:
            ids = [
                record["technique_id"]
                for record in json.loads(attack_path.read_text(encoding="utf-8"))
            ]
            errors += [f"invalid-attack-id:{item}" for item in validate_attack(ids)]
        except Exception as exc:
            errors.append(f"invalid-attack-mapping:{exc}")

    d3fend_path = safe_file("mappings/d3fend.json")
    if d3fend_path is not None:
        try:
            ids = [
                record["d3fend_id"]
                for record in json.loads(d3fend_path.read_text(encoding="utf-8"))
                if record.get("d3fend_id") != "unmapped"
            ]
            errors += [f"invalid-d3fend-id:{item}" for item in validate_d3fend(ids)]
        except Exception as exc:
            errors.append(f"invalid-d3fend-mapping:{exc}")

    checksum_path = required_paths["checksums.sha256"]
    if checksum_path is not None:
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            match = HEX_RE.match(line)
            if not match:
                errors.append("invalid-checksum-line")
                continue
            expected, rel = match.groups()
            path, unsafe = _safe_dataset_path(root, rel)
            if unsafe:
                errors.append(unsafe)
                continue
            if path is None or not path.is_file():
                errors.append(f"checksum-missing-file:{rel}")
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                errors.append(f"checksum-mismatch:{rel}")

    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
        "events": counts,
        "manifest": manifest,
    }
