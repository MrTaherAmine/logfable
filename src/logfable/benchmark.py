from __future__ import annotations

import csv
import datetime as dt
import json
import statistics
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast


def _alerts(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    if suffix in {".jsonl", ".ndjson"}:
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    data: object = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return cast(list[dict[str, Any]], data)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
        if isinstance(alerts, list):
            return cast(list[dict[str, Any]], alerts)
    raise ValueError("alert import must be a JSON array or object with an alerts array")


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    if isinstance(value, str) and "," in value:
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(value)]


def _parse_time(value: Any) -> dt.datetime | None:
    if value in (None, ""):
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _index_truth(rows: list[dict[str, Any]]) -> dict[str, dict[str, set[str]]]:
    indexes: dict[str, dict[str, set[str]]] = {
        "event_id": defaultdict(set),
        "correlation_id": defaultdict(set),
        "step": defaultdict(set),
        "technique": defaultdict(set),
    }
    for row in rows:
        eid = str(row["event_id"])
        indexes["event_id"][eid].add(eid)
        if row.get("correlation_id"):
            indexes["correlation_id"][str(row["correlation_id"])].add(eid)
        if row.get("step"):
            indexes["step"][str(row["step"])].add(eid)
        for technique in row.get("techniques", []) or []:
            indexes["technique"][str(technique)].add(eid)
    return indexes


def _entity_time_matches(alert: dict[str, Any], truth: list[dict[str, Any]]) -> set[str]:
    user = alert.get("user") or alert.get("user_id")
    host = alert.get("host") or alert.get("host_id")
    start = _parse_time(alert.get("start_time") or alert.get("window_start"))
    end = _parse_time(alert.get("end_time") or alert.get("window_end"))
    if not any((user, host, start, end)):
        return set()
    matches: set[str] = set()
    for row in truth:
        if user and str(row.get("user")) != str(user):
            continue
        if host and str(row.get("host")) != str(host):
            continue
        event_time = _parse_time(row.get("event_time"))
        if event_time is None:
            continue
        if start and event_time < start:
            continue
        if end and event_time > end:
            continue
        matches.add(str(row["event_id"]))
    return matches


def _alert_matches(
    alert: dict[str, Any],
    truth: list[dict[str, Any]],
    indexes: dict[str, dict[str, set[str]]],
) -> set[str]:
    matches: set[str] = set()
    for eid in _as_list(alert.get("event_id")) + _as_list(alert.get("event_ids")):
        matches.update(indexes["event_id"].get(eid, set()))
    for cid in _as_list(alert.get("correlation_id")) + _as_list(alert.get("correlation_ids")):
        matches.update(indexes["correlation_id"].get(cid, set()))
    for step in _as_list(alert.get("scenario_step")) + _as_list(alert.get("scenario_steps")):
        matches.update(indexes["step"].get(step, set()))
    techniques = (
        _as_list(alert.get("technique"))
        + _as_list(alert.get("technique_id"))
        + _as_list(alert.get("techniques"))
    )
    for technique in techniques:
        matches.update(indexes["technique"].get(technique, set()))
    matches.update(_entity_time_matches(alert, truth))
    return matches


def _coverage(rows: Iterable[dict[str, Any]], matched: set[str], key: str) -> dict[str, Any]:
    out: dict[str, dict[str, int | float]] = {}
    for row in rows:
        values = row.get(key, []) if key == "techniques" else [row.get(key)]
        for value in values or []:
            if value is None:
                continue
            item = out.setdefault(str(value), {"total": 0, "matched": 0})
            item["total"] += 1
            item["matched"] += int(str(row["event_id"]) in matched)
    for item in out.values():
        item["coverage"] = item["matched"] / item["total"] if item["total"] else 0.0
    return out


def benchmark(dataset: Path, alerts_path: Path) -> dict[str, Any]:
    gt_path = dataset / "instructor/ground-truth.json"
    if not gt_path.exists():
        raise ValueError("benchmark requires instructor ground truth")
    truth_raw: object = json.loads(gt_path.read_text(encoding="utf-8"))
    if not isinstance(truth_raw, list):
        raise ValueError("ground truth must be a JSON array")
    truth_rows = cast(list[dict[str, Any]], truth_raw)
    truth = {str(row["event_id"]): row for row in truth_rows}
    indexes = _index_truth(truth_rows)
    alerts = _alerts(alerts_path)
    lookalike_path = dataset / "instructor/benign-lookalikes.json"
    lookalikes_raw: object = (
        json.loads(lookalike_path.read_text(encoding="utf-8")) if lookalike_path.exists() else []
    )
    lookalikes = (
        cast(list[dict[str, Any]], lookalikes_raw) if isinstance(lookalikes_raw, list) else []
    )
    lookalike_ids = {str(r["event_id"]) for r in lookalikes}

    matched: set[str] = set()
    false_positive_alerts: list[dict[str, Any]] = []
    delays: list[float] = []
    lookalike_fp_alerts = 0

    for alert in alerts:
        hits = _alert_matches(alert, truth_rows, indexes)
        if hits:
            matched.update(hits)
            alert_time = _parse_time(alert.get("alert_time"))
            if alert_time:
                parsed_refs = [_parse_time(truth[event_id].get("event_time")) for event_id in hits]
                refs: list[dt.datetime] = [parsed for parsed in parsed_refs if parsed is not None]
                if refs:
                    delays.append(max(0.0, (alert_time - min(refs)).total_seconds()))
            continue

        false_positive_alerts.append(alert)
        alert_ids = set(_as_list(alert.get("event_id")) + _as_list(alert.get("event_ids")))
        if alert_ids & lookalike_ids:
            lookalike_fp_alerts += 1

    tp = len(matched)
    fp = len(false_positive_alerts)
    fn = len(truth) - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "time_to_detect_seconds": {
            "mean": statistics.mean(delays) if delays else None,
            "median": statistics.median(delays) if delays else None,
        },
        "technique_coverage": _coverage(truth_rows, matched, "techniques"),
        "scenario_step_coverage": _coverage(truth_rows, matched, "step"),
        "source_coverage": _coverage(truth_rows, matched, "source_family"),
        "benign_lookalikes": {
            "events": len(lookalikes),
            "false_positive_alerts": lookalike_fp_alerts,
            "false_positive_rate": lookalike_fp_alerts / len(lookalikes) if lookalikes else 0.0,
        },
        "matching_contract": [
            "event_id/event_ids",
            "correlation_id/correlation_ids",
            "scenario_step/scenario_steps",
            "technique/technique_id/techniques",
            "user-or-host plus optional start/end time window",
        ],
        "alerts": len(alerts),
        "truth_events": len(truth),
    }


def write_reports(dataset: Path, result: dict[str, Any]) -> dict[str, str]:
    reports = dataset / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    json_path = reports / "benchmark.json"
    md_path = reports / "benchmark.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ttd = result["time_to_detect_seconds"]
    md = [
        "# LogFable detection benchmark",
        "",
        f"- True positives: **{result['true_positives']}**",
        f"- False positives: **{result['false_positives']}**",
        f"- False negatives: **{result['false_negatives']}**",
        f"- Precision: **{result['precision']:.4f}**",
        f"- Recall: **{result['recall']:.4f}**",
        f"- F1: **{result['f1']:.4f}**",
        f"- Mean time to detect: **{ttd['mean']} seconds**",
        f"- Median time to detect: **{ttd['median']} seconds**",
        (
            "- Benign-lookalike false-positive alerts: "
            f"**{result['benign_lookalikes']['false_positive_alerts']}** / "
            f"{result['benign_lookalikes']['events']}"
        ),
        "",
        (
            "Results describe this synthetic dataset and imported alert set only; "
            "they are not universal proof of detection coverage."
        ),
        "",
        "## Technique coverage",
        "",
        "| Technique | Matched | Total | Coverage |",
        "|---|---:|---:|---:|",
    ]
    for key, item in sorted(result["technique_coverage"].items()):
        md.append(f"| {key} | {item['matched']} | {item['total']} | {item['coverage']:.1%} |")
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    from .dataset import write_checksums

    write_checksums(dataset)
    return {"json": str(json_path), "markdown": str(md_path)}
