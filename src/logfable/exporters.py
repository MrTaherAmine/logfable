from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import ECS_VERSION, OCSF_VERSION
from .models import CanonicalEvent


class ExportError(ValueError):
    pass


def _csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet-formula prefixes in exported CSV cells."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _single_line(value: Any) -> str:
    """Keep line-oriented formats single-line and free of terminal controls."""
    text = str(value)
    return "".join(
        " " if character in "\r\n\t" or ord(character) < 32 or ord(character) == 127 else character
        for character in text
    )


def _cef_escape(value: Any) -> str:
    return _single_line(value).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as file_handle:
        for row in rows:
            file_handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            count += 1
    return count


def _analyst_rows(
    events: list[CanonicalEvent],
    labeled: bool,
) -> Iterator[dict[str, Any]]:
    for event in events:
        yield event.analyst_dict(labeled=labeled)


def _write_json_array(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as file_handle:
        file_handle.write("[\n")
        first = True
        for row in rows:
            if not first:
                file_handle.write(",\n")
            file_handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            first = False
            count += 1
        file_handle.write("\n]\n")
    return count


def export(
    events: list[CanonicalEvent],
    fmt: str,
    root: Path,
    *,
    labeled: bool = False,
) -> dict[str, Any]:
    """Export canonical events without materializing another full public event list."""
    root.mkdir(parents=True, exist_ok=True)
    lossy: list[str] = []
    version: str | None = None

    if fmt in {"generic-jsonl", "ndjson"}:
        path = root / ("events.jsonl" if fmt == "generic-jsonl" else "events.ndjson")
        count = _write_jsonl(path, _analyst_rows(events, labeled))
    elif fmt == "canonical-json":
        path = root / "events.json"
        count = _write_json_array(path, _analyst_rows(events, labeled))
    elif fmt == "csv":
        path = root / "events.csv"
        fields = [
            "event_id",
            "event_time",
            "observed_time",
            "category",
            "action",
            "outcome",
            "severity",
            "source_family",
            "host",
            "user",
            "source_ip",
            "destination_ip",
            "correlation_id",
            "message",
        ]
        count = 0
        with path.open("w", encoding="utf-8", newline="") as file_handle:
            writer = csv.DictWriter(file_handle, fieldnames=fields)
            writer.writeheader()
            for row in _analyst_rows(events, labeled):
                writer.writerow({key: _csv_safe(row.get(key)) for key in fields})
                count += 1
        lossy = ["nested canonical fields omitted from flat CSV profile"]
    elif fmt == "syslog":
        path = root / "events.syslog"
        count = 0
        with path.open("w", encoding="utf-8", newline="\n") as file_handle:
            for row in _analyst_rows(events, labeled):
                prefix = (
                    f"<134>1 {_single_line(row['event_time'])} "
                    f"{_single_line(row.get('host') or '-')} logfable - "
                    f"{_single_line(row['event_id'])} "
                )
                structured = (
                    f'[logfable@32473 source="{_single_line(row["source_family"])}" '
                    f'action="{_single_line(row["action"])}"] '
                )
                file_handle.write(prefix + structured + _single_line(row["message"]) + "\n")
                count += 1
        lossy = ["RFC5424 compatibility profile carries a subset of canonical fields"]
    elif fmt == "cef":
        path = root / "events.cef"
        count = 0
        with path.open("w", encoding="utf-8", newline="\n") as file_handle:
            for row in _analyst_rows(events, labeled):
                header = (
                    "CEF:0|LogFable|Synthetic Telemetry|1.0|"
                    f"{_cef_escape(row['action'])}|{_cef_escape(row['category'])}|"
                    f"{row['severity']}|"
                )
                extension = (
                    f"src={_cef_escape(row.get('source_ip') or '')} "
                    f"dst={_cef_escape(row.get('destination_ip') or '')} "
                    f"suser={_cef_escape(row.get('user') or '')} "
                    f"msg={_cef_escape(row['message'])}"
                )
                file_handle.write(header + extension + "\n")
                count += 1
        lossy = ["CEF extension profile carries a subset of canonical fields"]
    elif fmt == "leef":
        path = root / "events.leef"
        count = 0
        with path.open("w", encoding="utf-8", newline="\n") as file_handle:
            for row in _analyst_rows(events, labeled):
                prefix = (
                    f"LEEF:2.0|LogFable|Synthetic Telemetry|1.0|{_single_line(row['action'])}|\t"
                )
                extension = (
                    f"devTime={_single_line(row['event_time'])}\t"
                    f"src={_single_line(row.get('source_ip') or '')}\t"
                    f"dst={_single_line(row.get('destination_ip') or '')}\t"
                    f"usrName={_single_line(row.get('user') or '')}"
                )
                file_handle.write(prefix + extension + "\n")
                count += 1
        lossy = ["LEEF compatibility profile carries a subset of canonical fields"]
    elif fmt == "ecs":
        version = ECS_VERSION
        path = root / "events.ecs.jsonl"

        def ecs_rows() -> Iterator[dict[str, Any]]:
            for row in _analyst_rows(events, labeled):
                yield {
                    "@timestamp": row["event_time"],
                    "ecs": {"version": ECS_VERSION},
                    "event": {
                        "id": row["event_id"],
                        "category": [row["category"]],
                        "action": row["action"],
                        "outcome": row["outcome"],
                        "severity": row["severity"],
                    },
                    "host": {"id": row.get("host")},
                    "user": {"id": row.get("user")},
                    "source": {"ip": row.get("source_ip")},
                    "destination": {"ip": row.get("destination_ip")},
                    "message": row["message"],
                    "log": {"logger": row["source_family"]},
                    "logfable": {
                        "unmapped": {
                            "correlation_id": row.get("correlation_id"),
                            "extensions": row.get("extensions"),
                        }
                    },
                }

        count = _write_jsonl(path, ecs_rows())
        lossy = ["non-ECS canonical fields preserved under logfable.unmapped selectively"]
    elif fmt == "ocsf":
        version = OCSF_VERSION
        path = root / "events.ocsf.jsonl"

        def ocsf_rows() -> Iterator[dict[str, Any]]:
            for row in _analyst_rows(events, labeled):
                yield {
                    "class_uid": 1000,
                    "category_uid": 1,
                    "activity_id": 1,
                    "type_uid": 100001,
                    "severity_id": min(6, max(1, (int(row["severity"]) + 1) // 2)),
                    "time": int(datetime.fromisoformat(row["event_time"]).timestamp() * 1000),
                    "metadata": {
                        "version": OCSF_VERSION,
                        "product": {"name": "LogFable", "vendor_name": "LogFable"},
                    },
                    "actor": {"user": {"uid": row.get("user")}},
                    "src_endpoint": {"ip": row.get("source_ip")},
                    "dst_endpoint": {"ip": row.get("destination_ip")},
                    "message": row["message"],
                    "unmapped": {
                        "event_id": row["event_id"],
                        "source_family": row["source_family"],
                        "action": row["action"],
                        "correlation_id": row.get("correlation_id"),
                    },
                }

        count = _write_jsonl(path, ocsf_rows())
        lossy = [
            "OCSF compatibility profile uses a generic activity class; "
            "canonical-only fields retained in unmapped"
        ]
    elif fmt == "otel":
        path = root / "events.otel.jsonl"

        def otel_rows() -> Iterator[dict[str, Any]]:
            for row in _analyst_rows(events, labeled):
                yield {
                    "Timestamp": row["event_time"],
                    "ObservedTimestamp": row["observed_time"],
                    "SeverityNumber": row["severity"],
                    "SeverityText": str(row["severity"]),
                    "Body": row["message"],
                    "Attributes": {
                        "event.id": row["event_id"],
                        "event.action": row["action"],
                        "logfable.source_family": row["source_family"],
                        "user.id": row.get("user"),
                        "host.id": row.get("host"),
                    },
                }

        count = _write_jsonl(path, otel_rows())
        lossy = ["OpenTelemetry Logs profile maps canonical data to log record attributes"]
    elif fmt == "splunk-hec":
        path = root / "events.hec.jsonl"

        def hec_rows() -> Iterator[dict[str, Any]]:
            for row in _analyst_rows(events, labeled):
                yield {
                    "time": datetime.fromisoformat(row["event_time"]).timestamp(),
                    "host": row.get("host"),
                    "source": row["source_family"],
                    "sourcetype": "logfable:synthetic",
                    "event": row,
                }

        count = _write_jsonl(path, hec_rows())
    elif fmt == "elasticsearch-bulk":
        path = root / "events.bulk.ndjson"
        count = 0
        with path.open("w", encoding="utf-8", newline="\n") as file_handle:
            for row in _analyst_rows(events, labeled):
                action = {
                    "index": {
                        "_index": "logfable-synthetic",
                        "_id": row["event_id"],
                    }
                }
                file_handle.write(json.dumps(action, separators=(",", ":")) + "\n")
                file_handle.write(json.dumps(row, separators=(",", ":")) + "\n")
                count += 1
    elif fmt == "parquet":
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise ExportError("Parquet requires the optional 'parquet' extra") from exc
        path = root / "events.parquet"
        analyst = list(_analyst_rows(events, labeled))
        pq.write_table(pa.Table.from_pylist(analyst), path)
        count = len(analyst)
    else:
        raise ExportError(f"unsupported format: {fmt}")

    result: dict[str, Any] = {"path": str(path), "records": count, "lossy": lossy}
    if version:
        result["schema_version"] = version
    return result
