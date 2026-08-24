from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import IO, Any, cast

import yaml

from .branding import metadata as branding_metadata
from .constants import (
    ATTACK_VERSION,
    D3FEND_VERSION,
    ECS_VERSION,
    ENGINE_VERSION,
    OCSF_VERSION,
    SUPPORTED_FORMATS,
)
from .engine import GenerationConfig, generate
from .exporters import export
from .knowledge import status as knowledge_status
from .mappings import write_mappings
from .models import CanonicalEvent, Scenario
from .report import generate_report


class DatasetError(ValueError):
    pass


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checksums(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace(os.sep, "/"): _sha(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "checksums.sha256"
    }


def write_checksums(root: Path) -> None:
    sums = checksums(root)
    (root / "checksums.sha256").write_text(
        "".join(f"{digest}  {relative}\n" for relative, digest in sums.items()),
        encoding="utf-8",
    )


def _zip_dir(root: Path, destination: Path) -> None:
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(root))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _ground_truth(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    return [
        {
            "event_id": event.event_id,
            "step": event.internal.get("scenario_step"),
            "techniques": event.internal.get("techniques"),
            "event_time": event.event_time.isoformat(),
            "observed_time": event.observed_time.isoformat(),
            "source_family": event.source_family,
            "correlation_id": event.correlation_id,
            "user": event.user,
            "host": event.host,
        }
        for event in events
        if event.internal.get("classification") == "suspicious"
    ]


def _benign_lookalikes(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    return [
        {
            "event_id": event.event_id,
            "event_time": event.event_time.isoformat(),
            "observed_time": event.observed_time.isoformat(),
            "source_family": event.source_family,
            "correlation_id": event.correlation_id,
            "user": event.user,
            "host": event.host,
            "message": event.message,
        }
        for event in events
        if event.internal.get("benign_lookalike")
    ]


def generate_dataset(
    scenario: Scenario,
    config: GenerationConfig,
    formats: list[str],
    output: Path,
    *,
    student_package: bool = False,
    instructor_package: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    unknown = [fmt for fmt in formats if fmt not in SUPPORTED_FORMATS]
    if unknown:
        raise DatasetError(f"unsupported formats: {','.join(unknown)}")
    if student_package and config.labeled:
        raise DatasetError("student package cannot be combined with labeled research export")

    output = output.expanduser().absolute()
    if output.is_symlink():
        raise DatasetError(f"refusing symlink output path: {output}")
    if output.exists():
        if not overwrite:
            raise FileExistsError(output)
        dangerous = {Path("/").resolve(), Path.home().resolve(), Path.cwd().resolve()}
        resolved_output = output.resolve()
        if resolved_output in dangerous:
            raise DatasetError(f"refusing dangerous overwrite target: {output}")
        manifest_path = output / "manifest.json"
        recognized = False
        if manifest_path.is_file():
            try:
                existing_raw: object = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(existing_raw, dict):
                    existing = cast(dict[str, Any], existing_raw)
                    recognized = bool(
                        existing.get("engine_version") and existing.get("scenario_id")
                    )
            except (OSError, json.JSONDecodeError, TypeError):
                recognized = False
        if not recognized:
            raise DatasetError(f"refusing to overwrite non-LogFable directory: {output}")
        shutil.rmtree(output)

    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        events, entities, relationships, environment = generate(scenario, config)
        for directory in [
            "scenario",
            "environment",
            "telemetry/canonical",
            "telemetry/source",
            "telemetry/normalized",
            "mappings",
            "training",
            "instructor",
            "reports",
        ]:
            (temp_root / directory).mkdir(parents=True, exist_ok=True)

        (temp_root / "scenario/resolved-scenario.yaml").write_text(
            yaml.safe_dump(scenario.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        _write_json(
            temp_root / "environment/organization.json",
            {"name": environment["organization"], "preset": environment["preset"]},
        )
        _write_json(
            temp_root / "environment/entities.json",
            [entity.model_dump() for entity in entities],
        )
        _write_json(
            temp_root / "environment/relationships.json",
            [relationship.model_dump() for relationship in relationships],
        )

        canonical_path = temp_root / "telemetry/canonical/events.jsonl"
        source_handles: dict[str, IO[str]] = {}
        by_source: dict[str, int] = {}
        try:
            with canonical_path.open("w", encoding="utf-8", newline="\n") as canonical_file:
                for event in events:
                    record = event.analyst_dict(labeled=config.labeled)
                    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                    canonical_file.write(line)
                    source = str(record["source_family"])
                    by_source[source] = by_source.get(source, 0) + 1
                    if source not in source_handles:
                        source_directory = temp_root / "telemetry/source" / source
                        source_directory.mkdir(parents=True, exist_ok=True)
                        source_handles[source] = (source_directory / "events.jsonl").open(
                            "w",
                            encoding="utf-8",
                            newline="\n",
                        )
                    source_handles[source].write(line)
        finally:
            for file_handle in source_handles.values():
                file_handle.close()

        exports: dict[str, dict[str, Any]] = {}
        for fmt in formats:
            item = export(
                events,
                fmt,
                temp_root / "telemetry/normalized" / fmt,
                labeled=config.labeled,
            )
            item["path"] = str(Path(str(item["path"])).relative_to(temp_root)).replace(
                os.sep,
                "/",
            )
            exports[fmt] = item

        mapping_summary = write_mappings(scenario, temp_root / "mappings")
        ground_truth = _ground_truth(events)
        suspicious = [
            event for event in events if event.internal.get("classification") == "suspicious"
        ]
        lookalikes = _benign_lookalikes(events)
        _write_json(temp_root / "instructor/ground-truth.json", ground_truth)
        _write_json(temp_root / "instructor/benign-lookalikes.json", lookalikes)
        _write_json(
            temp_root / "instructor/answers.json",
            {"answers": scenario.ground_truth.get("answers", [])},
        )
        _write_json(temp_root / "instructor/scoring-rubric.json", scenario.scoring)
        opportunities = [
            {
                "step": step.id,
                "expected_detections": step.expected_detections,
                "sources": [evidence.source for evidence in step.evidence],
                "required_fields": [
                    "event_id",
                    "event_time",
                    "source_family",
                    "user",
                    "host",
                    "correlation_id",
                ],
            }
            for step in scenario.steps
        ]
        _write_json(
            temp_root / "instructor/detection-opportunities.json",
            opportunities,
        )
        (temp_root / "instructor/timeline.csv").write_text(
            "event_time,event_id,scenario_step\n"
            + "".join(
                f"{event.event_time.isoformat()},{event.event_id},"
                f"{event.internal.get('scenario_step')}\n"
                for event in suspicious
            ),
            encoding="utf-8",
        )
        student_brief = (
            f"# {scenario.title}\n\n{scenario.summary}\n\n"
            f"## Environment\nSynthetic organization: {environment['organization']}.\n\n"
            "## Questions\n"
            + "\n".join(
                f"{index + 1}. {question}" for index, question in enumerate(scenario.questions)
            )
            + "\n\n---\n"
            "Generated by LogFable · © 2026 Taher Amine ELHOUARI · "
            "https://www.taheramine.org\n"
        )
        (temp_root / "training/student-brief.md").write_text(
            student_brief,
            encoding="utf-8",
        )
        _write_json(temp_root / "training/questions.json", {"questions": scenario.questions})

        quality: dict[str, Any] = {
            "valid": True,
            "events": len(events),
            "sources": len(by_source),
            "unique_event_ids": len({event.event_id for event in events}) == len(events),
            "analyst_stream_contains_labels": config.labeled,
            "exports": exports,
        }
        _write_json(temp_root / "reports/quality.json", quality)
        (temp_root / "reports/summary.md").write_text(
            "# LogFable dataset summary\n\n"
            f"- Scenario: `{scenario.id}` v{scenario.version}\n"
            f"- Events: {len(events)}\n"
            f"- Sources: {len(by_source)}\n"
            f"- Seed: {config.seed}\n"
            "- Synthetic telemetry only.\n\n"
            "---\n"
            "LogFable · © 2026 Taher Amine ELHOUARI · "
            "https://www.taheramine.org · GitHub @MrTaherAmine\n",
            encoding="utf-8",
        )

        knowledge = knowledge_status()
        manifest: dict[str, Any] = {
            "generator": branding_metadata(ENGINE_VERSION),
            "engine_version": ENGINE_VERSION,
            "scenario_id": scenario.id,
            "scenario_version": scenario.version,
            "seed": config.seed,
            "configuration": {
                "duration_seconds": config.duration_seconds,
                "users": config.users,
                "noise": config.noise,
                "preset": config.preset,
                "target_events": config.target_events,
                "labeled": config.labeled,
            },
            "knowledge": {
                "attack": {"version": ATTACK_VERSION, **knowledge["attack"]},
                "d3fend": {"version": D3FEND_VERSION, **knowledge["d3fend"]},
                "ecs": {"version": ECS_VERSION},
                "ocsf": {"version": OCSF_VERSION},
            },
            "environment": environment,
            "event_count": len(events),
            "suspicious_events": len(suspicious),
            "mapping_summary": mapping_summary,
            "reproducibility_scope": (
                "same LogFable release, scenario version, knowledge versions, "
                "configuration, seed, and concurrency mode"
            ),
            "network_access_during_generation": False,
            "ground_truth_summary": {
                "steps": len({item["step"] for item in ground_truth}),
                "events": len(ground_truth),
            },
        }
        _write_json(temp_root / "manifest.json", manifest)
        generate_report(
            temp_root / "reports/report.html",
            scenario,
            events,
            manifest,
            quality,
            student_safe=False,
        )
        write_checksums(temp_root)
        os.replace(temp_root, output)

        made: dict[str, str] = {}
        if instructor_package:
            destination = output.parent / f"{output.name}-instructor.zip"
            _zip_dir(output, destination)
            made["instructor_package"] = str(destination)
        if student_package:
            with tempfile.TemporaryDirectory(
                prefix="logfable-student-",
                dir=output.parent,
            ) as temp_directory:
                student_root = Path(temp_directory) / output.name
                shutil.copytree(output, student_root)
                for relative in ["instructor", "mappings", "scenario"]:
                    shutil.rmtree(student_root / relative, ignore_errors=True)
                student_manifest_raw: object = json.loads(
                    (student_root / "manifest.json").read_text(encoding="utf-8")
                )
                if not isinstance(student_manifest_raw, dict):
                    raise DatasetError("student manifest is not a JSON object")
                student_manifest = cast(dict[str, Any], student_manifest_raw)
                student_manifest.pop("suspicious_events", None)
                student_manifest.pop("ground_truth_summary", None)
                student_manifest.pop("mapping_summary", None)
                _write_json(student_root / "manifest.json", student_manifest)
                generate_report(
                    student_root / "reports/report.html",
                    scenario,
                    events,
                    student_manifest,
                    quality,
                    student_safe=True,
                )
                write_checksums(student_root)
                destination = output.parent / f"{output.name}-student.zip"
                _zip_dir(student_root, destination)
                made["student_package"] = str(destination)
        return {
            "dataset": str(output),
            "events": len(events),
            "sources": len(by_source),
            "exports": exports,
            **made,
        }
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
