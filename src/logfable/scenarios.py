from __future__ import annotations

from collections import defaultdict, deque
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

import yaml

from .constants import (
    ATTACK_VERSION,
    D3FEND_VERSION,
    SCENARIO_SCHEMA_VERSION,
    SOURCE_FAMILIES,
    SUPPORTED_FORMATS,
)
from .knowledge import validate_attack, validate_attack_references, validate_d3fend
from .models import Scenario
from .safety import unsafe_indicators


class ScenarioValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def builtins() -> dict[str, Path]:
    base = files("logfable").joinpath("data", "scenarios")
    result: dict[str, Path] = {}
    for resource in base.iterdir():
        if resource.name.endswith((".yaml", ".yml")):
            stem = resource.name.rsplit(".", 1)[0]
            result[stem] = Path(str(resource))
    return result


def load_scenario(value: str | Path) -> Scenario:
    path = Path(value)
    if not path.exists():
        mapping = builtins()
        if str(value) not in mapping:
            raise FileNotFoundError(f"unknown scenario: {value}")
        path = mapping[str(value)]
    text = path.read_text(encoding="utf-8")
    raw: object = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ScenarioValidationError(["scenario-root-must-be-mapping"])
    scenario = Scenario.model_validate(cast(dict[str, Any], raw))
    errors = semantic_errors(scenario, raw_text=text)
    if errors:
        raise ScenarioValidationError(errors)
    return scenario


def semantic_errors(scenario: Scenario, raw_text: str = "") -> list[str]:
    errors: list[str] = []
    if scenario.schema_version != SCENARIO_SCHEMA_VERSION:
        errors.append(f"unsupported-schema-version:{scenario.schema_version}")
    if scenario.knowledge.get("attack_version") != ATTACK_VERSION:
        errors.append("attack-version-mismatch")
    if scenario.knowledge.get("d3fend_version") != D3FEND_VERSION:
        errors.append("d3fend-version-mismatch")

    step_ids = [step.id for step in scenario.steps]
    if len(step_ids) != len(set(step_ids)):
        errors.append("duplicate-step-id")
    all_ids = set(step_ids)
    for step in scenario.steps:
        for parent in step.after:
            if parent not in all_ids:
                errors.append(f"broken-step-reference:{step.id}->{parent}")
        for evidence in step.evidence:
            if evidence.source not in SOURCE_FAMILIES:
                errors.append(f"unknown-source:{evidence.source}")

    children: dict[str, list[str]] = defaultdict(list)
    indegree = {step_id: 0 for step_id in step_ids}
    for step in scenario.steps:
        for parent in step.after:
            if parent in indegree:
                children[parent].append(step.id)
                indegree[step.id] += 1
    queue = deque(step_id for step_id, count in indegree.items() if count == 0)
    seen = 0
    while queue:
        step_id = queue.popleft()
        seen += 1
        for child in children[step_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    if seen != len(step_ids):
        errors.append("cycle-detected")

    attack_ids = [mapping.technique_id for step in scenario.steps for mapping in step.attack]
    attack_references = [
        reference
        for step in scenario.steps
        for mapping in step.attack
        for reference in (
            mapping.detection_strategies + mapping.analytics + mapping.data_components
        )
    ]
    d3fend_ids = [
        mapping.d3fend_id
        for step in scenario.steps
        for mapping in step.d3fend
        if mapping.d3fend_id != "unmapped"
    ]
    errors += [f"invalid-attack-id:{item}" for item in validate_attack(attack_ids)]
    errors += [
        f"invalid-attack-reference:{item}" for item in validate_attack_references(attack_references)
    ]
    errors += [f"invalid-d3fend-id:{item}" for item in validate_d3fend(d3fend_ids)]

    if not scenario.authors or not scenario.license:
        errors.append("missing-attribution")
    if scenario.safety.get("synthetic_only") is not True:
        errors.append("unsafe-scenario:safety.synthetic_only must be true")
    errors += unsafe_indicators(raw_text)
    required_formats = scenario.variables.get("required_formats", [])
    if isinstance(required_formats, list):
        errors += [
            f"unsupported-format:{item}"
            for item in required_formats
            if item not in SUPPORTED_FORMATS
        ]
    return sorted(set(errors))


def validate_path(path: Path) -> dict[str, Any]:
    paths = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    results: list[dict[str, Any]] = []
    for candidate in paths:
        try:
            scenario = load_scenario(candidate)
            results.append({"path": str(candidate), "id": scenario.id, "valid": True, "errors": []})
        except Exception as exc:
            errors = exc.errors if isinstance(exc, ScenarioValidationError) else [str(exc)]
            results.append({"path": str(candidate), "valid": False, "errors": errors})
    return {"valid": all(bool(result["valid"]) for result in results), "results": results}


def scaffold(name: str, output: Path) -> Path:
    clean = "".join(
        character if character.isalnum() or character in "-_" else "-" for character in name.lower()
    ).strip("-")
    if not clean:
        raise ValueError("scenario name becomes empty")
    payload: dict[str, Any] = {
        "schema_version": SCENARIO_SCHEMA_VERSION,
        "id": clean,
        "version": "0.1.0",
        "title": name,
        "summary": "Describe the defensive training story.",
        "difficulty": "intermediate",
        "status": "experimental",
        "authors": ["YOUR NAME"],
        "license": "Apache-2.0",
        "tags": ["community"],
        "domains": ["enterprise"],
        "platforms": ["Windows"],
        "estimated_events": 200,
        "duration": "1h",
        "safety": {"synthetic_only": True, "no_execution": True},
        "knowledge": {
            "attack_version": ATTACK_VERSION,
            "d3fend_version": D3FEND_VERSION,
        },
        "environment": {"preset": "small-business"},
        "variables": {},
        "noise": {"percentage": 95},
        "impairments": {"max_clock_skew_seconds": 3},
        "steps": [],
        "telemetry": ["windows-security"],
        "detections": [],
        "ground_truth": {},
        "questions": ["What happened?"],
        "scoring": {"max_points": 10},
        "references": [],
    }
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"{clean}.yaml"
    if destination.exists():
        raise FileExistsError(destination)
    destination.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return destination
