from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .constants import ATTACK_VERSION, D3FEND_VERSION
from .models import Scenario


def build_attack(scenario: Scenario) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for step in scenario.steps:
        for mapping in step.attack:
            rows.append(
                {
                    "attack_version": ATTACK_VERSION,
                    "technique_id": mapping.technique_id,
                    "tactic": mapping.tactic,
                    "scenario_step": step.id,
                    "mapping_rationale": mapping.rationale,
                    "evidence_sources": sorted({evidence.source for evidence in step.evidence}),
                    "detection_strategies": mapping.detection_strategies,
                    "analytics": mapping.analytics,
                    "data_components": mapping.data_components,
                    "confidence": mapping.confidence,
                    "provenance": "scenario-author-reviewed",
                    "review_status": "reviewed",
                }
            )
    return rows


def build_d3fend(scenario: Scenario) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for step in scenario.steps:
        for mapping in step.d3fend:
            rows.append(
                {
                    "attack_id": step.attack[0].technique_id if step.attack else None,
                    "attack_version": ATTACK_VERSION,
                    "d3fend_id": mapping.d3fend_id,
                    "d3fend_version": D3FEND_VERSION,
                    "relationship": mapping.relationship,
                    "relationship_source": "LogFable project mapping",
                    "mapping_type": mapping.mapping_type,
                    "evidence": sorted({evidence.source for evidence in step.evidence}),
                    "rationale": mapping.rationale,
                    "confidence": mapping.confidence,
                    "source_url": mapping.source_url,
                    "review_status": mapping.review_status,
                    "reviewer": "LogFable maintainers",
                    "scenario_step": step.id,
                }
            )
    return rows


def write_mappings(scenario: Scenario, root: Path) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    attack_rows = build_attack(scenario)
    d3fend_rows = build_d3fend(scenario)
    (root / "attack.json").write_text(
        json.dumps(attack_rows, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (root / "d3fend.json").write_text(
        json.dumps(d3fend_rows, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    techniques = sorted({str(row["technique_id"]) for row in attack_rows})
    layer: dict[str, Any] = {
        "name": f"LogFable {scenario.id} coverage",
        "versions": {"attack": ATTACK_VERSION, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "mitre-attack" if "ics" not in scenario.domains else "mitre-ics-attack",
        "techniques": [
            {
                "techniqueID": technique,
                "score": 1,
                "comment": "Expected observable evidence; not proof of detection.",
            }
            for technique in techniques
        ],
    }
    (root / "attack-navigator-layer.json").write_text(
        json.dumps(layer, indent=2),
        encoding="utf-8",
    )
    with (root / "attack-d3fend-crosswalk.csv").open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "scenario_step",
                "attack_id",
                "d3fend_id",
                "mapping_type",
                "confidence",
            ],
        )
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in writer.fieldnames} for row in d3fend_rows)
    return {
        "attack_records": len(attack_rows),
        "d3fend_records": len(d3fend_rows),
        "techniques": len(techniques),
    }
