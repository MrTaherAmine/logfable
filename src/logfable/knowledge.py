from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any, cast

from .constants import ATTACK_VERSION, D3FEND_VERSION


class KnowledgeError(ValueError):
    pass


def _load(name: str) -> dict[str, Any]:
    path = files("logfable").joinpath("data", "knowledge", name)
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise KnowledgeError(f"knowledge file is not a JSON object: {name}")
    return cast(dict[str, Any], raw)


def attack_index() -> dict[str, Any]:
    return _load("attack-index.json")


def d3fend_index() -> dict[str, Any]:
    return _load("d3fend-index.json")


def status() -> dict[str, Any]:
    attack = attack_index()
    d3fend = d3fend_index()
    return {
        "attack": {
            "version": attack["version"],
            "objects": len(attack["objects"]),
            "sha256": digest_json(attack),
        },
        "d3fend": {
            "version": d3fend["version"],
            "objects": len(d3fend["objects"]),
            "sha256": digest_json(d3fend),
        },
    }


def digest_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify() -> dict[str, Any]:
    attack = attack_index()
    d3fend = d3fend_index()
    errors: list[str] = []
    if attack["version"] != ATTACK_VERSION:
        errors.append("attack-version-mismatch")
    if d3fend["version"] != D3FEND_VERSION:
        errors.append("d3fend-version-mismatch")
    if len({obj["id"] for obj in attack["objects"]}) != len(attack["objects"]):
        errors.append("duplicate-attack-id")
    if len({obj["id"] for obj in d3fend["objects"]}) != len(d3fend["objects"]):
        errors.append("duplicate-d3fend-id")
    return {"valid": not errors, "errors": errors, **status()}


def validate_attack(ids: list[str]) -> list[str]:
    known = {
        obj["id"]
        for obj in attack_index()["objects"]
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked")
        and not obj.get("deprecated")
    }
    return sorted(set(ids) - known)


def validate_attack_references(ids: list[str]) -> list[str]:
    known = {
        obj["id"]
        for obj in attack_index()["objects"]
        if obj.get("type") == "detection-reference"
        and not obj.get("revoked")
        and not obj.get("deprecated")
    }
    return sorted(set(ids) - known)


def validate_d3fend(ids: list[str]) -> list[str]:
    known = {obj["id"] for obj in d3fend_index()["objects"]}
    return sorted(set(ids) - known)
