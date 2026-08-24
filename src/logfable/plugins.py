from __future__ import annotations

from importlib import metadata
from typing import Any

API_VERSION = "1"


def list_plugins() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for entry_point in metadata.entry_points(group="logfable.plugins"):
        found.append(
            {
                "name": entry_point.name,
                "value": entry_point.value,
                "distribution": getattr(entry_point.dist, "name", None),
                "api_version": API_VERSION,
            }
        )
    return sorted(found, key=lambda item: str(item["name"]))
