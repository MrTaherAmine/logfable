from __future__ import annotations

import random
from collections import Counter
from typing import Any

from .models import Entity, Relationship

PRESETS: dict[str, dict[str, int]] = {
    "small-business": {"hosts_per_100": 65, "servers": 4, "cloud": 2, "k8s": 0, "ot": 0},
    "mid-sized": {"hosts_per_100": 72, "servers": 12, "cloud": 6, "k8s": 1, "ot": 0},
    "hybrid-enterprise": {"hosts_per_100": 78, "servers": 30, "cloud": 14, "k8s": 2, "ot": 0},
    "cloud-native-saas": {"hosts_per_100": 60, "servers": 5, "cloud": 28, "k8s": 4, "ot": 0},
    "university": {"hosts_per_100": 86, "servers": 18, "cloud": 8, "k8s": 1, "ot": 0},
    "segmented-it-ot": {"hosts_per_100": 65, "servers": 16, "cloud": 4, "k8s": 0, "ot": 12},
}
DEPTS = ["Engineering", "Finance", "Sales", "Operations", "Security", "Research"]


def generate_environment(
    seed: int,
    users: int,
    preset: str,
) -> tuple[list[Entity], list[Relationship], dict[str, Any]]:
    if preset not in PRESETS:
        raise ValueError(f"unknown environment preset: {preset}")
    cfg = PRESETS[preset]
    # Deterministic simulation RNG; never used for credentials, tokens, or cryptographic material.
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    entities: list[Entity] = [
        Entity(
            id="org-1",
            kind="organization",
            name="Northstar Example Cooperative",
            attributes={"domain": "northstar.example", "preset": preset},
        )
    ]
    relationships: list[Relationship] = []
    for department in DEPTS:
        entities.append(Entity(id=f"dept-{department}", kind="department", name=department))
        relationships.append(
            Relationship(source="org-1", target=f"dept-{department}", kind="contains")
        )

    for index in range(users):
        department = DEPTS[index % len(DEPTS)]
        user_id = f"user-{index + 1:04d}"
        entities.append(
            Entity(
                id=user_id,
                kind="human-identity",
                name=f"Alex{index + 1:04d} Example",
                attributes={
                    "username": f"alex{index + 1:04d}",
                    "email": f"alex{index + 1:04d}@northstar.example",
                    "department": department,
                    "privileged": index < max(2, users // 100),
                },
            )
        )
        relationships.append(
            Relationship(source=f"dept-{department}", target=user_id, kind="has-member")
        )

    for role in ["admins", "developers", "security-operators", "break-glass"]:
        role_id = f"group-{role}"
        entities.append(Entity(id=role_id, kind="group", name=role.replace("-", " ").title()))
        relationships.append(Relationship(source="org-1", target=role_id, kind="owns"))

    for index in range(max(3, users // 50)):
        service_id = f"svc-{index + 1:03d}"
        entities.append(
            Entity(
                id=service_id,
                kind="service-identity",
                name=f"svc-app-{index + 1:03d}",
                attributes={"interactive": False},
            )
        )
        relationships.append(Relationship(source="org-1", target=service_id, kind="owns"))

    host_count = max(8, users * cfg["hosts_per_100"] // 100)
    for index in range(host_count):
        host_id = f"host-{index + 1:04d}"
        os_name = ["Windows", "Linux", "macOS"][index % 3]
        entities.append(
            Entity(
                id=host_id,
                kind="endpoint",
                name=f"ws-{index + 1:04d}.northstar.example",
                attributes={
                    "os": os_name,
                    "ip": (
                        f"10.{10 + (index // 60000) % 20}."
                        f"{(index // 250) % 250}.{1 + (index % 250)}"
                    ),
                },
            )
        )
        relationships.append(Relationship(source="org-1", target=host_id, kind="owns"))
        if index < users:
            relationships.append(
                Relationship(
                    source=f"user-{index + 1:04d}",
                    target=host_id,
                    kind="primary-device",
                )
            )

    for index in range(cfg["servers"]):
        server_id = f"server-{index + 1:03d}"
        entities.append(
            Entity(
                id=server_id,
                kind="server",
                name=f"srv-{index + 1:03d}.northstar.example",
                attributes={
                    "ip": f"10.20.{index // 250}.{1 + index % 250}",
                    "os": "Linux" if index % 2 else "Windows Server",
                },
            )
        )
        relationships.append(Relationship(source="org-1", target=server_id, kind="owns"))

    for index in range(cfg["cloud"]):
        cloud_id = f"cloud-{index + 1:03d}"
        entities.append(
            Entity(
                id=cloud_id,
                kind="cloud-resource",
                name=f"resource-{index + 1:03d}",
                attributes={
                    "provider": ["aws", "azure", "gcp"][index % 3],
                    "region": "example-region-1",
                },
            )
        )
        relationships.append(Relationship(source="org-1", target=cloud_id, kind="owns"))

    for index in range(cfg["k8s"]):
        cluster_id = f"k8s-{index + 1:02d}"
        entities.append(
            Entity(
                id=cluster_id,
                kind="kubernetes-cluster",
                name=f"cluster-{index + 1}.northstar.example",
            )
        )
        relationships.append(Relationship(source="org-1", target=cluster_id, kind="owns"))
        for pod_index in range(3):
            pod_id = f"pod-{index + 1:02d}-{pod_index + 1:02d}"
            entities.append(
                Entity(
                    id=pod_id,
                    kind="pod",
                    name=f"app-{pod_index + 1}-{rng.randrange(1000, 9999)}",
                    attributes={"namespace": "prod" if pod_index < 2 else "dev"},
                )
            )
            relationships.append(Relationship(source=cluster_id, target=pod_id, kind="schedules"))

    if cfg["ot"]:
        zones = ["enterprise", "dmz", "operations", "cell-area"]
        for zone in zones:
            entities.append(Entity(id=f"zone-{zone}", kind="network-zone", name=zone.title()))
        for index in range(cfg["ot"]):
            kind = ["engineering-workstation", "historian", "hmi", "controller"][index % 4]
            asset_id = f"ot-{index + 1:03d}"
            entities.append(
                Entity(
                    id=asset_id,
                    kind=kind,
                    name=f"{kind}-{index + 1:02d}",
                    attributes={"ip": f"192.168.50.{10 + index}", "passive_only": True},
                )
            )
            relationships.append(
                Relationship(
                    source=f"zone-{zones[2 + (index % 2)]}",
                    target=asset_id,
                    kind="contains",
                )
            )

    summary: dict[str, Any] = {
        "organization": "Northstar Example Cooperative",
        "preset": preset,
        "users": users,
        "entities": len(entities),
        "relationships": len(relationships),
        "entity_kinds": dict(sorted(Counter(entity.kind for entity in entities).items())),
        "relationship_kinds": dict(
            sorted(Counter(relationship.kind for relationship in relationships).items())
        ),
    }
    return entities, relationships, summary
