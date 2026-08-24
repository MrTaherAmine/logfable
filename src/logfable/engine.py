from __future__ import annotations

import hashlib
import random
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Any

from .environment import generate_environment
from .models import CanonicalEvent, Entity, Relationship, Scenario, ScenarioStep

SOURCE_PRODUCTS = {
    "windows-security": "Synthetic Windows Security-style",
    "sysmon": "Synthetic Sysmon-style",
    "powershell": "Synthetic PowerShell Operational-style",
    "linux-auth": "Synthetic Linux auth",
    "auditd": "Synthetic auditd-style",
    "edr": "Generic synthetic EDR",
    "active-directory": "Synthetic AD-style",
    "entra": "Synthetic Entra-style",
    "m365": "Synthetic Microsoft 365-style",
    "idp": "Generic synthetic IdP",
    "oauth": "Synthetic OAuth audit",
    "dns": "Synthetic DNS",
    "proxy": "Synthetic secure web gateway",
    "firewall": "Synthetic firewall",
    "vpn": "Synthetic VPN",
    "dhcp": "Synthetic DHCP",
    "netflow": "Synthetic NetFlow-style",
    "zeek": "Zeek-inspired synthetic metadata",
    "cloudtrail": "Synthetic CloudTrail-style",
    "azure-activity": "Synthetic Azure Activity-style",
    "gcp-audit": "Synthetic GCP Audit-style",
    "cloud-control": "Generic cloud control-plane",
    "nginx": "Synthetic NGINX access",
    "apache": "Synthetic Apache access",
    "app-auth": "Synthetic application audit",
    "api-gateway": "Synthetic API gateway",
    "waf": "Synthetic WAF",
    "db-audit": "Synthetic DB audit",
    "object-storage": "Synthetic object storage access",
    "email-trace": "Synthetic message trace",
    "email-filter": "Synthetic email filtering",
    "email-link": "Synthetic email link interaction",
    "kubernetes-audit": "Synthetic Kubernetes audit",
    "container-runtime": "Synthetic container runtime",
    "registry": "Synthetic image registry",
    "git-audit": "Synthetic Git audit",
    "cicd": "Synthetic CI/CD",
    "artifact-registry": "Synthetic artifact registry",
    "mdm": "Generic synthetic MDM audit",
    "dlp": "Generic synthetic DLP audit",
    "ot-firewall": "Synthetic OT segmentation firewall",
    "ot-remote": "Synthetic OT remote gateway",
    "engineering-workstation": "Synthetic engineering workstation",
    "historian": "Synthetic historian auth",
    "ot-passive": "Synthetic passive industrial metadata",
}


class GenerationConfig:
    def __init__(
        self,
        *,
        duration_seconds: int,
        users: int,
        noise: int,
        seed: int,
        preset: str,
        target_events: int | None = None,
        labeled: bool = False,
    ) -> None:
        if not 0 <= noise <= 100:
            raise ValueError("noise must be 0..100")
        if users < 1:
            raise ValueError("users must be positive")
        self.duration_seconds = duration_seconds
        self.users = users
        self.noise = noise
        self.seed = seed
        self.preset = preset
        self.target_events = target_events
        self.labeled = labeled


def parse_duration(value: str) -> int:
    unit = value[-1].lower()
    amount = float(value[:-1])
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if multiplier is None or amount <= 0:
        raise ValueError("duration must look like 30m, 6h, or 1d")
    return int(amount * multiplier)


def _uid(seed: int, label: str) -> str:
    digest = hashlib.md5(f"{seed}:{label}".encode(), usedforsecurity=False).hexdigest()
    return str(uuid.UUID(digest))


def topological_steps(scenario: Scenario) -> list[ScenarioStep]:
    by_id = {step.id: step for step in scenario.steps}
    indegree = {step_id: 0 for step_id in by_id}
    children: dict[str, list[str]] = defaultdict(list)
    for step in scenario.steps:
        for parent in step.after:
            indegree[step.id] += 1
            children[parent].append(step.id)
    queue = deque(sorted(step_id for step_id, count in indegree.items() if count == 0))
    ordered: list[ScenarioStep] = []
    while queue:
        step_id = queue.popleft()
        ordered.append(by_id[step_id])
        for child in sorted(children[step_id]):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    if len(ordered) != len(by_id):
        raise ValueError("scenario graph has cycle")
    return ordered


def generate(
    scenario: Scenario,
    cfg: GenerationConfig,
) -> tuple[list[CanonicalEvent], list[Entity], list[Relationship], dict[str, Any]]:
    entities, relationships, environment = generate_environment(cfg.seed, cfg.users, cfg.preset)
    # Deterministic simulation RNG; never used for credentials, tokens, or cryptographic material.
    rng = random.Random(cfg.seed)  # noqa: S311  # nosec B311
    start = datetime(2026, 3, 2, 8, 0, tzinfo=UTC)
    events: list[CanonicalEvent] = []
    step_times: dict[str, datetime] = {}
    sequence = 0
    primary_user = "user-0001"
    primary_host = "host-0001"

    for step in topological_steps(scenario):
        if rng.random() > step.probability:
            continue
        base = max(
            [step_times[parent] for parent in step.after if parent in step_times],
            default=start,
        )
        delay_min, delay_max = step.delay_seconds
        step_time = base + timedelta(seconds=rng.randint(delay_min, delay_max))
        step_times[step.id] = step_time
        for evidence_index, evidence in enumerate(step.evidence):
            sequence += 1
            event_time = step_time + timedelta(seconds=evidence_index * 2)
            max_delay = int(scenario.impairments.get("max_ingestion_delay_seconds", 20))
            max_skew = int(scenario.impairments.get("max_clock_skew_seconds", 3))
            ingestion_delay = rng.randint(0, max_delay)
            clock_skew = rng.randint(-max_skew, max_skew)
            source_ip = (
                f"198.51.100.{10 + (sequence % 200)}"
                if step.actor == "attacker"
                else f"10.10.{sequence // 250}.{1 + sequence % 250}"
            )
            destination_ip = f"10.20.{sequence // 250}.{10 + sequence % 240}"
            internal = {
                "scenario_step": step.id,
                "classification": "suspicious",
                "techniques": [mapping.technique_id for mapping in step.attack],
            }
            events.append(
                CanonicalEvent(
                    event_id=_uid(cfg.seed, f"step:{step.id}:{evidence_index}"),
                    event_type=evidence.category,
                    category=evidence.category,
                    action=evidence.action,
                    outcome="success",
                    event_time=event_time + timedelta(seconds=clock_skew),
                    observed_time=event_time + timedelta(seconds=ingestion_delay),
                    severity=evidence.severity,
                    source_family=evidence.source,
                    source_product=SOURCE_PRODUCTS.get(
                        evidence.source, f"Synthetic {evidence.source}"
                    ),
                    dataset=scenario.id,
                    host=primary_host,
                    user=primary_user,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    session_id=_uid(cfg.seed, f"session:{step.id}"),
                    correlation_id=_uid(cfg.seed, f"corr:{step.id}"),
                    message=evidence.message,
                    fields=dict(evidence.fields),
                    internal=internal,
                )
            )

    suspicious_count = len(events)
    if cfg.target_events is not None:
        total = max(suspicious_count, cfg.target_events)
    elif cfg.noise == 100:
        total = max(suspicious_count, scenario.estimated_events)
    elif cfg.noise == 0:
        total = suspicious_count
    else:
        total = max(suspicious_count, round(suspicious_count / (1 - cfg.noise / 100)))
    benign_target = max(0, total - suspicious_count)
    sources = scenario.telemetry or ["windows-security"]
    benign_actions = [
        ("authentication", "login", "Routine successful sign-in"),
        ("dns", "query", "Routine DNS lookup"),
        ("network", "connect", "Routine application connection"),
        ("process", "start", "Routine signed application launch"),
        ("email", "delivery", "Routine internal mail delivery"),
        ("cloud", "read", "Routine cloud control-plane read operation"),
        ("admin", "maintenance", "Approved administrative maintenance"),
        ("cicd", "build", "Routine CI/CD build"),
    ]

    for index in range(benign_target):
        sequence += 1
        source = sources[index % len(sources)]
        category, action, message = benign_actions[index % len(benign_actions)]
        benign_lookalike = index % 97 == 0
        if benign_lookalike:
            message = "Benign lookalike: user mistyped a password during routine sign-in"
            action = "login-failure"
            category = "authentication"
        seconds = int((index + 1) * cfg.duration_seconds / max(1, benign_target + 1))
        jitter = rng.randint(-15, 15)
        event_time = start + timedelta(seconds=max(0, seconds + jitter))
        user_number = 1 + (index % cfg.users)
        host_number = 1 + (index % max(8, cfg.users * 7 // 10))
        events.append(
            CanonicalEvent(
                event_id=_uid(cfg.seed, f"benign:{index}"),
                event_type=category,
                category=category,
                action=action,
                outcome="failure" if "failure" in action else "success",
                event_time=event_time + timedelta(seconds=rng.randint(-2, 2)),
                observed_time=event_time + timedelta(seconds=rng.randint(0, 20)),
                severity=3 if "failure" in action else 2,
                source_family=source,
                source_product=SOURCE_PRODUCTS.get(source, f"Synthetic {source}"),
                dataset=scenario.id,
                host=f"host-{host_number:04d}",
                user=f"user-{user_number:04d}",
                source_ip=(
                    f"10.{10 + ((index // 62500) % 20)}.{(index // 250) % 250}.{1 + index % 250}"
                ),
                destination_ip=(
                    f"10.{30 + ((index // 62500) % 20)}."
                    f"{(index // 250) % 250}.{1 + (index * 7) % 250}"
                ),
                session_id=_uid(cfg.seed, f"benign-session:{user_number}:{index // 10}"),
                correlation_id=_uid(cfg.seed, f"benign-corr:{index}"),
                message=message,
                fields={"approved": True},
                internal={
                    "classification": "benign",
                    "benign_lookalike": benign_lookalike,
                },
            )
        )

    missing_rate = float(scenario.impairments.get("missing_event_rate", 0))
    duplicate_rate = float(scenario.impairments.get("duplicate_rate", 0))
    filtered: list[CanonicalEvent] = []
    for event in events:
        drop_hash = (
            int(hashlib.sha256((event.event_id + ":drop").encode()).hexdigest()[:8], 16)
            / 0xFFFFFFFF
        )
        if drop_hash < missing_rate:
            continue
        filtered.append(event)
        duplicate_hash = (
            int(hashlib.sha256((event.event_id + ":dup").encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        )
        if duplicate_hash < duplicate_rate:
            duplicate = event.model_copy(deep=True)
            duplicate.event_id = _uid(cfg.seed, f"dup:{event.event_id}")
            duplicate.extensions["impairment_duplicate_of"] = event.event_id
            filtered.append(duplicate)

    filtered.sort(key=lambda event: (event.observed_time, event.event_id))
    return filtered, entities, relationships, environment
