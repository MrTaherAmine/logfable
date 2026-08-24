from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AttackMapping(BaseModel):
    technique_id: str
    tactic: str
    detection_strategies: list[str] = Field(default_factory=list)
    analytics: list[str] = Field(default_factory=list)
    data_components: list[str] = Field(default_factory=list)
    rationale: str
    confidence: Literal["low", "medium", "high"] = "high"


class D3FENDMapping(BaseModel):
    d3fend_id: str
    relationship: str = "defensive-opportunity"
    mapping_type: Literal[
        "official-direct",
        "official-inferred",
        "official-crosswalk",
        "project-curated",
        "unmapped",
    ] = "project-curated"
    rationale: str
    confidence: Literal["low", "medium", "high"] = "medium"
    source_url: str
    review_status: Literal["reviewed", "needs-review"] = "reviewed"


class EvidenceSpec(BaseModel):
    source: str
    action: str
    category: str
    severity: int = Field(ge=0, le=10, default=5)
    message: str
    fields: dict[str, Any] = Field(default_factory=dict)


class ScenarioStep(BaseModel):
    id: str
    title: str
    after: list[str] = Field(default_factory=list)
    delay_seconds: tuple[int, int] = (5, 60)
    probability: float = Field(default=1.0, ge=0.0, le=1.0)
    actor: str = "attacker"
    target: str = "primary-user"
    state_changes: dict[str, Any] = Field(default_factory=dict)
    attack: list[AttackMapping] = Field(default_factory=list)
    d3fend: list[D3FENDMapping] = Field(default_factory=list)
    evidence: list[EvidenceSpec] = Field(default_factory=list)
    benign_lookalikes: list[str] = Field(default_factory=list)
    expected_detections: list[str] = Field(default_factory=list)
    instructor_notes: str = ""

    @field_validator("delay_seconds")
    @classmethod
    def valid_delay(cls, value: tuple[int, int]) -> tuple[int, int]:
        if value[0] < 0 or value[1] < value[0]:
            raise ValueError("invalid delay range")
        return value


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    id: str
    version: str
    title: str
    summary: str
    difficulty: Literal["beginner", "intermediate", "advanced"] = "intermediate"
    status: Literal["stable", "experimental"] = "stable"
    authors: list[str]
    license: str = "Apache-2.0"
    tags: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=lambda: ["enterprise"])
    platforms: list[str] = Field(default_factory=list)
    estimated_events: int = 1000
    duration: str = "2h"
    safety: dict[str, Any]
    knowledge: dict[str, str]
    environment: dict[str, Any]
    variables: dict[str, Any] = Field(default_factory=dict)
    noise: dict[str, Any] = Field(default_factory=dict)
    impairments: dict[str, Any] = Field(default_factory=dict)
    steps: list[ScenarioStep]
    telemetry: list[str]
    detections: list[dict[str, Any]] = Field(default_factory=list)
    ground_truth: dict[str, Any] = Field(default_factory=dict)
    questions: list[str]
    scoring: dict[str, Any]
    references: list[str] = Field(default_factory=list)


class Entity(BaseModel):
    id: str
    kind: str
    name: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    source: str
    target: str
    kind: str


class CanonicalEvent(BaseModel):
    event_id: str
    event_type: str
    category: str
    action: str
    outcome: Literal["success", "failure", "unknown"] = "success"
    event_time: datetime
    observed_time: datetime
    timezone: str = "UTC"
    severity: int = Field(ge=0, le=10)
    source_family: str
    source_product: str
    source_version_profile: str = "synthetic-compatibility"
    dataset: str
    host: str | None = None
    device: str | None = None
    container: str | None = None
    pod: str | None = None
    application: str | None = None
    user: str | None = None
    service_account: str | None = None
    workload: str | None = None
    cloud_resource: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    request_id: str | None = None
    transaction_id: str | None = None
    process: dict[str, Any] = Field(default_factory=dict)
    parent_process: dict[str, Any] = Field(default_factory=dict)
    file: dict[str, Any] = Field(default_factory=dict)
    registry: dict[str, Any] = Field(default_factory=dict)
    module: dict[str, Any] = Field(default_factory=dict)
    api: dict[str, Any] = Field(default_factory=dict)
    email: dict[str, Any] = Field(default_factory=dict)
    url: dict[str, Any] = Field(default_factory=dict)
    dns: dict[str, Any] = Field(default_factory=dict)
    authentication: dict[str, Any] = Field(default_factory=dict)
    authorization: dict[str, Any] = Field(default_factory=dict)
    cloud_operation: dict[str, Any] = Field(default_factory=dict)
    message: str
    fields: dict[str, Any] = Field(default_factory=dict)
    extensions: dict[str, Any] = Field(default_factory=dict)
    internal: dict[str, Any] = Field(default_factory=dict)

    def analyst_dict(self, labeled: bool = False) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        internal = data.pop("internal", {})
        if labeled:
            data["labels"] = {
                key: value
                for key, value in internal.items()
                if key in {"scenario_step", "classification", "techniques"}
            }
        return data
