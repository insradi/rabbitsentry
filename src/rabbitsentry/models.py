"""Versioned provider-neutral contracts. No SDK or reporting dependencies."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from rabbitsentry import __version__

Status = Literal["pass", "fail", "review", "unknown", "not_applicable", "skipped"]
Severity = Literal["critical", "high", "medium", "low", "informational"]


def utcnow() -> datetime:
    return datetime.now(UTC)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResourceRef(Contract):
    provider: str = "aws"
    account_id: str
    region: str = "global"
    resource_type: str
    identifier: str


class Evidence(Contract):
    collector: str
    operation: str
    observed_at: AwareDatetime = Field(default_factory=utcnow)
    complete: bool = True
    data: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("data", mode="before")
    @classmethod
    def canonical_json(cls, value):
        def encode(item):
            if isinstance(item, datetime) and item.tzinfo is not None:
                return item.astimezone(UTC).isoformat()
            raise ValueError("Evidence must contain JSON values or timezone-aware timestamps")

        return json.loads(json.dumps(value, default=encode, allow_nan=False))


class InventoryItem(Contract):
    resource: ResourceRef
    observations: list[Evidence] = Field(default_factory=list)


class CheckResult(Contract):
    check_id: str
    check_version: str = "1.0"
    module_id: str
    resource: ResourceRef
    status: Status
    severity: Severity = "informational"
    title: str
    explanation: str
    next_step: str
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    fingerprint: str = ""

    @model_validator(mode="after")
    def derive_fingerprint(self):
        subject = self.resource.model_dump()
        subject["check_id"] = self.check_id
        digest = hashlib.sha256(json.dumps(subject, sort_keys=True).encode()).hexdigest()
        if self.fingerprint and self.fingerprint != digest:
            raise ValueError("Result fingerprint does not match its subject and check")
        self.fingerprint = digest
        return self


class Coverage(Contract):
    module_id: str
    region: str
    operation: str
    state: Literal["complete", "partial", "failed", "skipped"]
    resource_count: int = Field(default=0, ge=0)
    reason: str = ""
    subject: str = ""


class Policy(Contract):
    key_age_days: int = Field(default=90, gt=0, strict=True)


class Assessment(Contract):
    schema_version: str = "1.0"
    tool_version: str = __version__
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    run_status: Literal["complete", "partial", "cancelled"] = "partial"
    started_at: AwareDatetime = Field(default_factory=utcnow)
    finished_at: AwareDatetime | None = None
    account_id: str
    principal: str
    requested_regions: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    attempted_regions: list[str] = Field(default_factory=list)
    selected_modules: dict[str, str] = Field(default_factory=dict)
    policy: Policy = Field(default_factory=Policy)
    inventory: list[InventoryItem] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    results: list[CheckResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    demonstration: bool = False
    unassessed: list[str] = Field(
        default_factory=lambda: [
            "EC2 backup coverage, backup freshness, external backups and restore tests",
            "Server operating systems, application vulnerabilities and runtime compromise",
            "Billing, unselected regions and services outside the selected module catalogue",
            "End-to-end network reachability and organisation-wide account coverage",
        ]
    )

    @field_validator("schema_version")
    @classmethod
    def supported_schema(cls, value):
        if value != "1.0":
            raise ValueError("Unsupported report schema; this version supports 1.0")
        return value

    @field_validator("started_at", "finished_at")
    @classmethod
    def normalize_time(cls, value):
        return value.astimezone(UTC) if value is not None else None

    def has_gaps(self) -> bool:
        return (
            any(c.state in {"partial", "failed"} for c in self.coverage)
            or any(r.status == "unknown" for r in self.results)
            or bool(self.errors)
        )

    @model_validator(mode="after")
    def consistent_status(self):
        if self.run_status == "complete" and self.has_gaps():
            raise ValueError("A complete report cannot contain incomplete coverage or unknowns")
        if self.finished_at and self.finished_at < self.started_at:
            raise ValueError("Finish time precedes start time")
        return self

    def finish(self, when: datetime | None = None) -> None:
        when = when or utcnow()
        if when.tzinfo is None:
            raise ValueError("Finish time must include a timezone")
        self.finished_at = when.astimezone(UTC)
        if self.run_status != "cancelled":
            self.run_status = "partial" if self.has_gaps() else "complete"
        self.consistent_status()
