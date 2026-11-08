"""Small trusted-module contract shared by collectors and pure evaluators."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from rabbitsentry.models import CheckResult, Coverage, InventoryItem, ResourceRef


@dataclass(frozen=True)
class Check:
    title: str
    severity: str
    next_step: str
    reference: str


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    scope: Literal["account", "region"]
    operations: tuple[tuple[str, str], ...]
    checks: dict[str, Check]
    collect: Callable
    evaluate: Callable
    version: str = "1.0"
    model_version: str = "1.0"


@dataclass
class ModuleOutput:
    inventory: list = field(default_factory=list)
    results: list = field(default_factory=list)
    coverage: list = field(default_factory=list)


class Evaluation:
    def __init__(self, module_id, checks, account_id, region):
        self.module_id, self.checks = module_id, checks
        self.account_id, self.region = account_id, region
        self.output = ModuleOutput()

    def subject(self, kind, identifier):
        return ResourceRef(
            account_id=self.account_id,
            region=self.region,
            resource_type=kind,
            identifier=identifier,
        )

    @property
    def scope(self):
        return self.subject("scope", self.account_id if self.region == "global" else self.region)

    def inventory(self, resource, collection, data):
        self.output.inventory.append(
            InventoryItem(resource=resource, observations=[collection.evidence(data)])
        )

    def gap(self, collection, reason):
        self.output.coverage.append(
            Coverage(
                module_id=self.module_id,
                region=self.region,
                operation=collection.action,
                state="partial",
                reason=reason,
                resource_count=len(collection.items),
            )
        )

    def emit(self, check_id, resource, status, explanation, *evidence):
        definition = self.checks[check_id]
        self.output.results.append(
            CheckResult(
                check_id=check_id,
                module_id=self.module_id,
                resource=resource,
                status=status,
                severity=definition.severity,
                title=definition.title,
                explanation=explanation,
                next_step=definition.next_step,
                evidence=list(evidence),
                references=[definition.reference],
            )
        )

    def empty(self, collection, checks):
        if collection.items:
            return False
        status = "not_applicable" if collection.complete else "unknown"
        reason = (
            "No resources returned by the completed collection."
            if collection.complete
            else "Collection is incomplete; absence of resources has not been established."
        )
        for check in checks:
            self.emit(check, self.scope, status, reason, collection.evidence())
        return True


def find(collections, operation, username=None):
    return next(
        c
        for c in collections
        if c.operation == operation and (username is None or c.selector.get("UserName") == username)
    )
