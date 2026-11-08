"""Bounded read operations, pagination and partial observations."""

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from rabbitsentry.models import Evidence, utcnow

from .operations import OPERATIONS

CONFIG = Config(
    connect_timeout=5,
    read_timeout=20,
    retries={"mode": "standard", "total_max_attempts": 3},
    user_agent_extra="RabbitSentry/0.1.0",
)
EXPIRED = {
    "ExpiredToken",
    "ExpiredTokenException",
    "RequestExpired",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "TokenRefreshRequired",
}


@dataclass
class Collection:
    service: str
    operation: str
    region: str
    selector: dict = field(default_factory=dict)
    observed_at: datetime = field(default_factory=utcnow)
    items: list[dict] = field(default_factory=list)
    complete: bool = True
    error_code: str = ""
    absence_confirmed: bool = False

    @property
    def action(self):
        return OPERATIONS[(self.service, self.operation)].action

    def evidence(self, data=None):
        return Evidence(
            collector="aws.native",
            operation=self.action,
            observed_at=self.observed_at,
            complete=self.complete,
            data=data if data is not None else {"items": self.items, "error_code": self.error_code},
        )


class AwsProvider:
    def __init__(self, session, *, client_factory=None, budget_seconds=600, clock=time.monotonic):
        self.session = session
        self.client_factory = client_factory or session.client
        self.clock = clock
        self.deadline = clock() + budget_seconds
        self.history: list[Collection] = []
        self.halt_reason = ""
        self._cache = {}
        self._clients = {}

    def _halted(self):
        if not self.halt_reason and self.clock() >= self.deadline:
            self.halt_reason = "BudgetExceeded"
        return bool(self.halt_reason)

    def collect(self, service, operation, region, **params) -> Collection:
        if (service, operation) not in OPERATIONS:
            raise ValueError("Operation is outside the assessment read allowlist")
        cache_key = (service, operation, region, json.dumps(params, sort_keys=True))
        if cache_key in self._cache:
            return self._cache[cache_key]
        result = Collection(
            service,
            operation,
            region,
            selector={k: v for k, v in params.items() if k == "UserName"},
        )
        self.history.append(result)
        self._cache[cache_key] = result
        try:
            if self._halted():
                result.complete, result.error_code = False, self.halt_reason
                return result
            client_key = (service, region)
            if client_key not in self._clients:
                self._clients[client_key] = self.client_factory(
                    service,
                    region_name="us-east-1" if region == "global" else region,
                    config=CONFIG,
                )
            client = self._clients[client_key]
            if client.can_paginate(operation):
                pages = iter(client.get_paginator(operation).paginate(**params))
            else:
                # A generator defers the request until after the budget check.
                def single_page():
                    yield getattr(client, operation)(**params)

                pages = single_page()
            while True:
                if self._halted():
                    result.complete, result.error_code = False, self.halt_reason
                    break
                try:
                    page = next(pages)
                except StopIteration:
                    break
                result.items.extend(OPERATIONS[(service, operation)].extract(page))
        except KeyboardInterrupt:
            self.halt_reason = "Cancelled"
            result.complete, result.error_code = False, "Cancelled"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ServiceError")
            result.error_code = (
                code if re.fullmatch(r"[A-Za-z][A-Za-z0-9.]{0,63}", code) else "ServiceError"
            )
            result.complete = False
            if code in EXPIRED:
                self.halt_reason = "CredentialsExpired"
        except BotoCoreError as exc:
            result.complete, result.error_code = False, type(exc).__name__
            if type(exc).__name__ in {
                "NoCredentialsError",
                "CredentialRetrievalError",
                "TokenRetrievalError",
                "UnauthorizedSSOTokenError",
            }:
                self.halt_reason = "CredentialsExpired"
        except (ValueError, TypeError, KeyError):
            result.complete, result.error_code = False, "MalformedResponse"
        return result
