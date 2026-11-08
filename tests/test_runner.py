from dataclasses import replace
from unittest.mock import Mock

import pytest

from rabbitsentry.aws.provider import Collection
from rabbitsentry.models import Policy
from rabbitsentry.modules import REGISTRY
from rabbitsentry.modules.base import ModuleOutput
from rabbitsentry.runner import AssessmentFailed, InvalidConfiguration, run_assessment


class FakeProvider:
    def __init__(self):
        self.session = Mock(region_name="eu-west-1")
        self.session.get_available_regions.return_value = ["eu-west-1", "eu-central-1", "us-east-1"]
        self.history = []
        self.halt_reason = ""
        self.identity = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test"}
        self.denied = False
        self.interrupt_operation = ""

    def collect(self, service, operation, region, **params):
        items = []
        if operation == "get_caller_identity":
            items = [self.identity]
        elif operation == "describe_regions":
            items = [
                {"RegionName": "eu-west-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "eu-central-1", "OptInStatus": "opted-in"},
                {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
            ]
        elif operation == "get_account_summary":
            items = [{"AccountAccessKeysPresent": 0, "AccountPasswordPresent": 0}]
        denied = self.denied and service != "sts"
        if operation == self.interrupt_operation:
            self.halt_reason = "Cancelled"
        reason = self.halt_reason or ("AccessDenied" if denied else "")
        result = Collection(
            service,
            operation,
            region,
            items=[] if reason else items,
            complete=not reason,
            error_code=reason,
        )
        self.history.append(result)
        return result


def test_identity_mismatch_aborts_before_inventory():
    provider = FakeProvider()
    with pytest.raises(AssessmentFailed, match="expected"):
        run_assessment(provider, "eu-west-1", expected_account="999999999999")
    assert [c.operation for c in provider.history] == ["get_caller_identity"]


@pytest.mark.parametrize(
    "regions,modules",
    [
        ("cn-north-1", None),
        ("eu-west-1,eu-west-1", None),
        ("eu-west-1,", None),
        ("all-enabled,eu-west-1", None),
        ("eu-west-1", ["bad"]),
        ("eu-west-1", []),
        ("eu-west-1", ["aws.iam", "aws.iam"]),
    ],
)
def test_invalid_scope_rejected_without_calls(regions, modules):
    provider = FakeProvider()
    with pytest.raises(InvalidConfiguration):
        run_assessment(provider, regions, modules=modules)
    assert not provider.history


def test_unsupported_partition_is_fatal():
    provider = FakeProvider()
    provider.identity["Arn"] = "arn:aws-cn:iam::123456789012:root"
    with pytest.raises(AssessmentFailed, match="partition"):
        run_assessment(provider, "eu-west-1")
    assert len(provider.history) == 1


def test_iam_once_and_explicit_regions_with_disabled_module_coverage():
    provider = FakeProvider()
    report = run_assessment(provider, "eu-west-1,eu-central-1", modules=["aws.iam", "aws.network"])
    assert report.run_status == "complete"
    assert len([c for c in provider.history if c.operation == "get_account_summary"]) == 1
    assert len([c for c in provider.history if c.operation == "describe_security_groups"]) == 2
    assert {c.module_id for c in report.coverage if c.state == "skipped"} == {
        "aws.compute",
        "aws.database",
    }
    assert report.attempted_regions == ["eu-west-1", "eu-central-1"]


def test_all_enabled_requires_bootstrap_and_filters_disabled_regions():
    provider = FakeProvider()
    report = run_assessment(provider, "all-enabled")
    assert report.regions == ["eu-central-1", "eu-west-1"]
    provider = FakeProvider()
    provider.session.region_name = None
    with pytest.raises(InvalidConfiguration, match="configured"):
        run_assessment(provider, "all-enabled")
    assert not provider.history


def test_all_denied_after_bootstrap_still_produces_partial_report():
    provider = FakeProvider()
    provider.denied = True
    report = run_assessment(provider, "eu-west-1")
    assert report.run_status == "partial"
    assert any(c.state == "failed" for c in report.coverage)
    assert all(r.status == "unknown" for r in report.results)


def test_cancellation_and_remaining_scope_are_preserved():
    provider = FakeProvider()
    provider.interrupt_operation = "describe_security_groups"
    report = run_assessment(provider, "eu-west-1,eu-central-1")
    assert report.run_status == "cancelled"
    assert any(r.check_id == "IAM001" and r.status == "pass" for r in report.results)
    assert any(c.region == "eu-central-1" and c.state == "failed" for c in report.coverage)


def test_extension_module_requires_no_runner_or_reporting_changes():
    custom = replace(
        REGISTRY["aws.network"],
        id="example.module",
        checks={},
        operations=(),
        collect=lambda provider, region: [],
        evaluate=lambda *args: ModuleOutput(),
    )
    report = run_assessment(
        FakeProvider(), "eu-west-1", registry={custom.id: custom}, policy=Policy(key_age_days=30)
    )
    assert report.selected_modules == {"example.module": "1.0"}
    assert report.run_status == "complete" and report.policy.key_age_days == 30


def test_interrupt_while_recording_coverage_still_preserves_report(monkeypatch):
    from rabbitsentry import runner

    original = runner.collection_coverage
    interrupted = [False]

    def interrupt_once(collection, module_id):
        if module_id == "aws.iam" and not interrupted[0]:
            interrupted[0] = True
            raise KeyboardInterrupt
        return original(collection, module_id)

    monkeypatch.setattr(runner, "collection_coverage", interrupt_once)
    try:
        report = runner.run_assessment(FakeProvider(), "eu-west-1")
    except KeyboardInterrupt:
        pytest.fail("Cancellation escaped without preserving the resolved assessment")
    assert report.run_status == "cancelled"
    assert report.inventory and report.results
    assert any(c.state == "failed" and c.module_id == "aws.database" for c in report.coverage)
