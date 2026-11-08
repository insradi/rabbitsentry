from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from rabbitsentry.models import Assessment, CheckResult, Coverage, ResourceRef


def subject(identifier="sg-1"):
    return ResourceRef(
        provider="aws",
        account_id="123456789012",
        region="eu-west-1",
        resource_type="security_group",
        identifier=identifier,
    )


def result(status="pass", resource=None, check_id="NET001"):
    return CheckResult(
        check_id=check_id,
        module_id="aws.network",
        resource=resource or subject(),
        status=status,
        title="Example",
        explanation="Observed",
        next_step="Review",
    )


def assessment():
    return Assessment(
        account_id="123456789012",
        principal="arn:aws:iam::123456789012:root",
        requested_regions=["eu-west-1"],
        regions=["eu-west-1"],
    )


def test_fingerprints_are_stable_and_subject_specific():
    assert result().fingerprint == result().fingerprint
    assert result().fingerprint != result(resource=subject("sg-2")).fingerprint
    assert result().fingerprint != result(check_id="NET002").fingerprint


@pytest.mark.parametrize("change", ["unknown", "failed_collection"])
def test_finish_marks_unknown_or_failed_collection_partial(change):
    report = assessment()
    if change == "unknown":
        report.results.append(result("unknown"))
    else:
        report.coverage.append(
            Coverage(
                module_id="aws.network",
                region="eu-west-1",
                operation="ec2:DescribeSecurityGroups",
                state="failed",
                reason="AccessDenied",
            )
        )
    report.finish()
    assert report.run_status == "partial"
    assert report.finished_at >= report.started_at


def test_findings_do_not_mean_incomplete_and_cancelled_stays_cancelled():
    report = assessment()
    report.results.append(result("fail"))
    report.finish()
    assert report.run_status == "complete"
    report.run_status = "cancelled"
    report.finish()
    assert report.run_status == "cancelled"


def test_import_rejects_incompatible_schema_and_inconsistent_complete_status():
    report = assessment()
    report.finish()
    payload = report.model_dump(mode="json")
    payload["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        Assessment.model_validate(payload)
    payload["schema_version"] = "1.0"
    payload["results"] = [result("unknown").model_dump(mode="json")]
    with pytest.raises(ValidationError):
        Assessment.model_validate(payload)


def test_timezones_are_required_and_json_roundtrips():
    with pytest.raises(ValidationError):
        Assessment(account_id="123456789012", principal="test", started_at=datetime(2026, 11, 8))
    report = assessment()
    report.started_at = datetime(2026, 11, 8, tzinfo=UTC)
    report.finish(datetime(2026, 11, 9, tzinfo=UTC))
    assert Assessment.model_validate_json(report.model_dump_json()) == report
