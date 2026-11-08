import json
from pathlib import Path

import boto3
from botocore.stub import Stubber

from rabbitsentry.aws.operations import OPERATIONS, read_policy
from rabbitsentry.aws.provider import AwsProvider
from rabbitsentry.modules import REGISTRY
from rabbitsentry.runner import run_assessment


def test_policy_allowlist_and_module_declarations_agree():
    policy = json.loads(Path("permissions/aws-readonly.json").read_text())
    assert policy == read_policy()
    declared = {operation for module in REGISTRY.values() for operation in module.operations}
    bootstrap = {("sts", "get_caller_identity"), ("ec2", "describe_regions")}
    assert declared | bootstrap == set(OPERATIONS)
    assert len({check for module in REGISTRY.values() for check in module.checks}) == 12


def test_real_provider_two_regions_and_corroborated_login_absence():
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
    clients = {
        (service, region): session.client(service, region_name=region)
        for service, region in [
            ("sts", "eu-west-1"),
            ("iam", "us-east-1"),
            ("ec2", "eu-west-1"),
            ("ec2", "eu-central-1"),
        ]
    }
    provider = AwsProvider(
        session, client_factory=lambda service, region_name, config: clients[(service, region_name)]
    )
    stubs = {key: Stubber(client) for key, client in clients.items()}
    stubs[("sts", "eu-west-1")].add_response(
        "get_caller_identity",
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
            "UserId": "testing",
        },
    )
    iam = stubs[("iam", "us-east-1")]
    iam.add_response(
        "get_account_summary",
        {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountPasswordPresent": 0}},
    )
    from datetime import UTC, datetime

    iam.add_response(
        "list_users",
        {
            "Users": [
                {
                    "UserName": "alice",
                    "UserId": "AIDA12345678901234567",
                    "Path": "/",
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "CreateDate": datetime(2026, 1, 1, tzinfo=UTC),
                }
            ],
            "IsTruncated": False,
        },
    )
    iam.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": "alice"})
    iam.add_response(
        "list_mfa_devices", {"MFADevices": [], "IsTruncated": False}, {"UserName": "alice"}
    )
    iam.add_response(
        "list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False}, {"UserName": "alice"}
    )
    for region in ("eu-west-1", "eu-central-1"):
        stubs[("ec2", region)].add_response("describe_security_groups", {"SecurityGroups": []})
    for stub in stubs.values():
        stub.activate()
    try:
        report = run_assessment(
            provider, "eu-west-1,eu-central-1", modules=["aws.iam", "aws.network"]
        )
        assert report.run_status == "complete"
        assert next(r for r in report.results if r.check_id == "IAM003").status == "not_applicable"
        assert len([c for c in report.coverage if c.operation == "ec2:DescribeSecurityGroups"]) == 2
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    finally:
        for stub in stubs.values():
            stub.deactivate()
