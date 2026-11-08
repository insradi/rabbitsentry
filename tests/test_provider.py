from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber

from rabbitsentry.aws.provider import AwsProvider


def setup_provider(service="ec2", budget=600, clock=lambda: 0):
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
    client = session.client(service, region_name="eu-west-1")
    factory = Mock(return_value=client)
    provider = AwsProvider(session, client_factory=factory, budget_seconds=budget, clock=clock)
    return provider, client, factory


def test_pagination_cache_and_response_projection():
    provider, client, factory = setup_provider()
    with Stubber(client) as stub:
        stub.add_response(
            "describe_volumes",
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-a",
                        "Encrypted": True,
                        "Tags": [{"Key": "secret", "Value": "do-not-store"}],
                    }
                ],
                "NextToken": "page2",
            },
            {},
        )
        stub.add_response(
            "describe_volumes", {"Volumes": [{"VolumeId": "vol-b"}]}, {"NextToken": "page2"}
        )
        result = provider.collect("ec2", "describe_volumes", "eu-west-1")
        assert result.complete
        assert [x["VolumeId"] for x in result.items] == ["vol-a", "vol-b"]
        assert "secret" not in str(result.items)
        assert provider.collect("ec2", "describe_volumes", "eu-west-1") is result
        stub.assert_no_pending_responses()
    config = factory.call_args.kwargs["config"]
    assert config.retries["total_max_attempts"] == 3
    assert config.connect_timeout == 5 and config.read_timeout == 20


def test_failed_later_page_preserves_evidence_and_sanitizes_error():
    provider, client, _ = setup_provider()
    with Stubber(client) as stub:
        stub.add_response(
            "describe_volumes", {"Volumes": [{"VolumeId": "vol-a"}], "NextToken": "more"}, {}
        )
        stub.add_client_error(
            "describe_volumes", "AccessDenied", "DO-NOT-SAVE", expected_params={"NextToken": "more"}
        )
        result = provider.collect("ec2", "describe_volumes", "eu-west-1")
    assert not result.complete and len(result.items) == 1
    assert result.error_code == "AccessDenied"
    assert "DO-NOT-SAVE" not in str(result)


def test_mutations_rejected_before_client_creation():
    provider, _, factory = setup_provider()
    with pytest.raises(ValueError, match="allowlist"):
        provider.collect("ec2", "delete_volume", "eu-west-1", VolumeId="vol-x")
    factory.assert_not_called()


def test_expired_credentials_prevent_later_calls():
    provider, client, factory = setup_provider()
    with Stubber(client) as stub:
        stub.add_client_error("describe_volumes", "ExpiredToken", "private text")
        assert not provider.collect("ec2", "describe_volumes", "eu-west-1").complete
        later = provider.collect("rds", "describe_db_instances", "eu-west-1")
    assert provider.halt_reason == "CredentialsExpired"
    assert later.error_code == "CredentialsExpired"
    assert factory.call_count == 1


def test_budget_prevents_any_new_request():
    now = [0]
    provider, _, factory = setup_provider(clock=lambda: now[0])
    now[0] = 601
    result = provider.collect("ec2", "describe_volumes", "eu-west-1")
    assert result.error_code == "BudgetExceeded"
    factory.assert_not_called()


def test_cancellation_preserves_pages():
    provider, _, factory = setup_provider()

    def pages(**params):
        yield {"Volumes": [{"VolumeId": "vol-a"}]}
        raise KeyboardInterrupt

    client = Mock()
    client.can_paginate.return_value = True
    client.get_paginator.return_value.paginate = pages
    factory.return_value = client
    result = provider.collect("ec2", "describe_volumes", "eu-west-1")
    assert result.items == [{"VolumeId": "vol-a"}]
    assert provider.halt_reason == "Cancelled"
    assert not result.complete


def test_access_key_identifiers_are_reduced_to_suffix():
    provider, client, _ = setup_provider("iam")
    with Stubber(client) as stub:
        stub.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {"UserName": "alice", "AccessKeyId": "AKIA123456789012ABCD", "Status": "Active"}
                ],
                "IsTruncated": False,
            },
            {"UserName": "alice"},
        )
        result = provider.collect("iam", "list_access_keys", "global", UserName="alice")
    assert result.items == [{"KeySuffix": "ABCD", "Status": "Active"}]
    assert "AKIA" not in str(result)
