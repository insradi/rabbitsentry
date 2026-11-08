from datetime import UTC, datetime, timedelta

import pytest

from rabbitsentry.aws.provider import Collection
from rabbitsentry.models import Policy
from rabbitsentry.modules import REGISTRY

NOW = datetime(2026, 11, 8, tzinfo=UTC)
ACCOUNT = "123456789012"


def collection(service, operation, items, *, complete=True, error="", user=None):
    return Collection(
        service,
        operation,
        "global" if service == "iam" else "eu-west-1",
        selector={"UserName": user} if user else {},
        items=items,
        complete=complete,
        error_code=error,
        observed_at=NOW,
    )


def evaluate(module, *collections):
    return REGISTRY[module].evaluate(
        list(collections), ACCOUNT, "global" if module == "aws.iam" else "eu-west-1", Policy(), NOW
    )


def statuses(output):
    return {r.check_id: r.status for r in output.results}


@pytest.mark.parametrize(
    "protocol,low,high,cidr,expected",
    [
        ("tcp", 20, 24, "0.0.0.0/0", "fail"),
        ("6", 5432, 5432, "::/0", "fail"),
        ("17", 6379, 6379, "::/0", "fail"),
        ("-1", None, None, "::/0", "fail"),
        ("icmp", -1, -1, "0.0.0.0/0", "pass"),
        ("tcp", 443, 443, "0.0.0.0/0", "pass"),
        ("tcp", 22, 22, "10.0.0.0/8", "pass"),
        ("tcp", None, None, "::/0", "unknown"),
    ],
)
def test_security_group_rules(protocol, low, high, cidr, expected):
    rule = {"IpProtocol": protocol, "FromPort": low, "ToPort": high}
    rule["Ipv6Ranges" if ":" in cidr else "IpRanges"] = [
        {"CidrIpv6" if ":" in cidr else "CidrIp": cidr}
    ]
    result = evaluate(
        "aws.network",
        collection(
            "ec2", "describe_security_groups", [{"GroupId": "sg-1", "IpPermissions": [rule, rule]}]
        ),
    )
    assert len(result.results) == 1
    assert statuses(result) == {"NET001": expected}


def test_missing_security_group_fields_and_empty_partial_collection():
    assert statuses(
        evaluate(
            "aws.network", collection("ec2", "describe_security_groups", [{"GroupId": "sg-x"}])
        )
    ) == {"NET001": "unknown"}
    result = evaluate(
        "aws.network", collection("ec2", "describe_security_groups", [], complete=False)
    )
    assert statuses(result) == {"NET001": "unknown"}
    assert result.results[0].resource.resource_type == "scope"
    assert statuses(evaluate("aws.network", collection("ec2", "describe_security_groups", []))) == {
        "NET001": "not_applicable"
    }


def test_compute_review_and_missing_fields():
    instances = collection("ec2", "describe_instances", [{"InstanceId": "i-a"}])
    volumes = collection(
        "ec2",
        "describe_volumes",
        [{"VolumeId": "vol-a", "Encrypted": False, "State": "available", "Attachments": []}],
        complete=False,
    )
    output = evaluate("aws.compute", instances, volumes)
    assert statuses(output) == {"EBS001": "fail", "EBS002": "review"}
    assert len(output.inventory) == 2
    volumes.items[0] = {"VolumeId": "vol-a", "Encrypted": True, "State": "available"}
    assert statuses(evaluate("aws.compute", instances, volumes)) == {
        "EBS001": "pass",
        "EBS002": "unknown",
    }


def iam_fixture(summary=None, login=True, mfa=None, keys=None, login_error="", later_error=""):
    return [
        collection("iam", "get_account_summary", [summary or {}]),
        collection(
            "iam",
            "list_users",
            [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}],
        ),
        collection(
            "iam",
            "get_login_profile",
            [{"UserName": "alice"}] if login else [],
            user="alice",
            complete=not login_error,
            error=login_error,
        ),
        collection(
            "iam",
            "list_mfa_devices",
            mfa or [],
            user="alice",
            complete=not later_error,
            error=later_error,
        ),
        collection(
            "iam",
            "list_access_keys",
            keys or [],
            user="alice",
            complete=not later_error,
            error=later_error,
        ),
    ]


def test_root_and_console_mfa():
    result = evaluate(
        "aws.iam",
        *iam_fixture(
            {"AccountAccessKeysPresent": 1, "AccountPasswordPresent": 1, "AccountMFAEnabled": 0}
        ),
    )
    assert statuses(result) == {
        "IAM001": "fail",
        "IAM002": "fail",
        "IAM003": "fail",
        "IAM004": "not_applicable",
    }
    assert next(r for r in result.results if r.check_id == "IAM001").severity == "critical"
    result = evaluate("aws.iam", *iam_fixture({"AccountPasswordPresent": 0}))
    assert statuses(result)["IAM001"] == "unknown"
    assert statuses(result)["IAM002"] == "not_applicable"


@pytest.mark.parametrize(
    "later_error,expected",
    [("", "not_applicable"), ("AccessDenied", "unknown"), ("NoSuchEntity", "unknown")],
)
def test_absent_login_requires_later_corroboration(later_error, expected):
    output = evaluate(
        "aws.iam", *iam_fixture(login=False, login_error="NoSuchEntity", later_error=later_error)
    )
    assert statuses(output)["IAM003"] == expected
    if later_error == "NoSuchEntity":
        assert statuses(output)["IAM004"] == "unknown"


def test_old_keys_aggregate_and_partial_cannot_pass():
    fixture = iam_fixture(
        keys=[
            {"KeySuffix": suffix, "Status": "Active", "CreateDate": NOW - timedelta(days=days)}
            for suffix, days in [("ABCD", 150), ("EFGH", 200)]
        ]
    )
    output = evaluate("aws.iam", *fixture)
    results = [r for r in output.results if r.check_id == "IAM004"]
    assert len(results) == 1 and results[0].status == "review"
    assert "age_days" in str(results[0].evidence)
    fixture[-1].complete = False
    assert statuses(evaluate("aws.iam", *fixture))["IAM004"] == "review"
    fixture[-1].items = [{"KeySuffix": "ABCD", "Status": "Active", "CreateDate": NOW}]
    assert statuses(evaluate("aws.iam", *fixture))["IAM004"] == "unknown"


def db_instance(**changes):
    return {
        "DBInstanceIdentifier": "db-a",
        "Engine": "postgres",
        "PubliclyAccessible": False,
        "StorageEncryptionType": "sse-kms",
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 7,
        "DeletionProtection": True,
        "MultiAZ": True,
        **changes,
    }


def db_output(instances, clusters=None):
    return evaluate(
        "aws.database",
        collection("rds", "describe_db_instances", instances),
        collection("rds", "describe_db_clusters", clusters or []),
    )


@pytest.mark.parametrize(
    "encryption,flag,status",
    [
        ("sse-rds", False, "pass"),
        ("sse-kms", True, "pass"),
        ("none", False, "fail"),
        ("none", True, "unknown"),
        ("sse-kms", False, "unknown"),
        ("future", True, "unknown"),
        (None, True, "pass"),
        (None, False, "unknown"),
        (None, None, "unknown"),
    ],
)
def test_database_encryption_semantics(encryption, flag, status):
    data = db_instance(StorageEncryptionType=encryption, StorageEncrypted=flag)
    if encryption is None:
        del data["StorageEncryptionType"]
    assert statuses(db_output([data]))["RDS002"] == status


def test_standalone_database_triggers_and_replica_deferral():
    data = db_instance(
        PubliclyAccessible=True,
        StorageEncryptionType="none",
        StorageEncrypted=False,
        BackupRetentionPeriod=0,
        DeletionProtection=False,
        MultiAZ=False,
    )
    assert statuses(db_output([data])) == {
        "RDS001": "review",
        "RDS002": "fail",
        "RDS003": "fail",
        "RDS004": "review",
        "RDS005": "review",
    }
    data["ReadReplicaSourceDBInstanceIdentifier"] = "source"
    assert statuses(db_output([data]))["RDS003"] == "skipped"
    assert statuses(db_output([data]))["RDS005"] == "skipped"


def cluster(engine="aurora-postgresql", **changes):
    return {
        "DBClusterIdentifier": "cluster-a",
        "Engine": engine,
        "EngineMode": "provisioned",
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 7,
        "DeletionProtection": True,
        "DBClusterInstanceClass": "db.r6g.large",
        "PubliclyAccessible": False,
        **changes,
    }


def test_cluster_ownership_avoids_duplicate_results():
    members = [
        db_instance(
            DBInstanceIdentifier=f"member-{i}",
            DBClusterIdentifier="cluster-a",
            Engine="aurora-postgresql",
        )
        for i in range(2)
    ]
    output = db_output(members, [cluster()])
    assert len(output.inventory) == 3
    assert len(output.results) == 6  # two public-access checks, four cluster checks
    assert len([r for r in output.results if r.check_id == "RDS003"]) == 1
    assert statuses(output)["RDS005"] == "not_applicable"
    members[0]["Engine"] = members[1]["Engine"] = "postgres"
    output = db_output(members, [cluster(engine="postgres")])
    assert len(output.results) == 5
    assert {r.resource.resource_type for r in output.results} == {"rds_cluster"}


@pytest.mark.parametrize(
    "change",
    [
        {"EngineMode": "serverless"},
        {"EngineMode": "express"},
        {"GlobalClusterIdentifier": "global-a"},
        {"ClusterScalabilityType": "limitless"},
        {"Engine": "docdb"},
        {"Engine": "neptune"},
        {"Engine": "custom-oracle-ee"},
    ],
)
def test_known_cluster_exclusions_propagate_to_members(change):
    output = db_output([db_instance(DBClusterIdentifier="cluster-a")], [cluster(**change)])
    assert output.results and all(r.status == "skipped" for r in output.results)


def test_missing_owner_and_unknown_engines_are_unknown():
    for data in [
        db_instance(DBClusterIdentifier="missing"),
        db_instance(Engine="future-db"),
        db_instance(Engine="aurora-mysql"),
    ]:
        assert set(statuses(db_output([data])).values()) == {"unknown"}


def test_aurora_declared_member_missing_from_inventory_is_unknown():
    output = db_output([], [cluster(DBClusterMembers=[{"DBInstanceIdentifier": "db-missing"}])])
    assert statuses(output)["RDS001"] == "unknown"
    assert any(c.state == "partial" for c in output.coverage)


@pytest.mark.parametrize(
    "change",
    [{"ClusterScalabilityType": "future-mode"}, {"EngineMode": "future-mode"}, {"Engine": None}],
)
def test_unknown_cluster_discriminators_are_not_treated_as_supported(change):
    output = db_output([db_instance(DBClusterIdentifier="cluster-a")], [cluster(**change)])
    assert output.results and all(r.status == "unknown" for r in output.results)


def test_explicit_standard_cluster_scalability_is_supported():
    output = db_output(
        [db_instance(DBClusterIdentifier="cluster-a")], [cluster(ClusterScalabilityType="standard")]
    )
    assert not any(r.status == "unknown" for r in output.results)


@pytest.mark.parametrize(
    "membership,expected", [([], "not_applicable"), ([{}], "unknown"), (42, "unknown")]
)
def test_empty_or_invalid_aurora_membership_is_explicit(membership, expected):
    output = db_output([], [cluster(DBClusterMembers=membership)])
    assert statuses(output)["RDS001"] == expected
