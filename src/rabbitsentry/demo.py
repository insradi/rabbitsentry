"""Synthetic observations evaluated by the same modules as a real assessment."""

from datetime import timedelta

from rabbitsentry.aws.provider import Collection
from rabbitsentry.models import Assessment, utcnow
from rabbitsentry.modules import REGISTRY
from rabbitsentry.runner import collection_coverage


def build_demo():
    now = utcnow()
    account, region = "123456789012", "eu-west-1"
    report = Assessment(
        account_id=account,
        principal=f"arn:aws:iam::{account}:role/SyntheticDemo",
        requested_regions=[region],
        regions=[region],
        attempted_regions=[region],
        demonstration=True,
        selected_modules={key: spec.version for key, spec in REGISTRY.items()},
    )

    def c(service, operation, items, user=None):
        return Collection(
            service,
            operation,
            "global" if service == "iam" else region,
            items=items,
            selector={"UserName": user} if user else {},
            observed_at=now,
        )

    samples = {
        "aws.iam": [
            c(
                "iam",
                "get_account_summary",
                [
                    {
                        "AccountAccessKeysPresent": 1,
                        "AccountPasswordPresent": 1,
                        "AccountMFAEnabled": 0,
                    }
                ],
            ),
            c(
                "iam",
                "list_users",
                [
                    {
                        "UserName": "legacy-deploy",
                        "Arn": f"arn:aws:iam::{account}:user/legacy-deploy",
                    },
                    {"UserName": "operator", "Arn": f"arn:aws:iam::{account}:user/operator"},
                ],
            ),
            c("iam", "get_login_profile", [{"UserName": "legacy-deploy"}], "legacy-deploy"),
            c("iam", "list_mfa_devices", [], "legacy-deploy"),
            c(
                "iam",
                "list_access_keys",
                [
                    {
                        "KeySuffix": "DEMO",
                        "Status": "Active",
                        "CreateDate": now - timedelta(days=180),
                    }
                ],
                "legacy-deploy",
            ),
            c("iam", "get_login_profile", [{"UserName": "operator"}], "operator"),
            c("iam", "list_mfa_devices", [{"EnableDate": now - timedelta(days=60)}], "operator"),
            c("iam", "list_access_keys", [], "operator"),
        ],
        "aws.network": [
            c(
                "ec2",
                "describe_security_groups",
                [
                    {
                        "GroupId": "sg-demo-admin",
                        "GroupName": "legacy-admin",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            },
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 5432,
                                "ToPort": 5432,
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            },
                        ],
                    },
                    {
                        "GroupId": "sg-demo-web",
                        "GroupName": "web",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                    },
                ],
            )
        ],
        "aws.compute": [
            c(
                "ec2",
                "describe_instances",
                [
                    {
                        "InstanceId": "i-demo-web",
                        "InstanceType": "t3.small",
                        "State": {"Name": "running"},
                        "SecurityGroups": [{"GroupId": "sg-demo-web"}],
                    }
                ],
            ),
            c(
                "ec2",
                "describe_volumes",
                [
                    {
                        "VolumeId": "vol-demo-old",
                        "Encrypted": False,
                        "State": "available",
                        "Size": 100,
                        "Attachments": [],
                    },
                    {
                        "VolumeId": "vol-demo-root",
                        "Encrypted": True,
                        "State": "in-use",
                        "Size": 20,
                        "Attachments": [{"InstanceId": "i-demo-web", "State": "attached"}],
                    },
                ],
            ),
        ],
        "aws.database": [
            c(
                "rds",
                "describe_db_instances",
                [
                    {
                        "DBInstanceIdentifier": "demo-orders",
                        "Engine": "postgres",
                        "DBInstanceStatus": "available",
                        "PubliclyAccessible": True,
                        "StorageEncrypted": False,
                        "StorageEncryptionType": "none",
                        "BackupRetentionPeriod": 0,
                        "DeletionProtection": False,
                        "MultiAZ": False,
                    }
                ],
            ),
            c("rds", "describe_db_clusters", []),
        ],
    }
    for module_id, spec in REGISTRY.items():
        observations = samples[module_id]
        output = spec.evaluate(
            observations,
            account,
            "global" if spec.scope == "account" else region,
            report.policy,
            now,
        )
        report.inventory.extend(output.inventory)
        report.results.extend(output.results)
        report.coverage.extend(output.coverage)
        report.coverage.extend(collection_coverage(item, module_id) for item in observations)
    report.finish()
    return report
