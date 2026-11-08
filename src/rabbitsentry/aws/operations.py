"""The entire assessment API allowlist and corresponding response contracts."""

from collections.abc import Callable
from dataclasses import dataclass

from . import projections as p


@dataclass(frozen=True)
class Operation:
    action: str
    envelope: str | None
    project: Callable
    singleton: bool = False

    def extract(self, response):
        if self.envelope is None:
            return [self.project(response)]
        if self.envelope not in response:
            raise ValueError("Missing response envelope")
        data = response[self.envelope]
        if self.action == "ec2:DescribeInstances":
            return [self.project(i) for reservation in data for i in reservation["Instances"]]
        return [self.project(data)] if self.singleton else [self.project(i) for i in data]


OPERATIONS = {
    ("sts", "get_caller_identity"): Operation("sts:GetCallerIdentity", None,
        lambda x: p.pick(x, ["Account", "Arn"]), True),
    ("ec2", "describe_regions"): Operation("ec2:DescribeRegions", "Regions",
        lambda x: p.pick(x, ["RegionName", "OptInStatus"])),
    ("ec2", "describe_instances"): Operation("ec2:DescribeInstances", "Reservations", p.instance),
    ("ec2", "describe_volumes"): Operation("ec2:DescribeVolumes", "Volumes", p.volume),
    ("ec2", "describe_security_groups"): Operation("ec2:DescribeSecurityGroups",
                                                 "SecurityGroups", p.security_group),
    ("rds", "describe_db_instances"): Operation("rds:DescribeDBInstances", "DBInstances", p.database),
    ("rds", "describe_db_clusters"): Operation("rds:DescribeDBClusters", "DBClusters", p.database),
    ("iam", "get_account_summary"): Operation("iam:GetAccountSummary", "SummaryMap",
        lambda x: p.pick(x, ["AccountAccessKeysPresent", "AccountPasswordPresent", "AccountMFAEnabled"]),
        True),
    ("iam", "list_users"): Operation("iam:ListUsers", "Users",
        lambda x: p.pick(x, ["UserName", "UserId", "Arn", "CreateDate"])),
    ("iam", "get_login_profile"): Operation("iam:GetLoginProfile", "LoginProfile",
        lambda x: p.pick(x, ["UserName", "CreateDate"]), True),
    ("iam", "list_mfa_devices"): Operation("iam:ListMFADevices", "MFADevices",
        lambda x: p.pick(x, ["EnableDate"])),
    ("iam", "list_access_keys"): Operation("iam:ListAccessKeys", "AccessKeyMetadata", p.key),
}


def read_policy():
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "RabbitSentryAssessmentReads", "Effect": "Allow",
        "Action": sorted(op.action for op in OPERATIONS.values()), "Resource": "*",
    }]}
