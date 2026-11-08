"""RDS topology-aware checks on projected observations only."""

from .base import Check, Evaluation, ModuleSpec, find

REFERENCE = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html"
CHECKS = {
    "RDS001": Check(
        "Database public accessibility",
        "medium",
        "Confirm whether public accessibility is required; review security groups and routing separately.",
        REFERENCE,
    ),
    "RDS002": Check(
        "Database encryption at rest",
        "high",
        "Confirm the encryption setting and plan a supported encrypted migration if needed.",
        REFERENCE,
    ),
    "RDS003": Check(
        "Configured automated backups",
        "high",
        "Set retention to match recovery objectives and separately verify recent backups and restoration.",
        REFERENCE,
    ),
    "RDS004": Check(
        "Database deletion protection",
        "medium",
        "Enable deletion protection where appropriate after reviewing deployment and recovery procedures.",
        REFERENCE,
    ),
    "RDS005": Check(
        "Standalone database availability",
        "low",
        "Review recovery objectives and whether Multi-AZ is warranted for this primary database.",
        REFERENCE,
    ),
}
STANDARD = {
    "mysql",
    "mariadb",
    "postgres",
    "oracle-ee",
    "oracle-se2",
    "oracle-ee-cdb",
    "oracle-se2-cdb",
    "sqlserver-ee",
    "sqlserver-se",
    "sqlserver-ex",
    "sqlserver-web",
    "db2-ae",
    "db2-se",
}
AURORA = {"aurora", "aurora-mysql", "aurora-postgresql"}


def collect(provider, region):
    return [
        provider.collect("rds", operation, region)
        for operation in ("describe_db_instances", "describe_db_clusters")
    ]


def topology(data, is_cluster=False):
    engine = data.get("Engine", "")
    if not isinstance(engine, str):
        return "unknown", "The database engine field is missing or invalid."
    if (
        engine.startswith("custom-")
        or engine in {"docdb", "neptune"}
        or data.get("RdsCustomClusterConfiguration")
    ):
        return "excluded", "This engine is outside the initial catalogue."
    if data.get("GlobalClusterIdentifier"):
        return "excluded", "Aurora global database topology is outside this assessment."
    if (
        data.get("EngineMode") in {"serverless", "express"}
        or data.get("LimitlessDatabase") is not None
        or data.get("ClusterScalabilityType") == "limitless"
        or "VPCNetworkingEnabled" in data
        or "InternetAccessGatewayEnabled" in data
    ):
        return (
            "excluded",
            "Serverless v1, Express and Limitless topologies are outside the initial catalogue.",
        )
    if ("ClusterScalabilityType" in data and data["ClusterScalabilityType"] != "standard") or (
        "EngineMode" in data and data["EngineMode"] != "provisioned"
    ):
        return "unknown", "An unfamiliar database topology discriminator was returned."
    if is_cluster:
        if engine in AURORA and data.get("EngineMode") == "provisioned":
            return "aurora", "Regional Aurora cluster"
        if engine in {"mysql", "postgres"} and data.get("DBClusterInstanceClass"):
            return "multiaz", "Multi-AZ DB cluster"
    elif engine in STANDARD:
        return "standalone", "Standalone RDS instance"
    return (
        "unknown",
        "The engine or topology is unsupported or missing required identification fields.",
    )


def encryption_status(data):
    kind, flag = data.get("StorageEncryptionType"), data.get("StorageEncrypted")
    if "StorageEncryptionType" in data:
        if kind not in {"none", "sse-kms", "sse-rds"}:
            return "unknown"
        if (kind == "none" and flag is True) or (kind == "sse-kms" and flag is False):
            return "unknown"
        if flag is not None and type(flag) is not bool:
            return "unknown"
        return "fail" if kind == "none" else "pass"
    return "pass" if flag is True else "unknown"


def assess_field(ctx, check, resource, data, source):
    if check == "RDS002":
        status = encryption_status(data)
        reason = {
            "pass": "Storage encryption at rest is reported, including AWS-owned keys where applicable.",
            "fail": "StorageEncryptionType reports no encryption at rest.",
            "unknown": "Encryption fields are missing, unfamiliar or contradictory; a false legacy flag alone is not sufficient.",
        }[status]
    elif check == "RDS003":
        value = data.get("BackupRetentionPeriod")
        status = (
            "unknown" if type(value) is not int or value < 0 else "fail" if value == 0 else "pass"
        )
        reason = {
            "fail": "Automated backups are disabled by zero retention. This does not establish whether external backups exist.",
            "pass": "Automated backup retention is configured. Backup freshness and restore tests were not assessed.",
            "unknown": "Automated backup retention is missing or invalid.",
        }[status]
    else:
        field, trigger = {
            "RDS001": ("PubliclyAccessible", True),
            "RDS004": ("DeletionProtection", False),
            "RDS005": ("MultiAZ", False),
        }[check]
        value = data.get(field)
        status = "unknown" if type(value) is not bool else "review" if value == trigger else "pass"
        positive = {
            "RDS001": "Public accessibility is enabled; actual reachability depends on other network controls.",
            "RDS004": "Deletion protection is disabled.",
            "RDS005": "This standalone primary does not have Multi-AZ enabled.",
        }[check]
        reason = (
            positive
            if status == "review"
            else f"{field} is missing or invalid."
            if status == "unknown"
            else f"The {field} review condition is absent."
        )
    ctx.emit(check, resource, status, reason, source.evidence(data))


def verify_aurora_members(ctx, resource, data, source, instances):
    observed = {
        item["DBInstanceIdentifier"]
        for item in instances.items
        if item.get("DBInstanceIdentifier")
        and item.get("DBClusterIdentifier") == data["DBClusterIdentifier"]
    }
    members = data.get("DBClusterMembers")
    member_rows = members if isinstance(members, list) else []
    declared = {
        item["DBInstanceIdentifier"]
        for item in member_rows
        if isinstance(item, dict) and item.get("DBInstanceIdentifier")
    }
    malformed = members is not None and (
        not isinstance(members, list) or len(declared) != len(members)
    )
    missing = declared - observed
    inconsistent = members is not None and bool(observed - declared)
    if (
        missing
        or malformed
        or inconsistent
        or (not observed and (members is None or not instances.complete))
    ):
        reason = "Aurora membership and instance inventory cannot be reconciled; public accessibility is incomplete."
        ctx.gap(instances, reason)
        ctx.emit(
            "RDS001",
            resource,
            "unknown",
            reason,
            source.evidence({"DBClusterMembers": members}),
            instances.evidence(
                {"observed_member_ids": sorted(observed), "missing_member_ids": sorted(missing)}
            ),
        )
    elif not observed:
        ctx.emit(
            "RDS001",
            resource,
            "not_applicable",
            "The completed instance inventory and empty cluster membership contain no Aurora members to assess.",
            source.evidence({"DBClusterMembers": members}),
            instances.evidence(),
        )


def evaluate(collections, account_id, region, policy, now):
    ctx = Evaluation("aws.database", CHECKS, account_id, region)
    instances, clusters = [
        find(collections, op) for op in ("describe_db_instances", "describe_db_clusters")
    ]
    owners = {c["DBClusterIdentifier"]: c for c in clusters.items if c.get("DBClusterIdentifier")}
    if not instances.items and not clusters.items:
        status = "not_applicable" if instances.complete and clusters.complete else "unknown"
        for check in CHECKS:
            ctx.emit(
                check,
                ctx.scope,
                status,
                "No databases observed."
                if status == "not_applicable"
                else "Database inventory is incomplete; no-resource applicability cannot be established.",
                instances.evidence(),
                clusters.evidence(),
            )
        return ctx.output
    for source, is_cluster, id_field in [
        (clusters, True, "DBClusterIdentifier"),
        (instances, False, "DBInstanceIdentifier"),
    ]:
        for data in source.items:
            if not data.get(id_field):
                for check in CHECKS:
                    ctx.emit(
                        check,
                        ctx.scope,
                        "unknown",
                        "A database identifier is missing.",
                        source.evidence(data),
                    )
                continue
            resource = ctx.subject("rds_cluster" if is_cluster else "rds_instance", data[id_field])
            ctx.inventory(resource, source, data)
            kind, reason = topology(data, is_cluster)
            if not is_cluster and data.get("DBClusterIdentifier"):
                owner = owners.get(data["DBClusterIdentifier"])
                if owner is None:
                    kind, reason = "unknown", "The authoritative owner cluster was not collected."
                else:
                    kind, reason = topology(owner, True)
                    if kind == "multiaz":
                        continue  # The cluster owns every check; members remain inventoried.
                    if kind == "aurora":
                        assess_field(ctx, "RDS001", resource, data, source)
                        continue
            if kind in {"excluded", "unknown"}:
                for check in CHECKS:
                    ctx.emit(
                        check,
                        resource,
                        "skipped" if kind == "excluded" else "unknown",
                        reason,
                        source.evidence(data),
                    )
                continue
            for check in CHECKS:
                if is_cluster and check == "RDS005":
                    ctx.emit(
                        check,
                        resource,
                        "not_applicable",
                        "The standalone-primary Multi-AZ check does not apply to clusters.",
                        source.evidence(data),
                    )
                elif is_cluster and kind == "aurora" and check == "RDS001":
                    # Results belong to members, but missing declared members must remain visible.
                    verify_aurora_members(ctx, resource, data, source, instances)
                elif (
                    not is_cluster
                    and check in {"RDS003", "RDS005"}
                    and (
                        data.get("ReadReplicaSourceDBInstanceIdentifier")
                        or data.get("ReadReplicaSourceDBClusterIdentifier")
                    )
                ):
                    ctx.emit(
                        check,
                        resource,
                        "skipped",
                        "Backup and availability policy checks for standalone read replicas are deferred.",
                        source.evidence(data),
                    )
                else:
                    assess_field(ctx, check, resource, data, source)
    return ctx.output


SPEC = ModuleSpec(
    "aws.database",
    "region",
    (("rds", "describe_db_instances"), ("rds", "describe_db_clusters")),
    CHECKS,
    collect,
    evaluate,
)
