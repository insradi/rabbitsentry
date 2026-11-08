"""EC2 inventory and EBS configuration checks."""

from .base import Check, Evaluation, ModuleSpec, find

REFERENCE = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Volume.html"
CHECKS = {
    "EBS001": Check(
        "EBS encryption at rest",
        "medium",
        "Plan an encrypted replacement or snapshot copy after reviewing application impact.",
        REFERENCE,
    ),
    "EBS002": Check(
        "Unattached EBS volume",
        "low",
        "Confirm ownership, retention and recovery needs before deciding whether to retain or remove the volume.",
        REFERENCE,
    ),
}


def collect(provider, region):
    return [
        provider.collect("ec2", operation, region)
        for operation in ("describe_instances", "describe_volumes")
    ]


def evaluate(collections, account_id, region, policy, now):
    ctx = Evaluation("aws.compute", CHECKS, account_id, region)
    instances = find(collections, "describe_instances")
    for data in instances.items:
        if data.get("InstanceId"):
            ctx.inventory(ctx.subject("ec2_instance", data["InstanceId"]), instances, data)
        else:
            ctx.gap(instances, "An instance identifier is missing.")
    volumes = find(collections, "describe_volumes")
    if ctx.empty(volumes, CHECKS):
        return ctx.output
    for data in volumes.items:
        if not data.get("VolumeId"):
            for check in CHECKS:
                ctx.emit(
                    check,
                    ctx.scope,
                    "unknown",
                    "A volume identifier is missing.",
                    volumes.evidence(data),
                )
            continue
        resource = ctx.subject("ebs_volume", data["VolumeId"])
        ctx.inventory(resource, volumes, data)
        encrypted = data.get("Encrypted")
        status = "pass" if encrypted is True else "fail" if encrypted is False else "unknown"
        ctx.emit(
            "EBS001",
            resource,
            status,
            "Encryption is enabled."
            if status == "pass"
            else "Encryption is disabled."
            if status == "fail"
            else "The encryption flag is missing or invalid.",
            volumes.evidence(data),
        )
        state, attachments = data.get("State"), data.get("Attachments")
        if state not in {
            "available",
            "in-use",
            "creating",
            "deleting",
            "deleted",
            "error",
        } or not isinstance(attachments, list):
            status, reason = "unknown", "Volume state or attachment data is missing or invalid."
        elif state == "available" and not attachments:
            status, reason = (
                "review",
                "The volume is available and unattached: a potential cost-reduction candidate, subject to retention needs.",
            )
        elif state == "available" and attachments:
            status, reason = "unknown", "Available state contradicts the reported attachments."
        else:
            status, reason = (
                "pass",
                "The volume does not meet the available-and-unattached review condition.",
            )
        ctx.emit("EBS002", resource, status, reason, volumes.evidence(data))
    return ctx.output


SPEC = ModuleSpec(
    "aws.compute",
    "region",
    (("ec2", "describe_instances"), ("ec2", "describe_volumes")),
    CHECKS,
    collect,
    evaluate,
)
