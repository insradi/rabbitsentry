"""Resolve identity and scope, then coordinate trusted modules."""

import re

from botocore.session import get_session

from rabbitsentry.aws.operations import OPERATIONS
from rabbitsentry.models import Assessment, Coverage, Policy, utcnow
from rabbitsentry.modules import REGISTRY


class InvalidConfiguration(ValueError):
    pass


class AssessmentFailed(RuntimeError):
    pass


def validate_configuration(provider, regions, modules, expected_account, registry):
    requested = (
        [r.strip() for r in regions.split(",")] if isinstance(regions, str) else list(regions)
    )
    selected = list(registry) if modules is None else list(modules)
    if not requested or not all(requested) or len(set(requested)) != len(requested):
        raise InvalidConfiguration("Select a nonempty region list without duplicates.")
    if not selected or len(set(selected)) != len(selected) or set(selected) - registry.keys():
        raise InvalidConfiguration("Select known module IDs without duplicates; use modules list.")
    for module_id in selected:
        spec = registry[module_id]
        if spec.model_version != "1.0" or spec.scope not in {"account", "region"}:
            raise InvalidConfiguration("A module has an incompatible model or scope.")
        if set(spec.operations) - OPERATIONS.keys():
            raise InvalidConfiguration("A module declares operations outside the read allowlist.")
    if expected_account is not None and not re.fullmatch(r"\d{12}", expected_account):
        raise InvalidConfiguration("Expected account must be a 12-digit AWS account ID.")
    known = set(provider.session.get_available_regions("ec2", partition_name="aws"))
    if requested == ["all-enabled"]:
        bootstrap = provider.session.region_name
        if not bootstrap:
            raise InvalidConfiguration(
                "all-enabled needs a configured AWS region; configure one or select explicit regions."
            )
        if bootstrap not in known:
            raise InvalidConfiguration(
                "The configured bootstrap region must be a supported commercial AWS region."
            )
    else:
        if set(requested) - known:
            raise InvalidConfiguration(
                "Unsupported region selection. Use SDK-supported commercial AWS regions."
            )
        bootstrap = requested[0]
    if "aws.database" in selected:
        model = get_session().get_service_model("rds")
        if any(
            "StorageEncryptionType" not in model.shape_for(shape).members
            for shape in ("DBInstance", "DBCluster")
        ):
            raise InvalidConfiguration(
                "Upgrade boto3/botocore: this SDK lacks required RDS encryption fields."
            )
    return requested, selected, bootstrap, known


def collection_coverage(collection, module_id):
    if collection.absence_confirmed:
        state, reason = (
            "skipped",
            "Login profile absent; subsequent read corroborated user existence.",
        )
    elif collection.complete:
        state, reason = "complete", ""
    else:
        state = "partial" if collection.items else "failed"
        reason = collection.error_code or "Incomplete collection"
    return Coverage(
        module_id=module_id,
        region=collection.region,
        operation=collection.action,
        state=state,
        reason=reason,
        resource_count=len(collection.items),
        subject=collection.selector.get("UserName", ""),
    )


def run_assessment(
    provider,
    regions,
    modules=None,
    expected_account=None,
    policy=None,
    on_identity=None,
    *,
    registry=None,
):
    registry = REGISTRY if registry is None else registry
    requested, selected, bootstrap, known = validate_configuration(
        provider, regions, modules, expected_account, registry
    )
    started = utcnow()
    identity = provider.collect("sts", "get_caller_identity", bootstrap)
    if provider.halt_reason == "Cancelled":
        raise KeyboardInterrupt
    if not identity.complete or len(identity.items) != 1:
        raise AssessmentFailed(
            f"Identity could not be resolved ({identity.error_code or 'InvalidIdentity'})."
        )
    account, principal = identity.items[0].get("Account", ""), identity.items[0].get("Arn", "")
    if not re.fullmatch(r"\d{12}", account) or not principal.startswith("arn:aws:"):
        raise AssessmentFailed("Unsupported AWS partition or invalid identity response.")
    if expected_account and account != expected_account:
        raise AssessmentFailed(
            f"Resolved account {account} does not match expected account {expected_account}."
        )
    if on_identity:
        on_identity(account, principal)
    target_regions = requested
    discovery = None
    if requested == ["all-enabled"]:
        discovery = provider.collect("ec2", "describe_regions", bootstrap, AllRegions=True)
        if provider.halt_reason == "Cancelled":
            raise KeyboardInterrupt
        if not discovery.complete or any(
            not i.get("RegionName")
            or i.get("OptInStatus") not in {"opt-in-not-required", "opted-in", "not-opted-in"}
            for i in discovery.items
        ):
            raise AssessmentFailed(
                f"Enabled regions could not be resolved ({discovery.error_code or 'InvalidRegions'})."
            )
        target_regions = sorted(
            {r["RegionName"] for r in discovery.items if r["OptInStatus"] != "not-opted-in"}
        )
        if not target_regions or set(target_regions) - known:
            raise AssessmentFailed(
                "Discovered regions are empty or unsupported by this SDK; update the SDK or select explicit regions."
            )
    report = Assessment(
        account_id=account,
        principal=principal,
        requested_regions=requested,
        regions=target_regions,
        started_at=started,
        policy=policy or Policy(),
        selected_modules={module_id: registry[module_id].version for module_id in selected},
    )
    completed_scopes = set()
    try:
        report.coverage.append(collection_coverage(identity, "aws.bootstrap"))
        if discovery:
            report.coverage.append(collection_coverage(discovery, "aws.bootstrap"))
        _execute_modules(provider, report, registry, selected, completed_scopes)
    except KeyboardInterrupt:
        provider.halt_reason = "Cancelled"
        for module_id in selected:
            spec = registry[module_id]
            for region in ["global"] if spec.scope == "account" else target_regions:
                if (module_id, region) not in completed_scopes:
                    report.coverage.append(
                        Coverage(
                            module_id=module_id,
                            region=region,
                            operation="module",
                            state="failed",
                            reason="Cancelled before this scope finished; earlier evidence is retained.",
                        )
                    )
    if provider.halt_reason == "Cancelled":
        report.run_status = "cancelled"
    report.finish()
    return report


def _execute_modules(provider, report, registry, selected, completed_scopes):
    target_regions, account = report.regions, report.account_id
    for module_id, spec in registry.items():
        scopes = ["global"] if spec.scope == "account" else target_regions
        for region in scopes:
            if module_id not in selected:
                report.coverage.append(
                    Coverage(
                        module_id=module_id,
                        region=region,
                        operation="module",
                        state="skipped",
                        reason="Module disabled by selection.",
                    )
                )
                continue
            if (
                region != "global"
                and not provider.halt_reason
                and region not in report.attempted_regions
            ):
                report.attempted_regions.append(region)
            history_start = len(provider.history)
            collections = []
            try:
                try:
                    collections = spec.collect(provider, region)
                except KeyboardInterrupt:
                    provider.halt_reason = "Cancelled"
                    # Replay cached reads and create stopped-read records. No further requests.
                    collections = spec.collect(provider, region)
                try:
                    output = spec.evaluate(collections, account, region, report.policy, utcnow())
                except KeyboardInterrupt:
                    provider.halt_reason = "Cancelled"
                    output = spec.evaluate(collections, account, region, report.policy, utcnow())
                report.inventory.extend(output.inventory)
                report.results.extend(output.results)
                report.coverage.extend(output.coverage)
                for result in output.results:
                    if result.status in {"unknown", "skipped"}:
                        report.coverage.append(
                            Coverage(
                                module_id=module_id,
                                region=region,
                                operation=result.check_id,
                                state="partial" if result.status == "unknown" else "skipped",
                                reason=result.explanation,
                                subject=result.resource.identifier,
                            )
                        )
            except Exception as exc:
                report.errors.append(f"{module_id} {region}: {type(exc).__name__}")
                report.coverage.append(
                    Coverage(
                        module_id=module_id,
                        region=region,
                        operation="module",
                        state="failed",
                        reason="Module could not finish evaluation.",
                    )
                )
                collections = collections or provider.history[history_start:]
            report.coverage.extend(collection_coverage(c, module_id) for c in collections)
            completed_scopes.add((module_id, region))
