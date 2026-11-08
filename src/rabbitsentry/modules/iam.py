"""Account and user checks with explicit absence corroboration."""

from datetime import datetime

from .base import Check, Evaluation, ModuleSpec, find

REFERENCE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
CHECKS = {
    "IAM001": Check(
        "Root access keys",
        "critical",
        "Identify dependencies, replace root keys with suitable role credentials, and remove the root keys.",
        REFERENCE,
    ),
    "IAM002": Check(
        "Root console MFA",
        "high",
        "Register MFA for root console access and review root-account recovery procedures.",
        REFERENCE,
    ),
    "IAM003": Check(
        "Console user's registered MFA",
        "high",
        "Confirm the user's access requirements and register MFA; this check does not evaluate every policy enforcement path.",
        REFERENCE,
    ),
    "IAM004": Check(
        "Age of active access keys",
        "low",
        "Review use and ownership; prefer temporary role credentials and plan rotation without breaking dependencies.",
        REFERENCE,
    ),
}


def collect(provider, region):
    collections = [
        provider.collect("iam", "get_account_summary", "global"),
        provider.collect("iam", "list_users", "global"),
    ]
    for user in collections[1].items:
        if not user.get("UserName"):
            continue
        reads = [
            provider.collect("iam", operation, "global", UserName=user["UserName"])
            for operation in ("get_login_profile", "list_mfa_devices", "list_access_keys")
        ]
        login, mfa, keys = reads
        login.absence_confirmed = (
            login.error_code == "NoSuchEntity"
            and any(c.complete for c in (mfa, keys))
            and not any(c.error_code == "NoSuchEntity" for c in (mfa, keys))
        )
        collections.extend(reads)
    return collections


def key_age(data, now):
    created = data.get("CreateDate")
    if isinstance(created, str):
        try:
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(created, datetime) or created.tzinfo is None or created > now:
        return None
    return (now - created).total_seconds() / 86400


def evaluate(collections, account_id, region, policy, now):
    ctx = Evaluation("aws.iam", CHECKS, account_id, "global")
    summary = find(collections, "get_account_summary")
    account = ctx.subject("account", account_id)
    data = summary.items[0] if summary.items else {}
    if summary.items:
        ctx.inventory(account, summary, data)
    keys_present = data.get("AccountAccessKeysPresent")
    status = (
        "unknown"
        if type(keys_present) is not int or keys_present < 0
        else "fail"
        if keys_present > 0
        else "pass"
    )
    ctx.emit(
        "IAM001",
        account,
        status,
        "Root access keys are present."
        if status == "fail"
        else "No root access keys reported."
        if status == "pass"
        else "Root access-key presence could not be established.",
        summary.evidence(data),
    )
    password, mfa = data.get("AccountPasswordPresent"), data.get("AccountMFAEnabled")
    if type(password) is int and password == 0:
        status, reason = "not_applicable", "No root console password is reported."
    elif type(password) is int and password == 1 and type(mfa) is int and mfa in {0, 1}:
        status, reason = (
            ("pass", "Root MFA is enabled.")
            if mfa
            else ("fail", "Root has a console password without MFA.")
        )
    else:
        status, reason = "unknown", "Required root password/MFA fields are missing or invalid."
    ctx.emit("IAM002", account, status, reason, summary.evidence(data))
    users = find(collections, "list_users")
    if ctx.empty(users, ("IAM003", "IAM004")):
        return ctx.output
    for user in users.items:
        username = user.get("UserName")
        if not username:
            for check in ("IAM003", "IAM004"):
                ctx.emit(
                    check, ctx.scope, "unknown", "A user name is missing.", users.evidence(user)
                )
            continue
        resource = ctx.subject("iam_user", user.get("Arn") or username)
        ctx.inventory(resource, users, user)
        login, mfa, keys = [
            find(collections, operation, username)
            for operation in ("get_login_profile", "list_mfa_devices", "list_access_keys")
        ]
        changed = any(c.error_code == "NoSuchEntity" for c in (mfa, keys))
        if changed:
            status, reason = (
                "unknown",
                "The user may have changed or disappeared during collection.",
            )
        elif login.error_code == "NoSuchEntity" and any(c.complete for c in (mfa, keys)):
            status, reason = (
                "not_applicable",
                "No login profile; a subsequent per-user read confirmed the user still existed.",
            )
        elif login.complete and login.items and mfa.complete:
            status, reason = (
                ("pass", "A console user has registered MFA devices.")
                if mfa.items
                else ("fail", "A console user has no registered MFA device.")
            )
        else:
            status, reason = (
                "unknown",
                "Console login or registered MFA could not be established; absence is not assumed.",
            )
        ctx.emit("IAM003", resource, status, reason, login.evidence(), mfa.evidence())

        evidence_keys, old, active, invalid = [], [], [], False
        for key in keys.items:
            item = dict(key)
            if key.get("Status") == "Active":
                active.append(key)
                age = key_age(key, now)
                if age is None:
                    invalid = True
                else:
                    item["age_days"] = round(age, 2)
                    if age > policy.key_age_days:
                        old.append(item)
            elif key.get("Status") != "Inactive":
                invalid = True
            evidence_keys.append(item)
        if changed:
            status, reason = (
                "unknown",
                "The user may have changed or disappeared during collection.",
            )
        elif old:
            status, reason = (
                "review",
                f"{len(old)} active key(s) exceed {policy.key_age_days} days. Age does not establish last use or compromise.",
            )
        elif not keys.complete or invalid:
            status, reason = (
                "unknown",
                "Active key ages cannot be established from incomplete or invalid key data.",
            )
        elif not active:
            status, reason = "not_applicable", "The complete key list contains no active keys."
        else:
            status, reason = "pass", f"Observed active keys are within {policy.key_age_days} days."
        if invalid:
            ctx.gap(keys, "An access key has a missing/invalid status or creation date.")
        ctx.emit(
            "IAM004",
            resource,
            status,
            reason,
            keys.evidence(
                {
                    "keys": evidence_keys,
                    "threshold_days": policy.key_age_days,
                    "error_code": keys.error_code,
                }
            ),
        )
    return ctx.output


SPEC = ModuleSpec(
    "aws.iam",
    "account",
    tuple(
        ("iam", name)
        for name in (
            "get_account_summary",
            "list_users",
            "get_login_profile",
            "list_mfa_devices",
            "list_access_keys",
        )
    ),
    CHECKS,
    collect,
    evaluate,
)
