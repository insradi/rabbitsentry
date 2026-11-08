# AWS Assessment CLI Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. The user's implementation request authorises continuous local execution of the reviewed design.

**Goal:** Deliver an installable read-only AWS CLI with twelve checks, offline demonstration, and local HTML/JSON reports.

**Architecture:** A versioned result model connects a read-operation gateway, bundled collector/evaluator modules, the assessment runner, and offline report writers. SDK responses are projected before entering shared results. No AI service or remote report storage is involved.

**Tech Stack:** Python 3.12+, Boto3/Botocore, Typer, Jinja2, Pydantic 2, pytest, Ruff, setuptools.

**Spec:** `docs/superpowers/specs/2026-11-08-rabbitsentry-aws-assessment-design.md`

## Global Constraints

- Windows and Linux; one account, commercial AWS regions, IAM once per account.
- Only the twelve explicitly listed assessment API operations; authentication stays in SDK credential providers.
- Three total request attempts, five-second connect timeout, twenty-second read timeout, ten-minute run budget.
- Required explicit region selection; `all-enabled` needs a configured bootstrap region.
- Exit codes: complete 0, invalid invocation 2, incomplete report 3, fatal/output failure 1, cancellation 130.
- No live AWS calls during development. Tests block network access and use synthetic fixtures/SDK stubs.
- Preserve partial evidence, unknown results, skipped scope, report files, and credential privacy.
- Full application operation without AI or a server; no automatic remediation or dependency provisioning on customer hosts.

## Review Focus

1. Later-page failures and cancellation preserve earlier evidence without converting absent observations into a pass (tasks 2 and 4).
2. Unknown RDS variants, missing owner clusters, and contradictory encryption fields remain unknown (task 3).
3. An IAM user disappearing between requests cannot look like a safe account (task 3).
4. Imported reports with hostile strings or incompatible schemas cannot produce unsafe or misleading HTML (tasks 1 and 5).
5. Offline commands and installation must work without credential lookup, metadata-server calls, or untracked template dependencies (task 5).

## File Map

- `src/rabbitsentry/models.py`: validated JSON contracts, fingerprints, final status.
- `src/rabbitsentry/aws/provider.py`, `operations.py`, `projections.py`: read gateway, explicit operation definitions, evidence projections.
- `src/rabbitsentry/modules/base.py`, `iam.py`, `network.py`, `compute.py`, `database.py`: bundled module interface and pure check evaluation.
- `src/rabbitsentry/runner.py`: identity/scope validation, execution, coverage, status.
- `src/rabbitsentry/reporting.py`, `templates/report.html`: safe local output and offline regeneration.
- `src/rabbitsentry/cli.py`, `demo.py`, `__main__.py`: user commands and synthetic assessment.
- `tests/`: behaviour tests, Botocore Stubber tests, CLI end-to-end tests.
- `permissions/aws-readonly.json`, `docs/usage.md`, `docs/modules.md`: usable permission and extension documentation.
- `pyproject.toml`, `requirements-dev.lock`, `.github/workflows/ci.yml`: packaging, reproducible development dependencies, Windows/Linux checks.

## Task 1: Package and canonical result model

**Interfaces:** `ResourceRef`, `InventoryItem`, `Evidence`, `CheckResult`, `Coverage`, `Assessment`, `Policy`; all Pydantic models. `CheckResult.fingerprint` derives from provider/account/scope/type/resource/check. `Assessment.finish()` derives complete/partial while preserving cancelled. `Assessment.model_validate_json()` validates offline input.

- [x] Write `tests/test_models.py`: fingerprints stay stable across run IDs but differ across subjects/checks; schema major 2 is rejected; unknown results or failed coverage make a finished run partial; timestamps require timezones; inconsistent complete reports are rejected on import.
- [x] Attempt initial model tests; the first run exposed a blocked dependency before reaching application code. The approved Python 3.12 environment resolved it; see execution notes.
- [x] Implement models and package metadata; default schema `1.0`, key age 90 days, version `0.1.0`.
- [x] Rerun model tests, then full suite; expect pass. Commit this deliverable.

## Task 2: AWS read gateway and projections

**Interfaces:** `Collection` holds operation, region, selector, observed time, projected items, completion/error. `AwsProvider.collect(service, operation, region, **params) -> Collection` caches each exact request. `AwsProvider.history` preserves collections; `halt_reason` prevents further network calls. `OPERATIONS` is the assessment allowlist and IAM-action mapping.

- [x] Write `tests/test_provider.py`: SDK-stubbed pagination, failure after a successful page, read allowlist before dispatch, credential-expiry halt, budget halt, cancellation preservation, and projections that discard credentials/tags/response metadata.
- [x] Run provider tests; expect missing implementation.
- [x] Implement sequential SDK pagination with bounded retry/timeouts, projected response extraction, sanitised error codes, cache, and cancellation. `NoSuchEntity` remains evidence for evaluator interpretation.
- [x] Run provider tests and full suite; expect pass. Generate the matching read policy and commit.

## Task 3: Twelve native checks and module contract

**Interfaces:** `ModuleSpec` declares ID/version/scope/operations/check IDs/collector/evaluator. `collect(provider, region) -> list[Collection]`; `evaluate(collections, account_id, region, policy, now) -> ModuleOutput` returns inventory/results. `REGISTRY` is the explicit bundled registry. Evaluators make no network calls.

- [x] Write `tests/test_checks.py` with literal positive, negative, missing-field, no-resource, and partial-page cases. Include IPv6/all protocols/ranges, detached volumes, root password absence, corroborated/ambiguous missing login profiles, multiple old keys, standalone and cluster-owned RDS checks, exclusions, and encryption-type precedence.
- [x] Run check tests; expect missing implementation.
- [x] Implement the four modules against the shared contracts. Aggregate network matches per group and old keys per user. Mark known exclusions as skipped; unknown variants as unknown. Inventory only projected fields.
- [x] Run check tests and full suite; expect pass. Commit modules.

## Task 4: Assessment orchestration

**Interfaces:** `run_assessment(provider, regions, modules, expected_account, policy, on_identity=None) -> Assessment`; `InvalidConfiguration` and `AssessmentFailed` distinguish invocation and bootstrap errors. Selected module sets are validated before AWS collection. Explicit scope and SDK-supported regions are validated before identity collection.

- [x] Write `tests/test_runner.py`: account mismatch aborts inventory, unsupported partition, duplicate/invalid regions and modules, all-enabled discovery, IAM once across regions, selected module isolation, all operations denied, expired credentials, cancellation, missing fields, excluded scope, and registration of an independent test module.
- [x] Run runner tests; expect missing implementation.
- [x] Implement identity/scope bootstrap and module loops. Record every collection, skipped module, and unknown result; preserve successful evidence when later scopes fail.
- [x] Run runner tests and full suite; expect pass. Commit orchestration.

## Task 5: Commands, reports, demo, and distribution

**Interfaces:** `write_assessment(assessment, output_root=None) -> Path` creates a unique directory and both files. `render_report(assessment) -> str` escapes text. `write_html(assessment, path)` refuses overwrite. `build_demo() -> Assessment` uses synthetic collections and real evaluators. Typer exposes the design's four command families.

- [x] Write `tests/test_reporting.py` and `tests/test_cli.py`: complete/partial/cancelled labels, hostile names, unsupported import, no overwrite, no credential lookup in demo/report/help, all CLI exit paths, and all twelve checks represented in the demo.
- [x] Run these tests; expect missing implementation.
- [x] Implement self-contained HTML/JSON output, synthetic demo, command help and validation, local permission file, installation/use/module documentation, and Windows/Linux CI. Add an SDK capability check so required RDS fields are available in the installed dependency range.
- [x] Run full suite, Ruff, package build, installed CLI help/demo, and offline regeneration. Inspect rendered demo HTML. Commit the working CLI and lock dependency versions.

## Finish

- [x] Review the complete branch with a fresh reviewer; resolve important issues with reproducing tests.
- [x] Verify the complete suite, package contents, documentation commands, and clean Git status.
- [ ] Push the feature branch to the existing private GitHub repository. Keep `main` unchanged while the implementation is reviewed.
- [x] If the offered staging LXC is available, run installation and synthetic demo there; record the actual result separately from Windows verification.

## Execution notes

Implemented and verified on Windows and Linux with 93 offline tests. The initial model red run failed during dependency import; model implementation preceded a valid application-red run. Later tasks and review fixes followed observed red/green cycles. Tasks 3–5 were committed together as a working CLI. See `docs/verification.md` for actual validation and its limits. Integration follows the authorised GitHub project setup: push a feature branch and draft pull request; preserve main and the local checkout.
