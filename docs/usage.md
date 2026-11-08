# Usage and report semantics

Requires Python 3.12+. Install from this checkout with `python -m pip install .` in an isolated environment. Linux may require the distribution's `python3-venv` package. On Windows use an approved Python interpreter; installation does not require weakening application-control policies.

Every command also works as `python -m rabbitsentry ...`. This is useful on managed Windows machines where the generated console launcher is restricted. The wheel installs the read policy and usage/module documents under the environment's `share/rabbitsentry/` directory.

## Authentication and permissions

Use an existing named profile, temporary credentials, configured assumed role, or an already logged-in IAM Identity Center session. RabbitSentry uses [Boto3's credential providers](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html). It never accepts access keys as command arguments or creates a credential store.

An account administrator can review and grant [aws-readonly.json](../permissions/aws-readonly.json) through the customer's authorisation process. RabbitSentry does not attach policies or change IAM. Organisation policies, permission boundaries and session restrictions may still deny reads; those gaps appear in reports.

The twelve permitted assessment operations cover STS identity; EC2 regions, instances, volumes and security groups; RDS instances and clusters; IAM account summary, users, login profiles, MFA devices and access-key metadata. The provider allowlist and policy are checked together in tests. SDK authentication may separately refresh a session or assume a configured role. The allowlist is an accidental-call guard, not a sandbox for untrusted Python code.

## Commands

```console
rabbitsentry modules list
rabbitsentry demo --output ./reports/demo
rabbitsentry assess aws --profile customer-readonly --regions eu-west-1,eu-central-1 --expected-account 123456789012
rabbitsentry assess aws --profile customer-readonly --regions all-enabled --modules aws.iam,aws.database --key-age-days 120
rabbitsentry report ./assessment.json --output ./new-report.html
```

`--regions` is mandatory. Explicit regions must appear in the SDK's commercial-region metadata. `all-enabled` needs a configured commercial region for identity/discovery and selects opted-in and default-enabled regions. Unsupported partitions are rejected. Explicit inaccessible regions remain visible as failed/partial coverage.

Identity is read first and printed. A mismatched `--expected-account` aborts before inventory. IAM runs once per account; regional modules run for each selected region. All modules run by default; omitted modules remain visible as skipped coverage.

Collection is sequential and cached per run. Requests use at most three total SDK attempts, a five-second connect timeout and twenty-second read timeout. After ten minutes no new logical request starts; an in-flight request may finish its bounded attempts/backoff. Expired credentials stop further collection. Ctrl+C attempts to preserve observations once identity and region scope are known.

## Outputs and exit codes

Each invocation creates a unique subdirectory beneath `--output`, or `./reports/<account>/` by default. The demo defaults to `./reports/demo/`. Existing files are never overwritten. Keep canonical `assessment.json` beside `report.html`. Offline HTML conversion rejects unsupported schema versions and unfinished input.

| Exit | Meaning |
| --- | --- |
| 0 | Selected supported work and output completed, even when findings exist |
| 1 | Fatal bootstrap/configuration-read or output failure |
| 2 | Invalid arguments, module selection, policy or region selection |
| 3 | Usable report with incomplete requested coverage |
| 130 | Cancelled; output is attempted after scope resolution |

Output failure takes precedence over cancellation. Offline `report` returns 0 on successful rendering, even when the original run was partial or cancelled. Findings alone do not change the exit code.

Reports contain infrastructure metadata: names, addresses, account/role identifiers and evidence. Arbitrary tags, full access-key IDs, secrets and raw HTTP responses are excluded. Reports and local credentials are ignored by Git. Diagnostic errors use short codes, not AWS response messages.

## Interpretation

- **Fail:** the named configuration condition was positively observed.
- **Review:** the decision depends on ownership or customer requirements.
- **Pass:** the named condition was evaluated and its trigger was absent.
- **Unknown:** required evidence was incomplete, unavailable, contradictory or unrecognised.
- **Not applicable:** the condition does not apply, or a completed collection returned no resources.
- **Skipped:** intentionally disabled or explicitly outside the initial supported scope.

Earlier observations survive later-page failure. A fully observed resource may pass while overall scope remains partial. Empty incomplete collections cannot establish absence. Unknown results and partial/failed coverage make the run partial.

Security-group findings describe rules, not proven reachability. Key age does not establish last use or compromise. Configured RDS retention does not establish backup freshness or restorability. EC2 backups, external backup systems and restore tests remain unassessed.

RDS ownership avoids duplicate findings. Conventional regional Aurora and Multi-AZ clusters are supported. Known exclusions include RDS Custom, Aurora global databases, Serverless v1, Express, Limitless, DocumentDB and Neptune. Standalone-replica backup/availability checks are deferred. Unknown variants remain unknown. Encryption honours current [AWS encryption fields](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html), including `sse-rds` with a false legacy flag.

## Linux playground

Install under an ordinary application user and run the same demo/tests. No daemon, public listening port, nested container runtime or AWS credentials are required. A live-account smoke test needs explicit authorisation and should use a known expected account and narrow region/module selection.
