# RabbitSentry AWS assessment CLI design

Date: 8 November 2026

Status: Draft for review before implementation

## Purpose and agreed direction

RabbitSentry will help TechRabbit technicians assess a customer environment and explain actionable findings in a report. The first release is a local, read-only assessment CLI for AWS. Its modules must leave room for other infrastructure providers and continuous server monitoring later.

The user has selected an independently owned core with native AWS checks and optional integrations. Continuous monitoring is a later phase. The owner's chat supplies customer context: EC2 and RDS are common, inherited environments have operational and security gaps, and technicians want to run an assessment and prepare a report. Those examples do not establish that every customer has the same problems.

The language, initial checks, formats, and limits below are proposed implementation choices. They are not additional requirements attributed to the user or TechRabbit's owner.

## Approaches

| Approach | Tradeoff | Decision |
| --- | --- | --- |
| Own core, native AWS checks, optional integrations | Direct control of evidence, operational checks, reports, and future monitoring contracts; a smaller initial catalogue that we maintain | Selected by the user |
| Build around Prowler | Broad existing security coverage sooner; scanner installation and output compatibility become core dependencies | Considered, not selected |

[Prowler](https://github.com/prowler-cloud/prowler) remains a candidate optional integration. The first release neither installs nor invokes external scanners.

## First release boundaries

One invocation assesses one AWS account across explicitly selected commercial AWS regions. IAM checks run once for the account. The initial operator is a technician; the HTML report should also be understandable when shared with a customer after technician review.

Inventory covers EC2 instances, EBS volumes, security groups, RDS instances and supported DB clusters, and IAM users and account summary. Checks cover selected access configuration, storage encryption, database protection, and potential unused storage. The result describes the observed configuration at assessment time.

The release includes a working synthetic demonstration, installation instructions, a documented read-permission policy, and offline tests. It excludes organisation-wide account discovery, billing API queries, estimated savings, automatic fixes, host access, secret retrieval, application scanning, penetration testing, a hosted service, a database, scheduling, agents, and notifications. EC2 backup coverage and restore testing are explicitly not assessed yet; initial backup checks concern RDS configuration only.

Failure modes to avoid are treating missing permission as a clean result, claiming complete security coverage, calling an open security-group rule proven internet reachability, calling an unattached volume waste without review, or presenting configured backup retention as evidence of recoverability.

## Proposed implementation foundation

Use Python 3.12 or newer, Boto3 for AWS access, Typer for CLI handling, Jinja2 with automatic escaping for HTML, and pytest with Botocore Stubber for verification. Package it as an installable Python CLI using `pyproject.toml`; an isolated environment or pipx is the initial distribution method. Target Windows and Linux. Exact compatible dependency versions and the lock format are left to the implementation plan.

Python is proposed for the assessment workflow and AWS integration. A future host agent can use a different language; its compatibility boundary will be versioned data contracts, not Python objects.

### Component boundaries

1. **CLI and runner:** resolve account and scope, select modules, track collection outcomes, run checks, and write the report.
2. **AWS provider:** manage SDK sessions, read operations, pagination, timeouts, retries, and errors. It contains no report rendering or assessment rules.
3. **Modules:** declare metadata and collection requirements; convert observations into inventory and check results. Initially these are bundled Python modules in an explicit registry.
4. **Shared model:** versioned, provider-neutral resource references, observations, check results, and assessment metadata.
5. **Report writers:** consume the shared model to produce JSON and HTML without accessing AWS.

Collectors and check evaluation are separate. Checks are pure operations on already-collected observations. Shared collections are cached per assessment so two checks do not repeat the same API call. The assessment is not a transactional snapshot; observation timestamps preserve when each part was read.

A module declares its identifier, version, supported model version, scope (account or region), required operations, check definitions, and collector/evaluator entry points. Bundled modules use trusted in-process code. This is not a plugin security sandbox. Dynamic third-party code loading and subprocess protocols are deferred until an actual integration needs them.

Future monitoring may reuse resource references, observations, check identifiers, and evidence. Scheduling, durable state, transport, time-series metrics, and incident handling remain separate future components. The first release does not claim that batch reports alone define a complete monitoring protocol.

## CLI workflow

Proposed commands:

```text
rabbitsentry modules list
rabbitsentry assess aws --profile customer-readonly --regions eu-west-1,eu-central-1 --output ./reports/customer
rabbitsentry assess aws --profile customer-readonly --regions all-enabled --expected-account 123456789012
rabbitsentry report ./assessment.json --output ./report.html
rabbitsentry demo --output ./reports/demo
```

`--regions` is required for a live assessment: a comma-separated list or `all-enabled`. Region discovery uses the profile's configured AWS region; without one, `all-enabled` fails with instructions to configure it or select explicit regions. Explicit regions are validated against the SDK's commercial-region metadata; unsupported scope is rejected before collection. Disabled or inaccessible explicit regions are recorded as unavailable, not silently dropped.

`--profile` is optional and otherwise uses the SDK's normal credential resolution. Existing AWS profiles, temporary credentials, configured assumed roles, and logged-in IAM Identity Center sessions are supported through [Boto3 credential providers](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html). RabbitSentry does not request access keys as CLI arguments or store credentials in its own configuration.

The runner calls [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) first and displays the resolved account and identity. When supplied, `--expected-account` must match before inventory collection starts. Unsupported AWS partitions fail clearly. Identity or region-discovery failure aborts collection; the tool does not guess an account or region set.

All four modules run by default. `--modules` selects an explicit subset. Omitted modules remain visible as disabled coverage. Policy overrides are initially limited to a validated `--key-age-days` value, defaulting to 90 days. The chosen value is recorded in the report.

Each successful or partially successful run creates a new run directory beneath the output directory, containing `assessment.json` and `report.html`. Existing reports are never overwritten. Without `--output`, use `./reports/<account-id>/<UTC timestamp and short run ID>/`. A local demo uses synthetic data and never resolves AWS credentials or makes a network request.

Exit codes: `0` means completed collection and report generation, even when findings exist; `2` means invalid invocation; `3` means a usable report with incomplete requested coverage; `1` means a fatal run or output failure; `130` means cancellation. Findings do not change the exit code in this release. Once identity and target regions are resolved, even a report consisting entirely of collection-denial records is usable and exits `3`. Authentication or scope resolution failure before that point exits `1`; no assessment report is required. Credentials expiring during collection stop further AWS calls and produce a partial report with exit `3`.

Cancellation attempts to save a report marked `cancelled` once identity and scope are available, preserving collected observations and marking remaining work incomplete, then exits `130`. Failure to save requested output takes precedence with exit `1`. The offline `report` command preserves the original run status and coverage but returns `0` when rendering succeeds; it does not rerun or reclassify the assessment.

## Read-only access and collection behaviour

Assessment API calls pass through a provider operation allowlist. Ship an IAM policy matching those reads and document that the customer's AWS permissions enforce access independently. An allowlist protects against accidental calls in our code; it does not make untrusted Python modules safe.

| Area | Permitted assessment operations |
| --- | --- |
| Identity and regions | `sts:GetCallerIdentity`, `ec2:DescribeRegions` |
| EC2, storage, network | `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeSecurityGroups` |
| Databases | `rds:DescribeDBInstances`, `rds:DescribeDBClusters` |
| IAM | `iam:GetAccountSummary`, `iam:ListUsers`, `iam:GetLoginProfile`, `iam:ListMFADevices`, `iam:ListAccessKeys` |

Credential-provider authentication, including configured role assumption or session refresh, is handled separately by the SDK. Read-only refers to assessed infrastructure: local report files and normal credential-cache maintenance are permitted. RabbitSentry does not create a credential report, start a remote command, upload results, or change AWS configuration.

Paginate every list operation that supports pagination. Use bounded SDK retries and connection/read timeouts. Start with sequential collection for predictable API usage; parallelisation is not a first-release requirement. Proposed defaults are three total attempts per request, a five-second connect timeout, a twenty-second read timeout, and a ten-minute run budget. Stop scheduling new requests at the budget; an in-flight logical request may finish its bounded attempts and backoff. Include the resulting gaps in the report.

Access denial, throttling after retries, missing required fields, unsupported resource variants, and service errors are recorded at operation and scope level. Independent modules continue. A failed page makes that collection incomplete. Findings supported by already-read positive evidence may still be reported, but missing resources or empty partial responses cannot justify passing an absence-based check.

Use explicit projections of API responses for inventory and evidence. Do not persist raw HTTP traffic, credentials, session tokens, full environment variables, or arbitrary resource tags. Inventory includes identifiers, relevant state/configuration, names where needed, and the evidence used by checks. Diagnostic errors are sanitised. Report files can still contain customer infrastructure metadata and are saved locally; generated reports are excluded from source control.

## Initial modules and checks

Check identifiers are stable within the versioned catalogue. Severity expresses the proposed impact of the specific finding, not a claim that exploitation has occurred. Review items are counted separately from failures.

| Module and check | Trigger and result | Severity when triggered |
| --- | --- | --- |
| `aws.iam` / `IAM001` | Account summary reports root access keys present: fail | Critical |
| `aws.iam` / `IAM002` | Root password is present and root MFA is absent: fail; no root password: not applicable; missing fields: unknown | High |
| `aws.iam` / `IAM003` | IAM user has a login profile and a complete empty MFA-device list: fail, worded as no registered MFA; corroborated absence of a login profile: not applicable | High |
| `aws.iam` / `IAM004` | Active access key older than the configured age: review; do not infer last use or compromise | Low |
| `aws.network` / `NET001` | A security group permits `0.0.0.0/0` or `::/0` to a listed administrative/database port, or all protocols: fail on the group configuration | High |
| `aws.compute` / `EBS001` | EBS volume reports encryption disabled: fail | Medium |
| `aws.compute` / `EBS002` | EBS volume is `available` with no attachments: review as a potential cost-reduction candidate | Low |
| `aws.database` / `RDS001` | DB instance or applicable cluster reports public accessibility enabled: review | Medium |
| `aws.database` / `RDS002` | Applicable DB storage reports encryption disabled: fail | High |
| `aws.database` / `RDS003` | Applicable RDS backup-retention field equals zero: fail, explicitly stating automated backups disabled rather than no backups exist | High |
| `aws.database` / `RDS004` | Applicable deletion protection is disabled: review | Medium |
| `aws.database` / `RDS005` | A standalone primary RDS instance explicitly reports `MultiAZ=false`: review against the customer's availability needs | Low |

For `NET001`, initially inspect TCP and UDP ranges covering ports 22, 3389, 1433, 3306, 5432, 6379, 9200, 11211, and 27017; protocol `-1` covers all ports. Handle IPv4 and IPv6, numeric or named TCP/UDP protocols, and range bounds. Aggregate matching rules into one result per security group. The rule describes permissive configuration, not confirmed end-to-end reachability. EC2 and RDS inventory can link known attachments; absence of an attachment in this limited inventory does not prove the group is unused. [Security-group response semantics](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html).

IAM summary interpretation uses the actual returned fields, including `AccountPasswordPresent`; missing values never default to zero. `GetLoginProfile` returning `NoSuchEntity` is ambiguous: a subsequent successful per-user `ListAccessKeys` or `ListMFADevices` read corroborates continued existence and permits `IAM003=not_applicable`. Without corroboration, use unknown. A later per-user `NoSuchEntity` marks affected results unknown with a changed-during-scan reason. Denial is never treated as no password or no MFA. [Account summary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html), [login profiles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetLoginProfile.html), [MFA devices](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html).

`IAM004` emits one result per IAM user, aggregating that user's old active keys. Evidence contains creation time, status, age, and only the last four characters of each access-key ID. Full access-key IDs and secret credentials are not persisted. The user resource reference keeps the result fingerprint stable without per-key collisions. A complete list with no active keys is not applicable; active keys all within the threshold pass. Incomplete lists or missing dates cannot support a pass, while a positively observed old key can still produce a review item with incomplete coverage.

Database collection includes instances and clusters. The initial topology contract is:

| Topology | Assessment subjects |
| --- | --- |
| Standard standalone primary RDS instance | All five RDS checks use the instance |
| Standard standalone read replica | Public access, encryption, and deletion protection use the instance; backup and availability policy checks are explicitly deferred/skipped |
| Conventional regional Aurora cluster, provisioned or Serverless v2 | Public access uses each member instance; encryption, retention, and deletion protection use the cluster once; `RDS005` is not applicable |
| Non-Aurora Multi-AZ DB cluster | All applicable checks use the cluster once, including public access; member instances are inventoried without duplicate results; `RDS005` is not applicable |
| Known excluded topology | Inventory with a skipped reason; no inferred results |

Standard engine families are MySQL, MariaDB, PostgreSQL, Oracle, SQL Server, and Db2, plus the supported Aurora variants above. Known exclusions are RDS Custom, Aurora Serverless v1, Aurora Express, Aurora Limitless, clusters identified as members of an Aurora global database, and DocumentDB/Neptune returned by the API. Their member instances inherit that exclusion. Global database resources and relationships are outside the collection scope. Unknown engine/topology variants and missing authoritative cluster records produce unknown results and partial coverage, rather than being silently classified as known exclusions. An explicit cluster association always takes precedence over the standalone rules. [DB instance fields](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html), [DB cluster fields](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html).

`RDS002` evaluates encryption at rest, independent of key ownership. Prefer `StorageEncryptionType`: `sse-rds` and `sse-kms` indicate encryption; `none` indicates no encryption. In particular, `sse-rds` with `StorageEncrypted=false` is encrypted. An unknown type is unknown; a contradiction such as `none` with a true encryption flag, or `sse-kms` with a false flag, is unknown. When the type is absent, a true encryption flag is sufficient for pass; a false or missing flag is unknown because it cannot rule out AWS-owned-key encryption. These cases have dedicated fixtures.

Backup retention above zero establishes configured automated backups only. The report must explicitly identify backup freshness, external backup systems, and restore-test evidence as unassessed. [RDS backup retention](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.BackupRetention.html).

## Shared results and report contract

The JSON report has a top-level schema version, tool version, unique run ID, run status (`complete`, `partial`, or `cancelled`), UTC start/finish times, resolved account and principal, requested/attempted regions, selected modules and versions, effective policy, inventory, coverage records, check results, and sanitised errors. Fatal pre-assessment failures produce diagnostics rather than a misleading assessment object. The initial schema version is `1.0`; incompatible changes require a new major version. Unsupported major versions are rejected by the offline report command.

Resource references identify provider, account, region or global scope, resource type, and stable identifier/ARN. Observations include collector identity, source operation, observation time, subject, projected data, and completeness. No downstream component needs an SDK response class.

Each check result includes check ID/version, resource reference, status, severity if relevant, title, explanation, structured evidence with source/time, recommended next step, and supporting references. A stable result fingerprint derives from provider, account, scope, resource identifier, and check ID; the run ID is separate so future comparisons can relate assessments.

Statuses are `pass`, `fail`, `review`, `unknown`, `not_applicable`, and `skipped`. `pass` means the specific documented condition was evaluated successfully and not found. For review rules, it means the review trigger was absent. No supported resources after a complete collection is represented as not applicable at scope level, not an invented resource pass. Disabled modules use skipped coverage. Unknown and partial results remain prominent regardless of severity counts.

Coverage records track account/region/module/operation, state (`complete`, `partial`, `failed`, or `skipped`), resource count, and reason. Missing required fields on in-scope resources, unknown variants, denied or failed required reads, expired credentials, and interrupted pagination make the assessment partial. Known exclusions and user-disabled modules remain visible as skipped coverage and do not by themselves make the run partial. Cancellation has its own run status and records incomplete work.

A fully observed resource may pass its specific check even when a later inventory page fails; its required fields and any per-resource subcollection must be complete. The account/region scope remains partial. Checks based on absence across an incomplete collection are unknown. Scope-level unknown/not-applicable results use an explicit account or region scope subject, never a fabricated resource. Inventory and valid positive findings survive unrelated errors. Scope applicability and explicit unassessed areas accompany even a completed run; complete means the selected supported work finished, not that the account is comprehensively assessed.

HTML is self-contained with embedded styling and no remote assets or tracking. It presents scope and coverage, an executive summary, prioritised failures, separate review items, inventory, evidence and next steps, and collection gaps. It does not include a percentage security score or a blanket healthy verdict. All AWS-derived strings are treated as text and escaped. JSON is the canonical result; HTML can be regenerated offline.

## Acceptance criteria

1. A technician can install the CLI, list its modules, and generate a clearly labelled demonstration report without AWS access.
2. An authorised single-account assessment can collect paginated inventory in two selected regions, run IAM once, evaluate the twelve checks, and produce local HTML and versioned JSON.
3. Fixtures cover positive, negative, review, missing-field, no-resource, and unsupported-variant cases, including IPv6 and all-protocol rules, cluster ownership and exclusions, AWS-owned-key encryption, root accounts without passwords, ambiguous IAM-user disappearance, and multiple old keys on one user.
4. Tests prove permission denial, failed later pages, expired authentication, run-budget exhaustion, and account mismatch cannot produce a misleading complete or clean report.
5. The provider rejects operations outside the explicit allowlist before dispatch; the shipped IAM policy and module operation declarations agree with it.
6. Report generation handles hostile-looking names safely, avoids writing credentials, validates supported JSON versions, and preserves existing output files.
7. The local demo, offline report conversion, and command help are exercised end to end. Tests use synthetic fixtures and stubbed AWS responses; a live smoke test is separately identified if an account is later supplied for that purpose.
8. A small test module can register and emit the shared results without changes to report writers or CLI orchestration, demonstrating the intended extension boundary.

## Decisions left to implementation

The builder may choose internal file layout, data-validation library, compatible dependency pins, test helper structure, and report styling. Those choices must preserve the scope, command semantics, read-only operation boundary, evidence quality, and future module boundaries above. Licensing and public distribution can be decided before publishing; they do not block local implementation.
