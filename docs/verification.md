# Initial implementation verification

Verified on 8 November 2026. Application revision: `9cc4aa9`.

| Environment | Verification |
| --- | --- |
| Windows, Python 3.12 | 93 offline tests; Ruff; wheel/source build; installed wheel via `python -m rabbitsentry`; modules, demo and offline HTML regeneration |
| Debian 13 LXC, Python 3.13 | 93 offline tests; Ruff; wheel/source build; installed console entry point; modules, demo and offline HTML regeneration |
| Browser | Synthetic report summary, findings and expandable evidence visually inspected |

Package contents include the report template, read policy and documentation. The source archive also includes the test setup and dependency lock. The Linux application runs under an ordinary application user, with source, environment and reports under `/opt/rabbitsentry/`. No AWS credentials were placed in the playground.

A fresh code review found four important edge cases and one budget-boundary issue. All were reproduced, fixed and rechecked: cancellation while saving, missing Aurora members, inconsistent IAM pagination, unknown RDS topology values, and a final response crossing the run deadline. Regression tests cover these cases. The reviewer reported no remaining blockers from the targeted follow-up.

Tests use synthetic observations and Botocore Stubber with network connections blocked. No live AWS assessment has been performed. Initial live-account validation remains pending explicit account access and authorisation.

The GitHub workflow covers Python 3.12, 3.13 and 3.14 on Windows and Linux. Its actual run status is visible on the pull request; the local results above do not claim a GitHub-hosted run succeeded.
