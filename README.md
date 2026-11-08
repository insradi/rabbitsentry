# RabbitSentry

A local, read-only AWS assessment CLI for technicians. Evaluate twelve focused checks and produce an HTML report with a versioned JSON evidence file. No AI service or hosted backend is required.

## Project status

The first implementation supports Windows and Linux with Python 3.12+. It is tested with synthetic observations and AWS SDK stubs; live customer-account validation is still pending.

## Install and try it

```console
python -m venv .venv
```

Activate the environment (`.venv\Scripts\Activate.ps1` in PowerShell, or `source .venv/bin/activate` on Linux), then:

```console
python -m pip install .
rabbitsentry modules list
rabbitsentry demo --output ./reports/demo
```

The demo makes no network requests and needs no credentials. Open `report.html` in the new directory printed by the command. Every demo report is labelled as synthetic.

## Assess an authorised AWS account

Use an existing AWS profile or the SDK's standard credential chain. The supplied [read policy](permissions/aws-readonly.json) lists the assessment operations.

```console
rabbitsentry assess aws --profile customer-readonly --regions eu-west-1,eu-central-1 --expected-account 123456789012 --output ./reports/customer
rabbitsentry report ./reports/customer/RUN/assessment.json --output ./reports/customer/regenerated.html
```

Each run creates a new directory containing `assessment.json` and a self-contained `report.html`. Reports remain local. RabbitSentry does not change AWS infrastructure, execute server commands, retrieve secrets, or upload results.

## Initial catalogue

- Four modules covering IAM, network configuration, EC2/EBS, and RDS.
- Twelve initial checks with separate failure, review, and unknown results.
- Local HTML and versioned JSON reports.
- A synthetic demonstration that requires no AWS account.
- An independent core with optional integrations and no required AI service.

Missing permissions cannot produce a passing result. A completed report means selected supported work finished; it is not comprehensive security assurance. Backup freshness, restoration, application security and continuous server monitoring are outside this release.

## Development

```console
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
python -m pytest -q
python -m ruff check .
python -m ruff format --check --quiet .
python -m build
```

Tests block network access. The GitHub workflow runs tests and an installed-package demo on Windows and Linux.

See [usage and permissions](docs/usage.md), [module development](docs/modules.md), and the [approved design](docs/superpowers/specs/2026-11-08-rabbitsentry-aws-assessment-design.md).

Customer credentials, live assessment reports, and downloaded customer data do not belong in this repository.
