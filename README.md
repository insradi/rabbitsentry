# RabbitSentry

A modular, read-only infrastructure assessment CLI, starting with AWS.

RabbitSentry is intended to help technicians inspect customer infrastructure and produce reports with supporting evidence, recommended actions, and clear coverage gaps. Continuous server monitoring and other integrations can be added later.

## Project status

This is the initial project repository. The first-release design has been drafted and reviewed; application code has not been implemented yet.

## Proposed first release

- A Python CLI using existing AWS authentication profiles.
- Four modules covering IAM, network configuration, EC2/EBS, and RDS.
- Twelve initial checks with separate failure, review, and unknown results.
- Local HTML and versioned JSON reports.
- A synthetic demonstration that requires no AWS account.
- An independent core with optional integrations and no required AI service.

## Design

Read the [AWS assessment CLI design](docs/superpowers/specs/2026-11-08-rabbitsentry-aws-assessment-design.md) for the proposed checks, interfaces, permissions, reporting behaviour, and acceptance criteria.

Customer credentials, live assessment reports, and downloaded customer data do not belong in this repository.
