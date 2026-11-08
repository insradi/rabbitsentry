"""User commands; offline commands never construct an AWS session."""

from pathlib import Path
from typing import Annotated

import typer
from botocore.exceptions import BotoCoreError
from pydantic import ValidationError

from rabbitsentry import __version__
from rabbitsentry.demo import build_demo
from rabbitsentry.models import Policy
from rabbitsentry.modules import REGISTRY
from rabbitsentry.reporting import load_assessment, write_assessment, write_html
from rabbitsentry.runner import AssessmentFailed, InvalidConfiguration, run_assessment

app = typer.Typer(
    help="RabbitSentry: read-only AWS assessments and local evidence-based reports.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
assessment_app = typer.Typer(help="Assess authorised infrastructure using read operations.")
module_app = typer.Typer(help="Inspect the bundled module catalogue.")
app.add_typer(assessment_app, name="assess")
app.add_typer(module_app, name="modules")


def make_provider(profile):
    import boto3

    from rabbitsentry.aws.provider import AwsProvider

    return AwsProvider(boto3.Session(profile_name=profile))


def announce_output(report, directory):
    typer.echo(f"Assessment {report.run_status}. JSON and HTML saved to: {directory}")
    typer.echo(
        "Complete means selected supported work finished; it is not a security certification."
    )


@module_app.command("list")
def list_modules():
    """List bundled modules and their checks without contacting AWS."""
    typer.echo(f"RabbitSentry {__version__} | model 1.0")
    for spec in REGISTRY.values():
        typer.echo(f"{spec.id}  v{spec.version}  {spec.scope}  {', '.join(spec.checks)}")


@assessment_app.command("aws")
def assess_aws(
    regions: Annotated[
        str, typer.Option(help="Comma-separated commercial regions, or all-enabled.")
    ],
    profile: Annotated[
        str | None,
        typer.Option(help="Existing AWS profile; otherwise use the standard credential chain."),
    ] = None,
    expected_account: Annotated[
        str | None, typer.Option(help="Require this 12-digit account before inventory reads.")
    ] = None,
    modules: Annotated[
        str | None, typer.Option(help="Comma-separated module IDs; defaults to all modules.")
    ] = None,
    key_age_days: Annotated[
        int, typer.Option(min=1, help="Age threshold for active-key review.")
    ] = 90,
    output: Annotated[
        Path | None,
        typer.Option(help="Root for a new run directory; existing reports are preserved."),
    ] = None,
):
    """Assess one AWS account. Does not modify AWS infrastructure."""
    try:
        provider = make_provider(profile)
        report = run_assessment(
            provider,
            regions,
            modules=[m.strip() for m in modules.split(",")] if modules is not None else None,
            expected_account=expected_account,
            policy=Policy(key_age_days=key_age_days),
            on_identity=lambda account, principal: typer.echo(
                f"Account: {account}\nIdentity: {principal}"
            ),
        )
        directory = write_assessment(report, output)
        announce_output(report, directory)
    except InvalidConfiguration as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from None
    except AssessmentFailed as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    except BotoCoreError as exc:
        typer.echo(
            f"AWS configuration/authentication failed ({type(exc).__name__}). Check your profile or session.",
            err=True,
        )
        raise typer.Exit(1) from None
    except OSError as exc:
        typer.echo(
            f"Could not save the requested report ({type(exc).__name__}). Check the output location.",
            err=True,
        )
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        typer.echo("Cancelled before a report could be saved.", err=True)
        raise typer.Exit(130) from None
    raise typer.Exit({"complete": 0, "partial": 3, "cancelled": 130}[report.run_status])


@app.command("demo")
def demo(
    output: Annotated[
        Path | None, typer.Option(help="Root for the synthetic report directory.")
    ] = None,
):
    """Create a clearly labelled synthetic report. No credentials or network needed."""
    try:
        report = build_demo()
        directory = write_assessment(report, output or Path("reports") / "demo")
        announce_output(report, directory)
    except OSError as exc:
        typer.echo(f"Could not save demonstration ({type(exc).__name__}).", err=True)
        raise typer.Exit(1) from None


@app.command("report")
def report_command(
    source: Annotated[Path, typer.Argument(help="Existing assessment.json file.")],
    output: Annotated[Path, typer.Option(help="New HTML path; must not already exist.")],
):
    """Regenerate HTML from validated JSON offline, preserving the original run status."""
    try:
        report = load_assessment(source)
        destination = write_html(report, output)
        typer.echo(f"HTML saved to: {destination.resolve()} (original status: {report.run_status})")
    except (OSError, ValueError, ValidationError) as exc:
        typer.echo(
            f"Could not render report ({type(exc).__name__}). Use a finished schema 1.0 report and a new output path.",
            err=True,
        )
        raise typer.Exit(1) from None
