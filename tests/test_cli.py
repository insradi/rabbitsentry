from unittest.mock import Mock

import boto3
import pytest
from typer.testing import CliRunner

from rabbitsentry import cli
from rabbitsentry.demo import build_demo
from rabbitsentry.runner import AssessmentFailed, InvalidConfiguration

runner = CliRunner()


def test_help_modules_demo_and_offline_report_never_resolve_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(
        boto3, "Session", Mock(side_effect=AssertionError("No SDK session allowed"))
    )
    assert runner.invoke(cli.app, ["--help"]).exit_code == 0
    listed = runner.invoke(cli.app, ["modules", "list"])
    assert listed.exit_code == 0 and "aws.database" in listed.output
    demo = runner.invoke(cli.app, ["demo", "--output", str(tmp_path)])
    assert demo.exit_code == 0, demo.output
    source = next(tmp_path.glob("*/assessment.json"))
    target = tmp_path / "offline.html"
    result = runner.invoke(cli.app, ["report", str(source), "--output", str(target)])
    assert result.exit_code == 0 and target.exists()


@pytest.mark.parametrize("status,expected", [("complete", 0), ("partial", 3), ("cancelled", 130)])
def test_assess_exit_status_and_saved_report(status, expected, tmp_path, monkeypatch):
    report = build_demo()
    report.run_status = status
    monkeypatch.setattr(cli, "make_provider", lambda profile: object())
    monkeypatch.setattr(cli, "run_assessment", lambda *args, **kwargs: report)
    result = runner.invoke(
        cli.app, ["assess", "aws", "--regions", "eu-west-1", "--output", str(tmp_path)]
    )
    assert result.exit_code == expected, result.output
    assert len(list(tmp_path.glob("*/assessment.json"))) == 1


@pytest.mark.parametrize(
    "exception,expected",
    [
        (InvalidConfiguration("invalid"), 2),
        (AssessmentFailed("identity failed"), 1),
        (KeyboardInterrupt(), 130),
    ],
)
def test_bootstrap_errors_have_defined_exit_codes(exception, expected, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "make_provider", lambda profile: object())
    monkeypatch.setattr(cli, "run_assessment", Mock(side_effect=exception))
    result = runner.invoke(
        cli.app, ["assess", "aws", "--regions", "eu-west-1", "--output", str(tmp_path)]
    )
    assert result.exit_code == expected, result.output
    assert not list(tmp_path.iterdir())


def test_required_scope_and_policy_validated(tmp_path):
    assert runner.invoke(cli.app, ["assess", "aws"]).exit_code == 2
    assert (
        runner.invoke(
            cli.app, ["assess", "aws", "--regions", "eu-west-1", "--key-age-days", "0"]
        ).exit_code
        == 2
    )


def test_output_failure_takes_precedence_over_cancellation(monkeypatch, tmp_path):
    report = build_demo()
    report.run_status = "cancelled"
    monkeypatch.setattr(cli, "make_provider", lambda profile: object())
    monkeypatch.setattr(cli, "run_assessment", lambda *args, **kwargs: report)
    monkeypatch.setattr(cli, "write_assessment", Mock(side_effect=PermissionError("private")))
    result = runner.invoke(
        cli.app, ["assess", "aws", "--regions", "eu-west-1", "--output", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "private" not in result.output
