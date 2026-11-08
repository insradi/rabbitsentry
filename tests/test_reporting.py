import json

import pytest
from pydantic import ValidationError

from rabbitsentry.demo import build_demo
from rabbitsentry.models import Assessment
from rabbitsentry.reporting import load_assessment, render_report, write_assessment, write_html


def test_demo_covers_twelve_checks_and_json_roundtrips(tmp_path):
    report = build_demo()
    assert report.demonstration
    assert len({r.check_id for r in report.results}) == 12
    assert {r.status for r in report.results} >= {"pass", "fail", "review", "not_applicable"}
    directory = write_assessment(report, tmp_path)
    loaded = load_assessment(directory / "assessment.json")
    assert loaded == report
    assert "SYNTHETIC DEMONSTRATION" in (directory / "report.html").read_text(encoding="utf-8")
    assert "secret_access_key" not in (directory / "assessment.json").read_text(encoding="utf-8")


def test_html_escapes_aws_strings_and_preserves_status():
    report = build_demo()
    report.principal = '<script>alert("private")</script>'
    report.results[0].title = '<img src=x onerror="alert(1)">'
    for status in ("complete", "partial", "cancelled"):
        report.run_status = status
        html = render_report(report)
        assert "<script>alert(" not in html and "<img src=x" not in html
        assert "&lt;script&gt;" in html and "&lt;img" in html
        assert status.upper() in html
        assert "<script src=" not in html and "<link " not in html


def test_writers_never_overwrite_existing_files(tmp_path):
    report = build_demo()
    first = write_assessment(report, tmp_path)
    second = write_assessment(report, tmp_path)
    assert first != second
    destination = tmp_path / "customer.html"
    destination.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_html(report, destination)
    assert destination.read_text() == "keep"


def test_offline_import_rejects_unsupported_and_unfinished_reports(tmp_path):
    report = build_demo().model_dump(mode="json")
    path = tmp_path / "input.json"
    report["schema_version"] = "2.0"
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_assessment(path)
    unfinished = Assessment(account_id="123456789012", principal="test")
    path.write_text(unfinished.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="finished"):
        load_assessment(path)
