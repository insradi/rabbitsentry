"""Offline, escaped HTML and exclusive local output creation."""

import json
import tempfile
from collections import Counter
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from rabbitsentry.models import Assessment


def render_report(assessment: Assessment) -> str:
    env = Environment(
        loader=PackageLoader("rabbitsentry", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
    )
    env.filters["pretty"] = lambda value: json.dumps(value, ensure_ascii=False, indent=2)
    ranks = {
        value: index
        for index, value in enumerate(("critical", "high", "medium", "low", "informational"))
    }
    ordered = sorted(
        assessment.results,
        key=lambda r: (ranks[r.severity], r.check_id, r.resource.region, r.resource.identifier),
    )
    return env.get_template("report.html").render(
        report=assessment,
        results=ordered,
        counts=Counter(result.status for result in assessment.results),
        coverage_counts=Counter(c.state for c in assessment.coverage),
    )


def load_assessment(path: Path) -> Assessment:
    report = Assessment.model_validate_json(Path(path).read_text(encoding="utf-8"))
    if report.finished_at is None:
        raise ValueError("Input is not a finished assessment")
    return report


def write_html(assessment: Assessment, path: Path) -> Path:
    path = Path(path)
    html = render_report(assessment)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(html)
    return path


def write_assessment(assessment: Assessment, output_root: Path | None = None) -> Path:
    # Render before creating files; the JSON remains available if a later disk write fails.
    html = render_report(assessment)
    payload = assessment.model_dump_json(indent=2)
    root = Path(output_root) if output_root is not None else Path("reports") / assessment.account_id
    root.mkdir(parents=True, exist_ok=True)
    prefix = assessment.started_at.strftime("%Y%m%dT%H%M%SZ-") + assessment.run_id[:8] + "-"
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    with (directory / "assessment.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload + "\n")
    with (directory / "report.html").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(html)
    return directory.resolve()
