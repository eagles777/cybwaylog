"""HTML timeline report tests: self-contained, complete, honest."""

import json
import re

import pytest

from cybwaylog.engine import run_scan
from cybwaylog.report import build_report_data, render_report_html, write_report
from cybwaylog.synthlog import create_synthetic_log


@pytest.fixture
def run_dir(tmp_path):
    out = tmp_path / "run"
    run_scan(create_synthetic_log(), out)
    return out


def test_write_report_creates_file(run_dir, tmp_path):
    out = write_report(run_dir, tmp_path / "report.html")
    assert out.exists() and out.stat().st_size > 5000


def test_report_contains_every_fired_rule(run_dir, tmp_path):
    detections = json.loads((run_dir / "detections.json").read_text())
    fired = [d["rule_id"] for d in detections if d["status"] == "FAIL"]
    assert fired, "fixture should produce incidents"
    html = write_report(run_dir, tmp_path / "r.html").read_text(encoding="utf-8")
    for rid in fired:
        assert rid in html, f"{rid} missing from report"


def test_report_is_attributed_and_marked_synthetic(run_dir, tmp_path):
    html = write_report(run_dir, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "V. Vikram" in html
    assert "Synthetic data only" in html
    assert "Apache-2.0" in html


def test_report_loads_no_external_assets(run_dir, tmp_path):
    """Self-contained: no remote scripts, styles, images, or fonts."""
    html = write_report(run_dir, tmp_path / "r.html").read_text(encoding="utf-8")
    assert not re.search(r'(src|href)\s*=\s*["\']https?://', html)
    assert "<script" not in html.lower()


def test_report_shows_integrity_status(run_dir, tmp_path):
    html = write_report(run_dir, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "hash chain intact" in html
    assert "Run manifest verified" in html


def test_report_marks_response_as_not_executed(run_dir, tmp_path):
    """The report must never imply remediation was carried out."""
    html = write_report(run_dir, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "advisory — not executed" in html
    assert "awaiting human decision" in html


def test_clean_log_report_says_no_incidents(tmp_path):
    out = tmp_path / "clean"
    run_scan(create_synthetic_log(incidents=False), out)
    data = build_report_data(out, mock_runs=2)
    assert data["incident_count"] == 0
    html = render_report_html(data)
    assert "no incidents detected" in html


def test_embed_variant_has_no_html_wrapper(run_dir):
    data = build_report_data(run_dir, mock_runs=2)
    embed = render_report_html(data, embed=True)
    assert embed.lstrip().startswith("<style>")
    assert "<!doctype" not in embed.lower()


def test_timeline_is_chronological(run_dir):
    data = build_report_data(run_dir, mock_runs=2)
    stamps = [d["first_seen"] for d in data["timeline"]]
    assert stamps == sorted(stamps)


def test_triage_order_is_by_risk_score(run_dir):
    """Ranking order is what the top-1 benchmark measures — keep them consistent."""
    data = build_report_data(run_dir, mock_runs=2)
    scores = [d["risk_score"] for d in data["fired"]]
    assert scores == sorted(scores, reverse=True)
