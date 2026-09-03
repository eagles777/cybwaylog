"""CLI tests: init-log + scan --db, --clean, verify, benchmark, redteam,
controls, and the live-demo refusal ladder. All offline, $0."""

import json
import sqlite3
from pathlib import Path

import pytest

from cybwaylog.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_init_log_then_scan_reflects_edits(tmp_path):
    db = tmp_path / "mylog.sqlite"
    assert main(["init-log", "--out", str(db)]) == 0
    assert db.exists()

    # edit the log: remove the orphan-session DELETE (the CYL-012 incident)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM unified_audit_trail "
                 "WHERE session_id IS NOT NULL AND session_id NOT IN (SELECT session_id FROM dba_audit_session)")
    conn.commit()
    conn.close()

    out = tmp_path / "run"
    assert main(["scan", "--db", str(db), "--out", str(out)]) == 0
    detections = {d["rule_id"]: d for d in json.loads((out / "detections.json").read_text())}
    assert detections["CYL-012"]["status"] == "PASS" and detections["CYL-012"]["evidence"] == []
    assert sum(1 for d in detections.values() if d["status"] == "FAIL") == 13


def test_scan_without_db_uses_builtin_synthetic_log(tmp_path, capsys):
    out = tmp_path / "run"
    assert main(["scan", "--out", str(out)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["failed"] == 14 and summary["top_incident"] == "CYL-014"
    assert main(["verify", "--run-dir", str(out)]) == 0


def test_scan_clean_gives_zero_detections(tmp_path, capsys):
    out = tmp_path / "run"
    assert main(["scan", "--clean", "--out", str(out)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["failed"] == 0 and summary["passed"] == 14


def test_verify_detects_tampered_run(tmp_path, capsys):
    out = tmp_path / "run"
    main(["scan", "--out", str(out)])
    capsys.readouterr()
    (out / "detections.json").write_text("[]")
    assert main(["verify", "--run-dir", str(out)]) == 1


def test_benchmark_prints_headline_metrics(capsys):
    assert main(["benchmark", "--runs", "5", "--seed", "1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert {"precision", "recall", "f1", "top1_ranking_accuracy", "alert_fatigue_per_1000"} <= set(result)
    assert "per_run" not in result and result["cost_usd"] == 0


def test_redteam_command_catches_the_canary(capsys):
    assert main(["redteam"]) == 0
    hits = json.loads(capsys.readouterr().out)["injection_hits"]
    assert any(h["id"] == "RT-01" for h in hits)


def test_controls_command_is_clean_on_repo(capsys):
    assert main(["controls", "--root", str(REPO_ROOT)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"secret_scan_hits": [], "policy_violations": []}


# ---------- live-demo refusal ladder (no network, ever) ----------

@pytest.fixture
def no_live_env(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("CYBWAYLOG_ALLOW_SPEND", raising=False)


def test_live_demo_refuses_without_confirmation_flag(no_live_env, capsys):
    assert main(["live-demo"]) == 1
    assert "Refusing" in capsys.readouterr().out


def test_live_demo_refuses_positive_budget_without_env_override(no_live_env, capsys):
    assert main(["live-demo", "--i-understand-costs", "--budget", "0.50"]) == 1
    out = capsys.readouterr().out
    assert "Refusing" in out and "$0.00" in out


def test_live_demo_refuses_without_free_tier_key(no_live_env, capsys):
    assert main(["live-demo", "--i-understand-costs"]) == 1
    assert "GOOGLE_API_KEY" in capsys.readouterr().out


def test_live_demo_default_budget_is_zero():
    from cybwaylog.budget import DEFAULT_CEILING_USD
    assert DEFAULT_CEILING_USD == 0.0
