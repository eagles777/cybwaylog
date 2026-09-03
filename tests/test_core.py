"""Core test suite: synthetic activity log, rule engine, tamper-evident audit
log, manifest, and repo-hygiene controls. All offline, $0."""

import hashlib
import json
import re
from pathlib import Path

import pytest

from cybwaylog.auditlog import AuditLog, verify_manifest, write_manifest
from cybwaylog.controls import policy_lint, secret_scan
from cybwaylog.engine import run_scan
from cybwaylog.rules import FAIL, PASS, RISK_BANDS, RULES, run_all_rules, top_incident
from cybwaylog.synthlog import SCAN_DATE, USERS, create_synthetic_log

RULE_IDS = [f"CYL-{i:03d}" for i in range(1, 15)]
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def seeded():
    return create_synthetic_log()


@pytest.fixture(scope="module")
def clean():
    return create_synthetic_log(incidents=False)


@pytest.fixture(scope="module")
def seeded_detections(seeded):
    return {d.rule_id: d for d in run_all_rules(seeded)}


@pytest.fixture(scope="module")
def clean_detections(clean):
    return {d.rule_id: d for d in run_all_rules(clean)}


def _fingerprint(conn) -> str:
    h = hashlib.sha256()
    for table in ("unified_audit_trail", "dba_audit_session", "audit_policy_state"):
        for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1"):
            h.update(repr(row).encode())
    return h.hexdigest()


# ---------- synthetic log ----------

def test_synthetic_log_has_expected_tables(seeded):
    tables = {r[0] for r in seeded.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"unified_audit_trail", "dba_audit_session", "dba_users_snapshot", "audit_policy_state",
            "change_windows", "sensitive_objects", "db_metadata"} <= tables


def test_synthetic_data_is_fake_only(seeded):
    users = {r[0] for r in seeded.execute("SELECT DISTINCT dbusername FROM unified_audit_trail")}
    users |= {r[0] for r in seeded.execute("SELECT username FROM dba_users_snapshot")}
    assert users and all(u.endswith("_FAKE") for u in users)
    hosts = {r[0] for r in seeded.execute("SELECT DISTINCT userhost FROM unified_audit_trail")}
    assert all("fake" in h.lower() for h in hosts)
    ips = {r[0] for r in seeded.execute("SELECT DISTINCT client_ip FROM unified_audit_trail")}
    assert all(ip.startswith("10.") for ip in ips)  # private range only


def test_scan_date_is_frozen(seeded):
    meta = dict(seeded.execute("SELECT key, value FROM db_metadata"))
    assert meta["scan_date"] == SCAN_DATE == "2026-07-17"


def test_synthetic_log_is_deterministic_per_seed():
    a, b, c = create_synthetic_log(seed=42), create_synthetic_log(seed=42), create_synthetic_log(seed=7)
    assert _fingerprint(a) == _fingerprint(b)
    assert _fingerprint(a) != _fingerprint(c)


def test_baseline_covers_fourteen_days_and_eight_accounts(clean):
    days = {r[0][:10] for r in clean.execute("SELECT event_ts FROM unified_audit_trail")}
    assert len(days) == 14
    assert clean.execute("SELECT COUNT(*) FROM dba_users_snapshot").fetchone()[0] == len(USERS) == 8
    n = clean.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    assert n > 1000


def test_seeded_log_is_a_superset_of_the_baseline(seeded, clean):
    n_seeded = seeded.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    n_clean = clean.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    assert n_seeded > n_clean


# ---------- rule engine ----------

def test_rule_count_and_ids_in_order(seeded_detections):
    assert len(RULES) == 14
    assert list(seeded_detections) == RULE_IDS


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_fires_on_its_seeded_incident(seeded_detections, rule_id):
    d = seeded_detections[rule_id]
    assert d.status == FAIL, d
    assert d.evidence and d.accounts and d.first_seen and d.recommended_response


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_does_not_fire_on_clean_log(clean_detections, rule_id):
    d = clean_detections[rule_id]
    assert d.status == PASS, d.evidence
    assert d.evidence == [] and d.event_ids == [] and d.recommended_response == ""


def test_clean_log_yields_zero_detections(clean):
    assert [d.rule_id for d in run_all_rules(clean) if d.status == FAIL] == []


def test_seeded_log_fires_every_rule(seeded_detections):
    assert all(d.status == FAIL for d in seeded_detections.values())


def test_evidence_references_real_row_values(seeded, seeded_detections):
    users = {r[0] for r in seeded.execute("SELECT DISTINCT dbusername FROM unified_audit_trail")}
    event_ids = {r[0] for r in seeded.execute("SELECT event_id FROM unified_audit_trail")}
    for d in seeded_detections.values():
        assert set(d.accounts) <= users, d.rule_id
        assert set(d.event_ids) <= event_ids, d.rule_id
        for text in d.evidence:
            assert any(acct in text for acct in d.accounts), (d.rule_id, text)
            for eid in re.findall(r"\bevent (\d+)\b", text):
                assert int(eid) in event_ids, (d.rule_id, eid)


def test_evidence_never_leaks_free_text_fields(seeded_detections):
    for d in seeded_detections.values():
        for text in d.evidence:
            assert "IGNORE ALL PREVIOUS" not in text.upper()
            assert "client_info" not in text


def test_detections_carry_nist_and_mitre_references(seeded_detections):
    for d in seeded_detections.values():
        assert any("NIST 800-53" in r for r in d.references), d.rule_id
        assert any(re.search(r"MITRE ATT&CK T\d{4}", r) for r in d.references), d.rule_id


def test_severity_and_risk_scores_are_consistent_and_unique(seeded_detections):
    scores = [d.risk_score for d in seeded_detections.values()]
    assert len(scores) == len(set(scores))
    for d in seeded_detections.values():
        lo, hi = RISK_BANDS[d.severity]
        assert lo <= d.risk_score <= hi, d.rule_id
    assert {d.severity for d in seeded_detections.values()} == {"high", "medium", "low"}


def test_top_incident_is_the_correlation_rule(seeded_detections, clean_detections):
    assert top_incident(list(seeded_detections.values())) == "CYL-014"
    assert top_incident(list(clean_detections.values())) is None


def test_detections_serialize_to_json(seeded_detections):
    payload = json.dumps([d.to_dict() for d in seeded_detections.values()])
    assert '"CYL-001"' in payload


def test_correlation_rule_needs_both_halves(seeded):
    # remove the audit-off event -> CYL-006 and CYL-014 pass, CYL-004 still fails
    conn = create_synthetic_log()
    conn.execute("DELETE FROM unified_audit_trail WHERE action_name = 'NOAUDIT'")
    conn.execute("UPDATE audit_policy_state SET enabled = 1")
    conn.commit()
    status = {d.rule_id: d.status for d in run_all_rules(conn)}
    assert status["CYL-006"] == PASS and status["CYL-014"] == PASS and status["CYL-004"] == FAIL


# ---------- audit log: hash chain + tamper detection ----------

def test_audit_chain_verifies_when_intact(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append("event", {"i": i})
    ok, msg = log.verify_chain()
    assert ok, msg


def test_log_tamper_detection_modified_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", {"i": i})
    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["detail"]["i"] = 999  # attacker edits a historical entry
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    ok, msg = log.verify_chain()
    assert not ok and "entry 3" in msg


def test_log_tamper_detection_deleted_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", {"i": i})
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _ = log.verify_chain()
    assert not ok


def test_log_tamper_detection_reordered_entries(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.append("event", {"i": i})
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _ = log.verify_chain()
    assert not ok


# ---------- manifest ----------

def test_manifest_roundtrip_and_tamper_detection(tmp_path):
    (tmp_path / "detections.json").write_text('{"a": 1}')
    write_manifest(tmp_path)
    ok, problems = verify_manifest(tmp_path)
    assert ok, problems
    (tmp_path / "detections.json").write_text('{"a": 2}')  # tamper
    ok, problems = verify_manifest(tmp_path)
    assert not ok and "detections.json" in problems[0]


# ---------- engine end-to-end ----------

def test_run_scan_end_to_end(tmp_path):
    summary = run_scan(create_synthetic_log(), tmp_path)
    assert summary["mode"] == "mock" and summary["cost_usd"] == 0
    assert summary["failed"] == summary["total"] == len(RULES)
    assert sum(summary["by_severity"].values()) == 14
    assert summary["top_incident"] == "CYL-014" and summary["events_scanned"] > 1000
    detections = json.loads((tmp_path / "detections.json").read_text())
    assert [d["rule_id"] for d in detections] == RULE_IDS
    ok, msg = AuditLog(tmp_path / "audit.log.jsonl").verify_chain()
    assert ok, msg
    ok, problems = verify_manifest(tmp_path)
    assert ok, problems


def test_run_scan_clean_log_reports_nothing(tmp_path):
    summary = run_scan(create_synthetic_log(incidents=False), tmp_path)
    assert summary["failed"] == 0 and summary["passed"] == 14
    assert summary["by_severity"] == {"high": 0, "medium": 0, "low": 0}
    assert summary["top_incident"] is None


# ---------- controls ----------

def test_secret_scan_detects_planted_secret(tmp_path):
    bad = tmp_path / "config.py"
    planted = 'API_KEY = "sk-ant-' + "abcdefghijklmnop1234" + '"\n'  # split so repo scan skips it
    bad.write_text(planted)
    hits = secret_scan(tmp_path)
    assert hits and hits[0]["pattern"] == "anthropic_api_key"


def test_secret_scan_repo_is_clean():
    assert secret_scan(REPO_ROOT) == []


def test_policy_lint_repo_is_clean():
    assert policy_lint(REPO_ROOT) == []


def test_policy_lint_detects_unignored_env(tmp_path):
    (tmp_path / ".env").write_text("X=1\n")
    violations = policy_lint(tmp_path)
    assert violations and ".env" in violations[0]["term"]


def test_policy_lint_flags_email_like_string(tmp_path):
    (tmp_path / "notes.md").write_text("contact: someone" + "@" + "example.test\n")
    violations = policy_lint(tmp_path)
    assert [v["term"] for v in violations] == ["email-like string"]


@pytest.mark.parametrize("parts", [("citi", "zen"), ("emplo", "yer")])  # joined at runtime: the repo must not contain them
def test_policy_lint_flags_personal_info_words(tmp_path, parts):
    word = "".join(parts)
    (tmp_path / "README.md").write_text(f"The author's {word} status is not your business.\n")
    violations = policy_lint(tmp_path)
    assert [v["term"] for v in violations] == [word]
