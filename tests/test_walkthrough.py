"""The published walkthrough must keep telling the truth.

If a rule changes and the example's claims stop holding, this fails the build
rather than letting the repository ship a demo that no longer does what its
narration says.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from cybwaylog.rules import run_all_rules
from cybwaylog.synthlog import create_synthetic_log

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from insider_threat_walkthrough import fired, inject_insider_scenario  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "examples" / "insider_threat_walkthrough.py"


@pytest.fixture
def clean():
    return create_synthetic_log(incidents=False)


def test_clean_trail_produces_no_detections(clean):
    assert fired(clean) == []


def test_injection_produces_the_four_documented_detections(clean):
    inject_insider_scenario(clean)
    ids = {d.rule_id for d in fired(clean)}
    assert ids == {"CYL-001", "CYL-004", "CYL-006", "CYL-014"}


def test_correlation_ranks_first(clean):
    """The walkthrough's central claim."""
    inject_insider_scenario(clean)
    assert fired(clean)[0].rule_id == "CYL-014"


def test_correlation_needs_both_halves(clean):
    """Remove the audit-off half and the correlation must stop firing."""
    inject_insider_scenario(clean)
    clean.execute("DELETE FROM unified_audit_trail WHERE action_name='NOAUDIT'")
    clean.execute("UPDATE audit_policy_state SET enabled=1 WHERE policy_name='ORA_LOGON_FAILURES'")
    clean.commit()
    ids = {d.rule_id for d in fired(clean)}
    assert "CYL-014" not in ids
    assert "CYL-004" in ids  # the export alone still stands


def test_evidence_cites_real_injected_values(clean):
    inject_insider_scenario(clean)
    export = next(d for d in fired(clean) if d.rule_id == "CYL-004")
    joined = " ".join(export.evidence)
    assert "1,200,000" in joined
    assert "SALARIES_FAKE" in joined
    assert "DBA_ONE_FAKE" in joined


def test_script_runs_end_to_end_offline():
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert "0" in r.stdout and "CYL-014" in r.stdout
    assert "never executed" in r.stdout
