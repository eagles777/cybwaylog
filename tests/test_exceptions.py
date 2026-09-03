"""Exception (NIST CA-5-style, public structure) tests.

Covers every promise made in the spec:
- fourth decision path with mandatory paperwork
- blank fields rejected
- everything logged to the tamper-evident chain
- exception expires at review_date -> incident is open again
- an accepted exception is NOT a confirmation: no response dry-run
- AI can only DRAFT the paperwork; a draft can never be accepted as-is
"""

from datetime import date

import pytest

from cybwaylog.agents import VERDICT_PASS, draft_exception
from cybwaylog.auditlog import AuditLog
from cybwaylog.gate import ApprovalGate, ApprovalRequired, IncompleteRiskAcceptance
from cybwaylog.rules import run_all_rules
from cybwaylog.synthlog import create_synthetic_log

PAPERWORK = dict(
    justification="Synthetic reporting job RPT_RO_FAKE legitimately opens many short sessions on month-end.",
    compensating_control="Sessions limited to WS-RPT-FAKE; per-session row counts monitored.",
    accepted_by="reviewer",
    review_date="2026-10-01",
)


@pytest.fixture
def gate_and_incident(tmp_path):
    gate = ApprovalGate(AuditLog(tmp_path / "a.jsonl"))
    incident = next(d for d in run_all_rules(create_synthetic_log()) if d.rule_id == "CYL-011").to_dict()
    gate.submit(incident, VERDICT_PASS)
    return gate, incident


def test_exception_happy_path_is_logged(gate_and_incident):
    gate, inc = gate_and_incident
    gate.accept_exception(inc["rule_id"], **PAPERWORK)
    assert gate.status(inc["rule_id"], as_of=date(2026, 7, 17)) == "exception_accepted"
    events = [e["event"] for e in gate.log.entries()]
    assert events[-1] == "incident_exception_accepted"
    logged = gate.log.entries()[-1]["detail"]
    assert logged["accepted_by"] == "reviewer" and logged["review_date"] == "2026-10-01"
    ok, msg = gate.log.verify_chain()
    assert ok, msg


@pytest.mark.parametrize("blank_field", ["justification", "compensating_control", "accepted_by", "review_date"])
def test_blank_paperwork_field_is_rejected(gate_and_incident, blank_field):
    gate, inc = gate_and_incident
    incomplete = {**PAPERWORK, blank_field: "   "}
    with pytest.raises(IncompleteRiskAcceptance, match=blank_field):
        gate.accept_exception(inc["rule_id"], **incomplete)
    assert gate.status(inc["rule_id"]) == "pending"  # nothing changed
    assert [e["event"] for e in gate.log.entries()] == ["incident_submitted"]  # nothing logged


def test_invalid_review_date_is_rejected(gate_and_incident):
    gate, inc = gate_and_incident
    with pytest.raises(ValueError):
        gate.accept_exception(inc["rule_id"], **{**PAPERWORK, "review_date": "next quarter"})
    assert gate.status(inc["rule_id"]) == "pending"


def test_exception_expires_and_incident_reopens(gate_and_incident):
    gate, inc = gate_and_incident
    gate.accept_exception(inc["rule_id"], **PAPERWORK)
    rid = inc["rule_id"]
    assert gate.status(rid, as_of=date(2026, 10, 1)) == "exception_accepted"   # on the review date
    assert gate.status(rid, as_of=date(2026, 10, 2)) == "expired"              # day after
    assert rid in gate.open_incidents(as_of=date(2026, 10, 2))
    assert rid not in gate.open_incidents(as_of=date(2026, 9, 1))


def test_accepted_exception_still_cannot_dry_run_response(gate_and_incident):
    gate, inc = gate_and_incident
    gate.accept_exception(inc["rule_id"], **PAPERWORK)
    with pytest.raises(ApprovalRequired):
        gate.dry_run_response(inc)  # accepted exception != confirmed incident


def test_unsubmitted_incident_cannot_receive_exception(tmp_path):
    gate = ApprovalGate(AuditLog(tmp_path / "a.jsonl"))
    with pytest.raises(KeyError):
        gate.accept_exception("CYL-011", **PAPERWORK)


def test_ai_draft_is_unsigned_and_rejected_as_is(gate_and_incident):
    gate, inc = gate_and_incident
    draft = draft_exception(inc)
    assert draft["draft"] is True and draft["accepted_by"] == "" and draft["review_date"] == ""
    assert draft["rule_id"] == inc["rule_id"] and "[DRAFT" in draft["justification"]
    with pytest.raises(IncompleteRiskAcceptance):
        gate.accept_exception(inc["rule_id"], justification=draft["justification"],
                              compensating_control=draft["compensating_control"],
                              accepted_by=draft["accepted_by"], review_date=draft["review_date"])
    assert gate.status(inc["rule_id"]) == "pending"


def test_human_completed_draft_is_accepted(gate_and_incident):
    gate, inc = gate_and_incident
    draft = draft_exception(inc)
    gate.accept_exception(inc["rule_id"], justification=draft["justification"],
                          compensating_control="Synthetic host restriction + per-session row monitoring.",
                          accepted_by="reviewer", review_date="2026-10-01")
    assert gate.status(inc["rule_id"], as_of=date(2026, 7, 17)) == "exception_accepted"
    assert gate.log.entries()[-1]["detail"]["accepted_by"] == "reviewer"
