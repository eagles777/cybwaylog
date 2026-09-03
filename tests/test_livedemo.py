"""Live-demo guardrail tests. ALL OFFLINE — the network layer is replaced by
a fake transport; no real API call is ever made in tests or CI."""

import json

import pytest

from cybwaylog.agents import CheckerAgent
from cybwaylog.auditlog import AuditLog
from cybwaylog.budget import BudgetCeiling, BudgetExceeded
from cybwaylog.livedemo import build_prompt, event_snapshot, run_live_demo, withheld_event_ids
from cybwaylog.providers import FreeTierQuotaExhausted, GeminiProvider
from cybwaylog.redteam import CANARY_COMMENT
from cybwaylog.rules import FAIL, SEVERITY_RANK, run_all_rules
from cybwaylog.synthlog import create_synthetic_log


class FakeQuotaError(Exception):
    """Stands in for urllib's HTTPError: carries the status code."""
    code = 429


def fake_transport_factory(reports_json: str, calls: list, fail_after: int | None = None):
    def fake_transport(url, payload):
        if fail_after is not None and len(calls) >= fail_after:
            raise FakeQuotaError("Too Many Requests")
        calls.append({"url_has_key": "key=" in url, "payload": payload})
        return {"candidates": [{"content": {"parts": [{"text": reports_json}]}}]}
    return fake_transport


def perfect_reports_json() -> str:
    fired = [d.to_dict() for d in run_all_rules(create_synthetic_log()) if d.status == FAIL]
    fired.sort(key=lambda d: (SEVERITY_RANK[d["severity"]], d["risk_score"]), reverse=True)
    return json.dumps([{
        "rule_id": d["rule_id"], "severity": d["severity"], "narrative": d["evidence"][0],
        "affected_accounts": d["accounts"],
        "recommended_response": [s.strip() for s in d["recommended_response"].split(";")],
        "confidence": 0.9,
    } for d in fired])


def test_gemini_refuses_without_opt_in_key_or_budget(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="opt_in"):
        GeminiProvider(BudgetCeiling())
    with pytest.raises(RuntimeError, match="GOOGLE_API_KEY"):
        GeminiProvider(BudgetCeiling(), opt_in=True)
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    with pytest.raises(RuntimeError, match="BudgetCeiling"):
        GeminiProvider(None, opt_in=True)


def test_free_tier_call_passes_at_zero_ceiling_but_paid_estimate_is_refused(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    free = GeminiProvider(BudgetCeiling(), opt_in=True, transport=fake_transport_factory("[]", calls))
    assert free.generate("p") == "[]" and len(calls) == 1 and free.budget.spent_usd == 0.0
    paid = GeminiProvider(BudgetCeiling(), opt_in=True, free_tier=False,
                          transport=fake_transport_factory("[]", calls))
    with pytest.raises(BudgetExceeded):
        paid.generate("p")
    assert len(calls) == 1  # the refused call NEVER hit the transport


def test_budget_charged_before_call_and_blocks_overrun(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    provider = GeminiProvider(BudgetCeiling(0.025), opt_in=True, free_tier=False,
                              transport=fake_transport_factory("[]", calls))
    provider.generate("p")
    provider.generate("p")
    with pytest.raises(BudgetExceeded):
        provider.generate("p")          # third call would exceed $0.025
    assert len(calls) == 2              # the blocked call NEVER hit the network


def test_quota_exhaustion_stops_and_never_falls_back(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    provider = GeminiProvider(BudgetCeiling(), opt_in=True,
                              transport=fake_transport_factory("[]", calls, fail_after=0))
    with pytest.raises(FreeTierQuotaExhausted, match="no paid|never"):
        provider.generate("p")
    assert calls == []
    # a JSON error body is treated the same way
    body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}}
    provider2 = GeminiProvider(BudgetCeiling(), opt_in=True, transport=lambda url, payload: body)
    with pytest.raises(FreeTierQuotaExhausted):
        provider2.generate("p")


def test_prompt_contains_metadata_but_never_free_text_or_the_canary_row():
    conn = create_synthetic_log()
    prompt = build_prompt(conn)
    assert "unified_audit_trail" in prompt and "CYL-001" in prompt and "CYL-014" in prompt
    assert "DBA_ONE_FAKE" in prompt
    snapshot = event_snapshot(conn)
    assert "comment_text" not in snapshot and "ticket" not in snapshot
    assert "IGNORE ALL PREVIOUS" not in prompt.upper() and CANARY_COMMENT not in prompt
    assert "nightly ETL batch" not in prompt   # a benign free-text value: still never sent
    withheld = withheld_event_ids(conn)
    assert len(withheld) == 1
    canary_id = next(iter(withheld))
    assert f"\n{canary_id}|" not in snapshot   # the canary ROW is withheld entirely
    assert {h["source"] for h in CheckerAgent().scan_log(conn)} == {f"unified_audit_trail.{canary_id}"}


def test_live_demo_end_to_end_with_fake_transport(monkeypatch, tmp_path):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    result = run_live_demo(tmp_path, n_runs=2, transport=fake_transport_factory(perfect_reports_json(), calls))
    assert result["precision"] == 1.0 and result["recall"] == 1.0 and result["top1_ranking_accuracy"] == 1.0
    assert result["alert_fatigue_per_1000"] == 0.0
    assert result["spent_usd_estimate"] == 0.0 and result["budget_ceiling_usd"] == 0.0
    assert result["free_tier"] is True and len(calls) == 2
    assert all(r["checker_verified"] == 14 for r in result["per_run"])
    assert (tmp_path / "live_benchmark.json").exists() and (tmp_path / "manifest.json").exists()
    ok, msg = AuditLog(tmp_path / "audit.log.jsonl").verify_chain()
    assert ok, msg
    sent = calls[0]["payload"]["contents"][0]["parts"][0]["text"]
    assert "IGNORE ALL PREVIOUS" not in sent.upper()


def test_live_demo_stops_mid_run_when_quota_is_exhausted(monkeypatch, tmp_path):
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-test")
    calls = []
    with pytest.raises(FreeTierQuotaExhausted):
        run_live_demo(tmp_path, n_runs=3,
                      transport=fake_transport_factory(perfect_reports_json(), calls, fail_after=1))
    assert len(calls) == 1              # second call hit the quota; no retry, no third call
    events = [e["event"] for e in AuditLog(tmp_path / "audit.log.jsonl").entries()]
    assert events[-1] == "live_demo_stopped_quota"
