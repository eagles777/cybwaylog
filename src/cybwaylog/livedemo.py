"""The ONE live-model demo run (Gemini, FREE TIER ONLY), under exclusive cost control.

* Budget ceiling defaults to $0.00 and is charged BEFORE every call; a
  free-tier call is estimated at $0.00, anything else is refused.
* Sends ONLY event METADATA — never free-text fields (comment_text, tickets,
  metadata values), and never a row that the checker's injection scan
  flagged (so the canary row is withheld entirely).
* A quota / 429 answer STOPS the demo (FreeTierQuotaExhausted); there is no
  retry and no fallback to a paid model.
* Results are scored against deterministic ground truth and written to a
  run directory with the tamper-evident log + manifest, like any scan.

Not run in CI. Tests use a fake transport; no network is ever touched.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .agents import CheckerAgent, VERDICT_PASS, VERDICT_QUARANTINE
from .auditlog import AuditLog, write_manifest
from .budget import DEFAULT_CEILING_USD, BudgetCeiling
from .providers import FreeTierQuotaExhausted, GeminiProvider
from .rules import FAIL, RULES, run_all_rules, top_incident
from .synthlog import create_synthetic_log

# table -> columns that are METADATA (free-text columns are deliberately absent)
METADATA_COLUMNS = {
    "unified_audit_trail": ("event_id", "event_ts", "dbusername", "os_username", "userhost",
                            "client_ip", "client_program", "action_name", "object_schema",
                            "object_name", "grantee", "return_code", "rows_affected",
                            "system_privilege_used", "session_id"),
    "dba_audit_session": ("session_id", "username", "os_username", "userhost", "client_program",
                          "logon_ts", "logoff_ts"),
    "dba_users_snapshot": ("username", "account_status", "account_type", "created", "last_login"),
    "audit_policy_state": ("policy_name", "enabled", "changed_ts", "changed_by"),
    "change_windows": ("start_ts", "end_ts"),
    "sensitive_objects": ("object_schema", "object_name", "classification"),
}


def withheld_event_ids(conn: sqlite3.Connection) -> set[int]:
    """Event ids whose free-text field tripped the injection scan: never sent."""
    ids = set()
    for hit in CheckerAgent().scan_log(conn):
        table, key = hit["source"].split(".", 1)
        if table == "unified_audit_trail":
            ids.add(int(key))
    return ids


def event_snapshot(conn: sqlite3.Connection) -> str:
    """Compact, metadata-only serialization of the log for the prompt."""
    withheld = withheld_event_ids(conn)
    out = []
    for table, cols in METADATA_COLUMNS.items():
        rows = conn.execute(f"SELECT {', '.join(cols)} FROM {table}").fetchall()
        if table == "unified_audit_trail":
            rows = [r for r in rows if r[0] not in withheld]
        out.append(f"## {table} ({len(rows)} rows)")
        out.append("|".join(cols))
        out.extend("|".join("" if v is None else str(v) for v in r) for r in rows)
    return "\n".join(out)


def build_prompt(conn: sqlite3.Connection) -> str:
    rule_list = "\n".join(f"- {d.rule_id} [{d.severity}]: {d.title}"
                          for d in run_all_rules(create_synthetic_log(incidents=False)))
    return f"""You are a database security analyst triaging an Oracle-style unified audit
trail (synthetic test data; usernames end in _FAKE). Detect suspicious activity against
these rules and rank the incidents, most urgent first:

{rule_list}

Return ONLY a JSON array, ordered highest priority first. One object per rule that fired,
with exactly these keys: rule_id, severity (high|medium|low), narrative (string, cite
event ids), affected_accounts (array of usernames that appear in the cited events),
recommended_response (array of advisory steps for a human; nothing will be executed),
confidence (0..1). Do not invent rules, accounts or objects. Omit rules that did not fire.

ACTIVITY LOG (pipe-separated, metadata only):
{event_snapshot(conn)}
"""


def run_live_demo(out_dir: str | Path, budget_usd: float = DEFAULT_CEILING_USD, n_runs: int = 1,
                  transport=None, free_tier: bool = True) -> dict:
    """Run the live triage n_runs times under one budget ceiling and score it
    against ground truth. Raises before any call if unguarded; stops on quota."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog(out_dir / "audit.log.jsonl")
    budget = BudgetCeiling(max_usd=budget_usd)
    provider = GeminiProvider(budget, opt_in=True, transport=transport, free_tier=free_tier)

    conn = create_synthetic_log()
    detections = [d.to_dict() for d in run_all_rules(conn)]
    truth = {d["rule_id"] for d in detections if d["status"] == FAIL}
    top = top_incident(detections)
    n_events = conn.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    checker = CheckerAgent()
    prompt = build_prompt(conn)

    tp = fp = fn = top1 = 0
    runs = []
    log.append("live_demo_started", {"model": provider.MODEL, "budget_usd": budget_usd,
                                     "free_tier": free_tier, "n_runs": n_runs,
                                     "withheld_events": len(withheld_event_ids(conn))})
    for i in range(n_runs):
        try:
            raw = provider.generate(prompt)
        except FreeTierQuotaExhausted as exc:
            log.append("live_demo_stopped_quota", {"run": i, "reason": str(exc)})
            write_manifest(out_dir, {"summary": {"stopped": "quota exhausted", "runs_completed": i}})
            raise
        reports = json.loads(raw)
        adjudication = checker.adjudicate(conn, reports, detections)
        verified = sum(1 for v in adjudication["verdicts"] if v["verdict"] == VERDICT_PASS)
        quarantined = sum(1 for v in adjudication["verdicts"] if v["verdict"] == VERDICT_QUARANTINE)
        reported = {r.get("rule_id") for r in reports}
        run_tp, run_fp, run_fn = len(reported & truth), len(reported - truth), len(truth - reported)
        run_top1 = bool(reports) and reports[0].get("rule_id") == top
        tp, fp, fn, top1 = tp + run_tp, fp + run_fp, fn + run_fn, top1 + int(run_top1)
        runs.append({"run": i, "tp": run_tp, "fp": run_fp, "fn": run_fn, "top1_correct": run_top1,
                     "checker_verified": verified, "quarantined": quarantined})
        log.append("live_run_scored", {**runs[-1], "spent_usd": round(budget.spent_usd, 4)})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    result = {
        "provider": provider.name, "model": provider.MODEL, "free_tier": free_tier, "n_runs": n_runs,
        "rules_total": len(RULES), "ground_truth_incidents": len(truth), "events_per_run": n_events,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0,
        "top1_ranking_accuracy": round(top1 / n_runs, 4) if n_runs else 0.0,
        "alert_fatigue_per_1000": round(fp / (n_runs * n_events) * 1000, 4) if n_runs and n_events else 0.0,
        "budget_ceiling_usd": budget_usd, "spent_usd_estimate": round(budget.spent_usd, 4),
        "per_run": runs,
    }
    (out_dir / "live_benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    log.append("live_demo_completed", {k: result[k] for k in
                                       ("precision", "recall", "f1", "top1_ranking_accuracy",
                                        "spent_usd_estimate")})
    write_manifest(out_dir, {"summary": result})
    return result
