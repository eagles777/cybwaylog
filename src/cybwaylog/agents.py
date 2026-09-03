"""AI layer: triage agent + independent checker agent.

Governance invariants:
- The checker NEVER grades its own generation: it re-derives ground truth
  from the raw log rows with the deterministic rule engine and checks the
  triage agent's output against it.
- Every incident report is adjudicated PASS / REVIEW / QUARANTINE.
- Nothing here executes a response, closes an incident, or spends money.
- Free-text log fields never reach a prompt; they are scanned for injection.
"""

from __future__ import annotations

import json
import re
import sqlite3

from .redteam import scan_text_for_injection
from .rules import FAIL, run_all_rules

VERDICT_PASS = "PASS"              # verified against raw rows
VERDICT_REVIEW = "REVIEW"          # malformed / severity disagrees -> human must look
VERDICT_QUARANTINE = "QUARANTINE"  # fabricated or injection-tainted

REQUIRED_FIELDS = {"rule_id", "severity", "narrative", "affected_accounts",
                   "recommended_response", "confidence"}

TRIAGE_PROMPT = ("Triage these database-activity detections. For each, return a strict-JSON "
                 "incident report {rule_id, severity, narrative, affected_accounts, "
                 "recommended_response[], confidence}, ordered highest priority first.")

_OBJECT_REF = re.compile(r"\b([A-Z][A-Z0-9_$]*)\.([A-Z][A-Z0-9_$]*)\b")


class TriageAgent:
    """Reads detections, asks the provider for strict-JSON incident reports in triage order."""

    def __init__(self, provider):
        self.provider = provider

    def triage(self, conn: sqlite3.Connection) -> list[dict]:
        return self.triage_detections([d.to_dict() for d in run_all_rules(conn)])

    def triage_detections(self, detections: list[dict]) -> list[dict]:
        ground_truth = [d for d in detections if d["status"] == FAIL]
        raw = self.provider.complete(prompt=TRIAGE_PROMPT, ground_truth_detections=ground_truth)
        reports = json.loads(raw)  # strict JSON or it raises
        if not isinstance(reports, list) or not all(isinstance(r, dict) for r in reports):
            raise ValueError("triage output must be a JSON list of incident reports")
        return reports


def draft_exception(detection: dict) -> dict:
    """AI-drafted exception paperwork (NIST CA-5-style, mock, $0).

    Deliberately leaves accepted_by and review_date BLANK: the gate refuses
    blank fields, so an AI draft can never be accepted as-is — a human must
    complete and sign it. That is the governance invariant, encoded.
    """
    return {
        "rule_id": detection["rule_id"],
        "justification": (f"[DRAFT — human must review] Activity flagged by '{detection['title']}' "
                          "may be expected for this account; see evidence: "
                          + "; ".join(detection.get("evidence", []))),
        "compensating_control": "[DRAFT — human must specify the compensating control]",
        "accepted_by": "",   # intentionally blank: only a human may sign
        "review_date": "",   # intentionally blank: human sets the expiry
        "draft": True,
    }


class CheckerAgent:
    """Independent verifier. Deterministic; re-reads the RAW rows itself."""

    # (table, key column, free-text column) — everything an attacker could write into
    TEXT_SOURCES = (
        ("unified_audit_trail", "event_id", "comment_text"),
        ("change_windows", "ticket", "ticket"),
        ("db_metadata", "key", "value"),
    )

    def scan_log(self, conn: sqlite3.Connection) -> list[dict]:
        """Scan free-text log fields for published injection patterns BEFORE
        they could reach any LLM prompt. This is what catches the canary."""
        hits = []
        for table, key_col, text_col in self.TEXT_SOURCES:
            for key, text in conn.execute(f"SELECT {key_col}, {text_col} FROM {table}"):
                for hit in scan_text_for_injection(text or ""):
                    hits.append({**hit, "source": f"{table}.{key}"})
        return hits

    @staticmethod
    def _known_accounts(conn: sqlite3.Connection) -> set[str]:
        users = {r[0] for r in conn.execute("SELECT username FROM dba_users_snapshot")}
        users |= {r[0] for r in conn.execute("SELECT DISTINCT dbusername FROM unified_audit_trail")}
        return users

    def _unverifiable(self, report: dict, truth: dict, known_accounts: set[str]) -> list[str]:
        """Accounts / objects the report cites that are NOT in the rule's evidence rows."""
        problems = []
        ev_accounts = set(truth.get("accounts", []))
        ev_objects = set(truth.get("objects", []))
        # A schema owner (e.g. HR_FAKE in HR_FAKE.SALARIES_FAKE) is legitimately
        # mentionable when one of its objects is in the evidence rows.
        mentionable = ev_accounts | {o.split(".", 1)[0] for o in ev_objects if "." in o}
        cited = report.get("affected_accounts") or []
        if not isinstance(cited, list):
            cited = [cited]
        for acct in cited:
            if acct not in ev_accounts:
                problems.append(f"account {acct}")
        text = " ".join(str(report.get(k, "")) for k in ("narrative", "recommended_response"))
        for schema, name in _OBJECT_REF.findall(text):
            ref = f"{schema}.{name}"
            if ref not in ev_objects:
                problems.append(f"object {ref}")
        text_without_objects = _OBJECT_REF.sub(" ", text)   # object refs were checked above
        for acct in known_accounts:
            if acct not in mentionable and re.search(rf"\b{re.escape(acct)}\b", text_without_objects):
                problems.append(f"account {acct}")
        return sorted(set(problems))

    def adjudicate(self, conn: sqlite3.Connection, reports: list[dict],
                   detections: list[dict] | None = None) -> dict:
        """Adjudicate triage reports against ground truth re-derived from raw rows.
        ``detections`` may be supplied when the caller already ran the same
        deterministic engine on the same connection (benchmark loops)."""
        if detections is None:
            detections = [d.to_dict() for d in run_all_rules(conn)]
        truth = {d["rule_id"]: d for d in detections if d["status"] == FAIL}
        known_accounts = self._known_accounts(conn)
        verdicts = []
        for r in reports:
            missing = REQUIRED_FIELDS - set(r)
            tainted = scan_text_for_injection(json.dumps(
                [r.get(k, "") for k in ("narrative", "recommended_response", "affected_accounts")]))
            if tainted:
                verdict, reason = VERDICT_QUARANTINE, \
                    f"injection patterns detected: {sorted({t['id'] for t in tainted})}"
            elif r.get("rule_id") not in truth:
                verdict, reason = VERDICT_QUARANTINE, \
                    "not verifiable against raw log rows (possible fabricated incident)"
            else:
                unverifiable = self._unverifiable(r, truth[r["rule_id"]], known_accounts)
                if unverifiable:
                    verdict, reason = VERDICT_QUARANTINE, \
                        f"cites items not present in evidence rows (possible hallucination): {unverifiable}"
                elif missing:
                    verdict, reason = VERDICT_REVIEW, f"missing required fields: {sorted(missing)}"
                elif r.get("severity") != truth[r["rule_id"]]["severity"]:
                    verdict, reason = VERDICT_REVIEW, \
                        f"severity '{r.get('severity')}' disagrees with rule severity " \
                        f"'{truth[r['rule_id']]['severity']}'"
                else:
                    verdict, reason = VERDICT_PASS, "verified against raw log rows"
            verdicts.append({"report": r, "verdict": verdict, "reason": reason})

        reported_ids = {r.get("rule_id") for r in reports}
        missed = [truth[rid] for rid in truth if rid not in reported_ids]
        return {"verdicts": verdicts, "missed_incidents": missed}
