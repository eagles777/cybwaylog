#!/usr/bin/env python3
"""Live walkthrough: a clean audit trail, then an insider-threat scenario injected by hand.

Run it cold, with no arguments, no API key, and no network:

    python examples/insider_threat_walkthrough.py

It shows three things in about two seconds:

  1. A clean two-week trail produces ZERO detections — no false alarms on
     ordinary activity, which is the part most tools get wrong.
  2. Three hand-written rows are injected: an off-hours DBA logon, a
     1.2M-row export of a salary table, and logon auditing switched off
     22 minutes later.
  3. The re-scan finds four detections and ranks the CORRELATION first —
     above the individually-severe events that compose it. Each signal is
     explainable alone; together, in that order, inside an hour, they are
     an exfiltration-and-cover-up pattern.

Everything here is synthetic. No real database is contacted.
"""

from __future__ import annotations

import sqlite3
import sys

from cybwaylog.rules import run_all_rules
from cybwaylog.synthlog import create_synthetic_log

FRIDAY = "2026-07-17"  # a Friday; the events below land late that night
SESSION = 770001


def fired(conn: sqlite3.Connection):
    """Detections that actually triggered, worst first."""
    return sorted((d for d in run_all_rules(conn) if d.status == "FAIL"),
                  key=lambda d: -d.risk_score)


def inject_insider_scenario(conn: sqlite3.Connection) -> None:
    """Add three raw audit rows telling one story, plus the state they imply."""
    next_id = conn.execute("SELECT MAX(event_id) FROM unified_audit_trail").fetchone()[0] + 1
    common = ("DBA_ONE_FAKE", "dba1", "WS-DBA1-FAKE", "10.0.1.31", "sqlplus")

    events = [
        # 23:14 — the DBA signs in on a Friday night.
        (next_id, f"{FRIDAY}T23:14:02", *common,
         "LOGON", "", "", "", 0, "", 0, "", str(SESSION), ""),
        # 23:19 — pulls the entire salary table.
        (next_id + 1, f"{FRIDAY}T23:19:40", *common,
         "SELECT", "HR_FAKE", "SALARIES_FAKE", "", 0, "h1", 1_200_000,
         "SELECT ANY TABLE", str(SESSION), ""),
        # 23:41 — switches off logon auditing.
        (next_id + 2, f"{FRIDAY}T23:41:55", *common,
         "NOAUDIT", "", "ORA_LOGON_FAILURES", "", 0, "h2", 0,
         "AUDIT SYSTEM", str(SESSION), ""),
    ]
    conn.executemany(
        "INSERT INTO unified_audit_trail VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", events)
    conn.execute(
        "INSERT INTO dba_audit_session VALUES (?,?,?,?,?,?,?)",
        (SESSION, "DBA_ONE_FAKE", "dba1", "WS-DBA1-FAKE", "sqlplus",
         f"{FRIDAY}T23:14:02", f"{FRIDAY}T23:55:00"))
    conn.execute(
        "UPDATE audit_policy_state SET enabled=0, changed_ts=?, changed_by='DBA_ONE_FAKE' "
        "WHERE policy_name='ORA_LOGON_FAILURES'", (f"{FRIDAY}T23:41:55",))
    conn.commit()


def main() -> int:
    rule = "─" * 78

    conn = create_synthetic_log(incidents=False)
    events = conn.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    before = fired(conn)

    print(rule)
    print("STEP 1 — a clean two-week audit trail")
    print(rule)
    print(f"  {events:,} events across 8 accounts")
    print(f"  detections: {len(before)}")
    print("  Ordinary activity produces no alerts at all.\n")

    inject_insider_scenario(conn)

    print(rule)
    print("STEP 2 — inject three rows by hand")
    print(rule)
    print(f"  {FRIDAY}T23:14  DBA_ONE_FAKE signs in from WS-DBA1-FAKE  (Friday, 23:14)")
    print(f"  {FRIDAY}T23:19  SELECT on HR_FAKE.SALARIES_FAKE -> 1,200,000 rows")
    print(f"  {FRIDAY}T23:41  NOAUDIT on ORA_LOGON_FAILURES   (22 minutes later)")
    print("  Each one is explainable on its own. DBAs work late; DBAs run big")
    print("  queries; DBAs change audit settings.\n")

    after = fired(conn)

    print(rule)
    print(f"STEP 3 — re-scan: {len(after)} detections, ranked by risk")
    print(rule)
    for d in after:
        print(f"\n  [risk {d.risk_score:>2}]  {d.rule_id}  {d.severity.upper():<6}  {d.title}")
        for line in d.evidence:
            print(f"      evidence  {line}")
        print(f"      refs      {', '.join(d.references)}")
        print(f"      response  {d.recommended_response.split(';')[0].strip()} "
              f"(advisory — never executed)")

    top = after[0] if after else None
    print(f"\n{rule}")
    if top and top.rule_id == "CYL-014":
        print("The correlation ranked FIRST — above the individually-severe events")
        print("that compose it. That ordering is what the top-1 ranking metric")
        print("measures, and it is the difference between an alert firehose and")
        print("triage an analyst can act on.")
    print("Nothing here was executed. Every finding awaits a logged human decision.")
    print(rule)
    return 0


if __name__ == "__main__":
    sys.exit(main())
