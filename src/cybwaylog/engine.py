"""Scan orchestrator: run all detection rules against an activity log, write
detections.json, a hash-chained audit log and a SHA-256 manifest into a run
directory.

Mock mode only in the core — no network, no API key, $0.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .auditlog import AuditLog, write_manifest
from .rules import FAIL, run_all_rules, top_incident


def run_scan(conn: sqlite3.Connection, out_dir: str | Path) -> dict:
    """Run every rule, persist detections.json + audit log + manifest.
    Returns a summary dict {total, failed, passed, by_severity, ...}."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog(out_dir / "audit.log.jsonl")

    events_scanned = conn.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    meta = dict(conn.execute("SELECT key, value FROM db_metadata").fetchall())
    log.append("scan_started", {"mode": "mock", "cost_usd": 0, "events": events_scanned,
                                "scan_date": meta.get("scan_date", "")})
    detections = run_all_rules(conn)
    for d in detections:
        log.append("rule_evaluated", {"rule_id": d.rule_id, "status": d.status,
                                      "evidence_count": len(d.evidence)})

    (out_dir / "detections.json").write_text(
        json.dumps([d.to_dict() for d in detections], indent=2), encoding="utf-8")

    fired = [d for d in detections if d.status == FAIL]
    summary = {
        "total": len(detections),
        "failed": len(fired),
        "passed": len(detections) - len(fired),
        "by_severity": {sev: sum(1 for d in fired if d.severity == sev)
                        for sev in ("high", "medium", "low")},
        "top_incident": top_incident(detections),
        "events_scanned": events_scanned,
        "scan_date": meta.get("scan_date", ""),
        "mode": "mock",
        "cost_usd": 0,
    }
    log.append("scan_completed", summary)
    write_manifest(out_dir, {"summary": summary})
    return summary
