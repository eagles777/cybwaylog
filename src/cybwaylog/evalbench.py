"""EVAL BENCHMARK: measure the AI triage agent against ground truth over N
seeded runs. Headline metrics of the project:

  precision / recall / F1     incident-level: reported rule ids vs. seeded incidents
  top1_ranking_accuracy       share of runs in which the single highest-priority
                              seeded incident is ranked #1 by the triage output
  alert_fatigue_per_1000      false positives per 1,000 audit events scanned

Ground truth = the deterministic rule engine on the same raw log. Numbers
produced with MockProvider are MOCK HARNESS numbers (they measure the
governance harness, not a real model). Deterministic (seeded), offline, $0.
"""

from __future__ import annotations

from .agents import CheckerAgent, TriageAgent, VERDICT_QUARANTINE
from .providers import MockProvider
from .rules import FAIL, run_all_rules, top_incident
from .synthlog import create_synthetic_log


def run_benchmark(n_runs: int = 50, seed: int = 42, provider_factory=None) -> dict:
    """Run the triage agent n_runs times (fresh provider seed each run) and score it."""
    if provider_factory is None:
        provider_factory = lambda s: MockProvider(seed=s)  # noqa: E731

    conn = create_synthetic_log()
    detections = [d.to_dict() for d in run_all_rules(conn)]
    truth = {d["rule_id"] for d in detections if d["status"] == FAIL}
    top = top_incident(detections)
    n_events = conn.execute("SELECT COUNT(*) FROM unified_audit_trail").fetchone()[0]
    checker = CheckerAgent()

    tp = fp = fn = top1 = quarantined = 0
    per_run = []
    for i in range(n_runs):
        reports = TriageAgent(provider_factory(seed + i)).triage_detections(detections)
        reported = {r["rule_id"] for r in reports}
        run_tp, run_fp, run_fn = len(reported & truth), len(reported - truth), len(truth - reported)
        run_top1 = bool(reports) and reports[0]["rule_id"] == top
        run_q = sum(1 for v in checker.adjudicate(conn, reports, detections)["verdicts"]
                    if v["verdict"] == VERDICT_QUARANTINE)
        tp, fp, fn = tp + run_tp, fp + run_fp, fn + run_fn
        top1 += int(run_top1)
        quarantined += run_q
        per_run.append({"run": i, "tp": run_tp, "fp": run_fp, "fn": run_fn,
                        "top1_correct": run_top1, "quarantined": run_q})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n_runs": n_runs,
        "events_per_run": n_events,
        "ground_truth_incidents": len(truth),
        "top_incident": top,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "top1_ranking_accuracy": round(top1 / n_runs, 4) if n_runs else 0.0,
        "alert_fatigue_per_1000": round(fp / (n_runs * n_events) * 1000, 4) if n_runs and n_events else 0.0,
        "checker_quarantined": quarantined,
        "provider": "mock",
        "cost_usd": 0,
        "per_run": per_run,
    }
