"""Command-line interface for Cybwaylog (mock mode, $0, defensive only)."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

from . import __version__
from .auditlog import AuditLog, verify_manifest
from .budget import DEFAULT_CEILING_USD
from .controls import policy_lint, secret_scan
from .engine import run_scan
from .synthlog import create_synthetic_log

ALLOW_SPEND_ENV = "CYBWAYLOG_ALLOW_SPEND"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cybwaylog",
        description="Governed-AI database activity auditor (mock mode, $0, defensive only)",
    )
    parser.add_argument("--version", action="version", version=f"cybwaylog {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run all detection rules against an activity log")
    p_scan.add_argument("--db", default=None,
                        help="Path to a SQLite activity log to scan. Omit to use the built-in synthetic log.")
    p_scan.add_argument("--out", default="runs/latest", help="Run output directory")
    p_scan.add_argument("--clean", action="store_true",
                        help="Use the incident-free synthetic baseline (expects zero detections)")
    p_scan.add_argument("--seed", type=int, default=42)

    p_init = sub.add_parser("init-log", help="Write a synthetic activity log to a SQLite file you can edit and re-scan")
    p_init.add_argument("--out", default="cybwaylog_sample.sqlite")
    p_init.add_argument("--clean", action="store_true", help="Baseline only, no seeded incidents")
    p_init.add_argument("--seed", type=int, default=42)

    p_verify = sub.add_parser("verify", help="Verify audit-log hash chain and run manifest")
    p_verify.add_argument("--run-dir", default="runs/latest")

    p_ctl = sub.add_parser("controls", help="Run policy-lint and secret-scan over the repo")
    p_ctl.add_argument("--root", default=".")

    p_bench = sub.add_parser("benchmark", help="Measure triage precision/recall/ranking vs ground truth (mock, $0)")
    p_bench.add_argument("--runs", type=int, default=50)
    p_bench.add_argument("--seed", type=int, default=42)

    sub.add_parser("redteam", help="Scan raw log free-text fields for published OWASP-LLM injection patterns (incl. canary)")

    p_report = sub.add_parser("report", help="Generate a standalone HTML timeline report from a run")
    p_report.add_argument("--run-dir", default="runs/latest")
    p_report.add_argument("--out", default="report.html")

    p_live = sub.add_parser("live-demo", help="ONE free-tier live Gemini run (requires GOOGLE_API_KEY)")
    p_live.add_argument("--budget", type=float, default=DEFAULT_CEILING_USD,
                        help=f"Hard cost ceiling in USD (default {DEFAULT_CEILING_USD:.2f} = free tier only)")
    p_live.add_argument("--runs", type=int, default=1)
    p_live.add_argument("--out", default="runs/live-demo")
    p_live.add_argument("--i-understand-costs", action="store_true",
                        help="Required. Confirms you know this makes a real (free-tier) API call.")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if args.db:
            conn = sqlite3.connect(args.db)
        else:
            conn = create_synthetic_log(seed=args.seed, incidents=not args.clean)
        summary = run_scan(conn, args.out)
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "init-log":
        create_synthetic_log(args.out, seed=args.seed, incidents=not args.clean).close()
        print(f"Synthetic activity log written to {args.out}. "
              f"Open it in any SQLite browser, edit the rows, then: cybwaylog scan --db {args.out}")
        return 0

    if args.command == "verify":
        log_ok, msg = AuditLog(f"{args.run_dir}/audit.log.jsonl").verify_chain()
        man_ok, problems = verify_manifest(args.run_dir)
        print(f"audit log: {msg}")
        print(f"manifest: {'ok' if man_ok else problems}")
        return 0 if (log_ok and man_ok) else 1

    if args.command == "controls":
        secrets = secret_scan(args.root)
        policy = policy_lint(args.root)
        print(json.dumps({"secret_scan_hits": secrets, "policy_violations": policy}, indent=2))
        return 0 if not (secrets or policy) else 1

    if args.command == "benchmark":
        from .evalbench import run_benchmark
        result = run_benchmark(n_runs=args.runs, seed=args.seed)
        result.pop("per_run")
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "redteam":
        from .agents import CheckerAgent
        hits = CheckerAgent().scan_log(create_synthetic_log())
        print(json.dumps({"injection_hits": hits}, indent=2))
        return 0 if hits else 1  # the canary MUST be caught

    if args.command == "report":
        from .report import write_report
        out = write_report(args.run_dir, args.out)
        print(f"Report written to {out} — open it in any browser.")
        return 0

    if args.command == "live-demo":
        if not args.i_understand_costs:
            print("Refusing: pass --i-understand-costs to confirm a real API call. "
                  "Everything else in this tool is offline; only this command talks to a model.")
            return 1
        if args.budget > DEFAULT_CEILING_USD and os.environ.get(ALLOW_SPEND_ENV) != "1":
            print(f"Refusing: budget ${args.budget:.2f} exceeds the project's $0.00 zero-spend policy. "
                  f"Free tier only. (Override requires {ALLOW_SPEND_ENV}=1, which this project "
                  "does not recommend.)")
            return 1
        if not os.environ.get("GOOGLE_API_KEY"):
            print("Refusing: GOOGLE_API_KEY is not set. A free-tier key (no billing attached) is "
                  "required, in a gitignored .env or CI secret — never in the repo.")
            return 1
        from .livedemo import run_live_demo
        result = run_live_demo(args.out, budget_usd=args.budget, n_runs=args.runs)
        print(json.dumps(result, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
