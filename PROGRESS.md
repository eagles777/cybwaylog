# PROGRESS.md

Session log so work compounds across sessions.

## Session 1 — 2026-09-02/03 — Cybwaylog v1.0 built end to end (mock, $0)

Sibling project to Cybwaydb: that one audits database *configuration* (static state), this one audits
database *activity* (dynamic behavior). The governance spine (hash-chained audit log, budget ceiling,
policy-lint/secret-scan, provider gating, approval gate) was carried over and adapted; everything else
is new.

### Core
- `synthlog.py` — synthetic Oracle-style activity generator: `unified_audit_trail`,
  `dba_audit_session`, `dba_users_snapshot`, `audit_policy_state`, `change_windows`,
  `sensitive_objects`, `db_metadata` (frozen `scan_date` 2026-07-17). ~2,032 events over 14 days for
  8 `*_FAKE` accounts, plus exactly one seeded incident per rule so ground truth is known.
  `incidents=False` yields a clean baseline with zero detections. An injection **canary** is planted
  in a free-text `comment_text` field, which the rule reader deliberately never loads.
- `rules.py` — 14 detection rules CYL-001..CYL-014, each with severity, a distinct risk score
  (drives triage ranking), NIST SP 800-53 control IDs, MITRE ATT&CK technique IDs (ID + name only),
  evidence built solely from raw rows, and an advisory recommended response. CYL-014 is a
  **correlation** rule (mass export followed by audit-off within an hour, risk 97 — the designated
  worst incident).
- `engine.py` / `cli.py` — `scan`, `init-log`, `verify`, `controls`, `benchmark`, `redteam`,
  `report`, `live-demo`.

### AI layer (mock-first)
- `agents.py` — `TriageAgent` (strict-JSON incident reports) and `CheckerAgent` (re-derives truth from
  raw rows; PASS / REVIEW / QUARANTINE; quarantines hallucinated accounts/objects and injection-tainted
  narratives; `scan_log` catches the canary; never grades its own generation). `draft_exception`
  returns an unsigned draft the gate must reject.
- `gate.py` — confirm / dismiss_false_positive / escalate / accept_exception (NIST CA-5 style:
  justification, compensating control, named accepter, **expiring** review date that reopens the
  incident). All decisions hash-chained. `dry_run_response` always reports `executed=False`; there is
  no execute path.
- `budget.py` — **default ceiling $0.00**, checked before any call. `providers.py` — live providers
  refuse without opt-in AND env key AND budget; an exhausted free quota raises
  `FreeTierQuotaExhausted` rather than falling back to anything paid.
- `redteam.py` — 18 OWASP LLM Top 10-mapped patterns RT-01..RT-18 + canary.
- `evalbench.py` — precision/recall/F1 plus **top-1 ranking accuracy** and **alert-fatigue per 1,000
  events**. Deterministic.

### Extras
- `report.py` — self-contained HTML incident-timeline report (no external assets, no JavaScript):
  verdict, KPIs, governance pipeline, accuracy/triage meters, integrity status, timeline with
  severity stripes, evidence, advisory response, references.
- `docs/demo.html` — fully client-side interactive demo (vanilla JS, no network, no key). Toggling
  incidents re-runs the mirrored rule logic live; verified under Node with a DOM stub: 14 detections
  when all are on, 0 when off, correlation fires only with both triggers, rule ids match `rules.py`.
- Docs: README (hero, badges, rule table, benchmarks), BENCHMARKS.md, LEGAL.md, NOTICE,
  MAINTENANCE.md, BACKLOG.md, `docs/evidence/README.md`, `docs/NIST_AI_RMF_MAPPING.md` plus
  `tests/test_ai_rmf_mapping.py`, which fails the build if the mapping ever cites a path or test id
  that does not exist. That test caught three genuinely wrong citations on first run and they were
  corrected — the honesty check works.
- Screenshots captured headlessly for the README.

### Verified
- `pytest -q` → **150 passed**, all offline, $0.
- `cybwaylog controls --root .` → clean (no secrets, no policy violations).
- Privacy sweep across every text file → the only match is the scanner's own detection regex.
- Mock benchmark (50 runs, seed 42): precision 0.9984 · recall 0.8957 · F1 0.9443 ·
  top-1 ranking 0.78 · alert-fatigue 0.0098 per 1,000 events. Deterministic.
- No live-model run has been performed; `BENCHMARKS.md` and `docs/evidence/README.md` say so plainly.

### Notes for a future session
- Removed the internal build-spec file before committing: it contained the privacy keyword list
  itself, which would have published the very terms the policy forbids. Keep scaffolding out of the
  repo.
- MITRE mappings use a parent technique where a sub-technique ID was not certain (audit-off →
  T1562/T1562.001; DDL outside window → T1505.001; orphan session → T1070/T1550). Worth a review.
- A live free-tier run would want a compacted event snapshot; the full prompt is large.
- Repo visibility: PRIVATE until the owner reviews and explicitly approves going public.
