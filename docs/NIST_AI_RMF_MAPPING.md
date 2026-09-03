# NIST AI RMF 1.0 — Control Mapping for Cybwaylog

This document maps Cybwaylog's implemented controls to the four core functions of the
**NIST AI Risk Management Framework (AI RMF 1.0)** — GOVERN, MAP, MEASURE, MANAGE.
The AI RMF is a US Government work (public domain); function and category names are
referenced by identifier. Each row cites the code or artifact in this repository that
implements the control, so every claim here is verifiable by reading the source.
`tests/test_ai_rmf_mapping.py` fails the build if any path or test id cited below stops existing.

Scope note: Cybwaylog is a single-developer portfolio project. This mapping documents how its
design applies AI RMF principles; it is **not** a claim of organizational AI RMF conformance,
third-party assessment, or certification.

---

## GOVERN — policies, accountability, and human oversight

| AI RMF category | How Cybwaylog implements it | Evidence in repo |
|---|---|---|
| GOVERN 1 — Policies and procedures for AI risk are in place and transparent | Hard rules are written down and enforced in code: defensive-only scope, synthetic-data-only, mock-by-default, zero-spend, privacy constraints. Policy-lint and secret-scan fail the build on violations, including personal-information patterns. | `CLAUDE.md`, `LEGAL.md`, `src/cybwaylog/controls.py` (`policy_lint`, `secret_scan`, `PERSONAL_INFO_PATTERNS`) |
| GOVERN 2 — Accountability structures; roles and responsibilities | Every decision records a named human. Blank approver or reason is rejected. | `src/cybwaylog/gate.py` (`ApprovalGate.confirm`, `IncompleteRiskAcceptance`), `tests/test_ai_layer.py::test_gate_requires_approver_and_reason` |
| GOVERN 3 — Human oversight for consequential decisions | No AI output takes effect without a logged human decision. There is **no execute path**: recommended responses are advisory and `dry_run_response` always reports `executed=False`. An AI-drafted exception is unsigned by construction and cannot be accepted as-is. | `src/cybwaylog/gate.py` (`ApprovalRequired`), `src/cybwaylog/agents.py` (`draft_exception`), `tests/test_ai_layer.py::test_gate_confirm_flow_is_logged_and_never_executes`, `tests/test_exceptions.py` |
| GOVERN 4 — Transparency and documentation practices | Architecture, benchmarks, metric definitions, and honest limitations are published in the repo rather than hidden. | `README.md`, `BENCHMARKS.md`, `docs/evidence/README.md`, `MAINTENANCE.md` |
| GOVERN 6 — Third-party / supply-chain risk | Stdlib-only runtime (no third-party runtime dependencies); dev dependency pinned. LLM providers are pluggable and gated. | `pyproject.toml`, `src/cybwaylog/providers.py`, `MAINTENANCE.md` |

## MAP — context, intended use, and risk identification

| AI RMF category | How Cybwaylog implements it | Evidence in repo |
|---|---|---|
| MAP 1 — Context and intended purpose established | Purpose is narrow: triage a database activity trail against public NIST 800-53 / MITRE ATT&CK-mapped rules. Out-of-scope uses (offensive tooling, real data, autonomous response) are explicitly prohibited. | `README.md` ("Safety & scope"), `CLAUDE.md` |
| MAP 2 — AI system categorization; what the model does and does not do | The LLM's role is bounded: it drafts incident narratives and advisory responses as strict JSON. It does not decide, execute, or self-verify. Ground truth is a deterministic rule engine. | `src/cybwaylog/agents.py` (`TriageAgent.triage`), `src/cybwaylog/rules.py` |
| MAP 3 — Benefits and costs; resource constraints | Cost is a mapped risk: the budget ceiling defaults to `$0.00` and is checked before any call, so a paid call is refused by default. | `src/cybwaylog/budget.py` (`DEFAULT_CEILING_USD`, `BudgetCeiling.dry_run`, `BudgetExceeded`), `tests/test_ai_layer.py::test_budget_default_is_zero_and_refuses_any_positive_charge` |
| MAP 4 — Risks and impacts to individuals and data | Only event metadata is ever sent to a model; free-text fields are excluded from the rule reader by design, and the synthetic trail contains a planted injection canary so data-borne attacks are exercised rather than assumed. | `src/cybwaylog/rules.py` (`ActivityLog.EVENT_COLS`), `src/cybwaylog/redteam.py` (`CANARY_COMMENT`), `tests/test_ai_layer.py::test_injection_canary_is_caught_in_raw_log` |
| MAP 5 — Likelihood and magnitude of impact | Each detection carries a severity and a distinct risk score that drives triage ranking, so impact is explicit rather than implied. | `src/cybwaylog/rules.py`, `src/cybwaylog/report.py` |

## MEASURE — evaluation, testing, and monitoring

| AI RMF category | How Cybwaylog implements it | Evidence in repo |
|---|---|---|
| MEASURE 1 — Appropriate methods and metrics identified and applied | Triage output is scored against deterministic ground truth: precision, recall, F1, plus two operational metrics — top-1 ranking accuracy and false alerts per 1,000 events. | `src/cybwaylog/evalbench.py` (`run_benchmark`), `BENCHMARKS.md` |
| MEASURE 2 — Evaluated for trustworthy characteristics (validity, reliability, security, resilience) | **Validity/reliability:** deterministic benchmark over 50 seeded runs. **Security/resilience:** 18 OWASP LLM Top 10-mapped patterns, each quarantined end-to-end. **Independence:** the checker re-derives truth from raw rows and never grades its own generation. | `tests/test_ai_layer.py::test_benchmark_metrics_are_deterministic_and_sane`, `tests/test_ai_layer.py::test_redteam_pipeline_quarantines_each_pattern`, `src/cybwaylog/agents.py` (`CheckerAgent`) |
| MEASURE 2.7 — Security and resilience are evaluated | Injection detection runs on both AI output (narratives) and raw input data (`scan_log`). Tainted reports are quarantined, not merely flagged; hallucinated accounts and objects are quarantined too. | `src/cybwaylog/agents.py` (`CheckerAgent.scan_log`), `tests/test_ai_layer.py::test_checker_quarantines_hallucinated_account`, `tests/test_ai_layer.py::test_checker_quarantines_injection_tainted_narrative` |
| MEASURE 3 — Tracking identified risks over time | A clean baseline must produce zero detections, and the frozen scan date plus seeded generators make every run reproducible, so regressions are detectable rather than ambiguous. | `tests/test_cli.py::test_scan_clean_gives_zero_detections`, `tests/test_core.py::test_scan_date_is_frozen`, `tests/test_core.py::test_synthetic_log_is_deterministic_per_seed` |
| MEASURE 4 — Measurement results documented and shared | Benchmarks, metric definitions, and explicit limitations are published; the evidence directory states plainly that no live-model run has occurred yet. | `BENCHMARKS.md`, `docs/evidence/README.md` |

## MANAGE — responding to and managing risks

| AI RMF category | How Cybwaylog implements it | Evidence in repo |
|---|---|---|
| MANAGE 1 — Risks are prioritized and responded to | Every AI report is adjudicated PASS / REVIEW / QUARANTINE before a human sees it, and incidents are ordered by risk score for triage. | `src/cybwaylog/agents.py` (`VERDICT_PASS`, `VERDICT_REVIEW`, `VERDICT_QUARANTINE`), `src/cybwaylog/report.py` |
| MANAGE 2 — Minimizing negative impacts; residual-risk documentation | A formal exception path structured per NIST SP 800-53 CA-5: mandatory justification, compensating control, named accepter, and an **expiring** review date after which the incident reopens. | `src/cybwaylog/gate.py` (`EXCEPTION_FIELDS`, `STATUS_EXCEPTION`, `STATUS_EXPIRED`), `tests/test_exceptions.py` |
| MANAGE 3 — Third-party risks are managed | Live providers refuse to construct without explicit opt-in **and** an environment key **and** a budget; an exhausted free-tier quota raises rather than falling back to a paid tier. CI never holds a key. | `src/cybwaylog/providers.py` (`GeminiProvider`, `FreeTierQuotaExhausted`), `tests/test_ai_layer.py::test_live_provider_refuses_without_opt_in_key_or_budget`, `tests/test_cli.py::test_live_demo_refuses_positive_budget_without_env_override` |
| MANAGE 4 — Incident response, recovery, and monitoring | A tamper-evident hash-chained log plus SHA-256 manifest detect any edit, deletion, or reordering of the record; `cybwaylog verify` re-checks both. | `src/cybwaylog/auditlog.py` (`AuditLog.verify_chain`, `verify_manifest`), `tests/test_cli.py::test_verify_detects_tampered_run` |

---

## Known gaps (honest limitations)

- **No live-model evaluation yet.** All published numbers come from the deterministic mock provider.
- No formal bias/fairness evaluation (MEASURE 2.11). Activity triage is not a protected-class decision,
  but the analysis has not been performed.
- No production deployment, so post-deployment monitoring (MANAGE 4) is demonstrated through
  reproducibility and integrity verification rather than live telemetry.
- Single synthetic estate with one seeded incident per rule; real trails are noisier.
- This mapping is **self-assessed by the author**, not independently audited.

*Reference: NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0), January 2023.
Public domain (US Government work).*
