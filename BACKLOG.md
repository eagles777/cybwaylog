# BACKLOG.md

## v1.0 scope (see BUILD_SPEC.md)

- [x] Core: synthetic activity log, 14 detection rules, engine, CLI, tamper-evident log, controls, tests
- [x] AI layer: triage agent, independent checker, human triage gate with expiring exceptions, budget ($0.00 default), red-team suite, eval benchmark (precision/recall + top-1 ranking + alert-fatigue rate)
- [x] Extras: HTML timeline report, interactive browser demo, README/LEGAL/NOTICE/MAINTENANCE, NIST AI RMF mapping + honesty test, CI

## Later / optional

- [ ] One free-tier live-model run (owner's key, no billing attached) and committed evidence
- [ ] Multi-model comparison (free tiers / local model)
- [ ] Baseline learning per user (rolling statistics) instead of fixed thresholds
- [ ] Model card + AI risk register
- [ ] PyPI publish + Docker image
- [ ] Cross-link with Cybwaydb (config + activity = full-stack database assurance)
