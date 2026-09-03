# MAINTENANCE.md

How a future session keeps this project healthy.

## Runtime

- Python >= 3.10, **stdlib-only runtime** (sqlite3, json, hashlib, datetime, argparse, re, random). No third-party runtime dependencies by design.
- Dev dependency pinned in `pyproject.toml` (`pytest`). Bump deliberately; run the full suite after.

## Golden checks (run before every push)

```bash
pip install -e ".[dev]"
pytest -q                     # all tests, offline, $0
cybwaylog controls --root .   # secret-scan + policy-lint (also flags personal-info patterns)
cybwaylog scan --out runs/latest && cybwaylog verify --run-dir runs/latest
cybwaylog benchmark           # mock harness numbers must stay deterministic
```

## Invariants that must never regress

1. **Zero-spend:** `BudgetCeiling` default is `0.00`; live providers refuse without opt-in + key + budget and never fall back to a paid tier. CI has no key.
2. **No execute path:** recommended responses are advisory; `dry_run_response` always returns `executed=False`.
3. **Independent checker:** `CheckerAgent` re-derives truth from raw rows; it never consumes its own generation.
4. **Tamper evidence:** `AuditLog.verify_chain` and `verify_manifest` must detect edit/delete/reorder (tests cover this).
5. **Privacy:** no personal information anywhere; attribution is "V. Vikram" only. `policy_lint` flags email-like strings.
6. **Determinism:** frozen `scan_date` (2026-07-17) and seeded generators; benchmark numbers are reproducible.

## Adding a detection rule

1. Add the seeded incident to `synthlog.py` (so ground truth exists).
2. Add the rule to `rules.py` with severity, NIST 800-53 IDs, MITRE ATT&CK ID + name, evidence from raw rows only, advisory response.
3. Add the rule to the parametrized tests (fires on seeded log, silent on clean log).
4. Mirror the rule in `docs/demo.html` JS if it is user-toggleable.
5. Update `docs/NIST_AI_RMF_MAPPING.md` only if a new governance control is introduced.

## Regenerating artifacts

- Report: `cybwaylog report --run-dir runs/latest --out report.html` (gitignored output).
- Screenshots: headless Chromium via Playwright (dev-only; see PROGRESS.md for the command used).

## Releasing

Tag via GitHub Releases UI (`vX.Y.Z` on `main`). Never publish without the owner's explicit approval.
