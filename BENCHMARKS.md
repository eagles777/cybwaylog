# BENCHMARKS.md — Measured AI Performance

All numbers are produced by code in this repository and are reproducible with the commands shown.
Nothing here is estimated or copied from elsewhere.

## Ground truth

The synthetic activity generator (`src/cybwaylog/synthlog.py`) plants exactly **14 incidents** —
one per detection rule — inside a ~2,032-event, 14-day trail. The deterministic rule engine
(`src/cybwaylog/rules.py`) is the ground truth. The AI triage agent is scored against it; the agent
never sees the answer key.

## Mock provider — harness validation

`MockProvider` is deliberately imperfect (configurable miss, fabrication, and mis-ranking rates) so
the measurement pipeline itself is exercised and proven to detect degradation.

```bash
cybwaylog benchmark --runs 50 --seed 42
```

| Metric | Value |
|---|---|
| Precision | **0.9984** |
| Recall | **0.8957** |
| F1 | **0.9443** |
| Top-1 ranking accuracy | **0.78** |
| False alerts per 1,000 events | **0.0098** |
| Runs | 50 |
| Events per run | 2,032 |
| Ground-truth incidents per run | 14 |
| Quarantined by the independent checker | 4 |
| Cost | **$0.00** (mock provider, no network) |

Deterministic: the same seed always yields the same numbers, which is asserted in
`tests/test_ai_layer.py`.

## Live model

**None yet.** No live-model run has been performed for this project.

When one is performed it will be under the project's zero-spend policy — a free-tier key with **no
billing attached**, a budget ceiling of `$0.00` checked before every call, and an exhausted quota
stopping the run rather than falling back to a paid tier. The results, the hash-chained run log, and
the SHA-256 manifest will be committed under `docs/evidence/` so anyone can re-verify them, exactly
as was done in the sibling project Cybwaydb.

## Metric definitions

- **Precision** — of the incidents the AI reported, the fraction that were real. Low precision means
  crying wolf.
- **Recall** — of the real incidents, the fraction the AI caught. Low recall means missing attacks.
- **F1** — the harmonic mean of precision and recall; a single balance figure.
- **Top-1 ranking accuracy** — how often the single highest-risk seeded incident (CYL-014, the
  export-then-audit-off correlation, risk score 97) is ranked first by the triage output. Accuracy
  alone does not tell an analyst *what to look at first*; this does.
- **False alerts per 1,000 events** — the alert-fatigue rate. A tool that is accurate but noisy at
  scale still gets ignored, so this is measured explicitly.

## Reproducing

```bash
pip install -e ".[dev]"
cybwaylog benchmark --runs 50 --seed 42     # the table above
pytest -q                                    # 150 tests, offline
cybwaylog scan --out runs/latest && cybwaylog verify --run-dir runs/latest
```

## Honest limitations

- These are **mock-provider** numbers. They validate the harness; they are not a claim about any
  commercial model's performance on this task.
- One synthetic estate, one seeded incident per rule. Real audit trails are noisier and more varied.
- Top-1 ranking is measured against a single designated worst incident, not a full ranked ground truth.
- No live-model, multi-model, or adversarial-data-drift evaluation has been performed yet.
