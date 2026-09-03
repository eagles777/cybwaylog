# Evidence

This directory holds **committed, verifiable output** from real runs.

## Current status: no live-model evidence yet

No live-model run has been performed for Cybwaylog. All published numbers in `BENCHMARKS.md` come
from the deterministic mock provider and are reproducible offline with:

```bash
cybwaylog benchmark --runs 50 --seed 42
```

## What will be committed when a live run happens

Under the project's zero-spend policy (free-tier key, no billing attached, `$0.00` budget ceiling
checked before every call), a live run writes:

- `live-run/live_benchmark.json` — precision, recall, F1, top-1 ranking accuracy, alert-fatigue rate
- `live-run/audit.log.jsonl` — a tamper-evident, hash-chained log of the run; any edit, deletion, or
  reordering breaks the chain and is detected by `cybwaylog verify`
- `live-run/manifest.json` — SHA-256 of every output file

No API key, credential, or personal data appears in these artifacts — only event metadata and scores.
Anyone can re-verify the chain without a key:

```bash
cybwaylog verify --run-dir docs/evidence/live-run
```
