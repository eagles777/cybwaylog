# LEGAL.md — Source Material & Licensing

## Our code

Apache-2.0. Copyright © V. Vikram. See `LICENSE` and `NOTICE`.

## Third-party / reference material

| Source | Status | How we use it |
|---|---|---|
| NIST SP 800-53 rev5 / FISMA guidance | US Government work, public domain | Control-ID citations (e.g. AU-6, AC-2(12), SI-4, AC-7) |
| NIST AI RMF 1.0 (NIST AI 100-1) | US Government work, public domain | Function/category identifiers in `docs/NIST_AI_RMF_MAPPING.md` (self-assessed mapping, not a conformance claim) |
| MITRE ATT&CK® | © The MITRE Corporation; used with attribution per MITRE's terms | Technique **IDs and names only** (e.g. T1078) as references. No MITRE descriptive text is reproduced. ATT&CK is a registered trademark of The MITRE Corporation. |
| OWASP LLM Top 10 | © OWASP Foundation, CC BY-SA 4.0 | Category names referenced with attribution in `redteam.py`; test strings are our own |
| Oracle audit-trail view names (e.g. `UNIFIED_AUDIT_TRAIL`) | Facts about a public interface; not copyrightable | Column/table names used to shape synthetic data only; no Oracle documentation text reproduced |
| CIS Benchmarks | Copyrighted | **Excluded entirely** |

## Data

All users, hosts, IP addresses, timestamps, and events in this repository are synthetic and were generated for testing. No real database, log, credential, or organizational data exists here.

Oracle is a trademark of Oracle Corporation. This project is not affiliated with or endorsed by Oracle, NIST, MITRE, OWASP, or any employer of the author.
