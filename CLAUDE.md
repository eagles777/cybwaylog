# CLAUDE.md — Project Instructions for Cybwaylog

Cybwaylog is an open-source, governed-AI database *activity* auditor — a personal AI-engineering portfolio project and the sibling of Cybwaydb (which audits database *configuration*). Cybwaydb = is the database set up securely (static state). Cybwaylog = is anything suspicious happening in it (dynamic behavior). Together they form one product family. It is NOT connected to any employer and contains zero employer or organizational data. Everything in the repo is synthetic.

Act as a senior engineer + build partner: direct, practical, push back on weak ideas, no praise-padding. Build the code; the owner supervises and approves. Show passing tests before moving on. Track progress across sessions in PROGRESS.md so it compounds.

## STANDING SESSION REMINDER

At the START of every session, check whether the GitHub repo (eagles777/cybwaylog) is PUBLIC or PRIVATE and report the status before doing anything else. It stays PRIVATE until the owner reviews it and explicitly says to go public. Never change visibility on your own, and never publish anything (pages, releases, artifacts) without asking first.

## HARD RULES (never violate)

* PRIVACY (STRICT — highest priority): NEVER put personal information in this repo or any published artifact. No location/city, no citizenship, no employer or agency names, no job history, no career specifics, no contact info, no email. Attribution is limited to the author's name **V. Vikram** as copyright holder — nothing more. Before committing or publishing ANY personal detail, STOP, ask the owner first, and suggest a safer alternative. Never assume it is okay.
* DEFENSIVE security only. No offensive/exploit/malware code, no attacker tooling. "Red-team" = self-testing OUR OWN tool with published OWASP-LLM patterns to prove our gates catch them. If anything drifts toward "how to attack X," reframe as "how to detect X."
* Synthetic data only. Every user, host, IP, timestamp, and event is invented for testing. Never any real database, log, credential, or organizational data.
* Copyright: NIST SP 800-53 / NIST AI RMF = US Government works, public domain (cite control IDs). MITRE ATT&CK = reference technique IDs and names only, with attribution to The MITRE Corporation; never copy MITRE's descriptive text. OWASP LLM Top 10 = category names with attribution to the OWASP Foundation. Copyrighted third-party benchmarks (e.g. CIS) are EXCLUDED. Our code = Apache-2.0, V. Vikram = copyright holder. Maintain LEGAL.md + NOTICE.
* COST: ZERO-SPEND PROJECT. Never use a paid API. Default mode is MOCK (no key, no network, $0) and is the only mode CI uses. Any live call must use a free tier from a key with NO billing attached; the budget ceiling defaults to $0.00 and is checked BEFORE every call; if a free quota is exhausted, STOP and report — never fall back to anything paid. Never ask the owner to enable billing or start a paid trial. Keys live only in a gitignored .env or CI secrets — never in the repo, never in chat.
* Maintainability: pinned deps, stdlib-first runtime, MAINTENANCE.md + BACKLOG.md so a future session can maintain this.
