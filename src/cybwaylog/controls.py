"""Repo-hygiene controls: policy lint and secret scan.

Both are DEFENSIVE self-checks run over our own repository:
- secret_scan: detects credential-shaped strings before they get committed.
- policy_lint: enforces CLAUDE.md hard rules (no copyrighted benchmark
  content, no personal-information patterns, .env must be gitignored).

Deterministic, offline, stdlib-only.
"""

from __future__ import annotations

import re
from pathlib import Path

# Patterns for credential-shaped content (detection only).
SECRET_PATTERNS = [
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("generic_api_key", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("password_assignment", re.compile(r"(?i)\bpassword\b\s*[:=]\s*['\"](?!fake|synthetic|changeme|xxx)[^'\"]{6,}['\"]")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("oracle_connect_string", re.compile(r"(?i)\b\w+/\w+@[\w.-]+:\d+/\w+\b")),
]

# Terms that must never appear in this repo (CLAUDE.md hard rules).
POLICY_FORBIDDEN_TERMS = [
    "cis benchmark",          # copyrighted content excluded
    "cis_benchmark",
]

# Personal-information patterns (CLAUDE.md PRIVACY rule): no contact details,
# no nationality, no employment details. Email-like strings and the literal
# words below are flagged wherever they appear outside the policy files themselves.
PERSONAL_INFO_PATTERNS = [
    ("email-like string", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("citizen", re.compile(r"(?i)\bcitizen")),
    ("employer", re.compile(r"(?i)\bemployer")),
]

# Files that STATE the policy (and so legitimately contain the forbidden words).
POLICY_FILES = {"controls.py", "CLAUDE.md", "LEGAL.md"}

SCAN_EXTENSIONS = {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sql", ".cfg", ".ini", ".html", ".js"}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "runs"}


def _iter_files(root: str | Path):
    for p in Path(root).rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix.lower() in SCAN_EXTENSIONS:
            yield p


def secret_scan(root: str | Path, allowlist: set[str] | None = None) -> list[dict]:
    """Scan text files under root for credential-shaped strings.
    Returns a list of hits (empty = clean)."""
    allowlist = allowlist or set()
    hits = []
    for p in _iter_files(root):
        if p.name in allowlist:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if "secret-scan: allow" in line:
                continue
            for name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    hits.append({"file": str(p), "line": lineno, "pattern": name})
    return hits


def policy_lint(root: str | Path) -> list[dict]:
    """Enforce CLAUDE.md content rules across the repo."""
    violations = []
    for p in _iter_files(root):
        if p.name in POLICY_FILES:
            continue  # these files state the policy itself
        text = p.read_text(encoding="utf-8", errors="replace")
        lowered = text.lower()
        for term in POLICY_FORBIDDEN_TERMS:
            if term in lowered:
                violations.append({"file": str(p), "term": term})
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, pattern in PERSONAL_INFO_PATTERNS:
                if pattern.search(line):
                    violations.append({"file": str(p), "line": lineno, "term": name})
    env = Path(root) / ".env"
    if env.exists():
        gitignore = (Path(root) / ".gitignore")
        ignored = gitignore.exists() and ".env" in gitignore.read_text(encoding="utf-8")
        if not ignored:
            violations.append({"file": str(env), "term": ".env present but not gitignored"})
    return violations
