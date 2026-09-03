"""The NIST AI RMF mapping must only cite files that actually exist.

This keeps the mapping document honest: a claim that points at a module or
test that does not exist fails the build."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "NIST_AI_RMF_MAPPING.md"


def _cited_paths():
    text = DOC.read_text(encoding="utf-8")
    # backticked tokens that look like repo paths (contain a slash or a known extension)
    for tok in re.findall(r"`([^`]+)`", text):
        path = tok.split("::")[0].split(" (")[0].strip()
        if "/" in path or path.endswith((".md", ".toml", ".py")):
            yield path


def test_mapping_document_exists_and_covers_all_four_functions():
    text = DOC.read_text(encoding="utf-8")
    for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
        assert f"## {fn}" in text, f"missing AI RMF function section: {fn}"


def test_every_cited_repo_path_exists():
    missing = sorted({p for p in _cited_paths() if not (ROOT / p).exists()})
    assert not missing, f"AI RMF mapping cites non-existent paths: {missing}"


def test_cited_test_ids_exist():
    text = DOC.read_text(encoding="utf-8")
    for path, name in re.findall(r"`(tests/[^:`]+)::([A-Za-z_0-9]+)`", text):
        src = (ROOT / path).read_text(encoding="utf-8")
        assert f"def {name}(" in src, f"{path} has no test named {name}"
