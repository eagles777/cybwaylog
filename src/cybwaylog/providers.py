"""LLM provider abstraction. MOCK by default — no API key, no network, $0.

MockProvider simulates an imperfect triage LLM deterministically (seeded):
it mostly agrees with the ground-truth rule engine but occasionally misses
an incident, fabricates one (or an account), or mis-ranks a severity. That
imperfection is the whole point — it gives the independent checker and the
eval benchmark something real to catch and measure.

GeminiProvider / LiveProvider are guarded: they refuse without an explicit
opt-in, an API key from the environment (.env is gitignored), AND a
BudgetCeiling. The ceiling defaults to $0.00, so only a free-tier key with a
$0.00 per-call estimate can ever pass. A quota / 429 answer raises
FreeTierQuotaExhausted — the project STOPS; it never falls back to anything
paid. The core never imports network libraries.
"""

from __future__ import annotations

import json
import os
import random

from .budget import BudgetCeiling, BudgetExceeded  # noqa: F401  (re-exported for callers)

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}
FABRICATED_RULE_ID = "CYL-999"
PHANTOM_ACCOUNT = "GHOST_FAKE"


class FreeTierQuotaExhausted(RuntimeError):
    """The free quota is used up. STOP and report — never fall back to a paid path."""


def _steps(text) -> list[str]:
    if isinstance(text, list):
        return list(text)
    return [s.strip() for s in str(text).split(";") if s.strip()]


class MockProvider:
    """Deterministic simulated triage LLM. cost = $0 always."""

    name = "mock"
    cost_per_call_usd = 0.0

    def __init__(self, seed: int = 0, miss_rate: float = 0.10, fabricate_rate: float = 0.10,
                 misrank_rate: float = 0.05):
        self.rng = random.Random(seed)
        self.miss_rate = miss_rate
        self.fabricate_rate = fabricate_rate
        self.misrank_rate = misrank_rate

    def _wrong_severity(self, severity: str) -> str:
        return self.rng.choice([s for s in SEVERITY_RANK if s != severity])

    def _report(self, d: dict, severity: str) -> dict:
        return {
            "rule_id": d["rule_id"],
            "severity": severity,
            "narrative": f"{d['title']}. " + " ".join(d["evidence"][:3]),
            "affected_accounts": list(d.get("accounts", [])),
            "recommended_response": _steps(d.get("recommended_response", "")),
            "confidence": round(self.rng.uniform(0.60, 0.98), 2),
            "_rank": (SEVERITY_RANK[severity], d.get("risk_score", 0)),
        }

    def complete(self, prompt: str, ground_truth_detections: list[dict]) -> str:
        """Return strict-JSON incident reports in triage order (highest first),
        imperfectly derived from ground truth."""
        truth = [d for d in ground_truth_detections if d.get("status") == "FAIL"]
        truth.sort(key=lambda d: (SEVERITY_RANK[d["severity"]], d.get("risk_score", 0)), reverse=True)
        reports = []
        for d in truth:
            if self.rng.random() < self.miss_rate:
                continue  # simulated miss (false negative)
            severity = d["severity"]
            if self.rng.random() < self.misrank_rate:
                severity = self._wrong_severity(severity)  # simulated mis-ranking
            reports.append(self._report(d, severity))
        if self.rng.random() < self.fabricate_rate:
            if reports and self.rng.random() < 0.5:
                # hallucinated account inside an otherwise correct report
                self.rng.choice(reports)["affected_accounts"].append(PHANTOM_ACCOUNT)
            else:
                reports.append({
                    "rule_id": FABRICATED_RULE_ID,
                    "severity": "low",
                    "narrative": "Fabricated incident (simulated hallucination): unusual activity by "
                                 f"{PHANTOM_ACCOUNT} on APP_FAKE.PHANTOM_TABLE_FAKE",
                    "affected_accounts": [PHANTOM_ACCOUNT],
                    "recommended_response": ["Review the account"],
                    "confidence": 0.51,
                    "_rank": (SEVERITY_RANK["low"], 0),
                })
        reports.sort(key=lambda r: r["_rank"], reverse=True)   # the triage ranking
        for r in reports:
            r.pop("_rank")
        return json.dumps(reports)


class GeminiProvider:
    """Live Google Gemini provider for the ONE demo run. Guarded five ways:

    1. opt_in=True must be passed explicitly (mock is always the default)
    2. GOOGLE_API_KEY must exist in the environment (gitignored .env / CI secret)
    3. a BudgetCeiling must be supplied; BudgetCeiling.charge() runs BEFORE
       every network call — over budget means the call never happens. The
       ceiling defaults to $0.00: with free_tier=True the per-call estimate is
       $0.00 and passes; with free_tier=False the published-pricing estimate
       (> $0) is refused at the default ceiling.
    4. A quota / 429 answer raises FreeTierQuotaExhausted. No retry, no
       fallback to a paid model — ever.
    5. Required account setup: the key must be created WITHOUT billing, so
       charges are impossible at the account level too.

    Only event METADATA goes into the prompt — never free-text fields.
    """

    name = "gemini"
    MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
    FREE_TIER_COST_PER_CALL_USD = 0.0
    # Conservative per-call estimate at published Flash-class pricing (paid keys only).
    PAID_EST_COST_PER_CALL_USD = 0.01

    def __init__(self, budget: BudgetCeiling, opt_in: bool = False, transport=None,
                 free_tier: bool = True):
        if not opt_in:
            raise RuntimeError("Live mode requires explicit opt_in=True (mock is the default).")
        if not os.environ.get("GOOGLE_API_KEY"):
            raise RuntimeError("Live mode requires GOOGLE_API_KEY in the environment "
                               "(local gitignored .env or CI secret). Refusing to run.")
        if not isinstance(budget, BudgetCeiling):
            raise RuntimeError("Live mode requires a BudgetCeiling (default ceiling $0.00).")
        self.budget = budget
        self.free_tier = free_tier
        self.est_cost_per_call_usd = (self.FREE_TIER_COST_PER_CALL_USD if free_tier
                                      else self.PAID_EST_COST_PER_CALL_USD)
        self._transport = transport or self._http_post  # injectable for offline tests

    @staticmethod
    def _http_post(url: str, payload: dict) -> dict:
        import json as _json
        import urllib.request
        req = urllib.request.Request(
            url, data=_json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            return _json.loads(resp.read().decode("utf-8"))

    def generate(self, prompt: str) -> str:
        # Budget is charged BEFORE the network call. Over budget -> no call.
        self.budget.charge(self.est_cost_per_call_usd)
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.MODEL}:generateContent?key={os.environ['GOOGLE_API_KEY']}")
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
        }
        try:
            data = self._transport(url, payload)
        except Exception as exc:  # duck-typed: urllib HTTPError carries .code
            if getattr(exc, "code", None) == 429:
                raise FreeTierQuotaExhausted(
                    "Free-tier quota exhausted (HTTP 429). STOPPING — this project never "
                    "retries against or falls back to a paid model.") from exc
            raise
        err = data.get("error") if isinstance(data, dict) else None
        if err and (err.get("code") == 429 or err.get("status") == "RESOURCE_EXHAUSTED"):
            raise FreeTierQuotaExhausted(
                "Free-tier quota exhausted (RESOURCE_EXHAUSTED). STOPPING — no paid fallback.")
        return data["candidates"][0]["content"]["parts"][0]["text"]


class LiveProvider:
    """Guarded stub for a generic paid API. Never used by tests or CI, and it
    has no network path at all: at the default $0.00 ceiling its cost estimate
    is refused before anything else could happen."""

    name = "live"

    def __init__(self, budget: BudgetCeiling, opt_in: bool = False):
        if not opt_in:
            raise RuntimeError("Live mode requires explicit opt_in=True (mock is the default).")
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("Live mode requires ANTHROPIC_API_KEY in the environment "
                               "(local gitignored .env or CI secret). Refusing to run.")
        if not isinstance(budget, BudgetCeiling):
            raise RuntimeError("Live mode requires a BudgetCeiling (default ceiling $0.00).")
        self.budget = budget

    def complete(self, prompt: str, ground_truth_detections=None, estimated_cost_usd: float = 0.05) -> str:
        # Budget is charged BEFORE any call could be made ($0.00 ceiling -> refused here).
        self.budget.charge(estimated_cost_usd)
        raise NotImplementedError("Live API calls are implemented only for the one free-tier demo run.")
