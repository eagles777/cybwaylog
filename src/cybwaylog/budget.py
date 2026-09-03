"""Code-enforced budget ceiling for any live LLM call.

ZERO-SPEND PROJECT: the ceiling DEFAULTS TO $0.00, which means only calls
with an estimated cost of exactly $0.00 (a free-tier key with no billing
attached) can ever pass. The ceiling is charged BEFORE a call is made;
exceeding it raises and the call never happens. dry_run() lets a human see
the projected cost first.
"""

from __future__ import annotations

DEFAULT_CEILING_USD = 0.00


class BudgetExceeded(RuntimeError):
    pass


class BudgetCeiling:
    def __init__(self, max_usd: float = DEFAULT_CEILING_USD):
        if max_usd < 0:
            raise ValueError("budget must be >= 0")
        self.max_usd = float(max_usd)
        self.spent_usd = 0.0

    def dry_run(self, estimated_cost_usd: float) -> dict:
        projected = self.spent_usd + estimated_cost_usd
        return {
            "estimated_cost_usd": estimated_cost_usd,
            "spent_usd": self.spent_usd,
            "projected_usd": projected,
            "ceiling_usd": self.max_usd,
            "would_exceed": projected > self.max_usd,
        }

    def charge(self, estimated_cost_usd: float) -> None:
        if estimated_cost_usd < 0:
            raise ValueError("estimated cost must be >= 0")
        if self.dry_run(estimated_cost_usd)["would_exceed"]:
            raise BudgetExceeded(
                f"charge of ${estimated_cost_usd:.4f} would exceed ceiling "
                f"${self.max_usd:.2f} (spent ${self.spent_usd:.4f}). "
                "This is a zero-spend project: raise the ceiling only with an explicit override."
            )
        self.spent_usd += estimated_cost_usd
