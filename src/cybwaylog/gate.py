"""Human-in-the-loop triage gate, including NIST CA-5-style exceptions.

No incident is closed and no response step is "run" without an explicit,
logged human decision. There is NO execute path anywhere in this codebase:
dry_run_response() is the terminal state — it returns the recommended
steps for a human responder, marked executed=False, full stop.

Decisions:
  confirm                -> the incident is real; response steps may be dry-run
  dismiss_false_positive -> not an incident; stays blocked
  escalate               -> hand to a higher tier; stays open and blocked
  accept_exception       -> a HUMAN accepts the activity as known/acceptable,
                            with mandatory paperwork modeled on the PUBLIC
                            structure of NIST SP 800-53 rev5 CA-5 (Plan of
                            Action and Milestones): justification, compensating
                            control, named accepter, mandatory review date.
                            Blank fields -> IncompleteRiskAcceptance. The
                            exception EXPIRES after review_date and the
                            incident counts as open again.

Every decision is appended to the tamper-evident hash chain.
"""

from __future__ import annotations

from datetime import date

from .auditlog import AuditLog


class ApprovalRequired(RuntimeError):
    pass


class IncompleteRiskAcceptance(ValueError):
    pass


EXCEPTION_FIELDS = ("justification", "compensating_control", "accepted_by", "review_date")

STATUS_PENDING = "pending"
STATUS_CONFIRMED = "confirmed"
STATUS_DISMISSED = "dismissed_false_positive"
STATUS_ESCALATED = "escalated"
STATUS_EXCEPTION = "exception_accepted"
STATUS_EXPIRED = "expired"
OPEN_STATUSES = (STATUS_PENDING, STATUS_ESCALATED, STATUS_EXPIRED)


class ApprovalGate:
    def __init__(self, log: AuditLog):
        self.log = log
        self._decisions: dict[str, dict] = {}

    # -- intake -----------------------------------------------------------
    def submit(self, incident: dict, checker_verdict: str) -> None:
        rid = incident["rule_id"]
        self._decisions[rid] = {"status": STATUS_PENDING, "checker_verdict": checker_verdict}
        self.log.append("incident_submitted", {"rule_id": rid, "checker_verdict": checker_verdict})

    # -- human decisions ----------------------------------------------------
    def confirm(self, rule_id: str, approver: str, reason: str) -> None:
        self._decide(rule_id, STATUS_CONFIRMED, "incident_confirmed", approver, reason)

    def dismiss_false_positive(self, rule_id: str, approver: str, reason: str) -> None:
        self._decide(rule_id, STATUS_DISMISSED, "incident_dismissed_false_positive", approver, reason)

    def escalate(self, rule_id: str, approver: str, reason: str) -> None:
        self._decide(rule_id, STATUS_ESCALATED, "incident_escalated", approver, reason)

    def _decide(self, rule_id: str, status: str, event: str, approver: str, reason: str) -> None:
        if rule_id not in self._decisions:
            raise KeyError(f"incident {rule_id} was never submitted to the gate")
        if not (approver or "").strip() or not (reason or "").strip():
            raise ValueError("approver and reason are mandatory (they are logged)")
        self._decisions[rule_id].update(status=status, approver=approver, reason=reason)
        self.log.append(event, {"rule_id": rule_id, "approver": approver, "reason": reason})

    def accept_exception(self, rule_id: str, *, justification: str, compensating_control: str,
                         accepted_by: str, review_date: str) -> dict:
        """Fourth decision path (NIST CA-5 style): a HUMAN accepts the activity.
        Every field is mandatory; the exception expires at review_date."""
        if rule_id not in self._decisions:
            raise KeyError(f"incident {rule_id} was never submitted to the gate")
        record = {
            "justification": justification,
            "compensating_control": compensating_control,
            "accepted_by": accepted_by,
            "review_date": review_date,
        }
        blank = [k for k in EXCEPTION_FIELDS if not str(record[k] or "").strip()]
        if blank:
            raise IncompleteRiskAcceptance(f"exception rejected — blank fields: {blank}")
        date.fromisoformat(review_date)  # must be a valid ISO date
        self._decisions[rule_id].update(status=STATUS_EXCEPTION, **record)
        self.log.append("incident_exception_accepted", {"rule_id": rule_id, **record})
        return dict(self._decisions[rule_id])

    # -- state ----------------------------------------------------------------
    def status(self, rule_id: str, as_of: date | None = None) -> str:
        """Current state. An exception whose review_date has passed reverts to
        'expired' — the incident counts as open again."""
        d = self._decisions.get(rule_id)
        if d is None:
            return "unsubmitted"
        if d["status"] == STATUS_EXCEPTION and as_of is not None:
            if as_of > date.fromisoformat(d["review_date"]):
                return STATUS_EXPIRED
        return d["status"]

    def open_incidents(self, as_of: date) -> list[str]:
        """Rule IDs still requiring attention: pending, escalated, or expired."""
        return [rid for rid in self._decisions if self.status(rid, as_of=as_of) in OPEN_STATUSES]

    # -- terminal state: dry run only --------------------------------------------
    def dry_run_response(self, incident: dict) -> dict:
        """Return the recommended response steps as a dry-run plan. NEVER executes.
        Requires a prior explicit human confirmation (an accepted exception,
        a dismissal or an escalation does NOT count)."""
        rid = incident["rule_id"]
        if self.status(rid) != STATUS_CONFIRMED:
            raise ApprovalRequired(
                f"incident {rid} is '{self.status(rid)}' — a response requires explicit human confirmation")
        steps = incident.get("recommended_response", [])
        if isinstance(steps, str):
            steps = [s.strip() for s in steps.split(";") if s.strip()]
        plan = {"rule_id": rid, "steps": list(steps), "executed": False,
                "note": "dry run only; execution is out of scope by design — a human responder acts"}
        self.log.append("response_dry_run", plan)
        return plan
