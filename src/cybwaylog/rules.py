"""Detection rules: suspicious ACTIVITY in an Oracle-style unified audit trail.

Fourteen deterministic rules (CYL-001..CYL-014). Each rule reads only raw
rows, builds its evidence strings only from raw row values, and returns one
``Detection`` whose status is FAIL when the rule fired and PASS otherwise.

References cite NIST SP 800-53 rev5 control IDs (US Government work, public
domain) and MITRE ATT&CK technique IDs + names (ATT&CK is a registered
trademark of The MITRE Corporation; only identifiers and names are used,
never MITRE's descriptive text — see LEGAL.md).

``recommended_response`` is ADVISORY text for a human responder. Nothing in
this project executes a response; the gate only dry-runs it.

Deterministic, offline, $0.
"""

from __future__ import annotations

import sqlite3
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Callable

PASS = "PASS"
FAIL = "FAIL"

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}
# Risk score bands; every rule has a DISTINCT score inside its band so the
# "single highest-severity incident" used by the ranking benchmark is unique.
RISK_BANDS = {"high": (70, 100), "medium": (40, 69), "low": (10, 39)}

BUSINESS_START_HOUR = 8
BUSINESS_END_HOUR = 18

# Thresholds (mirrored by docs/demo.html)
FAILED_LOGON_BURST_MIN = 5          # >= 5 failed logons ...
FAILED_LOGON_BURST_WINDOW_S = 600   # ... within 10 minutes
GRANT_SPIKE_MIN = 3                 # >= 3 grants by one account within 1 hour
GRANT_SPIKE_WINDOW_S = 3600
EXPORT_MIN_ROWS = 50_000            # absolute floor for a "mass export"
EXPORT_MULTIPLIER = 10              # and >= 10x the account's median SELECT size
EXPORT_MIN_HISTORY = 5              # need this many SELECTs to trust the median
DORMANT_DAYS = 60
NEW_HOST_MIN_HISTORY = 10           # account needs >= 10 logons for a host to be "rare"
NEW_HOST_MAX_COUNT = 2              # a host seen <= 2 times is "never-before-seen"
SENSITIVE_REPEAT_MIN = 5            # >= 5 reads of one sensitive object ...
SENSITIVE_REPEAT_WINDOW_S = 86_400  # ... within 24 hours
SESSION_ANOMALY_MULTIPLIER = 3      # daily logons >= 3x the account's median ...
SESSION_ANOMALY_MIN = 10            # ... and at least 10
EXPORT_AUDIT_OFF_WINDOW_S = 3600    # export followed by audit-off within 1 hour

ADMIN_ROLES = {"DBA", "SYSDBA", "SYSOPER", "AUDIT_ADMIN", "EXP_FULL_DATABASE",
               "DATAPUMP_EXP_FULL_DATABASE", "IMP_FULL_DATABASE"}
ADMIN_PRIVS = {"ALTER SYSTEM", "ALTER USER", "CREATE USER", "DROP USER", "GRANT ANY PRIVILEGE",
               "GRANT ANY ROLE", "SELECT ANY TABLE", "AUDIT SYSTEM", "EXEMPT ACCESS POLICY",
               "BECOME USER", "ALTER ANY TABLE", "ALTER DATABASE", "SYSDBA", "SYSOPER"}
PRIVILEGED_ACTIONS = {"ALTER SYSTEM", "ALTER DATABASE", "CREATE USER", "DROP USER", "ALTER USER",
                      "AUDIT", "NOAUDIT"}
GRANT_ACTIONS = {"GRANT ROLE", "SYSTEM GRANT", "GRANT OBJECT"}
AUDIT_OFF_ACTIONS = {"NOAUDIT", "ALTER AUDIT POLICY", "DROP AUDIT POLICY"}
DDL_ACTIONS = {"CREATE TABLE", "ALTER TABLE", "DROP TABLE", "TRUNCATE TABLE", "CREATE INDEX",
               "DROP INDEX", "CREATE VIEW", "DROP VIEW", "CREATE PROCEDURE", "ALTER PROCEDURE",
               "DROP PROCEDURE", "CREATE TRIGGER", "DROP TRIGGER"}
INTERACTIVE_PROGRAMS = {"sqlplus", "sql*plus", "sql developer", "toad", "sqlcl", "dbeaver"}


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str                       # high / medium / low
    status: str                         # FAIL = fired, PASS = nothing found
    evidence: list[str]                 # built ONLY from raw row values
    references: list[str]               # NIST 800-53 + MITRE ATT&CK ids
    recommended_response: str           # advisory; "; "-separated steps; never executed
    risk_score: int = 0                 # distinct per rule, drives triage ranking
    event_ids: list[int] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)   # accounts present in evidence rows
    objects: list[str] = field(default_factory=list)    # objects present in evidence rows
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ActivityLog:
    """Read-once view over the raw tables so every rule works from the same rows."""

    EVENT_COLS = ("event_id", "event_ts", "dbusername", "os_username", "userhost", "client_ip",
                  "client_program", "action_name", "object_schema", "object_name", "grantee",
                  "return_code", "sql_text_hash", "rows_affected", "system_privilege_used",
                  "session_id")   # comment_text (free text) is deliberately NOT loaded by rules

    def __init__(self, conn: sqlite3.Connection):
        cols = ", ".join(self.EVENT_COLS)
        self.events: list[dict] = [
            dict(zip(self.EVENT_COLS, row)) for row in conn.execute(
                f"SELECT {cols} FROM unified_audit_trail ORDER BY event_ts, event_id")
        ]
        self.by_user: dict[str, list[dict]] = {}
        for e in self.events:
            self.by_user.setdefault(e["dbusername"], []).append(e)
        self.users: dict[str, dict] = {
            r[0]: {"account_status": r[1], "account_type": r[2], "created": r[3], "last_login": r[4]}
            for r in conn.execute(
                "SELECT username, account_status, account_type, created, last_login "
                "FROM dba_users_snapshot")
        }
        self.session_ids: set[int] = {r[0] for r in conn.execute("SELECT session_id FROM dba_audit_session")}
        self.policies: list[dict] = [
            {"policy_name": r[0], "enabled": r[1], "changed_ts": r[2], "changed_by": r[3]}
            for r in conn.execute("SELECT policy_name, enabled, changed_ts, changed_by FROM audit_policy_state")
        ]
        self.windows: list[tuple[str, str, str]] = list(conn.execute(
            "SELECT start_ts, end_ts, ticket FROM change_windows ORDER BY start_ts"))
        self.sensitive: dict[tuple[str, str], str] = {
            (r[0], r[1]): r[2] for r in conn.execute(
                "SELECT object_schema, object_name, classification FROM sensitive_objects")
        }
        self.window_start = self.events[0]["event_ts"] if self.events else ""

    def account_type(self, user: str) -> str:
        return self.users.get(user, {}).get("account_type", "USER")

    def in_change_window(self, ts: str) -> str | None:
        for start, end, ticket in self.windows:
            if start <= ts <= end:
                return ticket
        return None

    def successful_logons(self) -> list[dict]:
        return [e for e in self.events if e["action_name"] == "LOGON" and e["return_code"] == 0]


def _dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _seconds(a: str, b: str) -> float:
    return (_dt(b) - _dt(a)).total_seconds()


def _is_business_hours(ts: str) -> bool:
    d = _dt(ts)
    return d.weekday() < 5 and BUSINESS_START_HOUR <= d.hour < BUSINESS_END_HOUR


def _obj(e: dict) -> str:
    if e["object_schema"]:
        return f"{e['object_schema']}.{e['object_name']}"
    return e["object_name"]


def _where(e: dict) -> str:
    return f"from {e['userhost']} ({e['client_ip']}) via {e['client_program']} as OS user {e['os_username']}"


class Hit:
    """One piece of evidence: text + the raw events/accounts/objects it came from."""

    def __init__(self, text: str, events: list[dict] | None = None, accounts=(), objects=(), ts: str = ""):
        self.text = text
        self.events = events or []
        self.accounts = set(accounts) | {e["dbusername"] for e in self.events} | \
            {e["grantee"] for e in self.events if e["grantee"]}
        self.objects = set(objects) | {_obj(e) for e in self.events if _obj(e)}
        stamps = [e["event_ts"] for e in self.events] + ([ts] if ts else [])
        self.first = min(stamps) if stamps else ""
        self.last = max(stamps) if stamps else ""


def _detection(rule_id: str, title: str, severity: str, risk: int, refs: list[str],
               response: str, hits: list[Hit]) -> Detection:
    lo, hi = RISK_BANDS[severity]
    assert lo <= risk <= hi, f"{rule_id}: risk {risk} outside {severity} band"
    event_ids = sorted({e["event_id"] for h in hits for e in h.events})
    firsts = [h.first for h in hits if h.first]
    lasts = [h.last for h in hits if h.last]
    return Detection(
        rule_id=rule_id, title=title, severity=severity,
        status=FAIL if hits else PASS,
        evidence=[h.text for h in hits], references=refs,
        recommended_response=response if hits else "",
        risk_score=risk, event_ids=event_ids,
        accounts=sorted({a for h in hits for a in h.accounts}),
        objects=sorted({o for h in hits for o in h.objects}),
        first_seen=min(firsts) if firsts else "", last_seen=max(lasts) if lasts else "",
    )


RuleFunc = Callable[[ActivityLog], Detection]
RULES: list[tuple[str, RuleFunc]] = []


def rule(func: RuleFunc) -> RuleFunc:
    RULES.append((func.__name__, func))
    return func


# ---------------------------------------------------------------- rules --

@rule
def off_hours_privileged_logon(log: ActivityLog) -> Detection:
    hits = []
    for e in log.successful_logons():
        if log.account_type(e["dbusername"]) != "DBA":
            continue
        if _is_business_hours(e["event_ts"]) or log.in_change_window(e["event_ts"]):
            continue
        hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} (DBA account) LOGON at "
                        f"{e['event_ts']} {_where(e)} — outside business hours "
                        f"(Mon-Fri {BUSINESS_START_HOUR:02d}:00-{BUSINESS_END_HOUR:02d}:00) "
                        f"and not inside any approved change window", [e]))
    return _detection(
        "CYL-001", "Off-hours logon by a privileged (DBA) account", "medium", 55,
        ["NIST 800-53r5 AC-2(12)", "NIST 800-53r5 AU-6", "MITRE ATT&CK T1078 Valid Accounts"],
        "Contact the account owner to confirm the logon; if unconfirmed, treat the credential as "
        "compromised and rotate it through change control; review every action in the session; "
        "consider a temporary lock via the DBA on-call process",
        hits)


@rule
def failed_logon_burst(log: ActivityLog) -> Detection:
    hits = []
    for user, evs in log.by_user.items():
        failed = [e for e in evs if e["action_name"] == "LOGON" and e["return_code"] != 0]
        i = 0
        while i < len(failed):
            j = i
            while j + 1 < len(failed) and \
                    _seconds(failed[i]["event_ts"], failed[j + 1]["event_ts"]) <= FAILED_LOGON_BURST_WINDOW_S:
                j += 1
            burst = failed[i:j + 1]
            if len(burst) >= FAILED_LOGON_BURST_MIN:
                hosts = sorted({f"{e['userhost']} ({e['client_ip']})" for e in burst})
                codes = sorted({e["return_code"] for e in burst})
                hits.append(Hit(f"{user}: {len(burst)} failed logons (return_code {codes}) between "
                                f"{burst[0]['event_ts']} and {burst[-1]['event_ts']} from {hosts}; "
                                f"events {[e['event_id'] for e in burst]}", burst))
                i = j + 1
            else:
                i += 1
    return _detection(
        "CYL-002", "Failed-logon burst (5 or more failures within 10 minutes)", "medium", 50,
        ["NIST 800-53r5 AC-7", "NIST 800-53r5 AU-6",
         "MITRE ATT&CK T1110 Brute Force", "MITRE ATT&CK T1110.001 Brute Force: Password Guessing"],
        "Verify whether the source host is known to the account owner; check for a subsequent "
        "successful logon from the same host; ensure the profile lockout policy engaged; block the "
        "source at the network boundary via change control if it is not recognised",
        hits)


@rule
def privilege_grant_spike(log: ActivityLog) -> Detection:
    hits = []
    for e in log.events:
        if e["action_name"] in ("GRANT ROLE", "SYSTEM GRANT") and \
                (e["object_name"] in ADMIN_ROLES or e["object_name"] in ADMIN_PRIVS):
            hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} executed {e['action_name']} "
                            f"{e['object_name']} TO {e['grantee']} at {e['event_ts']} "
                            f"(privilege used: {e['system_privilege_used']}) — new administrative grant",
                            [e]))
    for user, evs in log.by_user.items():
        grants = [e for e in evs if e["action_name"] in GRANT_ACTIONS]
        for i in range(len(grants)):
            window = [g for g in grants[i:] if _seconds(grants[i]["event_ts"], g["event_ts"]) <= GRANT_SPIKE_WINDOW_S]
            if len(window) >= GRANT_SPIKE_MIN:
                hits.append(Hit(f"{user}: {len(window)} grants within one hour starting "
                                f"{window[0]['event_ts']}; events {[g['event_id'] for g in window]}",
                                window))
                break
    return _detection(
        "CYL-003", "New administrative grant or privilege-grant spike", "high", 82,
        ["NIST 800-53r5 AC-2(7)", "NIST 800-53r5 AC-6(1)",
         "MITRE ATT&CK T1098 Account Manipulation", "MITRE ATT&CK T1078 Valid Accounts"],
        "Confirm the grant against an approved change ticket; if none exists, ask the grantor for "
        "justification and revoke through change control; review the grantee's subsequent activity",
        hits)


def _mass_export_events(log: ActivityLog) -> list[dict]:
    out = []
    for user, evs in log.by_user.items():
        selects = [e for e in evs if e["action_name"] == "SELECT" and e["rows_affected"] > 0]
        threshold = EXPORT_MIN_ROWS
        if len(selects) >= EXPORT_MIN_HISTORY:
            median = statistics.median(e["rows_affected"] for e in selects)
            threshold = max(EXPORT_MIN_ROWS, EXPORT_MULTIPLIER * median)
        out.extend(e for e in selects if e["rows_affected"] >= threshold)
    return sorted(out, key=lambda e: (e["event_ts"], e["event_id"]))


@rule
def mass_data_export(log: ActivityLog) -> Detection:
    hits = []
    for e in _mass_export_events(log):
        selects = [x["rows_affected"] for x in log.by_user[e["dbusername"]]
                   if x["action_name"] == "SELECT" and x["rows_affected"] > 0]
        median = statistics.median(selects) if selects else 0
        hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} SELECT on {_obj(e)} returned "
                        f"{e['rows_affected']:,} rows at {e['event_ts']} {_where(e)} — the account's "
                        f"median SELECT is {median:,.0f} rows", [e]))
    return _detection(
        "CYL-004", "Mass data export (rows far above the account's own baseline)", "high", 88,
        ["NIST 800-53r5 AU-6", "NIST 800-53r5 SI-4", "NIST 800-53r5 AC-23",
         "MITRE ATT&CK T1213 Data from Information Repositories"],
        "Identify what the query returned and where the data went; confirm a business need with "
        "the data owner; if unconfirmed, treat as potential exfiltration and open an incident; "
        "preserve the session's audit records",
        hits)


@rule
def dormant_account_reactivation(log: ActivityLog) -> Detection:
    hits = []
    for user, evs in log.by_user.items():
        prev = log.users.get(user, {}).get("last_login")
        for e in (x for x in evs if x["action_name"] == "LOGON" and x["return_code"] == 0):
            if prev:
                idle_days = (_dt(e["event_ts"]) - _dt(prev)).days
                if idle_days > DORMANT_DAYS:
                    hits.append(Hit(f"event {e['event_id']}: {user} LOGON at {e['event_ts']} {_where(e)} "
                                    f"after {idle_days} days idle (previous logon {prev})", [e]))
            prev = e["event_ts"]
    return _detection(
        "CYL-005", "Dormant account reactivated (logon after more than 60 days idle)", "medium", 60,
        ["NIST 800-53r5 AC-2(3)", "NIST 800-53r5 IA-4", "MITRE ATT&CK T1078 Valid Accounts"],
        "Confirm with the account owner that the account is still needed; if not, lock it through "
        "change control; review what the session did; check whether the credential was recently reset",
        hits)


def _audit_off_events(log: ActivityLog) -> list[dict]:
    return [e for e in log.events if e["action_name"] in AUDIT_OFF_ACTIONS and e["return_code"] == 0]


@rule
def audit_policy_tampering(log: ActivityLog) -> Detection:
    hits = []
    for e in _audit_off_events(log):
        hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} executed {e['action_name']} on audit "
                        f"policy {e['object_name']} at {e['event_ts']} {_where(e)}", [e]))
    for p in log.policies:
        if not p["enabled"] and p["changed_ts"] >= log.window_start:
            hits.append(Hit(f"audit_policy_state: policy {p['policy_name']} is DISABLED "
                            f"(changed {p['changed_ts']} by {p['changed_by']})",
                            accounts=[p["changed_by"]], objects=[p["policy_name"]], ts=p["changed_ts"]))
    return _detection(
        "CYL-006", "Audit-policy tampering (audit policy disabled)", "high", 92,
        ["NIST 800-53r5 AU-9", "NIST 800-53r5 AU-12",
         "MITRE ATT&CK T1562 Impair Defenses",
         "MITRE ATT&CK T1562.001 Impair Defenses: Disable or Modify Tools"],
        "Re-enable the policy through the emergency change process; determine who disabled it and "
        "why; assume any activity while auditing was off is unobserved and review other telemetry; "
        "open an incident",
        hits)


@rule
def privileged_action_by_non_dba(log: ActivityLog) -> Detection:
    hits = []
    for e in log.events:
        if log.account_type(e["dbusername"]) == "DBA" or e["return_code"] != 0:
            continue
        if e["system_privilege_used"] in ADMIN_PRIVS or e["action_name"] in PRIVILEGED_ACTIONS:
            hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} ({log.account_type(e['dbusername'])} "
                            f"account) executed {e['action_name']} using system privilege "
                            f"'{e['system_privilege_used']}' at {e['event_ts']} {_where(e)}", [e]))
    return _detection(
        "CYL-007", "High-privilege action by a non-DBA account", "high", 85,
        ["NIST 800-53r5 AC-6(9)", "NIST 800-53r5 AC-6(10)",
         "MITRE ATT&CK T1078 Valid Accounts", "MITRE ATT&CK T1548 Abuse Elevation Control Mechanism"],
        "Determine how the account obtained the privilege; revoke it through change control if not "
        "approved; review what the action changed and whether it needs to be reversed; open an incident",
        hits)


@rule
def logon_from_new_host(log: ActivityLog) -> Detection:
    hits = []
    for user, evs in log.by_user.items():
        logons = [e for e in evs if e["action_name"] == "LOGON" and e["return_code"] == 0]
        if len(logons) < NEW_HOST_MIN_HISTORY:
            continue
        counts: dict[str, int] = {}
        for e in logons:
            counts[e["userhost"]] = counts.get(e["userhost"], 0) + 1
        for e in logons:
            n = counts[e["userhost"]]
            if n <= NEW_HOST_MAX_COUNT and len(logons) - n >= NEW_HOST_MIN_HISTORY:
                usual = sorted(h for h in counts if counts[h] > NEW_HOST_MAX_COUNT)
                hits.append(Hit(f"event {e['event_id']}: {user} LOGON at {e['event_ts']} {_where(e)} — "
                                f"host {e['userhost']} seen {n} time(s) versus {len(logons) - n} logons "
                                f"from {usual}", [e]))
    return _detection(
        "CYL-008", "Logon from a never-before-seen host for this account", "medium", 58,
        ["NIST 800-53r5 AC-2(12)", "NIST 800-53r5 SI-4", "MITRE ATT&CK T1078 Valid Accounts"],
        "Ask the account owner whether they used the new host; if not, treat the credential as "
        "compromised and rotate it; review the session's activity; add the host to the allowlist "
        "only after verification",
        hits)


@rule
def ddl_outside_change_window(log: ActivityLog) -> Detection:
    hits = []
    windows = [w[2] for w in log.windows]
    for e in log.events:
        if e["action_name"] in DDL_ACTIONS and e["return_code"] == 0 and not log.in_change_window(e["event_ts"]):
            hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} executed {e['action_name']} on "
                            f"{_obj(e)} at {e['event_ts']} — no approved change window covers this time "
                            f"(approved windows: {windows})", [e]))
    return _detection(
        "CYL-009", "Schema change (DDL) outside an approved change window", "low", 35,
        ["NIST 800-53r5 CM-3", "NIST 800-53r5 CM-5",
         "MITRE ATT&CK T1505.001 Server Software Component: SQL Stored Procedures"],
        "Match the change to a ticket; if none, ask the executor for justification and review the "
        "object definition for unexpected changes; record a retrospective change or roll back via "
        "change control",
        hits)


@rule
def repeated_sensitive_access_by_non_owner(log: ActivityLog) -> Detection:
    hits = []
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for e in log.events:
        key = (e["object_schema"], e["object_name"])
        if key in log.sensitive and e["dbusername"] != e["object_schema"] and e["return_code"] == 0 \
                and e["action_name"] in ("SELECT", "UPDATE", "DELETE", "INSERT"):
            groups.setdefault((e["dbusername"],) + key, []).append(e)
    for (user, schema, name), evs in groups.items():
        for i in range(len(evs)):
            window = [x for x in evs[i:] if _seconds(evs[i]["event_ts"], x["event_ts"]) <= SENSITIVE_REPEAT_WINDOW_S]
            if len(window) >= SENSITIVE_REPEAT_MIN:
                total = sum(x["rows_affected"] for x in window)
                hits.append(Hit(f"{user} (not the owner {schema}) accessed {schema}.{name} "
                                f"[{log.sensitive[(schema, name)]}] {len(window)} times between "
                                f"{window[0]['event_ts']} and {window[-1]['event_ts']} ({total:,} rows in "
                                f"total); events {[x['event_id'] for x in window]}", window))
                break
    return _detection(
        "CYL-010", "Repeated access to a sensitive object by a non-owner", "medium", 62,
        ["NIST 800-53r5 AC-3", "NIST 800-53r5 AC-6", "NIST 800-53r5 AU-6",
         "MITRE ATT&CK T1213 Data from Information Repositories"],
        "Confirm with the data owner whether this access is authorised; if not, revoke the object "
        "grant through change control and review what was read; consider a data-access policy for "
        "the object",
        hits)


@rule
def session_count_anomaly(log: ActivityLog) -> Detection:
    hits = []
    for user, evs in log.by_user.items():
        per_day: dict[str, list[dict]] = {}
        for e in evs:
            if e["action_name"] == "LOGON" and e["return_code"] == 0:
                per_day.setdefault(e["event_ts"][:10], []).append(e)
        if len(per_day) < 2:
            continue
        median = statistics.median(len(v) for v in per_day.values())
        threshold = max(SESSION_ANOMALY_MIN, SESSION_ANOMALY_MULTIPLIER * median)
        for day, logons in sorted(per_day.items()):
            if len(logons) >= threshold:
                hits.append(Hit(f"{user}: {len(logons)} logons on {day} versus a median of {median:.0f} "
                                f"per active day (threshold {threshold:.0f}); first event "
                                f"{logons[0]['event_id']} at {logons[0]['event_ts']}, last event "
                                f"{logons[-1]['event_id']} at {logons[-1]['event_ts']}", logons))
    return _detection(
        "CYL-011", "Per-account session-count anomaly", "low", 30,
        ["NIST 800-53r5 AC-2(12)", "NIST 800-53r5 AC-10", "NIST 800-53r5 SI-4",
         "MITRE ATT&CK T1078 Valid Accounts"],
        "Check for a misbehaving script or shared credential; confirm with the account owner; if "
        "unexplained, review the sessions' activity and consider a sessions-per-user limit",
        hits)


@rule
def action_without_logon_session(log: ActivityLog) -> Detection:
    hits = []
    for e in log.events:
        if e["action_name"] == "LOGON" or e["session_id"] is None:
            continue
        if e["session_id"] not in log.session_ids:
            hits.append(Hit(f"event {e['event_id']}: {e['dbusername']} {e['action_name']} on {_obj(e)} "
                            f"({e['rows_affected']:,} rows) at {e['event_ts']} in session "
                            f"{e['session_id']}, which has no logon record in dba_audit_session", [e]))
    return _detection(
        "CYL-012", "Activity with no matching logon session", "high", 75,
        ["NIST 800-53r5 AU-10", "NIST 800-53r5 AU-6", "NIST 800-53r5 AU-12",
         "MITRE ATT&CK T1070 Indicator Removal",
         "MITRE ATT&CK T1550 Use Alternate Authentication Material"],
        "Verify audit-trail integrity (gaps, purges, clock skew); check for session hijacking or "
        "injected activity; preserve evidence and open an incident if the gap cannot be explained",
        hits)


@rule
def service_account_used_interactively(log: ActivityLog) -> Detection:
    hits = []
    for e in log.successful_logons():
        if log.account_type(e["dbusername"]) == "SERVICE" and e["client_program"].lower() in INTERACTIVE_PROGRAMS:
            hits.append(Hit(f"event {e['event_id']}: service account {e['dbusername']} LOGON at "
                            f"{e['event_ts']} {_where(e)} — interactive client program "
                            f"'{e['client_program']}' on a service account", [e]))
    return _detection(
        "CYL-013", "Service account used interactively by a person", "medium", 52,
        ["NIST 800-53r5 AC-2(7)", "NIST 800-53r5 AC-6(5)", "NIST 800-53r5 IA-2",
         "MITRE ATT&CK T1078 Valid Accounts"],
        "Identify the person behind the OS user; rotate the service credential through change "
        "control; review what the session did; restrict the service account to its application hosts "
        "and non-interactive programs",
        hits)


@rule
def export_followed_by_audit_off(log: ActivityLog) -> Detection:
    hits = []
    offs = _audit_off_events(log)
    for x in _mass_export_events(log):
        for a in offs:
            gap = _seconds(x["event_ts"], a["event_ts"])
            if 0 <= gap <= EXPORT_AUDIT_OFF_WINDOW_S:
                hits.append(Hit(f"event {x['event_id']}: {x['dbusername']} exported {x['rows_affected']:,} "
                                f"rows from {_obj(x)} at {x['event_ts']}; then event {a['event_id']}: "
                                f"{a['dbusername']} executed {a['action_name']} on audit policy "
                                f"{a['object_name']} at {a['event_ts']} ({gap / 60:.0f} minutes later)",
                                [x, a]))
    return _detection(
        "CYL-014", "Mass export followed by audit-off within one hour (correlation)", "high", 97,
        ["NIST 800-53r5 AU-9", "NIST 800-53r5 IR-4", "NIST 800-53r5 SI-4",
         "MITRE ATT&CK T1213 Data from Information Repositories",
         "MITRE ATT&CK T1562 Impair Defenses", "MITRE ATT&CK T1070 Indicator Removal"],
        "Treat as an active exfiltration-and-cover-up pattern: open an incident immediately; "
        "preserve all audit records; re-enable auditing via emergency change; confirm the accounts "
        "involved with their owners and rotate credentials if unconfirmed",
        hits)


# ----------------------------------------------------------------- api --

def run_all_rules(conn: sqlite3.Connection) -> list[Detection]:
    """Evaluate every rule against the raw log, in fixed rule order."""
    log = ActivityLog(conn)
    return [func(log) for _, func in RULES]


def top_incident(detections: list[Detection | dict]) -> str | None:
    """Rule id of the single highest-priority fired detection (severity, then risk score)."""
    fired = [d if isinstance(d, dict) else d.to_dict() for d in detections]
    fired = [d for d in fired if d["status"] == FAIL]
    if not fired:
        return None
    return max(fired, key=lambda d: (SEVERITY_RANK[d["severity"]], d["risk_score"]))["rule_id"]
