"""Synthetic database ACTIVITY log, modeled on Oracle unified-audit-trail views.

ALL DATA IS FAKE. Every user, host, IP address, timestamp and event is
invented for testing (usernames end in _FAKE, hosts end in .fake.test or
-FAKE). No real database, log, credential or organizational data appears
here or anywhere else in this project.

What the generator produces (deterministic for a given seed):

* ~14 days of BASELINE traffic for 8 fake accounts: business-hours patterns
  for people, round-the-clock pooled sessions for service accounts, a
  nightly ETL batch, DDL only inside approved change windows, and a few
  harmless oddities (a typo'd password, an occasional cross-schema report)
  that sit BELOW every detection threshold. This is what "normal" looks like.
* With ``incidents=True`` (default) it also plants ONE seeded incident per
  detection rule so ground truth is known exactly. ``incidents=False`` yields
  a clean log on which every rule must PASS (zero detections).
* An injection CANARY (see redteam.CANARY_COMMENT) is planted in the
  free-text ``comment_text`` column of one otherwise harmless event, so the
  pipeline must prove it catches data-borne prompt injection.

Timestamps are ISO-8601 strings in the database's local time and sort
lexicographically. ``db_metadata.scan_date`` is frozen at 2026-07-17 so every
"days since" computation is reproducible.
"""

from __future__ import annotations

import hashlib
import random
import sqlite3
from datetime import date, datetime, timedelta

from .redteam import CANARY_COMMENT

SCAN_DATE = "2026-07-17"                 # frozen "today" for determinism
WINDOW_START = date(2026, 7, 3)          # first day of the 14-day audit window
WINDOW_DAYS = 14                         # window = 2026-07-03 .. 2026-07-16
BUSINESS_START_HOUR = 8                  # business hours: Mon-Fri 08:00-18:00
BUSINESS_END_HOUR = 18

SCHEMA = """
CREATE TABLE unified_audit_trail (
    event_id INTEGER PRIMARY KEY,
    event_ts TEXT NOT NULL,                -- ISO-8601, database local time
    dbusername TEXT NOT NULL,
    os_username TEXT NOT NULL,
    userhost TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_program TEXT NOT NULL,          -- JDBC Thin Client / sqlplus / SQL Developer ...
    action_name TEXT NOT NULL,             -- LOGON / LOGOFF / SELECT / ... / GRANT ROLE / NOAUDIT
    object_schema TEXT NOT NULL,           -- '' when not applicable
    object_name TEXT NOT NULL,             -- table, role, privilege or audit-policy name; '' if n/a
    grantee TEXT NOT NULL,                 -- target of GRANT / REVOKE / ALTER USER; '' otherwise
    return_code INTEGER NOT NULL,          -- 0 = success; 1017 = invalid username/password
    sql_text_hash TEXT NOT NULL,           -- hash of the statement (never the SQL text itself)
    rows_affected INTEGER NOT NULL,
    system_privilege_used TEXT NOT NULL,   -- '' when no system privilege was exercised
    session_id INTEGER,                    -- NULL for failed logons (no session was created)
    comment_text TEXT NOT NULL             -- FREE TEXT: client info / annotations. UNTRUSTED.
);

CREATE TABLE dba_audit_session (
    session_id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    os_username TEXT NOT NULL,
    userhost TEXT NOT NULL,
    client_program TEXT NOT NULL,
    logon_ts TEXT NOT NULL,
    logoff_ts TEXT                         -- NULL while the session is still open
);

CREATE TABLE dba_users_snapshot (
    username TEXT PRIMARY KEY,
    account_status TEXT NOT NULL,          -- OPEN / LOCKED / EXPIRED
    account_type TEXT NOT NULL,            -- DBA / SERVICE / USER
    created TEXT NOT NULL,
    last_login TEXT                        -- last successful logon BEFORE the audit window; NULL = never
);

CREATE TABLE audit_policy_state (
    policy_name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,              -- 1 = enabled, 0 = disabled
    changed_ts TEXT NOT NULL,
    changed_by TEXT NOT NULL
);

CREATE TABLE change_windows (              -- approved maintenance windows (change control)
    start_ts TEXT NOT NULL,
    end_ts TEXT NOT NULL,
    ticket TEXT NOT NULL
);

CREATE TABLE sensitive_objects (           -- data-classification register
    object_schema TEXT NOT NULL,
    object_name TEXT NOT NULL,
    classification TEXT NOT NULL,
    PRIMARY KEY (object_schema, object_name)
);

CREATE TABLE db_metadata (                 -- synthetic instance metadata
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX ix_uat_user_ts ON unified_audit_trail (dbusername, event_ts);
CREATE INDEX ix_uat_action ON unified_audit_trail (action_name);
"""

# (username, account_type, os_username, userhost, client_ip, client_program)
USERS = [
    ("APP_SVC_FAKE", "SERVICE", "appsvc", "app01.fake.test", "10.0.0.11", "JDBC Thin Client"),
    ("ETL_SVC_FAKE", "SERVICE", "etlsvc", "etl01.fake.test", "10.0.0.12", "JDBC Thin Client"),
    ("HR_FAKE", "SERVICE", "hrapp", "hr01.fake.test", "10.0.0.13", "JDBC Thin Client"),
    ("JDOE_FAKE", "USER", "jdoe", "WS-JDOE-FAKE", "10.0.1.21", "SQL Developer"),
    ("RPT_RO_FAKE", "USER", "rpt", "WS-RPT-FAKE", "10.0.1.22", "SQL Developer"),
    ("DBA_ONE_FAKE", "DBA", "dba1", "WS-DBA1-FAKE", "10.0.1.31", "sqlplus"),
    ("DBA_TWO_FAKE", "DBA", "dba2", "WS-DBA2-FAKE", "10.0.1.32", "sqlplus"),
    ("OLD_SVC_FAKE", "SERVICE", "oldsvc", "legacy01.fake.test", "10.0.0.19", "JDBC Thin Client"),
]
USER_PROFILE = {u[0]: u for u in USERS}

# dba_users_snapshot rows: (username, account_status, account_type, created, last_login-before-window)
USER_SNAPSHOT = [
    ("APP_SVC_FAKE", "OPEN", "SERVICE", "2024-02-10T09:00:00", "2026-07-02T23:41:10"),
    ("ETL_SVC_FAKE", "OPEN", "SERVICE", "2024-02-10T09:05:00", "2026-07-02T01:03:22"),
    ("HR_FAKE", "OPEN", "SERVICE", "2024-03-01T10:00:00", "2026-07-02T17:12:45"),
    ("JDOE_FAKE", "OPEN", "USER", "2024-03-05T11:30:00", "2026-07-02T16:55:03"),
    ("RPT_RO_FAKE", "OPEN", "USER", "2024-05-20T14:00:00", "2026-07-02T15:20:37"),
    ("DBA_ONE_FAKE", "OPEN", "DBA", "2024-01-15T08:00:00", "2026-07-02T17:30:00"),
    ("DBA_TWO_FAKE", "OPEN", "DBA", "2024-01-15T08:05:00", "2026-07-02T16:02:11"),
    ("OLD_SVC_FAKE", "OPEN", "SERVICE", "2023-06-01T09:00:00", "2026-03-15T14:02:00"),  # dormant
]

AUDIT_POLICIES = [
    # (policy_name, enabled, changed_ts, changed_by)
    ("ORA_SECURECONFIG", 1, "2025-11-03T10:00:00", "DBA_ONE_FAKE"),
    ("ORA_LOGON_FAILURES", 1, "2025-11-03T10:00:00", "DBA_ONE_FAKE"),
    ("ORA_ACCOUNT_MGMT", 1, "2025-11-03T10:00:00", "DBA_ONE_FAKE"),
    ("FAKE_APP_DML_POLICY", 1, "2026-02-14T11:20:00", "DBA_TWO_FAKE"),
]

CHANGE_WINDOWS = [
    ("2026-07-04T09:00:00", "2026-07-04T13:00:00", "CHG-FAKE-1001"),
    ("2026-07-11T09:00:00", "2026-07-11T13:00:00", "CHG-FAKE-1002"),
]

SENSITIVE_OBJECTS = [
    ("HR_FAKE", "EMPLOYEES_FAKE", "PII"),
    ("HR_FAKE", "SALARIES_FAKE", "PII/COMPENSATION"),
]

APP_OBJECTS = ["ORDERS_FAKE", "CUSTOMERS_FAKE", "PRODUCTS_FAKE"]
HR_OBJECTS = ["EMPLOYEES_FAKE", "SALARIES_FAKE"]
CATALOG_OBJECTS = ["DBA_USERS", "V_$SESSION", "DBA_TABLESPACES"]

FAILED_LOGON_RC = 1017                   # Oracle-style "invalid username/password"


def _ts(*args) -> datetime:
    return datetime(*args)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _sql_hash(action: str, schema: str, name: str, user: str) -> str:
    return hashlib.sha256(f"{action}|{schema}.{name}|{user}".encode("utf-8")).hexdigest()[:16]


class _LogBuilder:
    """Accumulates audit events and sessions with monotonically assigned ids."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events: list[tuple] = []
        self.sessions: list[tuple] = []
        self._next_event = 1
        self._next_session = 100001

    def event(self, ts: datetime, user: str, action: str, *, schema: str = "", name: str = "",
              grantee: str = "", rc: int = 0, rows: int = 0, priv: str = "",
              session: int | None = None, host: str | None = None, os_user: str | None = None,
              ip: str | None = None, program: str | None = None, comment: str = "") -> int:
        _, _, def_os, def_host, def_ip, def_prog = USER_PROFILE[user]
        eid = self._next_event
        self._next_event += 1
        self.events.append((
            eid, _iso(ts), user, os_user or def_os, host or def_host, ip or def_ip,
            program or def_prog, action, schema, name, grantee, rc,
            _sql_hash(action, schema, name, user), rows, priv, session, comment,
        ))
        return eid

    def session(self, user: str, logon: datetime, logoff: datetime, *, host: str | None = None,
                os_user: str | None = None, ip: str | None = None,
                program: str | None = None) -> int:
        """Register a successful session: dba_audit_session row + LOGON/LOGOFF events."""
        _, _, def_os, def_host, _, def_prog = USER_PROFILE[user]
        sid = self._next_session
        self._next_session += 1
        self.sessions.append((sid, user, os_user or def_os, host or def_host,
                              program or def_prog, _iso(logon), _iso(logoff)))
        self.event(logon, user, "LOGON", session=sid, host=host, os_user=os_user, ip=ip,
                   program=program)
        self.event(logoff, user, "LOGOFF", session=sid, host=host, os_user=os_user, ip=ip,
                   program=program)
        return sid

    def work_session(self, user: str, logon: datetime, minutes: int, actions: list[tuple],
                     **kw) -> int:
        """A session with evenly spread actions: [(action, schema, name, rows[, priv[, comment]]), ...]."""
        sid = self.session(user, logon, logon + timedelta(minutes=minutes), **kw)
        step = max(1, (minutes * 60) // (len(actions) + 1))
        for i, act in enumerate(actions, 1):
            action, schema, name, rows = act[:4]
            priv = act[4] if len(act) > 4 else ""
            comment = act[5] if len(act) > 5 else ""
            self.event(logon + timedelta(seconds=step * i), user, action, schema=schema,
                       name=name, rows=rows, priv=priv, session=sid, comment=comment,
                       host=kw.get("host"), os_user=kw.get("os_user"), ip=kw.get("ip"),
                       program=kw.get("program"))
        return sid


def _business_start(rng: random.Random, day: date, latest_hour: int = 16) -> datetime:
    return datetime(day.year, day.month, day.day, rng.randint(BUSINESS_START_HOUR, latest_hour),
                    rng.randint(0, 59), rng.randint(0, 59))


def _baseline(b: _LogBuilder, plant_canary: bool) -> None:
    rng = b.rng
    for day_idx in range(WINDOW_DAYS):
        day = WINDOW_START + timedelta(days=day_idx)
        weekday = day.weekday() < 5

        # APP_SVC_FAKE: pooled application sessions every two hours, 24x7, tiny row counts.
        for hour in range(0, 24, 2):
            start = datetime(day.year, day.month, day.day, hour, rng.randint(0, 59), rng.randint(0, 59))
            actions = []
            for _ in range(rng.randint(3, 6)):
                actions.append((rng.choice(["SELECT", "SELECT", "INSERT", "UPDATE"]), "APP_FAKE",
                                rng.choice(APP_OBJECTS), rng.randint(1, 50)))
            if plant_canary and day_idx == 3 and hour == 10:
                # The canary rides on a harmless application event's free-text field.
                a = actions[0]
                actions[0] = (a[0], a[1], a[2], a[3], "", CANARY_COMMENT)
            b.work_session("APP_SVC_FAKE", start, rng.randint(20, 90), actions)

        # ETL_SVC_FAKE: one nightly batch around 01:00 with large (but normal-for-it) row counts.
        start = datetime(day.year, day.month, day.day, 1, rng.randint(0, 30), rng.randint(0, 59))
        b.work_session("ETL_SVC_FAKE", start, rng.randint(25, 50), [
            ("SELECT", "APP_FAKE", "ORDERS_FAKE", rng.randint(5000, 20000), "", "nightly ETL batch"),
            ("INSERT", "APP_FAKE", "ORDERS_HIST_FAKE", rng.randint(5000, 20000), "", "nightly ETL batch"),
            ("SELECT", "APP_FAKE", "CUSTOMERS_FAKE", rng.randint(2000, 8000), "", "nightly ETL batch"),
        ])

        if not weekday:
            continue

        # JDOE_FAKE: developer, 2-4 sessions a day on the application schema.
        first = True
        for _ in range(rng.randint(2, 4)):
            start = _business_start(rng, day)
            if first and day_idx in (4, 11):
                # A mistyped password just before the first logon: ONE failed logon, no burst.
                b.event(start - timedelta(seconds=rng.randint(20, 90)), "JDOE_FAKE", "LOGON",
                        rc=FAILED_LOGON_RC)
            first = False
            actions = [(rng.choice(["SELECT", "SELECT", "SELECT", "UPDATE"]), "APP_FAKE",
                        rng.choice(APP_OBJECTS), rng.randint(1, 500))
                       for _ in range(rng.randint(2, 6))]
            b.work_session("JDOE_FAKE", start, rng.randint(10, 60), actions)

        # RPT_RO_FAKE: reporting analyst, 1-3 read-only sessions a day, mid-size row counts.
        for i in range(rng.randint(1, 3)):
            start = _business_start(rng, day)
            actions = [("SELECT", "APP_FAKE", rng.choice(APP_OBJECTS), rng.randint(500, 5000))
                       for _ in range(rng.randint(2, 5))]
            if i == 0 and day_idx in (3, 10):
                # A weekly cross-schema report: a single sensitive read, far below threshold.
                actions.append(("SELECT", "HR_FAKE", "EMPLOYEES_FAKE", rng.randint(200, 400)))
            b.work_session("RPT_RO_FAKE", start, rng.randint(10, 45), actions)

        # HR_FAKE: HR application (schema owner) working its own sensitive tables.
        for _ in range(rng.randint(3, 6)):
            start = _business_start(rng, day)
            actions = [(rng.choice(["SELECT", "SELECT", "UPDATE", "INSERT"]), "HR_FAKE",
                        rng.choice(HR_OBJECTS), rng.randint(1, 100))
                       for _ in range(rng.randint(2, 6))]
            b.work_session("HR_FAKE", start, rng.randint(5, 40), actions)

        # DBA_ONE_FAKE / DBA_TWO_FAKE: catalog housekeeping in business hours only.
        for _ in range(rng.randint(1, 2)):
            start = _business_start(rng, day)
            actions = [("SELECT", "SYS", rng.choice(CATALOG_OBJECTS), rng.randint(10, 200))
                       for _ in range(rng.randint(2, 5))]
            b.work_session("DBA_ONE_FAKE", start, rng.randint(10, 60), actions)
        start = _business_start(rng, day)
        b.work_session("DBA_TWO_FAKE", start, rng.randint(10, 40), [
            ("SELECT", "SYS", rng.choice(CATALOG_OBJECTS), rng.randint(10, 200))
            for _ in range(rng.randint(2, 4))
        ])

    # Approved change windows (Saturday mornings): the ONLY baseline DDL and grants.
    for start_s, _, ticket in CHANGE_WINDOWS:
        start = datetime.fromisoformat(start_s) + timedelta(minutes=10)
        b.work_session("DBA_ONE_FAKE", start, 140, [
            ("CREATE INDEX", "APP_FAKE", "IX_ORDERS_DATE_FAKE", 0, "CREATE ANY INDEX", ticket),
            ("ALTER TABLE", "APP_FAKE", "ORDERS_FAKE", 0, "ALTER ANY TABLE", ticket),
            ("GRANT OBJECT", "APP_FAKE", "ORDERS_FAKE", 0, "GRANT ANY OBJECT PRIVILEGE", ticket),
        ])


def _incidents(b: _LogBuilder, policies: list[list]) -> None:
    """One seeded incident per detection rule (rule ids in comments). Fixed timestamps."""
    T = _ts

    # CYL-001 / CYL-004 / CYL-006 / CYL-014: a compromised DBA credential is used at 02:07,
    # bulk-reads an HR table, then switches off the logon-failure audit policy 30 min later.
    sid = b.session("DBA_ONE_FAKE", T(2026, 7, 15, 2, 7, 12), T(2026, 7, 15, 2, 45, 50))
    b.event(T(2026, 7, 15, 2, 10, 44), "DBA_ONE_FAKE", "SELECT", schema="HR_FAKE",
            name="EMPLOYEES_FAKE", rows=1_850_000, session=sid)                       # CYL-004
    b.event(T(2026, 7, 15, 2, 41, 3), "DBA_ONE_FAKE", "NOAUDIT", name="ORA_LOGON_FAILURES",
            priv="AUDIT SYSTEM", session=sid)                                          # CYL-006
    for p in policies:
        if p[0] == "ORA_LOGON_FAILURES":
            p[1], p[2], p[3] = 0, "2026-07-15T02:41:03", "DBA_ONE_FAKE"

    # CYL-002: eight failed logons against DBA_TWO_FAKE from an unrecognised host in 6 minutes.
    for i in range(8):
        b.event(T(2026, 7, 8, 22, 13, 5) + timedelta(seconds=41 * i), "DBA_TWO_FAKE", "LOGON",
                rc=FAILED_LOGON_RC, host="WS-TEMP-FAKE", ip="10.0.1.99", os_user="guest",
                program="sqlplus")

    # CYL-003: a DBA grants the DBA role to a developer, outside any change window.
    sid = b.session("DBA_ONE_FAKE", T(2026, 7, 13, 16, 40, 0), T(2026, 7, 13, 16, 52, 0))
    b.event(T(2026, 7, 13, 16, 45, 30), "DBA_ONE_FAKE", "GRANT ROLE", name="DBA",
            grantee="JDOE_FAKE", priv="GRANT ANY ROLE", session=sid)

    # CYL-005: a service account idle since March logs on again at 03:25.
    sid = b.session("OLD_SVC_FAKE", T(2026, 7, 14, 3, 25, 10), T(2026, 7, 14, 3, 31, 0))
    b.event(T(2026, 7, 14, 3, 27, 2), "OLD_SVC_FAKE", "SELECT", schema="APP_FAKE",
            name="CUSTOMERS_FAKE", rows=250, session=sid)

    # CYL-007: the developer (now holding DBA) exercises ALTER SYSTEM.
    sid = b.session("JDOE_FAKE", T(2026, 7, 14, 9, 5, 0), T(2026, 7, 14, 9, 30, 0))
    b.event(T(2026, 7, 14, 9, 12, 47), "JDOE_FAKE", "ALTER SYSTEM", priv="ALTER SYSTEM",
            session=sid)

    # CYL-008: the developer's account logs on from a host it has never used.
    sid = b.session("JDOE_FAKE", T(2026, 7, 15, 11, 40, 5), T(2026, 7, 15, 12, 2, 0),
                    host="WS-UNKNOWN-FAKE", ip="10.0.2.77")
    for i, minute in enumerate((3, 14)):
        b.event(T(2026, 7, 15, 11, 40, 5) + timedelta(minutes=minute), "JDOE_FAKE", "SELECT",
                schema="APP_FAKE", name="ORDERS_FAKE", rows=120 + 35 * i, session=sid,
                host="WS-UNKNOWN-FAKE", ip="10.0.2.77")

    # CYL-009: schema change (DDL) on a Tuesday afternoon with no approved change window.
    sid = b.session("DBA_TWO_FAKE", T(2026, 7, 14, 15, 20, 0), T(2026, 7, 14, 15, 50, 0))
    b.event(T(2026, 7, 14, 15, 30, 21), "DBA_TWO_FAKE", "ALTER TABLE", schema="APP_FAKE",
            name="ORDERS_FAKE", priv="ALTER ANY TABLE", session=sid)

    # CYL-010: seven reads of the SALARIES table by a non-owner within 95 minutes.
    sid = b.session("JDOE_FAKE", T(2026, 7, 13, 10, 0, 0), T(2026, 7, 13, 11, 40, 0))
    for i, minute in enumerate((2, 17, 33, 48, 64, 79, 95)):
        b.event(T(2026, 7, 13, 10, 0, 0) + timedelta(minutes=minute), "JDOE_FAKE", "SELECT",
                schema="HR_FAKE", name="SALARIES_FAKE", rows=40 + 10 * i, session=sid)

    # CYL-011: forty logons in one day by an account that normally opens two or three.
    for i in range(40):
        start = T(2026, 7, 16, 9, 0, 0) + timedelta(minutes=10 * i)
        sid = b.session("RPT_RO_FAKE", start, start + timedelta(minutes=4))
        b.event(start + timedelta(minutes=1), "RPT_RO_FAKE", "SELECT", schema="APP_FAKE",
                name="ORDERS_FAKE", rows=500 + 37 * i, session=sid)

    # CYL-012: a DELETE whose session id has no logon record anywhere.
    b.event(T(2026, 7, 10, 14, 22, 9), "APP_SVC_FAKE", "DELETE", schema="APP_FAKE",
            name="ORDERS_FAKE", rows=1200, session=990001)

    # CYL-013: the application service account driven interactively from sqlplus by a person.
    sid = b.session("APP_SVC_FAKE", T(2026, 7, 12, 16, 5, 33), T(2026, 7, 12, 16, 19, 0),
                    os_user="jdoe", program="sqlplus")
    b.event(T(2026, 7, 12, 16, 9, 41), "APP_SVC_FAKE", "SELECT", schema="APP_FAKE",
            name="CUSTOMERS_FAKE", rows=3200, session=sid, os_user="jdoe", program="sqlplus")


def create_synthetic_log(path: str | None = None, seed: int = 42,
                         incidents: bool = True) -> sqlite3.Connection:
    """Build the synthetic activity log. ``path=None`` -> in-memory database.

    incidents=True  : baseline + one seeded incident per rule (+ the injection canary)
    incidents=False : baseline only -> every rule PASSes (zero detections, no canary)
    """
    rng = random.Random(seed)
    b = _LogBuilder(rng)
    policies = [list(p) for p in AUDIT_POLICIES]
    _baseline(b, plant_canary=incidents)
    if incidents:
        _incidents(b, policies)
    b.events.sort(key=lambda e: (e[1], e[0]))   # chronological order, ids as tiebreak

    conn = sqlite3.connect(path or ":memory:")
    conn.executescript(SCHEMA)
    conn.executemany("INSERT INTO unified_audit_trail VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     b.events)
    conn.executemany("INSERT INTO dba_audit_session VALUES (?,?,?,?,?,?,?)", b.sessions)
    conn.executemany("INSERT INTO dba_users_snapshot VALUES (?,?,?,?,?)", USER_SNAPSHOT)
    conn.executemany("INSERT INTO audit_policy_state VALUES (?,?,?,?)", policies)
    conn.executemany("INSERT INTO change_windows VALUES (?,?,?)", CHANGE_WINDOWS)
    conn.executemany("INSERT INTO sensitive_objects VALUES (?,?,?)", SENSITIVE_OBJECTS)
    conn.executemany("INSERT INTO db_metadata VALUES (?,?)", [
        ("db_name", "FAKEDB1"),
        ("host", "fakehost01.fake.test"),
        ("scan_date", SCAN_DATE),
        ("window_start", _iso(datetime(WINDOW_START.year, WINDOW_START.month, WINDOW_START.day))),
        ("window_days", str(WINDOW_DAYS)),
        ("generator_seed", str(seed)),
        ("incidents_seeded", "1" if incidents else "0"),
    ])
    conn.commit()
    return conn
