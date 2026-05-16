"""
Persistent Audit Trail for agentic M365 operations.

Every Graph API mutation, Securityzator remediation, and JIRA ticket
gets recorded here. Survives process restarts. Queryable by scenario,
user, time range, and event type.

Design:
  - SQLite at m365_faker/audit.db (alongside the module)
  - Thread-safe writes
  - Links chaos events → tickets → remediation → closure
  - Exposed via /Reporting/audit endpoint in Securityzator
"""
import sqlite3
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "audit.db")
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scenarios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,              -- e.g. "password_breach", "full_lifecycle"
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at    TEXT,
    status      TEXT DEFAULT 'running',     -- running, success, error, aborted
    summary     TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER REFERENCES scenarios(id),
    seq         INTEGER NOT NULL,           -- sequence within scenario
    timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
    source      TEXT NOT NULL DEFAULT 'agent', -- agent, automated, manual, secz, graph, jira
    event_type  TEXT NOT NULL,              -- user_create, license_assign, breach, remediation, etc.
    target      TEXT,                       -- UPN, user ID, group ID, etc.
    detail      TEXT,                       -- human-readable summary
    status      TEXT DEFAULT 'success',     -- success, error, pending
    metadata    TEXT DEFAULT '{}',          -- JSON blob for extra context
    ticket_key  TEXT                        -- JIRA ticket key if linked
);

CREATE INDEX IF NOT EXISTS idx_events_scenario ON events(scenario_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_target ON events(target);
"""


def _get_db() -> sqlite3.Connection:
    """Get thread-local DB connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init():
    """Initialize the audit database. Call once at startup."""
    db = _get_db()
    db.executescript(SCHEMA)
    db.commit()


# ── Scenario Management ──────────────────────────────────────────

def start_scenario(name: str, summary: str = "") -> int:
    """Begin a new scenario. Returns scenario_id for event linking."""
    db = _get_db()
    cur = db.execute(
        "INSERT INTO scenarios (name, summary, started_at) VALUES (?, ?, ?)",
        (name, summary, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return cur.lastrowid


def end_scenario(scenario_id: int, status: str = "success", summary: str = ""):
    """Mark a scenario as complete."""
    db = _get_db()
    db.execute(
        "UPDATE scenarios SET ended_at=?, status=?, summary=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), status, summary, scenario_id),
    )
    db.commit()


# ── Event Recording ──────────────────────────────────────────────

def log(
    event_type: str,
    detail: str = "",
    target: str = "",
    source: str = "agent",
    status: str = "success",
    metadata: dict = None,
    ticket_key: str = "",
    scenario_id: int = None,
) -> int:
    """Record an audit event. Returns event ID."""
    db = _get_db()

    # Auto-get next sequence for this scenario
    seq = 0
    if scenario_id:
        row = db.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE scenario_id=?",
            (scenario_id,),
        ).fetchone()
        seq = row[0] if row else 1

    cur = db.execute(
        """INSERT INTO events (scenario_id, seq, timestamp, source, event_type,
           target, detail, status, metadata, ticket_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scenario_id,
            seq,
            datetime.now(timezone.utc).isoformat(),
            source,
            event_type,
            target,
            detail,
            status,
            json.dumps(metadata or {}),
            ticket_key,
        ),
    )
    db.commit()
    return cur.lastrowid


# ── Querying ─────────────────────────────────────────────────────

def get_scenario(scenario_id: int) -> Optional[dict]:
    """Get a scenario with all its events."""
    db = _get_db()
    scenario = db.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
    if not scenario:
        return None

    events = db.execute(
        "SELECT * FROM events WHERE scenario_id=? ORDER BY seq",
        (scenario_id,),
    ).fetchall()

    return {
        "scenario": dict(scenario),
        "events": [dict(e) for e in events],
    }


def get_recent_scenarios(limit: int = 20) -> list:
    """List recent scenarios with event counts."""
    db = _get_db()
    rows = db.execute(
        """SELECT s.*, COUNT(e.id) as event_count
           FROM scenarios s
           LEFT JOIN events e ON e.scenario_id = s.id
           GROUP BY s.id
           ORDER BY s.started_at DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def query_events(
    event_type: str = None,
    target: str = None,
    source: str = None,
    since: str = None,
    limit: int = 50,
) -> list:
    """Query events with optional filters."""
    db = _get_db()
    clauses = []
    params = []

    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if target:
        clauses.append("target = ?")
        params.append(target)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)

    where = " AND ".join(clauses)
    if where:
        where = "WHERE " + where

    rows = db.execute(
        f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?",
        params + [limit],
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """Get audit summary statistics."""
    db = _get_db()
    total_scenarios = db.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
    total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    event_types = db.execute(
        "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    recent = db.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT 5"
    ).fetchall()

    return {
        "total_scenarios": total_scenarios,
        "total_events": total_events,
        "top_event_types": [dict(r) for r in event_types],
        "recent_events": [dict(r) for r in recent],
    }


# ── Convenience ──────────────────────────────────────────────────

class AuditContext:
    """Context manager that wraps an audit trail around operations.
    
    Usage:
        with AuditContext("password_breach") as audit:
            audit.log("user_lookup", "Found user", target=upn)
            # ... do work ...
            audit.log("breach_complete", "Password rotated")
        # Auto-closes scenario on exit
    """

    def __init__(self, name: str, source: str = "agent"):
        self.name = name
        self.source = source
        self.scenario_id = None

    def __enter__(self):
        self.scenario_id = start_scenario(self.name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        status = "error" if exc_type else "success"
        end_scenario(self.scenario_id, status)
        return False  # don't suppress exceptions

    def log(self, event_type: str, detail: str = "", source: str = None, **kwargs):
        return log(
            event_type=event_type,
            detail=detail,
            source=source or self.source,
            scenario_id=self.scenario_id,
            **kwargs,
        )


# ── Init on import ───────────────────────────────────────────────

init()


# ── CLI export mode (called by Securityzator reporter) ──────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Audit trail CLI")
    p.add_argument("action", choices=["stats", "scenarios", "events", "scenario"])
    p.add_argument("--id", type=int, help="Scenario ID for 'scenario' action")
    p.add_argument("--type", help="Filter by event_type")
    p.add_argument("--limit", type=int, default=50)
    args = p.parse_args()

    if args.action == "stats":
        print(json.dumps(get_stats(), indent=2, default=str))
    elif args.action == "scenarios":
        print(json.dumps(get_recent_scenarios(args.limit), indent=2, default=str))
    elif args.action == "events":
        print(json.dumps(query_events(event_type=args.type, limit=args.limit), indent=2, default=str))
    elif args.action == "scenario" and args.id:
        s = get_scenario(args.id)
        print(json.dumps(s, indent=2, default=str) if s else "{}")
