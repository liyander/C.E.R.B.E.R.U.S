"""SQLite storage for operational state (not raw telemetry)."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("CERBERUS_DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "cerberus.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'enforcer',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_providers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    base_url TEXT NOT NULL,
    api_key TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrations (
    key TEXT PRIMARY KEY,
    config TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'host',
    criticality TEXT NOT NULL DEFAULT 'medium',
    demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity INTEGER NOT NULL,
    asset_id INTEGER REFERENCES assets(id),
    source_ip TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    summary_meta TEXT NOT NULL DEFAULT '',
    demo INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    asset_id INTEGER REFERENCES assets(id),
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    severity INTEGER NOT NULL,
    ts TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    evidence_ref TEXT NOT NULL DEFAULT '{}',
    demo INTEGER NOT NULL DEFAULT 0,
    UNIQUE (source, source_event_id)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    rationale TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    decision_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    decided_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    messages TEXT NOT NULL DEFAULT '[]',
    message_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at);
CREATE TABLE IF NOT EXISTS user_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'info',
    audience TEXT NOT NULL DEFAULT 'all',
    in_app INTEGER NOT NULL DEFAULT 1,
    emailed INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notification_reads (
    notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (notification_id, user_id)
);
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    sent_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS watch_findings (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    asset TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    severity INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'firing',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    incident_id INTEGER,
    last_notified TEXT NOT NULL DEFAULT '',
    ai_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS watch_runs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    reason TEXT NOT NULL,
    ok INTEGER NOT NULL,
    firing INTEGER NOT NULL DEFAULT 0,
    fresh INTEGER NOT NULL DEFAULT 0,
    recovered INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    seconds REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
"""


def now() -> str:
    return iso(datetime.now(timezone.utc))


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**kwargs) -> str:
    return iso(datetime.now(timezone.utc) - timedelta(**kwargs))


def parse_ts(value) -> str:
    """Normalise any ISO-ish timestamp to the stored UTC format; fall back to now."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return iso(dt)
    except (ValueError, TypeError):
        return now()


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Autocommit: a request can hold its connection across a slow model call
    # without keeping a write lock open.
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


# One row per call to an AI model: what it was for, who asked, how many tokens and how long it took.
USAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_usage (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT 'other',
    actor TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    estimated INTEGER NOT NULL DEFAULT 0,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    ms INTEGER NOT NULL DEFAULT 0,
    ok INTEGER NOT NULL DEFAULT 1,
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ai_usage_ts ON ai_usage(ts);
"""


def init_db() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        conn.executescript(USAGE_SCHEMA)
        from .predict import SCHEMA as FORECAST_SCHEMA
        conn.executescript(FORECAST_SCHEMA)
        from .remote import SCHEMA as REMOTE_SCHEMA
        conn.executescript(REMOTE_SCHEMA)
        from .alerting import SCHEMA as ALERT_SCHEMA
        conn.executescript(ALERT_SCHEMA)
        conn.executescript(NOTES_SCHEMA)
        from .intel import SCHEMA as INTEL_SCHEMA
        conn.executescript(INTEL_SCHEMA)
        from .login_detection import SCHEMA as LOGIN_SCHEMA
        conn.executescript(LOGIN_SCHEMA)
        _migrate(conn)
        from . import secrets_store
        secrets_store.migrate(conn, DATA_DIR)


# Columns added after v0.1; applied to databases created by older versions.
USER_COLUMNS = {
    "email": "TEXT NOT NULL DEFAULT ''",
    "email_verified": "INTEGER NOT NULL DEFAULT 0",
    "disabled": "INTEGER NOT NULL DEFAULT 0",
    "last_login": "TEXT NOT NULL DEFAULT ''",
    "mfa_secret": "TEXT NOT NULL DEFAULT ''",
    "mfa_pending": "TEXT NOT NULL DEFAULT ''",
}


# Incident columns added for triage, prioritisation and the response workflow.
INCIDENT_COLUMNS = {
    "priority": "INTEGER NOT NULL DEFAULT 0",          # 0-100, highest first in the work queue
    "priority_meta": "TEXT NOT NULL DEFAULT '{}'",     # how the score was made up
    "assignee": "TEXT NOT NULL DEFAULT ''",            # username of the analyst who owns it
    "due_at": "TEXT NOT NULL DEFAULT ''",              # response deadline from its priority
    "ack_at": "TEXT NOT NULL DEFAULT ''",              # when someone first took it on
    "resolved_at": "TEXT NOT NULL DEFAULT ''",
    "close_reason": "TEXT NOT NULL DEFAULT ''",
    "ai_verdict": "TEXT NOT NULL DEFAULT ''",          # malicious | suspicious | benign | noise
    "ai_confidence": "TEXT NOT NULL DEFAULT ''",       # high | medium | low
    "ai_reason": "TEXT NOT NULL DEFAULT ''",
    "ai_technique": "TEXT NOT NULL DEFAULT ''",        # MITRE ATT&CK, e.g. "T1110 Brute Force"
    "triaged_at": "TEXT NOT NULL DEFAULT ''",
    "escalated_at": "TEXT NOT NULL DEFAULT ''",
}

# One row per analyst note or logged action on an incident.
NOTES_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'note',
    author TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_notes ON incident_notes(incident_id, id);
"""


def _migrate(conn) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    for name, ddl in USER_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
    inc = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)")}
    for name, ddl in INCIDENT_COLUMNS.items():
        if name not in inc:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} {ddl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(status, priority)")
    cmd = {row["name"] for row in conn.execute("PRAGMA table_info(server_commands)")}
    for name, ddl in (("incident_id", "INTEGER"), ("undo_command", "TEXT NOT NULL DEFAULT ''"), ("action", "TEXT NOT NULL DEFAULT ''")):
        if name not in cmd:
            conn.execute(f"ALTER TABLE server_commands ADD COLUMN {name} {ddl}")
    ast = {row["name"] for row in conn.execute("PRAGMA table_info(assets)")}
    for name, ddl in (("owner", "TEXT NOT NULL DEFAULT ''"), ("notes", "TEXT NOT NULL DEFAULT ''"), ("exposure", "TEXT NOT NULL DEFAULT ''")):
        if name not in ast:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {name} {ddl}")
    # The single v0.1 "enforcer" account becomes the first admin and is trusted as verified.
    conn.execute("UPDATE users SET role = 'admin', email_verified = 1 WHERE role = 'enforcer'")


def get_setting(conn, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_integration(conn, key: str) -> dict:
    row = conn.execute("SELECT config FROM integrations WHERE key = ?", (key,)).fetchone()
    if not row:
        return {}
    from .secrets_store import transform_config
    return transform_config(json.loads(row["config"]), DATA_DIR, reveal=True)


def set_integration(conn, key: str, config: dict) -> None:
    from .secrets_store import transform_config
    protected = transform_config(config, DATA_DIR, reveal=False)
    conn.execute(
        "INSERT INTO integrations (key, config, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at",
        (key, json.dumps(protected), now()),
    )


def audit(conn, actor: str, action: str, detail: dict | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_logs (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now(), actor, action, json.dumps(detail or {}, default=str)[:4000]),
    )
