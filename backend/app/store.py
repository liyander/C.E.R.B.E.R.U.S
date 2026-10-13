"""Event intake, asset resolution, deterministic correlation and bounded queries.

Correlation runs here, before any model sees the data: the AI interprets
incidents, it is not the mechanism that creates them.
"""
import json
from datetime import datetime, timedelta, timezone

from .db import ago, iso, now, parse_ts

CORRELATION_WINDOW_MINUTES = 60
INCIDENT_MIN_SEVERITY = 4
# Inventory-style findings are stored but never open an incident on their own.
NON_INCIDENT_TYPES = {"vulnerability", "alert_resolved"}
INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")


def clamp(value, low: int, high: int, default: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def text(value, limit: int = 300) -> str:
    return str(value if value is not None else "").strip()[:limit]


def severity_label(sev: int) -> str:
    if sev >= 9:
        return "critical"
    if sev >= 7:
        return "high"
    if sev >= 4:
        return "medium"
    return "low"


def resolve_asset(conn, name: str = "", ip: str = "", demo: bool = False) -> int | None:
    name, ip = text(name, 120), text(ip, 64)
    if not name and not ip:
        return None
    row = None
    if name:
        row = conn.execute("SELECT id FROM assets WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if not row and ip:
        row = conn.execute("SELECT id FROM assets WHERE ip = ?", (ip,)).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO assets (name, ip, demo, created_at) VALUES (?, ?, ?, ?)",
        (name or ip, ip, int(demo), now()),
    )
    return cur.lastrowid


def ingest_event(conn, ev: dict) -> dict:
    """Normalise, dedupe and correlate one event. Returns ids and whether it was new."""
    source = text(ev.get("source"), 40).lower() or "unknown"
    source_event_id = text(ev.get("source_event_id"), 200)
    if not source_event_id:
        raise ValueError("source_event_id is required")
    existing = conn.execute(
        "SELECT id, incident_id FROM events WHERE source = ? AND source_event_id = ?",
        (source, source_event_id),
    ).fetchone()
    if existing:
        return {"event_id": existing["id"], "incident_id": existing["incident_id"], "duplicate": True}

    demo = bool(ev.get("demo"))
    severity = clamp(ev.get("severity"), 1, 10, 5)
    event_type = text(ev.get("event_type"), 60) or "alert"
    ts = parse_ts(ev.get("timestamp") or ev.get("ts"))
    source_ip = text(ev.get("source_ip"), 64)
    rule_id = text(ev.get("rule_id"), 120)
    title = text(ev.get("title"), 200) or event_type
    asset_id = ev.get("asset_id") or resolve_asset(conn, ev.get("asset"), ev.get("asset_ip"), demo)
    evidence = ev.get("evidence_ref") if isinstance(ev.get("evidence_ref"), dict) else {}

    incident_id = _correlate(conn, asset_id, source_ip, rule_id, event_type, severity, ts, title, demo)
    cur = conn.execute(
        "INSERT INTO events (source, source_event_id, asset_id, incident_id, event_type, severity, ts, "
        "source_ip, username, rule_id, title, message, evidence_ref, demo) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (source, source_event_id, asset_id, incident_id, event_type, severity, ts, source_ip,
         text(ev.get("username"), 120), rule_id, title, text(ev.get("message"), 4000),
         json.dumps(evidence)[:4000], int(demo)),
    )
    return {"event_id": cur.lastrowid, "incident_id": incident_id, "duplicate": False}


def _correlate(conn, asset_id, source_ip, rule_id, event_type, severity, ts, title, demo):
    """Attach to a live incident on the same asset + source IP (or same rule), else open one."""
    # Window is relative to the event's own time so late or replayed events still group.
    event_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    cutoff = iso(event_time - timedelta(minutes=CORRELATION_WINDOW_MINUTES))
    where = "status IN ('open', 'investigating') AND asset_id IS ? AND last_seen >= ? AND demo = ?"
    params = [asset_id, cutoff, int(demo)]
    if source_ip:
        where += " AND source_ip = ?"
        params.append(source_ip)
    else:
        where += " AND source_ip = '' AND rule_id = ?"
        params.append(rule_id)
    match = conn.execute(
        f"SELECT id FROM incidents WHERE {where} ORDER BY last_seen DESC LIMIT 1", params
    ).fetchone()

    if match:
        effective = severity if event_type not in NON_INCIDENT_TYPES else 0
        # The incident is named after its most severe event, not whichever arrived first.
        conn.execute(
            "UPDATE incidents SET event_count = event_count + 1, severity = MAX(severity, ?), "
            "title = CASE WHEN ? > severity THEN ? ELSE title END, "
            "first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?) WHERE id = ?",
            (effective, effective, title, ts, ts, match["id"]),
        )
        return match["id"]
    if event_type in NON_INCIDENT_TYPES or severity < INCIDENT_MIN_SEVERITY:
        return None
    cur = conn.execute(
        "INSERT INTO incidents (title, severity, asset_id, source_ip, rule_id, first_seen, last_seen, "
        "event_count, demo) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
        (title, severity, asset_id, source_ip, rule_id, ts, ts, int(demo)),
    )
    return cur.lastrowid


def event_dict(row) -> dict:
    d = dict(row)
    d["ref"] = f"EVT-{d['id']}"
    d["severity_label"] = severity_label(d["severity"])
    try:
        d["evidence_ref"] = json.loads(d.get("evidence_ref") or "{}")
    except ValueError:
        d["evidence_ref"] = {}
    return d


def incident_dict(row) -> dict:
    d = dict(row)
    d["ref"] = f"INC-{d['id']:04d}"
    d["severity_label"] = severity_label(d["severity"])
    return d


def query_events(conn, *, q="", asset="", asset_id=None, source="", source_ip="", incident_id=None,
                 min_severity=1, hours=None, limit=100) -> list[dict]:
    where, params = ["e.severity >= ?"], [clamp(min_severity, 1, 10, 1)]
    if q := text(q, 100):
        like = f"%{q}%"
        where.append("(e.title LIKE ? OR e.message LIKE ? OR e.rule_id LIKE ? OR e.username LIKE ? "
                     "OR e.source_ip LIKE ? OR a.name LIKE ?)")
        params += [like] * 6
    if asset := text(asset, 120):
        where.append("(a.name = ? COLLATE NOCASE OR a.ip = ?)")
        params += [asset, asset]
    if asset_id:
        where.append("e.asset_id = ?")
        params.append(asset_id)
    if source := text(source, 40):
        where.append("e.source = ?")
        params.append(source.lower())
    if source_ip := text(source_ip, 64):
        where.append("e.source_ip = ?")
        params.append(source_ip)
    if incident_id:
        where.append("e.incident_id = ?")
        params.append(incident_id)
    if hours:
        where.append("e.ts >= ?")
        params.append(ago(hours=clamp(hours, 1, 720, 24)))
    rows = conn.execute(
        "SELECT e.*, a.name AS asset_name FROM events e LEFT JOIN assets a ON a.id = e.asset_id "
        f"WHERE {' AND '.join(where)} ORDER BY e.ts DESC, e.id DESC LIMIT ?",
        params + [clamp(limit, 1, 500, 100)],
    ).fetchall()
    return [event_dict(r) for r in rows]


def query_incidents(conn, *, status="", min_severity=1, limit=100) -> list[dict]:
    where, params = ["i.severity >= ?"], [clamp(min_severity, 1, 10, 1)]
    if status == "active":
        where.append("i.status IN ('open', 'investigating')")
    elif status in INCIDENT_STATUSES:
        where.append("i.status = ?")
        params.append(status)
    rows = conn.execute(
        "SELECT i.*, a.name AS asset_name FROM incidents i LEFT JOIN assets a ON a.id = i.asset_id "
        f"WHERE {' AND '.join(where)} ORDER BY i.last_seen DESC LIMIT ?",
        params + [clamp(limit, 1, 500, 100)],
    ).fetchall()
    return [incident_dict(r) for r in rows]


def get_incident(conn, incident_id: int) -> dict | None:
    row = conn.execute(
        "SELECT i.*, a.name AS asset_name, a.ip AS asset_ip FROM incidents i "
        "LEFT JOIN assets a ON a.id = i.asset_id WHERE i.id = ?",
        (incident_id,),
    ).fetchone()
    if not row:
        return None
    inc = incident_dict(row)
    inc["events"] = query_events(conn, incident_id=incident_id, limit=200)
    inc["approvals"] = [dict(r) for r in conn.execute(
        "SELECT * FROM approvals WHERE incident_id = ? ORDER BY id DESC", (incident_id,))]
    return inc


def expire_approvals(conn) -> None:
    conn.execute("UPDATE approvals SET status = 'expired' WHERE status = 'pending' AND expires_at < ?", (now(),))
