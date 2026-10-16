"""Audited, transactional incident regrouping."""
from contextlib import contextmanager

from . import store, triage
from .db import audit, now


@contextmanager
def _transaction(conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _refresh(conn, incident_id):
    row = conn.execute("SELECT COUNT(*) n, MIN(ts) first, MAX(ts) last, MAX(severity) severity FROM events WHERE incident_id=?", (incident_id,)).fetchone()
    if row["n"]:
        conn.execute("UPDATE incidents SET event_count=?, first_seen=?, last_seen=?, severity=? WHERE id=?",
                     (row["n"], row["first"], row["last"], row["severity"], incident_id))
        triage.rescore(conn, incident_id)
    else:
        conn.execute("UPDATE incidents SET event_count=0, status='resolved', resolved_at=?, close_reason='All events moved to another incident' WHERE id=?", (now(), incident_id))


def merge(conn, target_id: int, source_id: int, actor: str):
    if target_id == source_id:
        raise ValueError("Choose two different incidents")
    with _transaction(conn):
        target = conn.execute("SELECT * FROM incidents WHERE id=?", (target_id,)).fetchone()
        source = conn.execute("SELECT * FROM incidents WHERE id=?", (source_id,)).fetchone()
        if not target or not source:
            raise ValueError("Incident not found")
        if target["demo"] != source["demo"]:
            raise ValueError("Demo and live incidents cannot be merged")
        if not conn.execute("SELECT 1 FROM events WHERE incident_id=? LIMIT 1", (source_id,)).fetchone():
            raise ValueError("Source incident has no events")
        conn.execute("UPDATE events SET incident_id=? WHERE incident_id=?", (target_id, source_id))
        conn.execute("UPDATE incidents SET status='resolved', resolved_at=?, close_reason=? WHERE id=?",
                     (now(), f"Merged into INC-{target_id:04d}", source_id))
        _refresh(conn, target_id)
        conn.execute("UPDATE incidents SET event_count=0 WHERE id=?", (source_id,))
        triage._note(conn, target_id, "action", actor, f"Merged INC-{source_id:04d} into this incident. Original notes and approvals remain on the source incident.")
        triage._note(conn, source_id, "action", actor, f"Events moved to INC-{target_id:04d}.")
        audit(conn, actor, "incident.merge", {"target": target_id, "source": source_id})
    return {"target_id": target_id, "source_id": source_id}


def split(conn, incident_id: int, event_ids: list[int], actor: str):
    ids = list(dict.fromkeys(event_ids))
    if not ids or len(ids) > 200:
        raise ValueError("Choose 1 to 200 events")
    with _transaction(conn):
        original = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not original:
            raise ValueError("Incident not found")
        marks = ",".join("?" for _ in ids)
        rows = conn.execute(f"SELECT * FROM events WHERE incident_id=? AND id IN ({marks})", [incident_id, *ids]).fetchall()
        if len(rows) != len(ids):
            raise ValueError("Every selected event must belong to this incident")
        total = conn.execute("SELECT COUNT(*) FROM events WHERE incident_id=?", (incident_id,)).fetchone()[0]
        if len(rows) >= total:
            raise ValueError("Leave at least one event in the original incident")
        first = min(rows, key=lambda r: (r["ts"], r["id"]))
        cur = conn.execute("INSERT INTO incidents (title,severity,asset_id,source_ip,rule_id,first_seen,last_seen,event_count,demo) VALUES (?,?,?,?,?,?,?,?,?)",
                           (first["title"], first["severity"], first["asset_id"], first["source_ip"], first["rule_id"], first["ts"], first["ts"], 0, original["demo"]))
        new_id = cur.lastrowid
        conn.execute(f"UPDATE events SET incident_id=? WHERE id IN ({marks})", [new_id, *ids])
        _refresh(conn, incident_id)
        _refresh(conn, new_id)
        triage._note(conn, incident_id, "action", actor, f"Split {len(ids)} events into INC-{new_id:04d}.")
        triage._note(conn, new_id, "action", actor, f"Split from INC-{incident_id:04d}.")
        audit(conn, actor, "incident.split", {"original": incident_id, "created": new_id, "event_ids": ids})
    return {"original_id": incident_id, "incident_id": new_id}
