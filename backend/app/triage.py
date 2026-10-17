"""Incident triage, prioritisation and the response workflow.

Three things on top of the raw incident list:
  - a priority score (0-100) so analysts work the most important incident first, not just the newest;
  - an AI verdict (malicious / suspicious / benign / noise) with a reason and a MITRE ATT&CK technique,
    written automatically for each new incident so 1,000 open incidents become a short list worth reading;
  - a workflow: assign an incident to someone, a response deadline from its priority, notes and a timeline,
    stale-backlog clean-up, and response-time metrics (time to acknowledge and resolve).

Nothing here acts on a server; response actions that touch a machine go through the approval system.
"""
import json
import logging
import math
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from . import ai, insights, store
from .db import audit, db, get_setting, now, set_setting

log = logging.getLogger("cerberus.triage")

SLA_HOURS = ((85, 1), (70, 4), (50, 24), (25, 72), (0, 168))
OPEN = ("open", "investigating")
VERDICT_WEIGHT = {"malicious": 1.0, "suspicious": 0.6, "benign": 0.15, "noise": 0.05, "": 0.5}
VERDICT_TONE = {"malicious": "critical", "suspicious": "high", "benign": "low", "noise": "low", "": ""}
CRIT_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.35}
_lock = threading.Lock()



def _context(conn):
    """Everything priority scoring needs, read once: machine exposure/risk/kev, and live forecasts by IP."""
    try:
        machines, _ = insights.machines(conn)
    except Exception:
        machines = []
    by_ip, by_name = {}, {}
    for m in machines:
        by_ip[m["ip"]] = m
        for n in m["names"]:
            by_name[n.lower()] = m
    forecasts = {}
    for r in conn.execute("SELECT title, target, likelihood FROM forecasts WHERE status = 'active'"):
        forecasts[r["target"].lower()] = max(forecasts.get(r["target"].lower(), 0), r["likelihood"])
    return {"by_ip": by_ip, "by_name": by_name, "forecasts": forecasts}


def score(inc: dict, ctx: dict, rep: dict | None = None) -> tuple[int, dict]:
    """Priority 0-100 and how it was made up. Severity is the base; the rest raises it."""
    sev = inc["severity"]
    base = sev / 10 * 55
    parts = {"Severity": round(base, 1)}
    machine = ctx["by_ip"].get(inc.get("asset_ip") or "") or ctx["by_name"].get((inc.get("asset_name") or "").lower())
    crit = (machine or {}).get("criticality", inc.get("criticality") or "medium")
    parts["Asset importance"] = round(15 * CRIT_WEIGHT.get(crit, 0.55), 1)
    if machine and machine.get("exposure") == "internet-facing":
        parts["Internet-facing"] = 10.0
    if machine and machine.get("kev"):
        parts["Exploited vulnerabilities"] = round(min(10, 5 * math.log10(1 + machine["kev"])), 1)
    fc = ctx["forecasts"].get((inc.get("asset_name") or "").lower()) or (ctx["forecasts"].get(inc.get("source_ip") or "") if inc.get("source_ip") else 0)
    if fc:
        parts["Attack forecast"] = round(fc / 100 * 12, 1)
    if rep and rep.get("verdict"):
        tone = rep["verdict"].get("tone")
        if tone == "critical":
            parts["Bad reputation"] = 10.0
        elif tone == "high":
            parts["Scanner reputation"] = 4.0
        elif tone == "low" and rep.get("verdict", {}).get("label") == "Known benign":
            parts["Known-benign source"] = -8.0
    verdict = inc.get("ai_verdict") or ""
    weight = VERDICT_WEIGHT.get(verdict, 0.5)
    raw = sum(parts.values())
    adjusted = raw * (0.4 + 0.6 * weight) if verdict else raw
    if verdict == "malicious" and inc.get("ai_confidence") == "high":
        adjusted += 8
    parts["AI verdict"] = round(adjusted - raw, 1)
    value = int(max(1, min(100, round(adjusted))))
    return value, {"parts": {k: v for k, v in parts.items() if v}, "verdict": verdict, "asset_criticality": crit}


def _deadline(priority: int, start: datetime) -> str:
    hours = next(h for floor, h in SLA_HOURS if priority >= floor)
    return store.iso(start.replace(microsecond=0) + timedelta(hours=hours))


def rescore(conn, incident_id: int | None = None, ctx: dict | None = None) -> int:
    """Recompute priority (and the deadline for open ones). One incident, or every open incident."""
    ctx = ctx or _context(conn)
    where = "i.id = ?" if incident_id else "i.status IN ('open', 'investigating')"
    params = (incident_id,) if incident_id else ()
    rows = conn.execute("SELECT i.*, a.name AS asset_name, a.ip AS asset_ip, a.criticality FROM incidents i "
                        f"LEFT JOIN assets a ON a.id = i.asset_id WHERE {where}", params).fetchall()
    n = 0
    from . import intel
    for r in rows:
        inc = dict(r)
        rep = intel.cached(conn, inc["source_ip"]) if inc.get("source_ip") and insights.is_public(inc["source_ip"]) else None
        value, meta = score(inc, ctx, rep)
        due = inc["due_at"]
        if inc["status"] in OPEN and (not due or incident_id):
            try:
                start = datetime.strptime(inc["first_seen"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                start = datetime.now(timezone.utc)
            due = _deadline(value, start)
        conn.execute("UPDATE incidents SET priority = ?, priority_meta = ?, due_at = ? WHERE id = ?",
                     (value, json.dumps(meta, default=str), due, inc["id"]))
        n += 1
    return n



def _facts(conn, incident_id: int) -> str:
    inc = store.get_incident(conn, incident_id)
    if not inc:
        return ""
    events = inc.get("events", [])[:12]
    ip_note = ""
    if inc.get("source_ip"):
        ip_note = f"\nSource address {inc['source_ip']} is {'an internet' if insights.is_public(inc['source_ip']) else 'an internal'} address."
        from . import intel
        rep = intel.cached(conn, inc["source_ip"])
        if rep and rep.get("verdict"):
            ip_note += f" Threat intel: {rep['verdict']['label']} — {rep['verdict']['text']}"
    slim = {"ref": inc["ref"], "title": inc["title"], "severity": f"{inc['severity']} ({inc['severity_label']})",
            "asset": inc.get("asset_name") or inc.get("asset_ip") or "unknown", "source_ip": inc.get("source_ip", ""),
            "events": inc["event_count"], "first_seen": inc["first_seen"], "last_seen": inc["last_seen"],
            "sample_events": [{"title": e["title"], "message": e.get("message", "")[:200], "source": e["source"], "ts": e["ts"]} for e in events]}
    return json.dumps(slim, default=str) + ip_note


def triage_one(conn, provider: dict, incident_id: int, actor: str = "AI triage") -> dict | None:
    data = _facts(conn, incident_id)
    if not data:
        return None
    with ai.usage("triage", actor):
        verdict = ai.triage_incident(provider, data)
    conn.execute("UPDATE incidents SET ai_verdict = ?, ai_confidence = ?, ai_reason = ?, ai_technique = ?, triaged_at = ? WHERE id = ?",
                 (verdict["verdict"], verdict["confidence"], verdict["reason"], verdict["technique"], now(), incident_id))
    _note(conn, incident_id, "triage", "AI triage",
          f"Verdict: **{verdict['verdict']}** ({verdict['confidence']} confidence). {verdict['reason']}" + (f" MITRE: {verdict['technique']}." if verdict["technique"] else ""))
    rescore(conn, incident_id)
    return verdict


def triage_pending(limit: int = 8) -> dict:
    """Triage the newest open incidents that have no verdict yet. Called by the scheduler."""
    with db() as conn:
        provider = ai.active_provider(conn)
        if not provider or get_setting(conn, "triage_enabled", "1") == "0":
            return {"ok": False, "triaged": 0}
        ids = [r["id"] for r in conn.execute(
            "SELECT id FROM incidents WHERE status IN ('open', 'investigating') AND triaged_at = '' AND demo = 0 ORDER BY severity DESC, id DESC LIMIT ?", (limit,))]
    done, failed = 0, 0
    for i in ids:
        try:
            with db() as conn:
                if triage_one(conn, provider, i):
                    done += 1
        except ai.AIError as exc:
            failed += 1
            log.warning("triage of incident %s failed: %s", i, exc)
            if failed >= 3:
                break
    if done or failed:
        with db() as conn:
            set_setting(conn, "triage_last_run", now())
            set_setting(conn, "triage_last_result", f"{done} triaged" + (f", {failed} failed" if failed else ""))
    return {"ok": True, "triaged": done, "failed": failed}



def _note(conn, incident_id: int, kind: str, author: str, body: str, meta: dict | None = None) -> int:
    cur = conn.execute("INSERT INTO incident_notes (incident_id, kind, author, body, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                       (incident_id, kind, author, body[:4000], json.dumps(meta or {}, default=str), now()))
    return cur.lastrowid


def add_note(conn, incident_id: int, author: str, body: str) -> dict:
    body = (body or "").strip()
    if not body:
        raise ValueError("The note is empty")
    if not conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone():
        raise ValueError("No such incident")
    note_id = _note(conn, incident_id, "note", author, body)
    audit(conn, author, "incident.note", {"incident_id": incident_id})
    return {"id": note_id}


def closure_report(conn, provider: dict, incident_id: int, actor: str) -> str:
    """Write and store an AI closure report from the incident's facts, timeline, verdict and notes."""
    inc = store.get_incident(conn, incident_id)
    if not inc:
        raise ValueError("No such incident")
    facts = {"ref": inc["ref"], "title": inc["title"], "severity": f"{inc['severity']} ({inc['severity_label']})",
             "asset": inc.get("asset_name") or inc.get("asset_ip"), "source_ip": inc.get("source_ip"),
             "ai_verdict": inc.get("ai_verdict"), "ai_reason": inc.get("ai_reason"), "technique": inc.get("ai_technique"),
             "first_seen": inc["first_seen"], "last_seen": inc["last_seen"], "status": inc["status"], "events": inc["event_count"],
             "ai_assessment": inc.get("summary", "")[:1500],
             "notes": [{"who": n["author"], "kind": n["kind"], "text": n["body"]} for n in inc.get("notes", [])],
             "sample_events": [{"title": e["title"], "ts": e["ts"]} for e in inc.get("events", [])[:8]]}
    with ai.usage("closure", actor):
        text = ai.brief(provider, "closure", json.dumps(facts, default=str), "UTC")
    _note(conn, incident_id, "report", "AI closure report", text)
    conn.execute("UPDATE incidents SET summary = CASE WHEN summary = '' THEN ? ELSE summary END WHERE id = ?", (text, incident_id))
    audit(conn, actor, "incident.closure_report", {"incident_id": incident_id})
    return text


def notes(conn, incident_id: int) -> list[dict]:
    return [dict(r, meta=_loads(r["meta"])) for r in conn.execute(
        "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id", (incident_id,))]


def _loads(text: str) -> dict:
    try:
        return json.loads(text or "{}")
    except ValueError:
        return {}



def assign(conn, incident_id: int, assignee: str, actor: str) -> dict:
    row = conn.execute("SELECT status, ack_at FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        raise ValueError("No such incident")
    assignee = (assignee or "").strip()
    if assignee and not conn.execute("SELECT 1 FROM users WHERE username = ? AND disabled = 0", (assignee,)).fetchone():
        raise ValueError("No such user")
    ack = row["ack_at"] or (now() if assignee else "")
    new_status = "investigating" if assignee and row["status"] == "open" else row["status"]
    conn.execute("UPDATE incidents SET assignee = ?, ack_at = ?, status = ? WHERE id = ?", (assignee, ack, new_status, incident_id))
    _note(conn, incident_id, "assign", actor, f"Assigned to **{assignee}**" if assignee else "Unassigned")
    audit(conn, actor, "incident.assign", {"incident_id": incident_id, "assignee": assignee})
    return {"assignee": assignee, "status": new_status}


def set_status(conn, incident_id: int, status: str, reason: str, actor: str) -> dict:
    if status not in store.INCIDENT_STATUSES:
        raise ValueError("Unknown status")
    row = conn.execute("SELECT status, ack_at FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        raise ValueError("No such incident")
    closing = status in ("resolved", "false_positive")
    resolved = now() if closing else ""
    ack = row["ack_at"] or (now() if status == "investigating" else "")
    conn.execute("UPDATE incidents SET status = ?, resolved_at = ?, close_reason = ?, ack_at = ? WHERE id = ?",
                 (status, resolved, (reason or "")[:500], ack, incident_id))
    _note(conn, incident_id, "status", actor, f"Status → **{status.replace('_', ' ')}**" + (f": {reason}" if reason else ""))
    audit(conn, actor, "incident.status", {"incident_id": incident_id, "status": status, "reason": reason})
    return {"status": status}


def _auto_close(conn) -> int:
    """Close incidents that have been quiet for the configured number of days (0 = never)."""
    days = int(get_setting(conn, "auto_close_days", "0") or 0)
    if days <= 0:
        return 0
    cutoff = store.ago(days=days)
    rows = conn.execute("SELECT id FROM incidents WHERE status IN ('open', 'investigating') AND last_seen < ? AND demo = 0 AND severity < 9", (cutoff,)).fetchall()
    for r in rows:
        conn.execute("UPDATE incidents SET status = 'resolved', resolved_at = ?, close_reason = ? WHERE id = ?",
                     (now(), f"Auto-closed: quiet for {days} days", r["id"]))
        _note(conn, r["id"], "status", "CERBERUS", f"Auto-closed after {days} quiet days.")
    return len(rows)


def _escalate(conn) -> int:
    """Flag open incidents past their deadline that nobody has acknowledged. One summary notification per pass."""
    rows = conn.execute("SELECT id FROM incidents WHERE status IN ('open', 'investigating') AND due_at != '' AND due_at < ? "
                        "AND escalated_at = '' AND ack_at = '' AND demo = 0 AND priority >= 50 ORDER BY priority DESC", (now(),)).fetchall()
    if not rows:
        return 0
    stamp = now()
    for r in rows:
        conn.execute("UPDATE incidents SET escalated_at = ? WHERE id = ?", (stamp, r["id"]))
        _note(conn, r["id"], "escalate", "CERBERUS", "Past its response deadline with nobody assigned.")
    refs = ", ".join(f"INC-{r['id']:04d}" for r in rows[:5]) + (f" and {len(rows) - 5} more" if len(rows) > 5 else "")
    title = f"INC-{rows[0]['id']:04d} is overdue" if len(rows) == 1 else f"{len(rows)} incidents are overdue"
    conn.execute("INSERT INTO notifications (title, body, level, audience, in_app, emailed, created_by, created_at) VALUES (?, ?, 'warning', 'all', 1, 0, 'Triage', ?)",
                 (title, f"Past their response deadline with nobody assigned: {refs}. Open the incident queue to pick them up.", stamp))
    return len(rows)


_rescoring = threading.Event()


def kick_rescore() -> None:
    """Rescore every open incident in the background (used when the queue looks un-scored)."""
    if _rescoring.is_set():
        return
    _rescoring.set()

    def work():
        try:
            with db() as conn:
                rescore(conn)
        except Exception as exc:
            log.warning("background rescore failed: %s", exc)
        finally:
            _rescoring.clear()
    threading.Thread(target=work, name="cerberus-rescore", daemon=True).start()


def tick() -> None:
    """Scheduler: triage new incidents, keep priorities fresh, escalate the overdue, close the stale."""
    triage_pending()
    if not _lock.acquire(blocking=False):
        return
    try:
        with db() as conn:
            last = get_setting(conn, "triage_rescore_at")
            if not last or last <= store.ago(minutes=10):
                rescore(conn)
                _escalate(conn)
                _auto_close(conn)
                set_setting(conn, "triage_rescore_at", now())
    finally:
        _lock.release()



def suppressions(conn) -> list[dict]:
    rules = store.suppressions(conn)
    out = []
    for r in rules:
        n = conn.execute("SELECT COUNT(*) FROM incidents WHERE close_reason LIKE ? AND demo = 0",
                         (f"Suppressed by noise rule: {r.get('label') or r['value']}%",)).fetchone()[0]
        out.append({**r, "suppressed_count": n})
    return out


def add_suppression(conn, field: str, value: str, label: str, actor: str) -> dict:
    from .db import set_integration
    if field not in ("rule_id", "title_contains"):
        raise ValueError("Unknown match type")
    value = (value or "").strip()
    if not value:
        raise ValueError("Nothing to match on")
    rules = store.suppressions(conn)
    rule = {"id": secrets.token_hex(5), "field": field, "value": value[:200], "label": (label or value)[:120], "enabled": True, "created_by": actor, "created_at": now()}
    set_integration(conn, "suppressions", {"rules": rules + [rule]})
    store.invalidate_suppressions()
    swept = _sweep_suppression(conn, rule)
    audit(conn, actor, "suppression.add", {"field": field, "value": value, "closed": swept})
    return {"rule": rule, "closed": swept}


def delete_suppression(conn, rule_id: str, actor: str) -> None:
    from .db import set_integration
    set_integration(conn, "suppressions", {"rules": [r for r in store.suppressions(conn) if r["id"] != rule_id]})
    store.invalidate_suppressions()
    audit(conn, actor, "suppression.delete", {"id": rule_id})


def _sweep_suppression(conn, rule: dict) -> int:
    """Close the open incidents that already match a new suppression rule."""
    reason = f"Suppressed by noise rule: {rule.get('label') or rule['value']}"
    rows = conn.execute("SELECT id, rule_id, title FROM incidents WHERE status IN ('open', 'investigating') AND demo = 0").fetchall()
    n = 0
    for r in rows:
        if store.matches_suppression(r["rule_id"], r["title"], [rule]):
            conn.execute("UPDATE incidents SET status = 'resolved', ai_verdict = 'noise', resolved_at = ?, close_reason = ? WHERE id = ?", (now(), reason, r["id"]))
            _note(conn, r["id"], "status", "CERBERUS", f"Auto-closed as noise ({rule.get('label') or rule['value']}).")
            n += 1
    return n


def suppress_from_incident(conn, incident_id: int, by: str, actor: str) -> dict:
    row = conn.execute("SELECT rule_id, title FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        raise ValueError("No such incident")
    if by == "rule" and row["rule_id"]:
        return add_suppression(conn, "rule_id", row["rule_id"], f"Rule {row['rule_id']}", actor)
    phrase = re.split(r"[(:]| from | against | on ", row["title"])[0].strip()[:80]
    return add_suppression(conn, "title_contains", phrase, phrase, actor)


def settings(conn) -> dict:
    return {"triage_enabled": get_setting(conn, "triage_enabled", "1") != "0",
            "auto_close_days": int(get_setting(conn, "auto_close_days", "0") or 0),
            "last_run": get_setting(conn, "triage_last_run"), "last_result": get_setting(conn, "triage_last_result")}


def save_settings(conn, body: dict, actor: str) -> dict:
    set_setting(conn, "triage_enabled", "1" if body.get("triage_enabled", True) else "0")
    set_setting(conn, "auto_close_days", str(store.clamp(body.get("auto_close_days", 0), 0, 365, 0)))
    audit(conn, actor, "triage.settings", {k: body.get(k) for k in ("triage_enabled", "auto_close_days")})
    return settings(conn)
