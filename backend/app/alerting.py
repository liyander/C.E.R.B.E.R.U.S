"""Threat alert rules: email chosen people when a threat measure crosses a threshold an admin sets.

A rule watches one measure:
  - threat_level: the dashboard's overall threat level (0-100);
  - forecast: any attack-forecast warning's likelihood that an intrusion follows (0-100%);
  - risk: any machine's risk score (0-100);
  - incident: any open incident of at least this severity (1-10) opened in the last 24 hours.
When something reaches the threshold, the rule's recipients get one email listing everything over it.
The same thing is not sent again until the rule's quiet period has passed, unless it gets 10 points worse; an incident is sent once.
"""
import json
import logging
import re
import secrets
import threading

from . import dashboard, insights, mailer, store
from .db import audit, db, get_integration, get_setting, now, set_integration, set_setting

log = logging.getLogger("cerberus.alerting")

METRICS = {
    "threat_level": ("Overall threat level", "%", 0, 100, 70),
    "forecast": ("Attack forecast likelihood", "%", 1, 100, 80),
    "risk": ("Machine risk score", "/100", 1, 100, 70),
    "incident": ("Incident severity", "/10", 1, 10, 9),
}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_log (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    item TEXT NOT NULL,
    title TEXT NOT NULL,
    value INTEGER NOT NULL,
    recipients TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'sent',
    test INTEGER NOT NULL DEFAULT 0,
    sent_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_log_rule ON alert_log(rule_id, item, sent_at);
"""
_lock = threading.Lock()


def rules(conn) -> list[dict]:
    return get_integration(conn, "threat_alerts").get("rules", [])


def clean(rule: dict, users: dict[int, dict]) -> dict:
    """Validate one rule from the admin page. Raises ValueError with a readable reason."""
    metric = rule.get("metric")
    if metric not in METRICS:
        raise ValueError("Choose what the rule watches")
    _, _, low, high, _ = METRICS[metric]
    try:
        threshold = int(rule.get("threshold"))
    except (TypeError, ValueError):
        raise ValueError("The threshold must be a number")
    if not low <= threshold <= high:
        raise ValueError(f"The threshold for {METRICS[metric][0].lower()} must be between {low} and {high}")
    name = (rule.get("name") or "").strip()[:80] or f"{METRICS[metric][0]} at {threshold}{METRICS[metric][1]}"
    ids = sorted({int(u) for u in rule.get("users", []) if str(u).isdigit() and int(u) in users})
    extra = [e.strip().lower() for e in re.split(r"[,;\s]+", rule.get("extra", "") or "") if e.strip()]
    bad = [e for e in extra if not EMAIL.match(e)]
    if bad:
        raise ValueError(f"Not an email address: {', '.join(bad[:3])}")
    if not ids and not extra:
        raise ValueError("Pick at least one person to email, or add an email address")
    return {"id": rule.get("id") or secrets.token_hex(5), "name": name, "metric": metric, "threshold": threshold, "users": ids,
            "extra": ", ".join(dict.fromkeys(extra)), "cooldown_hours": store.clamp(rule.get("cooldown_hours", 6), 1, 168, 6), "enabled": bool(rule.get("enabled", True))}


def _users(conn) -> dict[int, dict]:
    return {r["id"]: dict(r) for r in conn.execute("SELECT id, username, email, email_verified, role, disabled FROM users")}


def save(conn, rule: dict, actor: str) -> dict:
    users = _users(conn)
    rule = clean(rule, users)
    current = rules(conn)
    current = [rule if r["id"] == rule["id"] else r for r in current] if any(r["id"] == rule["id"] for r in current) else current + [rule]
    set_integration(conn, "threat_alerts", {"rules": current})
    audit(conn, actor, "alert_rule.saved", {k: rule[k] for k in ("id", "name", "metric", "threshold", "enabled")})
    return rule


def delete(conn, rule_id: str, actor: str) -> None:
    set_integration(conn, "threat_alerts", {"rules": [r for r in rules(conn) if r["id"] != rule_id]})
    audit(conn, actor, "alert_rule.deleted", {"id": rule_id})


def recipients(conn, rule: dict) -> list[str]:
    users = _users(conn)
    chosen = [users[u]["email"] for u in rule.get("users", []) if u in users and users[u]["email"] and users[u]["email_verified"] and not users[u]["disabled"]]
    extra = [e.strip() for e in (rule.get("extra") or "").split(",") if e.strip()]
    return list(dict.fromkeys(chosen + extra))


# ---------- measuring ----------

def current(conn) -> dict[str, list[dict]]:
    """Everything each measure currently shows: [{item, title, value, href}], highest first."""
    level = dashboard.threat(conn)
    out = {"threat_level": [{"item": "overall", "title": f"Overall threat level {level['value']} ({level['label']})"
                              + (f": {level['drivers'][0]['text']}" if level["drivers"] else ""), "value": level["value"], "href": "#/dashboard"}]}
    out["forecast"] = [{"item": r["key"], "title": r["title"], "value": r["likelihood"], "href": "#/forecast"}
                       for r in conn.execute("SELECT key, title, likelihood FROM forecasts WHERE status = 'active' ORDER BY likelihood DESC LIMIT 20")]
    try:
        machines, _ = insights.machines(conn)
    except Exception:
        machines = []
    out["risk"] = sorted([{"item": m["ip"], "title": f"{', '.join(m['names'][:1]) or m['ip']} has a risk score of {m['risk']}/100", "value": m["risk"], "href": "#/risk"}
                          for m in machines if m.get("risk")], key=lambda x: -x["value"])
    out["incident"] = [{"item": f"inc:{r['id']}", "title": f"INC-{r['id']:04d} {r['title']}", "value": r["severity"], "href": f"#/incidents/{r['id']}"}
                       for r in conn.execute("SELECT id, title, severity FROM incidents WHERE status IN ('open', 'investigating') AND demo = 0 AND first_seen >= ? "
                                             "ORDER BY severity DESC, id DESC LIMIT 20", (store.ago(hours=24),))]
    return out


def _email(rule: dict, hits: list[dict], app_url: str, test: bool = False) -> tuple[str, str, str]:
    label, unit = METRICS[rule["metric"]][:2]
    worst = hits[0]
    critical = rule["metric"] == "incident" and worst["value"] >= 9 or rule["metric"] != "incident" and worst["value"] >= 85
    subject = f"{'[TEST] ' if test else ''}[CERBERUS alert] {worst['title']}" + (f" and {len(hits) - 1} more" if len(hits) > 1 else "")
    listing = "\n".join(f"- **{h['value']}{unit}** {h['title']}" for h in hits[:15])
    html_body = mailer.layout(
        banner="watch-critical" if critical else "watch", accent="#b91c1c" if critical else "#b45309",
        headline=worst["title"] if len(hits) == 1 else f"[[{len(hits)} threats]] are over your threshold",
        lead=("This is a test of the alert rule. Nothing new has crossed the threshold. " if test else "")
             + f"Your rule “{rule['name']}” fires when {label.lower()} reaches {rule['threshold']}{unit}.",
        key_line=f"{worst['value']}{unit}", key_sub=label,
        button=("Open CERBERUS", f"{app_url}/{worst['href']}") if app_url else None, body_html=mailer.md_to_html(listing),
        note="You receive this because an admin added you to this alert rule in CERBERUS (Administer, Threat alerts).", preheader=worst["title"])
    text = subject + "\n\n" + "\n".join(f"- {h['value']}{unit} {h['title']}" for h in hits[:15])
    return subject, html_body, text


def evaluate(conn, only: str = "") -> list[dict]:
    """Check every enabled rule now; email what is over its threshold and not recently sent. Returns what was sent."""
    sent = []
    values = None
    for rule in rules(conn):
        if not rule.get("enabled") or (only and rule["id"] != only):
            continue
        values = values or current(conn)
        over = [h for h in values.get(rule["metric"], []) if h["value"] >= rule["threshold"]]
        due = []
        for h in over:
            last = conn.execute("SELECT value, sent_at FROM alert_log WHERE rule_id = ? AND item = ? AND test = 0 ORDER BY id DESC LIMIT 1", (rule["id"], h["item"])).fetchone()
            if rule["metric"] == "incident" and last:
                continue  # an incident is one event: it is emailed once
            if not last or last["sent_at"] < store.ago(hours=rule.get("cooldown_hours", 6)) or h["value"] >= last["value"] + 10:
                due.append(h)
        if not due:
            continue
        to = recipients(conn, rule)
        status = "sent"
        try:
            if not to:
                raise mailer.MailError("nobody to send it to (no verified email)")
            mailer.send(conn, "threat_alert", to, _email(rule, due, mailer.config(conn).get("app_url", "")))
        except mailer.MailError as exc:
            status = f"failed: {exc}"[:200]
            log.warning("threat alert %s not sent: %s", rule["name"], exc)
        for h in due:
            conn.execute("INSERT INTO alert_log (rule_id, rule_name, item, title, value, recipients, status, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (rule["id"], rule["name"], h["item"], h["title"][:300], h["value"], ", ".join(to), status, now()))
        audit(conn, "threat alerts", "alert_rule.fired", {"rule": rule["name"], "items": len(due), "to": to, "status": status})
        sent.append({"rule": rule["name"], "items": len(due), "to": to, "status": status})
    return sent


def test(conn, rule_id: str, actor: str) -> dict:
    """Send the rule's email now with the current top item, whatever its value, marked as a test."""
    rule = next((r for r in rules(conn) if r["id"] == rule_id), None)
    if not rule:
        raise ValueError("No such rule")
    values = current(conn).get(rule["metric"]) or [{"item": "none", "title": f"Nothing to report for {METRICS[rule['metric']][0].lower()} right now", "value": 0, "href": "#/dashboard"}]
    to = recipients(conn, rule)
    if not to:
        raise ValueError("Nobody on this rule has a verified email address")
    mailer.send(conn, "threat_alert", to, _email(rule, values[:3], mailer.config(conn).get("app_url", ""), test=True))
    conn.execute("INSERT INTO alert_log (rule_id, rule_name, item, title, value, recipients, status, test, sent_at) VALUES (?, ?, ?, ?, ?, ?, 'sent', 1, ?)",
                 (rule["id"], rule["name"], values[0]["item"], values[0]["title"][:300], values[0]["value"], ", ".join(to), now()))
    audit(conn, actor, "alert_rule.tested", {"rule": rule["name"], "to": to})
    return {"to": to}


def tick() -> None:
    """Called by the background scheduler: evaluate the rules every two minutes."""
    with db() as conn:
        if not any(r.get("enabled") for r in rules(conn)):
            return
        last = get_setting(conn, "alerts_last_check")
        if last and last > store.ago(minutes=2):
            return
        set_setting(conn, "alerts_last_check", now())
        if not _lock.acquire(blocking=False):
            return
        try:
            evaluate(conn)
        finally:
            _lock.release()


def page(conn) -> dict:
    users = _users(conn)
    values = current(conn)
    return {"rules": rules(conn), "metrics": {k: {"label": v[0], "unit": v[1], "min": v[2], "max": v[3], "default": v[4]} for k, v in METRICS.items()},
            "now": {k: (v[0]["value"] if v else 0) for k, v in values.items()}, "top": {k: (v[0]["title"] if v else "") for k, v in values.items()},
            "users": [{"id": u["id"], "username": u["username"], "email": u["email"], "verified": bool(u["email_verified"]), "role": u["role"]}
                      for u in users.values() if not u["disabled"]],
            "email_ready": mailer.is_configured(mailer.config(conn)),
            "history": [dict(r) for r in conn.execute("SELECT * FROM alert_log ORDER BY id DESC LIMIT 60")]}
