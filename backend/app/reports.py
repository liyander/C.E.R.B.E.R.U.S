"""Scheduled security reports: a daily or weekly summary across every connected source, as a PDF by email.

The numbers are gathered here; the AI only writes the opening summary, and the report is still
sent (with a plain summary) when no model is available.
"""
import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone

from . import accounts, ai, grafana, mailer, openappsec, snort, store, wazuh
from .db import db, get_integration, get_setting, now, set_integration, set_setting

log = logging.getLogger("cerberus.reports")

DEFAULTS = {
    "enabled": False,
    "frequency": "weekly",
    "weekday": 0,
    "hour": 8,
    "send_to_admins": True,
    "extra_recipients": "",
    "ai_summary": True,
}
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
REPORT_TASK = ("Write the executive summary of this security report in at most 220 words for management: start with a one-line overall verdict, "
               "then three to five bullets on what matters most (with numbers and machine or source names), then one line on the most important action. "
               "Plain language; no jargon without a short explanation.")
_lock = threading.Lock()


def settings(conn) -> dict:
    saved = get_integration(conn, "reports")
    merged = {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS}}
    merged["frequency"] = merged["frequency"] if merged["frequency"] in ("daily", "weekly") else "weekly"
    merged["weekday"] = store.clamp(merged["weekday"], 0, 6, 0)
    merged["hour"] = store.clamp(merged["hour"], 0, 23, 8)
    return merged


def save_settings(conn, changes: dict) -> dict:
    merged = {**settings(conn), **{k: v for k, v in changes.items() if k in DEFAULTS}}
    bad = [e for e in _split(merged["extra_recipients"]) if not EMAIL.match(e)]
    if bad:
        raise ValueError(f"Not an email address: {', '.join(bad[:3])}")
    set_integration(conn, "reports", merged)
    return settings(conn)


def _split(text: str) -> list[str]:
    return [e.strip() for e in re.split(r"[,;\s]+", str(text or "")) if e.strip()]


def recipients(conn, s: dict) -> list[str]:
    found = (accounts.admin_emails(conn) if s["send_to_admins"] else []) + _split(s["extra_recipients"])
    return list(dict.fromkeys(found))


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "_Nothing to report._\n"
    out = "| " + " | ".join(headers) + " |\n|" + "---|" * len(headers) + "\n"
    for r in rows:
        out += "| " + " | ".join(str(c).replace("|", "/").replace("\n", " ") for c in r) + " |\n"
    return out


def gather(conn, days: int) -> dict:
    """The facts behind the report. Each source is optional."""
    hours = days * 24
    since = store.ago(hours=hours)
    g, w = get_integration(conn, "grafana"), wazuh.settings(conn)
    facts: dict = {"period": f"last {'24 hours' if days == 1 else f'{days} days'}", "problems": []}
    facts["incidents"] = {
        "opened": conn.execute("SELECT COUNT(*) FROM incidents WHERE first_seen >= ?", (since,)).fetchone()[0],
        "resolved": conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('resolved', 'false_positive') AND last_seen >= ?", (since,)).fetchone()[0],
        "open_now": conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')").fetchone()[0],
        "worst_open": [dict(r) for r in conn.execute(
            "SELECT i.id, i.title, i.severity, i.event_count, a.name AS asset FROM incidents i LEFT JOIN assets a ON a.id = i.asset_id "
            "WHERE i.status IN ('open', 'investigating') ORDER BY i.severity DESC, i.last_seen DESC LIMIT 10")]}
    facts["events_by_source"] = {r["source"]: r["n"] for r in conn.execute("SELECT source, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY source", (since,))}
    if wazuh.is_ready(w):
        try:
            facts["wazuh"] = wazuh.summary(w, hours=hours)
        except wazuh.WazuhError as exc:
            facts["problems"].append(f"Wazuh: {exc}")
    if snort.is_ready(g):
        try:
            facts["snort"] = snort.summary(g, hours=min(hours, 24), limit=1)
            facts["snort"].pop("latest_alerts", None)
        except grafana.GrafanaError as exc:
            facts["problems"].append(f"Snort: {exc}")
        try:
            facts["waf"] = openappsec.summary(g, hours=hours, limit=1, recorded=openappsec.inventory(conn))
            facts["waf"].pop("latest_requests", None)
        except grafana.GrafanaError as exc:
            facts["problems"].append(f"WAF: {exc}")
    try:
        from . import insights
        rows, problems = insights.machines(conn)
        facts["machines"] = [{"machine": ", ".join(m["names"]) or m["ip"], "ip": m["ip"], "risk": m["risk"], "exposure": m["exposure"],
                              "exploited_cves": m["kev"], "critical_cves": m["vulns"].get("Critical", 0), "config_score": m["sca"]} for m in rows]
        vulns = insights.vulnerabilities(conn)[0]
        facts["vulnerabilities"] = {"fix_now": [r["cve"] for r in vulns if r["tier"] == "now"], "fix_soon": sum(1 for r in vulns if r["tier"] == "soon"),
                                    "total": len(vulns), "top": [{"cve": r["cve"], "tier": r["tier"], "machines": r["agents"][:4], "package": ", ".join(r["packages"][:2])} for r in vulns[:8]]}
    except Exception as exc:
        facts["problems"].append(f"Risk and vulnerabilities: {str(exc)[:160]}")
    facts["tool_health"] = [dict(r) for r in conn.execute("SELECT title, detail, first_seen FROM watch_findings WHERE status = 'firing' AND kind = 'sensor' ORDER BY severity DESC")]
    facts["watch_firing"] = [dict(r) for r in conn.execute("SELECT title, severity FROM watch_findings WHERE status = 'firing' AND kind != 'sensor' ORDER BY severity DESC LIMIT 10")]
    usage = conn.execute("SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COUNT(DISTINCT run_id) FROM ai_usage WHERE ts >= ?", (since,)).fetchone()
    facts["ai_usage"] = {"model_calls": usage[0], "tokens": usage[1], "agent_runs": usage[2]}
    return facts


def build_markdown(conn, days: int, use_ai: bool = True) -> tuple[str, dict]:
    facts = gather(conn, days)
    summary = ""
    provider = ai.active_provider(conn) if use_ai else None
    if provider:
        try:
            with ai.usage("report", "scheduled report"):
                summary = ai.brief(provider, "report", json.dumps(facts, default=str), grafana.tz_label(0))
        except ai.AIError as exc:
            facts["problems"].append(f"AI summary: {exc}")
    inc = facts["incidents"]
    if not summary or summary.startswith("(The model"):
        summary = (f"In the {facts['period']}, {inc['opened']} incidents were opened and {inc['resolved']} closed; {inc['open_now']} remain open. "
                   + (f"{len(facts.get('vulnerabilities', {}).get('fix_now', []))} vulnerabilities on your machines are known to be exploited in the wild. "
                      if facts.get("vulnerabilities") else "")
                   + (f"{len(facts['tool_health'])} security tool problem(s) need attention." if facts["tool_health"] else "All security tools are reporting."))
    md = f"## Summary\n\n{summary}\n\n"
    md += (f"## Incidents\n\n{inc['opened']} opened, {inc['resolved']} closed, {inc['open_now']} open now.\n\n"
           + _table(["Incident", "Asset", "Severity", "Events"], [[f"INC-{i['id']:04d} {i['title']}", i["asset"] or "", i["severity"], i["event_count"]] for i in inc["worst_open"]]) + "\n")
    md += "## Detections by source\n\n" + _table(["Source", "Events recorded"], [[k, f"{v:,}"] for k, v in sorted(facts["events_by_source"].items(), key=lambda kv: -kv[1])]) + "\n"
    if facts.get("wazuh"):
        wz = facts["wazuh"]
        md += (f"### Wazuh\n\n{wz['total_alerts']:,} alerts. By level: " + ", ".join(f"{b['name']} {b['alerts']:,}" for b in wz["by_level"]) + ".\n\n"
               + _table(["Rule", "Level", "Alerts"], [[r["description"][:90], r["level"], f"{r['alerts']:,}"] for r in wz["top_rules"][:6]]) + "\n")
    if facts.get("snort"):
        sn = facts["snort"]
        md += (f"### Snort (last 24 hours)\n\n{sn['alerts']:,} alerts. " + ", ".join(f"priority {k}: {v:,}" for k, v in sn["by_priority"].items()) + ".\n\n"
               + _table(["Signature", "Priority", "Alerts"], [[r["message"][:80], r["priority"], f"{r['alerts']:,}"] for r in sn["top_signatures"][:6]]) + "\n")
    if facts.get("waf"):
        wf = facts["waf"]
        md += (f"### Web application firewall\n\n{wf['requests_judged']:,} requests judged: {wf['blocked']:,} blocked, {wf['detected_not_blocked']:,} let through.\n\n"
               + _table(["Attack type", "Requests"], [[r["type"], f"{r['requests']:,}"] for r in wf["attack_types"][:6]]) + "\n")
    if facts.get("machines"):
        md += "## Riskiest machines\n\n" + _table(["Machine", "Risk (0-100)", "Exposure", "Exploited CVEs", "Critical CVEs", "Config score"],
                                                   [[m["machine"], m["risk"], m["exposure"], m["exploited_cves"], m["critical_cves"], f"{m['config_score']}%" if m["config_score"] is not None else "n/a"]
                                                    for m in facts["machines"][:6]]) + "\n"
    if facts.get("vulnerabilities"):
        v = facts["vulnerabilities"]
        md += (f"## Vulnerabilities to fix first\n\n{len(v['fix_now'])} known to be exploited in the wild (fix now), {v['fix_soon']} likely to be exploited soon, out of {v['total']:,}.\n\n"
               + _table(["CVE", "Priority", "Machines", "Package"], [[r["cve"], {"now": "Fix now", "soon": "Fix soon", "plan": "Plan", "low": "Low"}[r["tier"]], ", ".join(r["machines"]), r["package"]] for r in v["top"]]) + "\n")
    md += "## Security tools\n\n" + ("All sensors, agents and log shippers are reporting.\n\n" if not facts["tool_health"] else
                                       "".join(f"- **{t['title']}** (since {t['first_seen']}): {t['detail']}\n" for t in facts["tool_health"]) + "\n")
    if facts["watch_firing"]:
        md += "## Other conditions AI watch is tracking\n\n" + "".join(f"- {f['title']}\n" for f in facts["watch_firing"]) + "\n"
    md += f"## AI use\n\n{facts['ai_usage']['agent_runs']} analyst runs, {facts['ai_usage']['model_calls']} model calls, {facts['ai_usage']['tokens']:,} tokens.\n"
    if facts["problems"]:
        md += "\n## Not included\n\n" + "".join(f"- {p}\n" for p in facts["problems"])
    return md, facts


def send(conn, actor: str, days: int | None = None, reason: str = "manual") -> dict:
    """Build the report and email it, with the PDF attached. Returns who it went to."""
    s = settings(conn)
    days = days or (1 if s["frequency"] == "daily" else 7)
    to = recipients(conn, s)
    if not to:
        raise mailer.MailError("Nobody to send it to: no admin has a verified email address and no extra recipients are set.")
    md, _ = build_markdown(conn, days, s["ai_summary"])
    title = f"{'Daily' if days == 1 else 'Weekly' if days == 7 else f'{days}-day'} security report"
    message, attachments = mailer.report_message(actor, title, f"Summary of the last {'24 hours' if days == 1 else f'{days} days'} across every connected source.", md,
                                                 mailer.config(conn).get("app_url", ""))
    count = mailer.send(conn, "scheduled_report", to, message, attachments=attachments)
    set_setting(conn, "reports_last_sent", now())
    set_setting(conn, "reports_last_result", f"{title} sent to {len(to)} recipient{'s' if len(to) != 1 else ''} ({reason})")
    return {"sent_to": to, "queued": count, "title": title}


def tick() -> None:
    """Called by the background scheduler; sends the report once when its day and hour come round."""
    with db() as conn:
        s = settings(conn)
        if not s["enabled"]:
            return
        from .watch import settings as watch_settings
        local = datetime.now(timezone.utc) + timedelta(minutes=watch_settings(conn)["tz_offset"])
        today = local.strftime("%Y-%m-%d")
        due = local.hour >= s["hour"] and (s["frequency"] == "daily" or local.weekday() == s["weekday"])
        if not due or get_setting(conn, "reports_last_day") == today:
            return
        set_setting(conn, "reports_last_day", today)
    if not _lock.acquire(blocking=False):
        return
    try:
        with db() as conn:
            send(conn, "scheduled report", reason="schedule")
    except Exception as exc:
        log.warning("scheduled report failed: %s", exc)
        with db() as conn:
            set_setting(conn, "reports_last_result", f"Failed: {str(exc)[:200]}")
    finally:
        _lock.release()


def status(conn) -> dict:
    s = settings(conn)
    history = [dict(r) for r in conn.execute("SELECT recipient, subject, status, error, created_at, sent_at FROM emails WHERE kind = 'scheduled_report' ORDER BY id DESC LIMIT 20")]
    return {"settings": s, "recipients": recipients(conn, s), "last_sent": get_setting(conn, "reports_last_sent"),
            "last_result": get_setting(conn, "reports_last_result"), "history": history, "weekdays": WEEKDAYS, "email_ready": mailer.is_configured(mailer.config(conn))}
