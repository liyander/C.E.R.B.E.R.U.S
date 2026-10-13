"""The only things the AI can do: typed, bounded, audited tool calls.

Every argument is validated here regardless of what the model asked for, and
nothing in this registry executes a response action - the model can only
queue a proposal for a human Enforcer.
"""
import json
from datetime import datetime, timedelta, timezone

from . import accounts, grafana, mailer, store
from .db import ago, audit, get_integration, iso, now

APPROVAL_TTL_HOURS = 24
RESPONSE_ACTIONS = ("block_ip", "disable_account", "isolate_host", "collect_forensics",
                    "quarantine_file", "change_policy")
MAX_RESULT_CHARS = 12000


def _fn(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required or []},
    }}


BASE_TOOLS = [
    _fn("search_events", "Search normalised security events (newest first). All filters optional.", {
        "query": {"type": "string", "description": "Text to find in title, message, rule, username, IP or asset"},
        "asset": {"type": "string", "description": "Exact asset name or IP"},
        "source": {"type": "string", "description": "Source engine, e.g. wazuh, snort, grafana, openappsec"},
        "source_ip": {"type": "string"},
        "min_severity": {"type": "integer", "description": "1-10"},
        "hours": {"type": "integer", "description": "Look-back window in hours (default 24, max 720)"},
        "limit": {"type": "integer", "description": "Max rows (default 25, max 50)"},
    }),
    _fn("list_incidents", "List correlated incidents.", {
        "status": {"type": "string", "enum": ["active", *store.INCIDENT_STATUSES]},
        "min_severity": {"type": "integer"},
        "limit": {"type": "integer"},
    }),
    _fn("get_incident", "Get one incident with its full event timeline and approval requests.", {
        "incident_id": {"type": "integer", "description": "Numeric id, e.g. 3 for INC-0003"},
    }, ["incident_id"]),
    _fn("list_assets", "List known assets with their open-incident counts.", {}),
    _fn("propose_response_action",
        "Queue a response action for human Enforcer approval. This does NOT execute anything.", {
            "incident_id": {"type": "integer"},
            "action": {"type": "string", "enum": list(RESPONSE_ACTIONS)},
            "target": {"type": "string", "description": "IP, account, host or file the action applies to"},
            "rationale": {"type": "string", "description": "Evidence-based justification citing EVT ids"},
        }, ["incident_id", "action", "target", "rationale"]),
]

# (required Grafana setting, tool spec)
GRAFANA_TOOLS = [
    ("prometheus_uid", _fn(
        "get_server_health",
        "Current health of every monitored server and endpoint, from Prometheus: up/down per scrape target, "
        "CPU, memory, disk, load and uptime per host, and HTTP probe results. Call this first for any "
        "status, health, availability or performance question.", {})),
    ("prometheus_uid", _fn(
        "query_prometheus",
        "Run a specific PromQL range query through Grafana; returns min/max/avg/last per series. Use for "
        "trends or metrics that get_server_health does not cover.", {
            "promql": {"type": "string"},
            "minutes": {"type": "integer", "description": "Look-back window (default 60, max 1440)"},
        }, ["promql"])),
    ("loki_uid", _fn("query_loki", "Run a LogQL query through Grafana; returns recent log lines.", {
        "logql": {"type": "string"},
        "minutes": {"type": "integer"},
        "limit": {"type": "integer", "description": "Max lines (default 30, max 50)"},
    }, ["logql"])),
]


REPORT_TOOL = _fn(
    "send_report_to_admins",
    "Email a report to the CERBERUS admins. Only call this when the user explicitly asks to send, email or "
    "report something to the admin(s). Recipients are fixed; you cannot choose them.", {
        "subject": {"type": "string", "description": "Short subject line, e.g. 'Server status 13 Oct'"},
        "report": {"type": "string", "description": "The complete report in markdown: the full answer with its "
                                                    "tables and evidence references, not a summary of it"},
    }, ["subject", "report"])


def available_tools(conn) -> list[dict]:
    cfg = get_integration(conn, "grafana")
    extra = [spec for key, spec in GRAFANA_TOOLS if cfg.get("url") and cfg.get(key)]
    if mailer.is_configured(mailer.config(conn)) and accounts.admin_emails(conn):
        extra.append(REPORT_TOOL)
    return BASE_TOOLS + extra


def _slim(event: dict) -> dict:
    keep = ("ref", "source", "event_type", "severity", "ts", "asset_name", "source_ip", "username",
            "rule_id", "title", "incident_id")
    out = {k: event[k] for k in keep if event.get(k) not in (None, "")}
    if event.get("message"):
        out["message"] = event["message"][:400]
    return out


def _search_events(conn, a, actor):
    events = store.query_events(
        conn, q=a.get("query", ""), asset=a.get("asset", ""), source=a.get("source", ""),
        source_ip=a.get("source_ip", ""), min_severity=a.get("min_severity", 1),
        hours=a.get("hours", 24), limit=store.clamp(a.get("limit"), 1, 50, 25))
    return {"count": len(events), "events": [_slim(e) for e in events]}


def _list_incidents(conn, a, actor):
    incidents = store.query_incidents(conn, status=str(a.get("status", "")),
                                      min_severity=a.get("min_severity", 1),
                                      limit=store.clamp(a.get("limit"), 1, 50, 25))
    keep = ("ref", "id", "title", "status", "severity", "asset_name", "source_ip", "first_seen",
            "last_seen", "event_count")
    return {"count": len(incidents), "incidents": [{k: i[k] for k in keep} for i in incidents]}


def _get_incident(conn, a, actor):
    inc = store.get_incident(conn, store.clamp(a.get("incident_id"), 1, 2**31, 0))
    if not inc:
        return {"error": "incident not found"}
    inc["events"] = [_slim(e) for e in inc["events"][:50]]
    inc.pop("summary_meta", None)
    return inc


def _list_assets(conn, a, actor):
    rows = conn.execute(
        "SELECT a.id, a.name, a.ip, a.kind, a.criticality, "
        "(SELECT COUNT(*) FROM incidents i WHERE i.asset_id = a.id AND i.status IN ('open','investigating')) "
        "AS open_incidents FROM assets a ORDER BY a.name LIMIT 200").fetchall()
    return {"assets": [dict(r) for r in rows]}


def _propose(conn, a, actor):
    incident_id = store.clamp(a.get("incident_id"), 1, 2**31, 0)
    action = str(a.get("action", ""))
    target = store.text(a.get("target"), 200)
    if action not in RESPONSE_ACTIONS:
        return {"error": f"action must be one of {list(RESPONSE_ACTIONS)}"}
    if not target:
        return {"error": "target is required"}
    if not conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone():
        return {"error": "incident not found"}
    dupe = conn.execute(
        "SELECT id FROM approvals WHERE incident_id = ? AND action = ? AND target = ? AND status = 'pending'",
        (incident_id, action, target)).fetchone()
    if dupe:
        return {"approval_id": dupe["id"], "status": "pending", "note": "identical request already pending"}
    expires = iso(datetime.now(timezone.utc) + timedelta(hours=APPROVAL_TTL_HOURS))
    cur = conn.execute(
        "INSERT INTO approvals (incident_id, action, target, rationale, requested_by, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (incident_id, action, target, store.text(a.get("rationale"), 2000), f"ai (asked by {actor})",
         now(), expires))
    return {"approval_id": cur.lastrowid, "status": "pending",
            "note": "Queued for Enforcer approval. Nothing has been executed."}


def _query_prometheus(conn, a, actor):
    return grafana.query_prometheus(get_integration(conn, "grafana"), a.get("promql", ""), a.get("minutes", 60))


def _send_report(conn, a, actor):
    subject = store.text(a.get("subject"), 150) or "Analyst report"
    report = str(a.get("report") or "").strip()[:60000]
    if len(report) < 20:
        return {"error": "report must contain the full report text in markdown"}
    full_subject = f"[CERBERUS report] {subject}"
    # A model that repeats the call must not send the same report twice.
    if conn.execute("SELECT 1 FROM emails WHERE kind = 'report' AND subject = ? AND created_at >= ?",
                    (full_subject, ago(minutes=5))).fetchone():
        return {"status": "already sent", "note": "This report was emailed moments ago; it was not sent again."}
    try:
        message, attachments = mailer.report_message(actor, subject, "", report, mailer.config(conn).get("app_url", ""))
        sent = mailer.send(conn, "report", accounts.admin_emails(conn), message, attachments=attachments)
    except mailer.MailError as exc:
        return {"error": str(exc)}
    return {"status": "queued", "recipients": sent, "attachment": attachments[0][0],
            "note": f"Report emailed to {sent} admin(s) with the full report attached as {attachments[0][0]}."}


def _server_health(conn, a, actor):
    return grafana.server_health(get_integration(conn, "grafana"))


def _query_loki(conn, a, actor):
    return grafana.query_loki(get_integration(conn, "grafana"), a.get("logql", ""),
                              a.get("minutes", 60), a.get("limit", 30))


HANDLERS = {
    "search_events": _search_events, "list_incidents": _list_incidents, "get_incident": _get_incident,
    "list_assets": _list_assets, "propose_response_action": _propose,
    "send_report_to_admins": _send_report, "get_server_health": _server_health, "query_prometheus": _query_prometheus, "query_loki": _query_loki,
}


def execute(conn, name: str, args, actor: str) -> str:
    """Run one tool call and return a size-capped JSON string for the model."""
    allowed = {t["function"]["name"] for t in available_tools(conn)}
    if not isinstance(args, dict):
        args = {}
    if name not in allowed:
        result = {"error": f"unknown or unavailable tool '{name}'"}
    else:
        try:
            result = HANDLERS[name](conn, args, actor)
        except grafana.GrafanaError as exc:
            result = {"error": str(exc)}
    # Report bodies can be long; the audit entry records that it was sent, not the whole text.
    logged = {k: (v if k != "report" else f"<{len(str(v))} characters>") for k, v in args.items()}
    audit(conn, f"ai (asked by {actor})", "ai.tool_call",
          {"tool": name, "arguments": logged, "error": result.get("error")})
    out = json.dumps(result, default=str)
    if len(out) > MAX_RESULT_CHARS:
        out = out[:MAX_RESULT_CHARS] + '... [truncated: narrow the query]'
    return out
