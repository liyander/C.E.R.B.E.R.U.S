"""The only things the AI can do: typed, bounded, audited tool calls.

Every argument is validated here regardless of what the model asked for, and
nothing in this registry executes a response action - the model can only
queue a proposal for a human Enforcer.
"""
import json
from datetime import datetime, timedelta, timezone

from . import accounts, grafana, mailer, openappsec, snort, store, wazuh
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
        "get_metric_history",
        "How a metric moved over time on a host: a timeline, the peak and when it happened, and the periods it was "
        "high. Use this for every WHEN / since when / how long question about load, CPU, memory, disk or response "
        "time, and to find the time window before asking why something happened.", {
            "metric": {"type": "string", "enum": ["load", "cpu", "memory", "disk", "response_time"]},
            "host": {"type": "string", "description": "Part of the instance name or IP, e.g. 172.16.3.100. Leave empty for all hosts."},
            "hours": {"type": "integer", "description": "Look-back window in hours (default 24, max 168)"},
        }, ["metric"])),
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


WAZUH_TOOLS = [
    _fn("wazuh_summary",
        "Totals from Wazuh for a period: alerts by level, the top rules, agents and source IPs. Use it for 'what is "
        "Wazuh seeing', 'who is attacking us', 'which machine has the most alerts'.", {
            "hours": {"type": "integer", "description": "Look-back window in hours (default 24, max 720)"},
            "agent": {"type": "string", "description": "Limit to one Wazuh agent name"},
        }),
    _fn("wazuh_agents",
        "Every machine enrolled in Wazuh: name, id, IP, operating system, whether it is active or disconnected and "
        "when it last reported. Use it for 'which agents are offline' and to get exact agent names.", {}),
    _fn("wazuh_configuration_assessment",
        "The Wazuh configuration assessment (SCA / CIS benchmark / hardening / compliance score) of one agent: per "
        "benchmark the score, passed, failed and not-applicable counts and last scan time, plus the checks with "
        "their remediation. This is the ONLY source for it; alert searches do not contain it.", {
            "agent": {"type": "string", "description": "Wazuh agent name, id or IP"},
            "result": {"type": "string", "enum": ["failed", "passed", "not applicable", "all"],
                       "description": "Which checks to list (default failed)"},
            "text": {"type": "string", "description": "Only checks mentioning these words, e.g. ssh, /tmp, password"},
            "limit": {"type": "integer", "description": "Max checks per benchmark (default 25, max 60)"},
            "offset": {"type": "integer", "description": "Skip this many checks, to page through a long list"},
        }, ["agent"]),
    _fn("search_wazuh_alerts",
        "Individual recent alerts straight from Wazuh, newest first, with their log line. Use it when you need the "
        "detail behind a grouped Wazuh event: exact times, users, URLs, log text.", {
            "agent": {"type": "string", "description": "Exact Wazuh agent name"},
            "rule_id": {"type": "string"},
            "source_ip": {"type": "string"},
            "text": {"type": "string", "description": "Words to find in the rule description or the log line"},
            "min_level": {"type": "integer", "description": "Wazuh level 0-15"},
            "hours": {"type": "integer", "description": "Look-back window in hours (default 24)"},
            "limit": {"type": "integer", "description": "Max alerts (default 20, max 30)"},
        }),
]

REPORT_TOOL = _fn(
    "send_report_to_admins",
    "Email a report to the CERBERUS admins. Only call this when the user explicitly asks to send, email or "
    "report something to the admin(s). Recipients are fixed; you cannot choose them.", {
        "subject": {"type": "string", "description": "Short subject line, e.g. 'Server status 13 Oct'"},
        "report": {"type": "string", "description": "The complete report in markdown: the full answer with its "
                                                    "tables and evidence references, not a summary of it"},
    }, ["subject", "report"])


SNORT_TOOL = _fn(
    "snort_alerts",
    "What the Snort network intrusion sensors alerted on in a period: totals by priority, the signatures that fired, the top source and target "
    "addresses, which sensors reported, and the newest individual alerts. Use it for questions about network attacks, scans, intrusion alerts, "
    "a signature, or what an IP address has been doing on the network.", {
        "hours": {"type": "integer", "description": "Look-back window in hours (default 1, max 24)"},
        "priority": {"type": "string", "enum": ["1", "2", "3"], "description": "Only this Snort priority (1 is the most serious)"},
        "text": {"type": "string", "description": "Only alerts mentioning this text: part of a signature name, or an IP address"},
        "limit": {"type": "integer", "description": "How many individual alerts to return (default 15, max 40)"},
    })


LOGINS_TOOL = _fn(
    "get_logins",
    "Who logged in to a server over SSH: the users, the addresses they came from, the method (password or key), how many times and when. "
    "outcome 'success' lists accepted logins, 'failed' lists rejected attempts. This is THE tool for 'who logged in to X', 'successful logins', "
    "'failed logins', 'did anyone log in as root'. One call answers it; do not search events or logs for the same thing.", {
        "host": {"type": "string", "description": "Server name, e.g. sietlms. Leave empty for every server."},
        "outcome": {"type": "string", "enum": ["success", "failed"], "description": "Accepted logins (default) or failed attempts"},
        "user": {"type": "string", "description": "Only this account"},
        "hours": {"type": "integer", "description": "Look-back window in hours (default 24, max 168)"},
    })


OPENAPPSEC_TOOL = _fn(
    "openappsec_events",
    "What the open-appsec web application firewall (WAF) judged in a period: how many requests it blocked or only detected, by severity and "
    "attack type (SQL injection, remote code execution, path traversal, scanning...), the most targeted paths, sources and protected sites, "
    "and the newest individual requests with what matched. Use it for any question about web attacks, the WAF, blocked requests or a URL path.", {
        "hours": {"type": "integer", "description": "Look-back window in hours (default 24, max 720)"},
        "action": {"type": "string", "enum": ["Prevent", "Detect"], "description": "Only blocked (Prevent) or only detected-and-allowed (Detect) requests"},
        "text": {"type": "string", "description": "Only requests mentioning this text: a path, source address, site or attack type"},
        "limit": {"type": "integer", "description": "How many individual requests to return (default 15, max 40)"},
    })


FORECAST_TOOL = _fn(
    "attack_forecast",
    "CERBERUS's early warnings: attacks that are building up toward an intrusion (scanning turning into exploit attempts, password guessing "
    "speeding up against real accounts, a vulnerable internet-facing machine under attack, a surge of hostile traffic, a login after many "
    "failures), each with a likelihood, the stage reached, the evidence, what usually happens next and what to do. Use it for 'is an attack "
    "coming', 'what is likely to be hacked', 'predict', 'early warning' or 'what should I do first'.", {})


PATCH_TOOL = _fn(
    "patch_status",
    "For the vulnerabilities Wazuh found: whether a patch is available (and the fixed version), whether it needs Ubuntu Pro, or has no patch "
    "yet; the fix-by date for each from CERBERUS's deadline policy; what is overdue; and the exact commands to run on each machine (apt, pip, "
    "npm, reboot, removing unused kernels). Use it for 'is there a patch for', 'how do I fix', 'what should I patch first', 'when must this be "
    "fixed', 'what is overdue'.", {
        "machine": {"type": "string", "description": "Only this machine (Wazuh agent name)"},
        "cve": {"type": "string", "description": "Only this CVE, e.g. CVE-2025-49844"},
    })


def _remote_tool(servers: list[dict]) -> dict:
    listing = "; ".join(f"{s['name']} ({s['host']}{', read-only' if not s.get('allow_changes') else ''})" for s in servers)
    return _fn(
        "run_server_command",
        "Run ONE shell command on a registered server over SSH, after an admin approves it. The admin sees the exact command and your reason "
        "and decides; you then get the output. Use read-only commands to investigate (logs, service status, installed versions, open ports) "
        "and change things (updates, restarts, reboot) only when the user asked for a fix. Commands that wipe data, stop security tools, edit "
        "accounts or keys, or are interactive are refused. Servers: " + listing + ".", {
            "server": {"type": "string", "description": "Server name, address or Wazuh agent name"},
            "command": {"type": "string", "description": "One single-line, non-interactive command, e.g. sudo journalctl -u ssh --since '1 hour ago' --no-pager | tail -n 100"},
            "reason": {"type": "string", "description": "One sentence for the approving admin: what this checks or changes, and why"},
        }, ["server", "command", "reason"])


def available_tools(conn) -> list[dict]:
    cfg = get_integration(conn, "grafana")
    extra = [spec for key, spec in GRAFANA_TOOLS if cfg.get("url") and cfg.get(key)]
    if cfg.get("url") and cfg.get("loki_uid"):
        extra.append(LOGINS_TOOL)
        extra.append(SNORT_TOOL)
    if openappsec.is_ready(cfg):
        extra.append(OPENAPPSEC_TOOL)
    if wazuh.is_ready(wazuh.settings(conn)):
        extra += WAZUH_TOOLS
    if mailer.is_configured(mailer.config(conn)) and accounts.admin_emails(conn):
        extra.append(REPORT_TOOL)
    if wazuh.is_ready(wazuh.settings(conn)):
        extra.append(PATCH_TOOL)
    from . import remote
    servers = remote.settings(conn)
    usable = [s for s in servers["servers"] if s.get("enabled", True) and s.get("host_key")]
    if servers["enabled"] and usable:
        extra.append(_remote_tool(usable))
    return BASE_TOOLS + extra + [FORECAST_TOOL]


def _patch_status(conn, args, actor):
    from . import patches
    return patches.summary_for_ai(conn, str(args.get("machine") or "")[:80], str(args.get("cve") or "")[:30])


def _forecast(conn, args, actor):
    from . import predict
    s = predict.status(conn)
    return {"last_check": s["last_run"], "result": s["last_result"], "alert_threshold": s["settings"]["alert_min"],
            "warnings": [{k: f.get(k) for k in ("likelihood", "title", "stage", "target", "attackers", "evidence", "next", "action", "first_seen")} for f in predict.active(conn, 12)]}


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


def _wazuh_summary(conn, a, actor):
    return wazuh.summary(wazuh.settings(conn), hours=a.get("hours", 24), agent=a.get("agent", ""))


def _local_times(rows: list[dict], keys: tuple, tz_minutes) -> None:
    """Rewrite Wazuh's UTC timestamps in the user's own time, as the Wazuh dashboard shows them."""
    tz = store.clamp(tz_minutes, -720, 840, 0)
    for row in rows:
        for key in keys:
            try:
                stamp = datetime.fromisoformat(str(row[key]).replace("Z", "+00:00")) + timedelta(minutes=tz)
                row[key] = f"{stamp:%Y-%m-%d %H:%M:%S} {grafana.tz_label(tz)}"
            except (KeyError, ValueError):
                pass


def _snort_alerts(conn, a, actor):
    return snort.summary(get_integration(conn, "grafana"), hours=a.get("hours", 1), priority=str(a.get("priority", "")), text=a.get("text", ""), limit=a.get("limit", 15))


def _get_logins(conn, a, actor):
    return grafana.logins(get_integration(conn, "grafana"), host=a.get("host", ""), outcome=a.get("outcome", "success"), user=a.get("user", ""),
                          hours=store.clamp(a.get("hours"), 1, 168, 24), tz_minutes=store.clamp(a.get("_tz"), -720, 840, 0))


def _openappsec_events(conn, a, actor):
    return openappsec.summary(get_integration(conn, "grafana"), hours=a.get("hours", 24), action=a.get("action", ""),
                              text=a.get("text", ""), limit=a.get("limit", 15), recorded=openappsec.inventory(conn))


def _wazuh_agents(conn, a, actor):
    result = wazuh.agents(wazuh.settings(conn))
    _local_times(result["agents"], ("last_seen",), a.get("_tz"))
    return result


def _wazuh_sca(conn, a, actor):
    result = wazuh.configuration_assessment(wazuh.settings(conn), agent=a.get("agent", ""), result=a.get("result", "failed"),
                                            text=a.get("text", ""), limit=a.get("limit", 25), offset=a.get("offset", 0))
    _local_times([result["agent"]], ("last_seen",), a.get("_tz"))
    _local_times(result["policies"], ("last_scan",), a.get("_tz"))
    return result


def _wazuh_search(conn, a, actor):
    return wazuh.search_alerts(wazuh.settings(conn), agent=a.get("agent", ""), rule_id=a.get("rule_id", ""),
                               source_ip=a.get("source_ip", ""), text=a.get("text", ""), min_level=a.get("min_level", 1),
                               hours=a.get("hours", 24), limit=a.get("limit", 20))


def _metric_history(conn, a, actor):
    return grafana.metric_history(get_integration(conn, "grafana"), str(a.get("metric", "")), str(a.get("host", "")),
                                  a.get("hours", 24), store.clamp(a.get("_tz"), -720, 840, 0))


def _query_loki(conn, a, actor):
    return grafana.query_loki(get_integration(conn, "grafana"), a.get("logql", ""),
                              a.get("minutes", 60), a.get("limit", 30))


HANDLERS = {
    "attack_forecast": _forecast, "patch_status": _patch_status,
    "run_server_command": lambda conn, a, actor: {"error": "Commands can only be run from the live chat, where an admin can approve each one."},
    "search_events": _search_events, "list_incidents": _list_incidents, "get_incident": _get_incident,
    "list_assets": _list_assets, "propose_response_action": _propose,
    "send_report_to_admins": _send_report, "wazuh_summary": _wazuh_summary, "search_wazuh_alerts": _wazuh_search,
    "snort_alerts": _snort_alerts, "get_logins": _get_logins, "openappsec_events": _openappsec_events, "wazuh_agents": _wazuh_agents, "wazuh_configuration_assessment": _wazuh_sca,
    "get_server_health": _server_health, "get_metric_history": _metric_history, "query_prometheus": _query_prometheus, "query_loki": _query_loki,
}


def execute(conn, name: str, args, actor: str, tz_minutes: int = 0) -> str:
    """Run one tool call and return a size-capped JSON string for the model."""
    allowed = {t["function"]["name"] for t in available_tools(conn)}
    if not isinstance(args, dict):
        args = {}
    if name not in allowed:
        result = {"error": f"unknown or unavailable tool '{name}'"}
    else:
        try:
            # The user's timezone travels beside the model's arguments so tools can return local times.
            result = HANDLERS[name](conn, {**args, "_tz": tz_minutes}, actor)
        except (grafana.GrafanaError, wazuh.WazuhError) as exc:
            result = {"error": str(exc)}
    # Report bodies can be long; the audit entry records that it was sent, not the whole text.
    logged = {k: (v if k != "report" else f"<{len(str(v))} characters>") for k, v in args.items()}
    audit(conn, f"ai (asked by {actor})", "ai.tool_call",
          {"tool": name, "arguments": logged, "error": result.get("error")})
    out = json.dumps(result, default=str)
    if len(out) > MAX_RESULT_CHARS:
        out = out[:MAX_RESULT_CHARS] + '... [truncated: narrow the query]'
    return out
