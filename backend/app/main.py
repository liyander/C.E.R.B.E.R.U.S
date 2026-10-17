"""CERBERUS API + static web UI."""
import hmac
import queue
import threading
import json
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import accounts, ai, alerting, apps, auth, dashboard, demo, detections, grafana, insights, intel, incident_ops, openappsec, patches, predict, remote, reports, response, triage, mailer, store, tools, watch, wazuh
from .db import DATA_DIR, ROOT, audit, db, get_integration, get_setting, init_db, now, set_integration, set_setting
from .secrets_store import decrypt, encrypt

WEB_DIR = ROOT / "web"
VERSION = "0.2.0"
UPSTREAM_FAILED = 424


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with db() as conn:
        if not get_setting(conn, "ingest_token"):
            set_setting(conn, "ingest_token", secrets.token_urlsafe(32))
    watch.start()
    yield


app = FastAPI(title="CERBERUS", version=VERSION, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(accounts.router)
User = Depends(auth.current_user)
Admin = Depends(auth.require_admin)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response



class ProviderBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: str = Field(max_length=30)
    base_url: str = Field(min_length=8, max_length=300, pattern=r"^https?://")
    api_key: str = Field(default="", max_length=500)
    model: str = Field(default="", max_length=200)


class ModelsPreviewBody(BaseModel):
    base_url: str = Field(min_length=8, max_length=300, pattern=r"^https?://")
    api_key: str = Field(default="", max_length=500)
    provider_id: int | None = None


class ChatBody(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    conversation_id: int | None = None
    tz_offset: int = Field(default=0, ge=-720, le=840)


class BriefBody(BaseModel):
    kind: str = Field(pattern=r"^(logs|log_line|infrastructure|overview|app_page|app_row|incidents|incident|events|assets|approvals|audit|insight)$")
    app: str = Field(default="", max_length=40)
    page: str = Field(default="", max_length=120)
    params: dict[str, str] = Field(default_factory=dict)
    item_id: int = Field(default=0, ge=0)
    title: str = Field(default="", max_length=200)
    source: str = Field(default="", max_length=80)
    min_severity: int = Field(default=1, ge=1, le=10)
    status: str = Field(default="active", max_length=30)
    query: str = Field(default="", max_length=1000)
    minutes: int = Field(default=15, ge=5, le=1440)
    start: str = Field(default="", max_length=40)
    end: str = Field(default="", max_length=40)
    line: str = Field(default="", max_length=4000)
    labels: dict[str, str] = Field(default_factory=dict)
    tz_offset: int = Field(default=0, ge=-720, le=840)


class WatchBody(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=1, le=120)
    tz_offset: int | None = Field(default=None, ge=-720, le=840)
    checks: dict[str, bool] | None = None
    disk_pct: int | None = Field(default=None, ge=50, le=100)
    memory_pct: int | None = Field(default=None, ge=50, le=100)
    cpu_pct: int | None = Field(default=None, ge=50, le=100)
    load_factor: float | None = Field(default=None, ge=0.1, le=10)
    log_errors_5m: int | None = Field(default=None, ge=1, le=1000000)
    notify_in_app: bool | None = None
    notify_email: bool | None = None
    email_min_severity: int | None = Field(default=None, ge=1, le=10)
    renotify_hours: int | None = Field(default=None, ge=1, le=168)
    ai_writeup: bool | None = None
    digest_enabled: bool | None = None
    digest_hour: int | None = Field(default=None, ge=0, le=23)


class WazuhBody(BaseModel):
    enabled: bool = False
    url: str = Field(default="", max_length=300, pattern=r"^(https?://[^\s]+)?$")
    username: str = Field(default="", max_length=120)
    password: str = Field(default="", max_length=300)
    verify_tls: bool = True
    min_level: int = Field(default=7, ge=0, le=15)
    exclude_rules: str = Field(default="", max_length=500, pattern=r"^[0-9,; ]*$")
    poll_minutes: int = Field(default=2, ge=1, le=60)


class OpenAppsecBody(BaseModel):
    assets: str = Field(default="", max_length=20000)
    agents: str = Field(default="", max_length=20000)


class FindingBody(BaseModel):
    key: str = Field(min_length=1, max_length=300)
    dismissed: bool = True


class WatchRunBody(BaseModel):
    tz_offset: int = Field(default=0, ge=-720, le=840)


class ContextBody(BaseModel):
    labels: dict[str, str]
    ns: str = Field(pattern=r"^\d{10,20}$")


class RenameBody(BaseModel):
    title: str = Field(min_length=1, max_length=120)


class ReportBody(BaseModel):
    conversation_id: int
    index: int = Field(ge=0)


class GrafanaBody(BaseModel):
    url: str = Field(default="", max_length=300, pattern=r"^(https?://.+)?$")
    token: str = Field(default="", max_length=500)
    verify_tls: bool = True
    prometheus_uid: str = Field(default="", max_length=80, pattern=r"^[A-Za-z0-9_-]*$")
    loki_uid: str = Field(default="", max_length=80, pattern=r"^[A-Za-z0-9_-]*$")


class DecisionBody(BaseModel):
    decision: str = Field(pattern=r"^(approved|denied)$")
    note: str = Field(default="", max_length=1000)


class IncidentPatch(BaseModel):
    status: str
    reason: str = Field(default="", max_length=500)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": VERSION, "time": now()}



@app.get("/api/v1/overview")
def overview(user=User):
    with db() as conn:
        store.expire_approvals(conn)
        one = lambda sql, *p: conn.execute(sql, p).fetchone()[0]
        active = "status IN ('open', 'investigating')"
        grafana_cfg = get_integration(conn, "grafana")
        provider = ai.active_provider(conn)
        return {
            "assets": one("SELECT COUNT(*) FROM assets"),
            "open_incidents": one(f"SELECT COUNT(*) FROM incidents WHERE {active}"),
            "critical": one(f"SELECT COUNT(*) FROM incidents WHERE {active} AND severity >= 9"),
            "high": one(f"SELECT COUNT(*) FROM incidents WHERE {active} AND severity BETWEEN 7 AND 8"),
            "pending_approvals": one("SELECT (SELECT COUNT(*) FROM approvals WHERE status = 'pending') + (SELECT COUNT(*) FROM server_commands WHERE status = 'pending' AND expires_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"),
            "medium": one(f"SELECT COUNT(*) FROM incidents WHERE {active} AND severity BETWEEN 4 AND 6"),
            "low": one(f"SELECT COUNT(*) FROM incidents WHERE {active} AND severity < 4"),
            "events_24h": one("SELECT COUNT(*) FROM events WHERE ts >= ?", store.ago(hours=24)),
            "hourly": store.event_stats(conn, hours=24)["hourly"],
            "loki_configured": bool(grafana_cfg.get("url") and grafana_cfg.get("loki_uid")),
            "metrics_configured": bool(grafana_cfg.get("url") and grafana_cfg.get("prometheus_uid")),
            "top_assets": [dict(r) for r in conn.execute(
                "SELECT a.name, COUNT(*) AS events FROM events e JOIN assets a ON a.id = e.asset_id "
                "WHERE e.ts >= ? GROUP BY a.id ORDER BY events DESC, a.name LIMIT 5", (store.ago(hours=24),))],
            "sources": [dict(r) for r in conn.execute(
                "SELECT source, COUNT(*) AS events, MAX(ts) AS last_seen FROM events GROUP BY source "
                "ORDER BY events DESC")],
            "recent_incidents": store.query_incidents(conn, status="active", limit=6),
            "ai_tools": [t["function"]["name"] for t in tools.available_tools(conn)],
            "ai_provider": {"name": provider["name"], "model": provider["model"]} if provider else None,
            "grafana_configured": bool(grafana_cfg.get("url")),
            "has_demo_data": bool(one("SELECT COUNT(*) FROM events WHERE demo = 1")),
            "watch": {"enabled": watch.settings(conn)["enabled"], "last_run": get_setting(conn, "watch_last_run"),
                      "firing": one("SELECT COUNT(*) FROM watch_findings WHERE status = 'firing'")},
            "email_configured": mailer.is_configured(mailer.config(conn)),
            "unread_notifications": accounts.unread_count(conn, user),
            "version": VERSION,
        }


@app.get("/api/v1/events")
def list_events(q: str = "", source: str = "", min_severity: int = 1, asset_id: int | None = None,
                start: str = "", end: str = "", limit: int = 200, user=User):
    with db() as conn:
        return store.query_events(conn, q=q, source=source, min_severity=min_severity,
                                  asset_id=asset_id, start=start, end=end, limit=limit)


@app.get("/api/v1/events/stats")
def events_stats(hours: int = 24, q: str = "", source: str = "", min_severity: int = 1, user=User):
    with db() as conn:
        return store.event_stats(conn, hours=hours, q=q, source=source, min_severity=min_severity)


@app.get("/api/v1/logs")
def logs_explore(query: str = "", minutes: int = 60, limit: int = 200, start: str = "", end: str = "", user=User):
    """Read-only log search through Grafana's Loki datasource."""
    with db() as conn:
        cfg = get_integration(conn, "grafana")
        audit(conn, user["username"], "logs.query", {"query": query[:300], "minutes": minutes, "start": start, "end": end})
    try:
        result = grafana.loki_explore(cfg, query, minutes, limit, start, end)
    except grafana.GrafanaError as exc:
        raise HTTPException(UPSTREAM_FAILED, str(exc))
    result["patterns"] = grafana.log_patterns(result["lines"])
    return result


@app.post("/api/v1/logs/context")
def logs_context(body: ContextBody, user=User):
    """The lines just before and after one log line, from the same stream."""
    with db() as conn:
        cfg = get_integration(conn, "grafana")
    try:
        return grafana.loki_context(cfg, body.labels, body.ns)
    except grafana.GrafanaError as exc:
        raise HTTPException(UPSTREAM_FAILED, str(exc))



@app.get("/api/v1/integrations/wazuh")
def wazuh_get(user=Admin):
    with db() as conn:
        return wazuh.status(conn)


@app.put("/api/v1/integrations/wazuh")
def wazuh_save(body: WazuhBody, user=Admin):
    with db() as conn:
        current = wazuh.settings(conn)
        cfg = body.model_dump()
        cfg["url"] = cfg["url"].rstrip("/")
        if not cfg["password"] and (cfg["url"], cfg["username"]) == (current["url"], current["username"]):
            cfg["password"] = current["password"]
        cfg["mode"] = current["mode"] if cfg["url"] == current["url"] else ""
        set_integration(conn, "wazuh", cfg)
        audit(conn, user["username"], "integration.wazuh_saved", {"url": cfg["url"], "enabled": cfg["enabled"], "min_level": cfg["min_level"]})
    return {"ok": True}


@app.post("/api/v1/integrations/wazuh/test")
def wazuh_test(user=Admin):
    """Sign in to Wazuh and report what it holds; remembers whether the address is a dashboard or an indexer."""
    with db() as conn:
        cfg = wazuh.settings(conn)
        try:
            result = wazuh.test(cfg)
        except wazuh.WazuhError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))
        set_integration(conn, "wazuh", {**cfg, "mode": result["mode"]})
    return result


@app.get("/api/v1/integrations/openappsec")
def openappsec_get(user=Admin):
    """What an admin recorded from the open-appsec portal, plus the agent IDs seen live so they can be copied in."""
    with db() as conn:
        recorded, cfg = openappsec.inventory(conn), get_integration(conn, "grafana")
    seen = []
    if openappsec.is_ready(cfg):
        try:
            seen = [{"id": agent_id, "server": a["host"]} for agent_id, a in openappsec.live_agents(cfg).items()]
        except grafana.GrafanaError:
            pass
    return {"assets": openappsec.format_lines(recorded["assets"], openappsec.ASSET_FIELDS),
            "agents": openappsec.format_lines(recorded["agents"], openappsec.AGENT_FIELDS), "ready": openappsec.is_ready(cfg), "seen_agents": seen}


@app.put("/api/v1/integrations/openappsec")
def openappsec_save(body: OpenAppsecBody, user=Admin):
    assets = openappsec.parse_lines(body.assets, openappsec.ASSET_FIELDS)
    agents = openappsec.parse_lines(body.agents, openappsec.AGENT_FIELDS)
    with db() as conn:
        set_integration(conn, "openappsec", {"assets": assets, "agents": agents})
        audit(conn, user["username"], "integration.openappsec_saved", {"assets": len(assets), "agents": len(agents)})
    return {"assets": len(assets), "agents": len(agents)}


@app.post("/api/v1/integrations/wazuh/sync")
def wazuh_sync(user=Admin):
    return wazuh.sync("manual")



@app.get("/api/v1/watch")
def watch_status(user=User):
    with db() as conn:
        return watch.status(conn)


@app.put("/api/v1/watch")
def watch_save(body: WatchBody, user=Admin):
    changes = body.model_dump(exclude_none=True)
    with db() as conn:
        saved = watch.save_settings(conn, changes)
        audit(conn, user["username"], "watch.settings", {k: v for k, v in changes.items() if k != "tz_offset"})
    return {"ok": True, "settings": saved}


@app.post("/api/v1/watch/run")
def watch_run(body: WatchRunBody, user=Admin):
    """Run one check now, whether or not the schedule is on."""
    return watch.run("manual", body.tz_offset)


@app.post("/api/v1/watch/findings")
def watch_finding(body: FindingBody, user=User):
    """Dismiss a finding you have seen and accept for now, or restore it. Any signed-in user may triage."""
    with db() as conn:
        changed = watch.set_dismissed(conn, body.key, body.dismissed, user["username"])
    if not changed:
        raise HTTPException(404, "That finding has already changed")
    return {"ok": True, "changed": changed}


@app.post("/api/v1/watch/digest")
def watch_digest(user=Admin):
    """Send today's digest now, to see what it looks like."""
    with db() as conn:
        if not watch.send_digest(conn, watch.settings(conn)):
            raise HTTPException(409, "The digest could not be sent. Check that email is set up and an admin has a verified address.")
    return {"ok": True}


@app.get("/api/v1/ai/sources")
def ai_sources(user=User):
    """The systems that can be tagged with @ in the chat."""
    with db() as conn:
        return ai.sources(conn)


@app.post("/api/v1/ai/brief")
def ai_brief(body: BriefBody, user=User):
    """A short AI-written briefing. The server collects the data itself; the model gets no tools."""
    tz = grafana.tz_label(body.tz_offset)
    with db() as conn:
        provider = _require_provider(conn)
        cfg = get_integration(conn, "grafana")
        audit(conn, user["username"], "ai.brief", {"kind": body.kind, "query": body.query[:300]})
        try:
            task = {"app_page": "page", "app_row": "item"}.get(body.kind, body.kind)
            if body.kind == "log_line":
                data = json.dumps({"labels": body.labels, "line": body.line})
            elif body.kind == "app_page":
                try:
                    data = json.dumps(apps.digest(apps.render(conn, body.app, body.page, body.params)), default=str)
                except KeyError:
                    raise HTTPException(404, "That page does not exist")
                except apps.NotConnected as exc:
                    raise HTTPException(409, f"{exc} is not connected")
                except apps.errors() as exc:
                    raise HTTPException(UPSTREAM_FAILED, str(exc))
            elif body.kind == "insight":
                view = insights.PAGES.get(body.page)
                if not view or (body.page == "ai-usage" and user["role"] != "admin"):
                    raise HTTPException(404, "That page does not exist")
                data = json.dumps(apps.digest(view(conn, body.params)), default=str)
                task = "ip" if body.page == "ip" and body.params.get("ip") else "forecast" if body.page == "forecast" else "page"
            elif body.kind == "app_row":
                data = json.dumps({"from_page": body.title, "item": body.line})
            elif body.kind == "incidents":
                status = body.status if body.status in ("active", "resolved", "false_positive") else ""
                data = json.dumps({"showing": status or "all", "incidents": store.query_incidents(conn, status=status, limit=25)}, default=str)
            elif body.kind == "incident":
                incident = store.get_incident(conn, body.item_id)
                if not incident:
                    raise HTTPException(404, "Incident not found")
                data = json.dumps(incident, default=str)
            elif body.kind == "events":
                data = json.dumps({"filters": {"search": body.query, "source": body.source, "min_severity": body.min_severity},
                                   "last_24h": {k: v for k, v in store.event_stats(conn, hours=24, q=body.query, source=body.source, min_severity=body.min_severity).items() if k != "hourly"},
                                   "newest_events": store.query_events(conn, q=body.query, source=body.source, min_severity=body.min_severity, limit=50)}, default=str)
            elif body.kind == "assets":
                data = json.dumps(list_assets(user)[:60], default=str)
            elif body.kind == "approvals":
                data = json.dumps([a for a in list_approvals(user) if a.get("status") == "pending"][:20] or "There are no pending approvals.", default=str)
            elif body.kind == "audit":
                if user["role"] != "admin":
                    raise HTTPException(403, "Only admins can read the audit log")
                rows = conn.execute("SELECT ts, actor, action, detail FROM audit_logs ORDER BY id DESC LIMIT 120").fetchall()
                data = json.dumps([{**dict(r), "detail": str(r["detail"] or "")[:160]} for r in rows], default=str)
            elif body.kind == "logs":
                found = grafana.loki_explore(cfg, body.query, body.minutes, 200, body.start, body.end)
                levels = {k: sum(v[k] for v in found["volume"]) for k in grafana.LOG_LEVELS}
                data = json.dumps({"query": found["query"], "window_minutes": found["minutes"], "total_lines": found["total"],
                                   "lines_by_level": levels, "common_patterns_in_newest_lines": grafana.log_patterns(found["lines"], 20),
                                   "newest_lines": [{"time": l["ts"], "host": l["labels"].get("host"),
                                                     "program": l["labels"].get("program"), "line": l["line"][:300]}
                                                    for l in found["lines"][:40]]})
            elif body.kind == "infrastructure":
                data = json.dumps(grafana.server_health(cfg))
            else:
                snapshot = {"active_incidents": store.query_incidents(conn, status="active", limit=12),
                            "events_last_24h": {k: v for k, v in store.event_stats(conn, hours=24).items() if k != "hourly"}}
                try:
                    snapshot["infrastructure"] = grafana.server_health(cfg)
                except grafana.GrafanaError:
                    snapshot["infrastructure"] = "not connected"
                data = json.dumps(snapshot, default=str)
            with ai.usage("brief", user["username"]):
                return {"text": ai.brief(provider, task, data, tz), "model": provider["model"]}
        except grafana.GrafanaError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))
        except ai.AIError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))


@app.get("/api/v1/logs/labels")
def logs_labels(user=User):
    """Values for the log filter pickers. A label that Loki does not have simply comes back empty."""
    with db() as conn:
        cfg = get_integration(conn, "grafana")
    out = {}
    for name in ("job", "host", "program"):
        try:
            out[name] = grafana.loki_label_values(cfg, name)
        except grafana.GrafanaError as exc:
            if name == "job":
                raise HTTPException(UPSTREAM_FAILED, str(exc))
            out[name] = []
    return out


class DetectionsBody(BaseModel):
    enabled: bool = True
    snort: bool = True
    snort_priority: int = Field(default=1, ge=1, le=3)
    waf: bool = True
    waf_mode: str = Field(default="detected", pattern=r"^(detected|critical|all)$")
    multi_source: bool = True
    multi_min: int = Field(default=2, ge=2, le=4)
    interval_minutes: int = Field(default=5, ge=1, le=60)


class ForecastBody(BaseModel):
    enabled: bool = True
    interval_minutes: int = Field(default=10, ge=5, le=60)
    alert_min: int = Field(default=70, ge=40, le=95)
    notify_in_app: bool = True
    email: bool = True
    incident: bool = True
    ai: bool = True


class ServerBody(BaseModel):
    id: str = Field(default="", max_length=20)
    name: str = Field(min_length=1, max_length=60)
    host: str = Field(min_length=1, max_length=200)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=60)
    auth: str = Field(default="key", pattern=r"^(key|password)$")
    password: str = Field(default="", max_length=200)
    sudo_password: str = Field(default="", max_length=200)
    clear_sudo_password: bool = False
    agent: str = Field(default="", max_length=120)
    allow_changes: bool = False
    enabled: bool = True


class CommandDecisionBody(BaseModel):
    decision: str = Field(pattern=r"^(approved|denied)$")
    note: str = Field(default="", max_length=500)


class PlanCommandsBody(BaseModel):
    agent: str = Field(min_length=1, max_length=120)


class ReportSettingsBody(BaseModel):
    enabled: bool = False
    frequency: str = Field(default="weekly", pattern=r"^(daily|weekly)$")
    weekday: int = Field(default=0, ge=0, le=6)
    hour: int = Field(default=8, ge=0, le=23)
    send_to_admins: bool = True
    extra_recipients: str = Field(default="", max_length=1000)
    ai_summary: bool = True


class ReportRunBody(BaseModel):
    days: int = Field(default=7, ge=1, le=31)


@app.get("/api/v1/insights/{name}")
def insight_page(name: str, request: Request, user=User):
    """Cross-source views: one IP, asset risk, vulnerability priority and (admins) AI usage."""
    view = insights.PAGES.get(name)
    if not view or (name == "ai-usage" and user["role"] != "admin"):
        raise HTTPException(404, "That page does not exist")
    with db() as conn:
        return view(conn, {k: str(v)[:200] for k, v in request.query_params.items()})


@app.get("/api/v1/intel/{ip}")
def intel_lookup(ip: str, refresh: bool = False, user=User):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Not an IP address")
    with db() as conn:
        if not intel.enabled(conn):
            raise HTTPException(400, "No threat-intel source is enabled (Integrations).")
        return intel.lookup(conn, ip, force=refresh)


@app.get("/api/v1/integrations/intel")
def intel_settings(user=Admin):
    with db() as conn:
        return intel.public_view(conn)


@app.put("/api/v1/integrations/intel")
def intel_settings_save(body: dict = Body(...), user=Admin):
    with db() as conn:
        saved = intel.save_settings(conn, body, user["username"])
        audit(conn, user["username"], "integration.intel", {"greynoise": saved["greynoise_enabled"], "abuseipdb": saved["abuseipdb_enabled"]})
        return saved


@app.get("/api/v1/integrations/detections")
def detections_get(user=Admin):
    with db() as conn:
        return detections.status(conn)


@app.put("/api/v1/integrations/detections")
def detections_save(body: DetectionsBody, user=Admin):
    with db() as conn:
        saved = detections.save_settings(conn, body.model_dump())
        audit(conn, user["username"], "integration.detections_saved", saved)
        return detections.status(conn)


@app.post("/api/v1/integrations/detections/run")
def detections_run(user=Admin):
    return detections.run("manual")


@app.get("/api/v1/integrations/forecast")
def forecast_get(user=Admin):
    with db() as conn:
        return predict.status(conn)


@app.put("/api/v1/integrations/forecast")
def forecast_save(body: ForecastBody, user=Admin):
    with db() as conn:
        saved = predict.save_settings(conn, body.model_dump())
        audit(conn, user["username"], "integration.forecast_saved", saved)
        return predict.status(conn)


@app.post("/api/v1/forecast/run")
def forecast_run(user=Admin):
    result = predict.run("manual")
    with db() as conn:
        audit(conn, user["username"], "forecast.run", {k: result.get(k) for k in ("warnings", "alerted")})
    return result


@app.get("/api/v1/dashboard")
def dashboard_view(user=User):
    with db() as conn:
        return dashboard.vitals(conn)


@app.get("/api/v1/alert-rules")
def alert_rules(user=Admin):
    with db() as conn:
        return alerting.page(conn)


@app.post("/api/v1/alert-rules")
def alert_rule_save(body: dict = Body(...), user=Admin):
    with db() as conn:
        try:
            rule = alerting.save(conn, body, user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        fired = alerting.evaluate(conn, only=rule["id"]) if rule["enabled"] else []
        return {"rule": rule, "fired": fired}


@app.delete("/api/v1/alert-rules/{rule_id}")
def alert_rule_delete(rule_id: str, user=Admin):
    with db() as conn:
        alerting.delete(conn, rule_id, user["username"])
        return {"ok": True}


@app.post("/api/v1/alert-rules/{rule_id}/test")
def alert_rule_test(rule_id: str, user=Admin):
    with db() as conn:
        try:
            return alerting.test(conn, rule_id, user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except mailer.MailError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))


@app.get("/api/v1/servers")
def servers_get(user=Admin):
    with db() as conn:
        return {**remote.public_view(conn), "commands": remote.history(conn, 80)}


@app.get("/api/v1/servers/agents")
def servers_agents(user=Admin):
    """Wazuh agents, so a server can be linked to its patch plan. Empty when Wazuh is not connected."""
    with db() as conn:
        w = wazuh.settings(conn)
    if not wazuh.is_ready(w):
        return []
    try:
        rows = insights._cached(("server-agents",), 300, lambda: wazuh.agents(w)["agents"])
    except Exception:
        return []
    return [{k: a.get(k, "") for k in ("name", "ip", "os", "status")} for a in rows if a.get("id") != "000"]


@app.put("/api/v1/servers/settings")
def servers_toggle(body: dict = Body(...), user=Admin):
    with db() as conn:
        remote.set_enabled(conn, bool(body.get("enabled")), user["username"])
        return remote.public_view(conn)


@app.post("/api/v1/servers")
def servers_save(body: ServerBody, user=Admin):
    with db() as conn:
        try:
            saved = remote.save_server(conn, body.model_dump(), user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"id": saved["id"], "name": saved["name"]}


@app.delete("/api/v1/servers/{server_id}")
def servers_delete(server_id: str, user=Admin):
    with db() as conn:
        remote.delete_server(conn, server_id, user["username"])
        return {"ok": True}


@app.post("/api/v1/servers/{server_id}/test")
def servers_test(server_id: str, user=Admin):
    with db() as conn:
        try:
            return remote.test(conn, server_id, user["username"])
        except remote.RemoteError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))


@app.get("/api/v1/commands")
def commands_list(status: str = "", user=Admin):
    with db() as conn:
        return remote.history(conn, 100, status if status in ("pending", "approved", "running", "done", "failed", "denied", "expired") else "")


@app.post("/api/v1/commands/{command_id}/decision")
def commands_decide(command_id: int, body: CommandDecisionBody, user=Admin):
    with db() as conn:
        try:
            return remote.decide(conn, command_id, body.decision, body.note, user["username"])
        except remote.RemoteError as exc:
            raise HTTPException(409, str(exc))


@app.post("/api/v1/commands/plan")
def commands_from_plan(body: PlanCommandsBody, user=Admin):
    """Queue a machine's patch plan as separate commands, each waiting for its own approval."""
    with db() as conn:
        commands = patches.runnable(conn, body.agent)
        if not commands:
            raise HTTPException(400, f"Nothing to patch on {body.agent}, or patch availability is still being checked.")
        try:
            made = remote.propose_plan(conn, body.agent, commands, f"Patch plan for {body.agent}", user["username"])
        except remote.RemoteError as exc:
            raise HTTPException(400, str(exc))
        errors = [m["error"] for m in made if "error" in m]
        if errors and len(errors) == len(made):
            raise HTTPException(400, errors[0])
        return {"queued": [m for m in made if "id" in m], "errors": errors}


@app.get("/api/v1/reports")
def reports_get(user=Admin):
    with db() as conn:
        return reports.status(conn)


@app.put("/api/v1/reports")
def reports_save(body: ReportSettingsBody, user=Admin):
    with db() as conn:
        try:
            reports.save_settings(conn, body.model_dump())
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        audit(conn, user["username"], "reports.settings_saved", body.model_dump())
        return reports.status(conn)


@app.post("/api/v1/reports/preview")
def reports_preview(body: ReportRunBody, user=Admin):
    with db() as conn:
        markdown, _ = reports.build_markdown(conn, body.days, reports.settings(conn)["ai_summary"])
        return {"markdown": markdown}


@app.post("/api/v1/reports/send")
def reports_send(body: ReportRunBody, user=Admin):
    with db() as conn:
        try:
            result = reports.send(conn, user["username"], body.days)
        except mailer.MailError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))
        audit(conn, user["username"], "reports.sent", {"days": body.days, "to": result["sent_to"]})
        return result


@app.get("/api/v1/apps")
def apps_catalog(user=User):
    """The applications in the navbar switcher, each with its own menu."""
    with db() as conn:
        return apps.catalog(conn)


@app.get("/api/v1/apps/{app_id}/{page_id}")
def apps_page(app_id: str, page_id: str, request: Request, user=User):
    """One read-only page of a connected application, described as tiles, bars and tables."""
    with db() as conn:
        try:
            return apps.render(conn, app_id, page_id, dict(request.query_params))
        except KeyError:
            raise HTTPException(404, "That page does not exist")
        except apps.NotConnected as exc:
            return {"app": app_id, "page": page_id, "connected": False, "app_name": str(exc)}
        except apps.errors() as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))


@app.get("/api/v1/infrastructure")
def infrastructure(user=User):
    """Live server health from Prometheus: targets, per-host resource use and HTTP probes."""
    with db() as conn:
        cfg = get_integration(conn, "grafana")
    try:
        return grafana.server_health(cfg)
    except grafana.GrafanaError as exc:
        raise HTTPException(UPSTREAM_FAILED, str(exc))


@app.get("/api/v1/incidents")
def list_incidents(status: str = "", user=User):
    with db() as conn:
        return store.query_incidents(conn, status=status, limit=200)


@app.get("/api/v1/incidents/queue")
def incident_queue(status: str = "active", assignee: str = "", verdict: str = "", user=User):
    with db() as conn:
        incidents = store.query_queue(conn, status=status, assignee=assignee, verdict=verdict)
        stats = store.triage_stats(conn)
        if stats["open"] and incidents and max((i["priority"] for i in incidents), default=0) == 0:
            triage.kick_rescore()
        return {"incidents": incidents, "stats": stats, "settings": triage.settings(conn),
                "team": [r["username"] for r in conn.execute("SELECT username FROM users WHERE disabled = 0 ORDER BY username")]}


@app.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: int, user=User):
    with db() as conn:
        store.expire_approvals(conn)
        inc = store.get_incident(conn, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


@app.post("/api/v1/incidents/{incident_id}/merge")
def incident_merge(incident_id: int, body: dict = Body(...), user=User):
    try:
        with db() as conn:
            return incident_ops.merge(conn, incident_id, int(body.get("source_id", 0)), user["username"])
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/v1/incidents/{incident_id}/split")
def incident_split(incident_id: int, body: dict = Body(...), user=User):
    ids = body.get("event_ids")
    if not isinstance(ids, list) or any(type(i) is not int or i <= 0 for i in ids):
        raise HTTPException(400, "event_ids must be a list of positive event IDs")
    try:
        with db() as conn:
            return incident_ops.split(conn, incident_id, ids, user["username"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.patch("/api/v1/incidents/{incident_id}")
def incident_update(incident_id: int, body: IncidentPatch, user=User):
    with db() as conn:
        try:
            return triage.set_status(conn, incident_id, body.status, getattr(body, "reason", "") or "", user["username"])
        except ValueError as exc:
            raise HTTPException(404 if "No such" in str(exc) else 422, str(exc))


@app.post("/api/v1/incidents/{incident_id}/assign")
def incident_assign(incident_id: int, body: dict = Body(...), user=User):
    with db() as conn:
        try:
            return triage.assign(conn, incident_id, body.get("assignee", ""), user["username"])
        except ValueError as exc:
            raise HTTPException(404 if "No such incident" in str(exc) else 400, str(exc))


@app.post("/api/v1/incidents/{incident_id}/note")
def incident_note(incident_id: int, body: dict = Body(...), user=User):
    with db() as conn:
        try:
            return triage.add_note(conn, incident_id, user["username"], body.get("body", ""))
        except ValueError as exc:
            raise HTTPException(400, str(exc))


@app.get("/api/v1/incidents/{incident_id}/response")
def incident_response(incident_id: int, user=User):
    with db() as conn:
        inc = store.get_incident(conn, incident_id)
        if not inc:
            raise HTTPException(404, "Incident not found")
        return {"available": response.available(conn, inc), "playbook": response.playbook_for(inc),
                "commands": response.incident_commands(conn, incident_id)}


@app.post("/api/v1/incidents/{incident_id}/respond")
def incident_respond(incident_id: int, body: dict = Body(...), user=User):
    with db() as conn:
        try:
            return response.run_action(conn, incident_id, str(body.get("action", "")), str(body.get("server", "")), user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))


@app.post("/api/v1/incidents/{incident_id}/playbook")
def incident_playbook_step(incident_id: int, body: dict = Body(...), user=User):
    """Propose one playbook step: a read-only check, or an action, for approval."""
    with db() as conn:
        inc = store.get_incident(conn, incident_id)
        if not inc:
            raise HTTPException(404, "Incident not found")
        pb = response.playbook_for(inc)
        try:
            step = pb["steps"][int(body.get("index", -1))]
        except (ValueError, IndexError, TypeError):
            raise HTTPException(400, "No such step")
        server = str(body.get("server", ""))
        try:
            if step.get("action"):
                return response.run_action(conn, incident_id, step["action"], server, user["username"])
            if step.get("command"):
                result = remote.propose(conn, server, step["command"], f"Playbook step: {step['text']} (incident {inc['ref']})",
                                        f"{user['username']} (incident {inc['ref']})", origin="plan", incident_id=incident_id, action="playbook")
                if "error" in result:
                    raise HTTPException(400, result["error"])
                triage._note(conn, incident_id, "action", user["username"], f"Proposed playbook step on {result['server']} (command #{result['id']}): {step['text']}")
                return result
            raise HTTPException(400, "This step is a note or a link, not a command")
        except ValueError as exc:
            raise HTTPException(400, str(exc))


@app.post("/api/v1/incidents/{incident_id}/closure")
def incident_closure(incident_id: int, user=User):
    with db() as conn:
        provider = _require_provider(conn)
        try:
            text = triage.closure_report(conn, provider, incident_id, user["username"])
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        except ai.AIError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))
    return {"report": text}


@app.post("/api/v1/incidents/{incident_id}/triage")
def incident_triage(incident_id: int, user=User):
    with db() as conn:
        provider = _require_provider(conn)
        if not store.get_incident(conn, incident_id):
            raise HTTPException(404, "Incident not found")
        try:
            verdict = triage.triage_one(conn, provider, incident_id, user["username"])
        except ai.AIError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))
    return verdict or {"error": "nothing to triage"}


@app.post("/api/v1/incidents/{incident_id}/suppress")
def incident_suppress(incident_id: int, body: dict = Body(...), user=Admin):
    with db() as conn:
        try:
            return triage.suppress_from_incident(conn, incident_id, str(body.get("by", "title")), user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))


@app.get("/api/v1/suppressions")
def suppressions_list(user=Admin):
    with db() as conn:
        return triage.suppressions(conn)


@app.post("/api/v1/suppressions")
def suppressions_add(body: dict = Body(...), user=Admin):
    with db() as conn:
        try:
            return triage.add_suppression(conn, str(body.get("field", "")), str(body.get("value", "")), str(body.get("label", "")), user["username"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))


@app.delete("/api/v1/suppressions/{rule_id}")
def suppressions_delete(rule_id: str, user=Admin):
    with db() as conn:
        triage.delete_suppression(conn, rule_id, user["username"])
        return {"ok": True}


@app.get("/api/v1/triage/settings")
def triage_settings(user=Admin):
    with db() as conn:
        return triage.settings(conn)


@app.put("/api/v1/triage/settings")
def triage_settings_save(body: dict = Body(...), user=Admin):
    with db() as conn:
        return triage.save_settings(conn, body, user["username"])


@app.get("/api/v1/assets")
def list_assets(user=User):
    with db() as conn:
        rows = conn.execute(
            "SELECT a.*, (SELECT COUNT(*) FROM events e WHERE e.asset_id = a.id) AS event_count, "
            "(SELECT MAX(ts) FROM events e WHERE e.asset_id = a.id) AS last_event, "
            "(SELECT COUNT(*) FROM incidents i WHERE i.asset_id = a.id AND i.status IN ('open','investigating')) "
            "AS open_incidents FROM assets a ORDER BY open_incidents DESC, a.name").fetchall()
        return [dict(r) for r in rows]


@app.patch("/api/v1/assets/{asset_id}")
def asset_update(asset_id: int, body: dict = Body(...), user=Admin):
    """Set importance, owner, notes, kind or exposure. Importance feeds incident priority."""
    fields, params = [], []
    crit = body.get("criticality")
    if crit in ("critical", "high", "medium", "low"):
        fields.append("criticality = ?"); params.append(crit)
    if "owner" in body:
        fields.append("owner = ?"); params.append(str(body["owner"])[:120])
    if "notes" in body:
        fields.append("notes = ?"); params.append(str(body["notes"])[:1000])
    if body.get("kind"):
        fields.append("kind = ?"); params.append(str(body["kind"])[:60])
    if body.get("exposure") in ("internet-facing", "internal", ""):
        fields.append("exposure = ?"); params.append(body.get("exposure"))
    if not fields:
        raise HTTPException(400, "Nothing to update")
    with db() as conn:
        cur = conn.execute(f"UPDATE assets SET {', '.join(fields)} WHERE id = ?", params + [asset_id])
        if not cur.rowcount:
            raise HTTPException(404, "Asset not found")
        audit(conn, user["username"], "asset.update", {"asset_id": asset_id, **{k: body.get(k) for k in ("criticality", "owner", "kind", "exposure") if k in body}})
        if crit:
            triage.rescore(conn)
    return {"ok": True}


@app.get("/api/v1/audit")
def list_audit(limit: int = 200, user=Admin):
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                            (store.clamp(limit, 1, 500, 200),)).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in rows]



@app.get("/api/v1/approvals")
def list_approvals(user=User):
    with db() as conn:
        store.expire_approvals(conn)
        rows = conn.execute(
            "SELECT p.*, i.title AS incident_title FROM approvals p LEFT JOIN incidents i ON i.id = p.incident_id "
            "ORDER BY (p.status = 'pending') DESC, p.id DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]


@app.post("/api/v1/approvals/{approval_id}/decision")
def decide_approval(approval_id: int, body: DecisionBody, user=Admin):
    with db() as conn:
        store.expire_approvals(conn)
        cur = conn.execute(
            "UPDATE approvals SET status = ?, decided_by = ?, decision_note = ?, decided_at = ? "
            "WHERE id = ? AND status = 'pending'",
            (body.decision, user["username"], body.note, now(), approval_id))
        if not cur.rowcount:
            raise HTTPException(409, "This request is no longer pending (already decided or expired)")
        audit(conn, user["username"], f"approval.{body.decision}", {"approval_id": approval_id, "note": body.note})
    return {"ok": True, "executed": False,
            "note": "Decision recorded. No response executor is connected, so nothing was executed."}



def _public_provider(row) -> dict:
    d = dict(row)
    key = decrypt(d.pop("api_key"), DATA_DIR)
    d["has_key"] = bool(key)
    d["key_hint"] = f"…{key[-4:]}" if len(key) >= 12 else ""
    return d


def _provider_or_404(conn, provider_id: int) -> dict:
    row = conn.execute("SELECT * FROM ai_providers WHERE id = ?", (provider_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Provider not found")
    return {**dict(row), "api_key": decrypt(row["api_key"], DATA_DIR)}


@app.get("/api/v1/ai/providers")
def providers_list(user=Admin):
    with db() as conn:
        rows = conn.execute("SELECT * FROM ai_providers ORDER BY id").fetchall()
        return {"providers": [_public_provider(r) for r in rows], "presets": ai.PRESETS}


@app.post("/api/v1/ai/providers")
def providers_create(body: ProviderBody, user=Admin):
    with db() as conn:
        first = conn.execute("SELECT COUNT(*) FROM ai_providers").fetchone()[0] == 0
        cur = conn.execute(
            "INSERT INTO ai_providers (name, kind, base_url, api_key, model, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (body.name, body.kind, body.base_url.rstrip("/"), encrypt(body.api_key.strip(), DATA_DIR), body.model.strip(),
             int(first), now()))
        audit(conn, user["username"], "ai.provider_created", {"name": body.name, "base_url": body.base_url})
        return {"id": cur.lastrowid}


@app.put("/api/v1/ai/providers/{provider_id}")
def providers_update(provider_id: int, body: ProviderBody, user=Admin):
    with db() as conn:
        current = _provider_or_404(conn, provider_id)
        base_url = body.base_url.rstrip("/")
        key = body.api_key.strip() or (current["api_key"] if base_url == current["base_url"] else "")
        conn.execute("UPDATE ai_providers SET name = ?, kind = ?, base_url = ?, api_key = ?, model = ? WHERE id = ?",
                     (body.name, body.kind, base_url, encrypt(key, DATA_DIR), body.model.strip(), provider_id))
        audit(conn, user["username"], "ai.provider_updated", {"id": provider_id, "base_url": base_url})
    return {"ok": True}


@app.delete("/api/v1/ai/providers/{provider_id}")
def providers_delete(provider_id: int, user=Admin):
    with db() as conn:
        _provider_or_404(conn, provider_id)
        conn.execute("DELETE FROM ai_providers WHERE id = ?", (provider_id,))
        audit(conn, user["username"], "ai.provider_deleted", {"id": provider_id})
    return {"ok": True}


@app.post("/api/v1/ai/providers/{provider_id}/activate")
def providers_activate(provider_id: int, user=Admin):
    with db() as conn:
        _provider_or_404(conn, provider_id)
        conn.execute("UPDATE ai_providers SET is_active = (id = ?)", (provider_id,))
        audit(conn, user["username"], "ai.provider_activated", {"id": provider_id})
    return {"ok": True}


@app.post("/api/v1/ai/providers/{provider_id}/test")
def providers_test(provider_id: int, user=Admin):
    with db() as conn:
        provider = _provider_or_404(conn, provider_id)
    return ai.test_provider(provider)


@app.post("/api/v1/ai/models")
def models_preview(body: ModelsPreviewBody, user=Admin):
    """List models for a base URL before saving it (used by the provider form)."""
    base_url, key = body.base_url.rstrip("/"), body.api_key.strip()
    if not key and body.provider_id:
        with db() as conn:
            saved = _provider_or_404(conn, body.provider_id)
        if saved["base_url"] == base_url:
            key = saved["api_key"]
    try:
        return {"models": ai.list_models({"base_url": base_url, "api_key": key})}
    except ai.AIError as exc:
        raise HTTPException(UPSTREAM_FAILED, str(exc))


def _require_provider(conn) -> dict:
    provider = ai.active_provider(conn)
    if not provider:
        raise HTTPException(409, "No AI provider is active. Add one under AI providers.")
    return provider



MAX_CONVERSATIONS = 200
MAX_STORED_MESSAGES = 200
HISTORY_FOR_MODEL = 20


def _conversation(conn, conversation_id: int, user: dict):
    row = conn.execute("SELECT * FROM conversations WHERE id = ? AND user_id = ?",
                       (conversation_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "Conversation not found")
    return row


def _store_messages(conn, conversation_id: int, messages: list[dict]) -> None:
    del messages[:-MAX_STORED_MESSAGES]
    conn.execute("UPDATE conversations SET messages = ?, message_count = ?, updated_at = ? WHERE id = ?",
                 (json.dumps(messages, default=str), len(messages), now(), conversation_id))


def _begin_turn(conn, user: dict, body: ChatBody) -> tuple[int, list[dict]]:
    """Record the question before the model runs, so it is kept even if the answer fails."""
    question = body.message.strip()
    if body.conversation_id:
        row = _conversation(conn, body.conversation_id, user)
        conversation_id, messages = row["id"], json.loads(row["messages"])
    else:
        cur = conn.execute("INSERT INTO conversations (user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                           (user["id"], " ".join(question.split())[:80] or "New chat", now(), now()))
        conversation_id, messages = cur.lastrowid, []
        conn.execute(
            "DELETE FROM conversations WHERE user_id = ? AND id NOT IN (SELECT id FROM conversations "
            "WHERE user_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?)", (user["id"], user["id"], MAX_CONVERSATIONS))
    if messages and messages[-1]["role"] == "user":
        messages.pop()
    messages.append({"role": "user", "content": question})
    _store_messages(conn, conversation_id, messages)
    return conversation_id, messages


@app.post("/api/v1/ai/chat/stream")
def ai_chat_stream(body: ChatBody, user=User):
    """Answer one question, streaming newline-delimited JSON steps as the analyst works."""
    line = lambda step: json.dumps(step, default=str) + "\n"

    def steps():
        started = time.monotonic()
        with db() as conn:
            provider = ai.active_provider(conn)
            if not provider:
                yield line({"type": "error", "detail": "No AI provider is active. An admin can add one under AI providers."})
                return
            try:
                conversation_id, messages = _begin_turn(conn, user, body)
            except HTTPException as exc:
                yield line({"type": "error", "detail": exc.detail})
                return
            yield line({"type": "started", "conversation_id": conversation_id})
            audit(conn, user["username"], "ai.query", {"question": body.message[:500], "conversation_id": conversation_id})
            history = [{"role": m["role"], "content": m["content"][:8000]} for m in messages[-HISTORY_FOR_MODEL:]]
            try:
                with ai.usage("chat", user["username"]):
                    for step in ai.investigate_steps(conn, provider, history, user["username"], body.tz_offset, commands=True):
                        if step["type"] == "final":
                            answer = {"role": "assistant", "content": step["reply"], "trace": step["trace"],
                                      "model": step["model"], "tools_supported": step["tools_supported"],
                                      "seconds": round(time.monotonic() - started)}
                            messages.append(answer)
                            _store_messages(conn, conversation_id, messages)
                            step = {"type": "final", "conversation_id": conversation_id, "message": answer}
                        yield line(step)
            except ai.AIError as exc:
                yield line({"type": "error", "detail": str(exc)})

    def with_heartbeat():
        """Run the work in the background and send a small 'still working' line every few seconds.

        A slow model can think for minutes without producing anything. Proxies and tunnels close a
        connection that stays silent that long, which the user would see as a failed answer.
        """
        outbox: queue.Queue = queue.Queue()

        def work():
            try:
                for item in steps():
                    outbox.put(item)
            except Exception as exc:
                outbox.put(line({"type": "error", "detail": f"The analyst stopped unexpectedly: {exc}"[:300]}))
            finally:
                outbox.put(None)

        threading.Thread(target=work, daemon=True).start()
        began = time.monotonic()
        while True:
            try:
                item = outbox.get(timeout=10)
            except queue.Empty:
                yield line({"type": "waiting", "seconds": round(time.monotonic() - began)})
                continue
            if item is None:
                return
            yield item

    return StreamingResponse(with_heartbeat(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/v1/ai/conversations")
def conversations_list(user=User):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, title, message_count, created_at, updated_at FROM conversations "
            "WHERE user_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?", (user["id"], MAX_CONVERSATIONS)).fetchall()
        return [dict(r) for r in rows]


@app.get("/api/v1/ai/conversations/{conversation_id}")
def conversations_get(conversation_id: int, user=User):
    with db() as conn:
        row = _conversation(conn, conversation_id, user)
    return {"id": row["id"], "title": row["title"], "messages": json.loads(row["messages"]),
            "updated_at": row["updated_at"]}


@app.put("/api/v1/ai/conversations/{conversation_id}")
def conversations_rename(conversation_id: int, body: RenameBody, user=User):
    with db() as conn:
        _conversation(conn, conversation_id, user)
        conn.execute("UPDATE conversations SET title = ? WHERE id = ?", (body.title.strip(), conversation_id))
    return {"ok": True}


@app.delete("/api/v1/ai/conversations/{conversation_id}")
def conversations_delete(conversation_id: int, user=User):
    with db() as conn:
        _conversation(conn, conversation_id, user)
        conn.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
    return {"ok": True}


@app.post("/api/v1/ai/conversations/{conversation_id}/feedback")
def conversation_feedback(conversation_id: int, body: dict = Body(...), user=User):
    rating = body.get("rating")
    index = body.get("index")
    if rating not in ("up", "down") or type(index) is not int or index < 0:
        raise HTTPException(400, "Choose an answer and a rating")
    with db() as conn:
        row = _conversation(conn, conversation_id, user)
        messages = json.loads(row["messages"])
        if index >= len(messages) or messages[index]["role"] != "assistant":
            raise HTTPException(404, "Answer not found")
        messages[index]["feedback"] = rating
        _store_messages(conn, conversation_id, messages)
        audit(conn, user["username"], "ai.feedback", {"conversation_id": conversation_id, "index": index, "rating": rating})
    return {"ok": True}


@app.post("/api/v1/ai/report")
def ai_report(body: ReportBody, request: Request, user=User):
    """Email one stored answer to the admins, exactly as it was given."""
    with db() as conn:
        row = _conversation(conn, body.conversation_id, user)
        messages = json.loads(row["messages"])
        if body.index >= len(messages) or messages[body.index]["role"] != "assistant":
            raise HTTPException(404, "That answer is no longer part of this conversation")
        question = next((m["content"] for m in reversed(messages[:body.index]) if m["role"] == "user"), "")
        recipients = accounts.admin_emails(conn)
        if not recipients:
            raise HTTPException(409, "No admin has a verified email address yet")
        try:
            message, attachments = mailer.report_message(
                user["username"], row["title"], question, messages[body.index]["content"],
                accounts.app_url(conn, request))
            sent = mailer.send(conn, "report", recipients, message, attachments=attachments)
        except mailer.MailError as exc:
            raise HTTPException(409, str(exc))
        audit(conn, user["username"], "ai.report_emailed", {"conversation_id": row["id"], "recipients": sent})
    return {"sent": sent}


@app.post("/api/v1/incidents/{incident_id}/investigate")
def incident_investigate(incident_id: int, user=User):
    with db() as conn:
        provider = _require_provider(conn)
        inc = store.get_incident(conn, incident_id)
        if not inc:
            raise HTTPException(404, "Incident not found")
        audit(conn, user["username"], "ai.investigate", {"incident_id": incident_id})
        try:
            result = ai.investigate(conn, provider, [{"role": "user", "content": ai.incident_prompt(inc)}],
                                    user["username"])
        except ai.AIError as exc:
            raise HTTPException(UPSTREAM_FAILED, str(exc))
        meta = f"{provider['model']} · {now()} · {len(result['trace'])} evidence queries"
        conn.execute("UPDATE incidents SET summary = ?, summary_meta = ? WHERE id = ?",
                     (result["reply"], meta, incident_id))
    return result



@app.get("/api/v1/integrations")
def integrations(user=Admin):
    with db() as conn:
        cfg = get_integration(conn, "grafana")
        token = cfg.pop("token", "")
        return {"grafana": {**cfg, "has_token": bool(token)}, "ingest_token": get_setting(conn, "ingest_token")}


@app.put("/api/v1/integrations/grafana")
def grafana_save(body: GrafanaBody, user=Admin):
    with db() as conn:
        current = get_integration(conn, "grafana")
        cfg = body.model_dump()
        cfg["url"] = cfg["url"].rstrip("/")
        if not cfg["token"] and cfg["url"] == current.get("url"):
            cfg["token"] = current.get("token", "")
        set_integration(conn, "grafana", cfg)
        audit(conn, user["username"], "integration.grafana_saved", {"url": cfg["url"]})
    return {"ok": True}


@app.post("/api/v1/integrations/grafana/test")
def grafana_test(user=Admin):
    with db() as conn:
        cfg = get_integration(conn, "grafana")
    try:
        return grafana.test_connection(cfg)
    except grafana.GrafanaError as exc:
        raise HTTPException(UPSTREAM_FAILED, str(exc))


@app.post("/api/v1/integrations/ingest-token/rotate")
def rotate_ingest_token(user=Admin):
    with db() as conn:
        token = secrets.token_urlsafe(32)
        set_setting(conn, "ingest_token", token)
        audit(conn, user["username"], "integration.ingest_token_rotated")
    return {"ingest_token": token}


def _check_ingest_token(request: Request) -> None:
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    with db() as conn:
        expected = get_setting(conn, "ingest_token")
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(401, "Invalid ingest token")


def _ingest_all(events: list[dict], actor: str) -> dict:
    stats = {"received": len(events), "new": 0, "duplicates": 0, "rejected": 0, "incidents": []}
    with db() as conn:
        for ev in events:
            try:
                result = store.ingest_event(conn, {**ev, "demo": False, "asset_id": None})
            except ValueError:
                stats["rejected"] += 1
                continue
            stats["duplicates" if result["duplicate"] else "new"] += 1
            if result["incident_id"] and result["incident_id"] not in stats["incidents"]:
                stats["incidents"].append(result["incident_id"])
        audit(conn, actor, "ingest", {k: v for k, v in stats.items() if k != "incidents"})
    return stats


@app.post("/api/v1/webhooks/grafana")
def grafana_webhook(request: Request, payload: dict = Body(...)):
    _check_ingest_token(request)
    return _ingest_all(grafana.normalize_webhook(payload), "grafana-webhook")


@app.post("/api/v1/ingest/events")
def ingest_events(request: Request, payload: dict = Body(...)):
    """Generic intake for already-normalised events: {"events": [{source, source_event_id, ...}]}."""
    _check_ingest_token(request)
    events = payload.get("events")
    if not isinstance(events, list) or len(events) > 500:
        raise HTTPException(422, 'Body must be {"events": [...]} with at most 500 events')
    return _ingest_all([e for e in events if isinstance(e, dict)], "ingest-api")



@app.post("/api/v1/demo")
def demo_load(user=Admin):
    with db() as conn:
        created = demo.load(conn)
        audit(conn, user["username"], "demo.loaded", {"events": created})
    return {"created": created}


@app.delete("/api/v1/demo")
def demo_clear(user=Admin):
    with db() as conn:
        demo.clear(conn)
        audit(conn, user["username"], "demo.cleared")
    return {"ok": True}



app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})
