"""CERBERUS API + static web UI."""
import hmac
import json
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import accounts, ai, apps, auth, demo, grafana, mailer, store, tools, watch, wazuh
from .db import ROOT, audit, db, get_integration, get_setting, init_db, now, set_integration, set_setting

WEB_DIR = ROOT / "web"
VERSION = "0.2.0"


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
    # The UI renders attacker-influenced log text; forbid inline/3rd-party script as a second line of defence.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ---------- models ----------

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
    tz_offset: int = Field(default=0, ge=-720, le=840)  # the browser's offset from UTC, in minutes


class BriefBody(BaseModel):
    kind: str = Field(pattern=r"^(logs|log_line|infrastructure|overview)$")
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


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": VERSION, "time": now()}


# ---------- read models ----------

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
            "pending_approvals": one("SELECT COUNT(*) FROM approvals WHERE status = 'pending'"),
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
        raise HTTPException(502, str(exc))
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
        raise HTTPException(502, str(exc))


# ---------- Wazuh ----------

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
        # A blank password keeps the saved one, but never carries it to a different address or account.
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
            raise HTTPException(502, str(exc))
        set_integration(conn, "wazuh", {**cfg, "mode": result["mode"]})
    return result


@app.post("/api/v1/integrations/wazuh/sync")
def wazuh_sync(user=Admin):
    return wazuh.sync("manual")


# ---------- AI watch (scheduled analyst) ----------

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


@app.post("/api/v1/ai/brief")
def ai_brief(body: BriefBody, user=User):
    """A short AI-written briefing. The server collects the data itself; the model gets no tools."""
    tz = grafana.tz_label(body.tz_offset)
    with db() as conn:
        provider = _require_provider(conn)
        cfg = get_integration(conn, "grafana")
        audit(conn, user["username"], "ai.brief", {"kind": body.kind, "query": body.query[:300]})
        try:
            if body.kind == "log_line":
                data = json.dumps({"labels": body.labels, "line": body.line})
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
            return {"text": ai.brief(provider, body.kind, data, tz), "model": provider["model"]}
        except grafana.GrafanaError as exc:
            raise HTTPException(502, str(exc))
        except ai.AIError as exc:
            raise HTTPException(502, str(exc))


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
                raise HTTPException(502, str(exc))
            out[name] = []
    return out


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
            raise HTTPException(502, str(exc))


@app.get("/api/v1/infrastructure")
def infrastructure(user=User):
    """Live server health from Prometheus: targets, per-host resource use and HTTP probes."""
    with db() as conn:
        cfg = get_integration(conn, "grafana")
    try:
        return grafana.server_health(cfg)
    except grafana.GrafanaError as exc:
        raise HTTPException(502, str(exc))


@app.get("/api/v1/incidents")
def list_incidents(status: str = "", user=User):
    with db() as conn:
        return store.query_incidents(conn, status=status, limit=200)


@app.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: int, user=User):
    with db() as conn:
        store.expire_approvals(conn)
        inc = store.get_incident(conn, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


@app.patch("/api/v1/incidents/{incident_id}")
def incident_update(incident_id: int, body: IncidentPatch, user=User):
    if body.status not in store.INCIDENT_STATUSES:
        raise HTTPException(422, "Unknown status")
    with db() as conn:
        cur = conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (body.status, incident_id))
        if not cur.rowcount:
            raise HTTPException(404, "Incident not found")
        audit(conn, user["username"], "incident.status", {"incident_id": incident_id, "status": body.status})
    return {"ok": True}


@app.get("/api/v1/assets")
def list_assets(user=User):
    with db() as conn:
        rows = conn.execute(
            "SELECT a.*, (SELECT COUNT(*) FROM events e WHERE e.asset_id = a.id) AS event_count, "
            "(SELECT MAX(ts) FROM events e WHERE e.asset_id = a.id) AS last_event, "
            "(SELECT COUNT(*) FROM incidents i WHERE i.asset_id = a.id AND i.status IN ('open','investigating')) "
            "AS open_incidents FROM assets a ORDER BY open_incidents DESC, a.name").fetchall()
        return [dict(r) for r in rows]


@app.get("/api/v1/audit")
def list_audit(limit: int = 200, user=Admin):
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                            (store.clamp(limit, 1, 500, 200),)).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in rows]


# ---------- approvals ----------

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
        # Conditional update makes a duplicate or late decision a no-op.
        cur = conn.execute(
            "UPDATE approvals SET status = ?, decided_by = ?, decision_note = ?, decided_at = ? "
            "WHERE id = ? AND status = 'pending'",
            (body.decision, user["username"], body.note, now(), approval_id))
        if not cur.rowcount:
            raise HTTPException(409, "This request is no longer pending (already decided or expired)")
        audit(conn, user["username"], f"approval.{body.decision}", {"approval_id": approval_id, "note": body.note})
    return {"ok": True, "executed": False,
            "note": "Decision recorded. No response executor is connected, so nothing was executed."}


# ---------- AI providers ----------

def _public_provider(row) -> dict:
    d = dict(row)
    key = d.pop("api_key")
    d["has_key"] = bool(key)
    d["key_hint"] = f"…{key[-4:]}" if len(key) >= 12 else ""
    return d


def _provider_or_404(conn, provider_id: int) -> dict:
    row = conn.execute("SELECT * FROM ai_providers WHERE id = ?", (provider_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Provider not found")
    return dict(row)


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
            (body.name, body.kind, body.base_url.rstrip("/"), body.api_key.strip(), body.model.strip(),
             int(first), now()))
        audit(conn, user["username"], "ai.provider_created", {"name": body.name, "base_url": body.base_url})
        return {"id": cur.lastrowid}


@app.put("/api/v1/ai/providers/{provider_id}")
def providers_update(provider_id: int, body: ProviderBody, user=Admin):
    with db() as conn:
        current = _provider_or_404(conn, provider_id)
        base_url = body.base_url.rstrip("/")
        # A blank key keeps the stored one, but never carries it to a different host.
        key = body.api_key.strip() or (current["api_key"] if base_url == current["base_url"] else "")
        conn.execute("UPDATE ai_providers SET name = ?, kind = ?, base_url = ?, api_key = ?, model = ? WHERE id = ?",
                     (body.name, body.kind, base_url, key, body.model.strip(), provider_id))
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
        raise HTTPException(502, str(exc))


def _require_provider(conn) -> dict:
    provider = ai.active_provider(conn)
    if not provider:
        raise HTTPException(409, "No AI provider is active. Add one under AI providers.")
    return provider


# ---------- AI console ----------
# Conversations are written by the server as part of answering, so history never
# depends on the browser saving anything.

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
        # Oldest conversations roll off so history cannot grow without bound.
        conn.execute(
            "DELETE FROM conversations WHERE user_id = ? AND id NOT IN (SELECT id FROM conversations "
            "WHERE user_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?)", (user["id"], user["id"], MAX_CONVERSATIONS))
    # A retry after a failed answer replaces the unanswered question instead of stacking a duplicate.
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
                for step in ai.investigate_steps(conn, provider, history, user["username"], body.tz_offset):
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

    return StreamingResponse(steps(), media_type="application/x-ndjson",
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
            raise HTTPException(502, str(exc))
        meta = f"{provider['model']} · {now()} · {len(result['trace'])} evidence queries"
        conn.execute("UPDATE incidents SET summary = ?, summary_meta = ? WHERE id = ?",
                     (result["reply"], meta, incident_id))
    return result


# ---------- integrations ----------

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
        raise HTTPException(502, str(exc))


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
                # Machine senders never get to set the demo flag or pick an internal asset id.
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


# ---------- demo data ----------

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


# ---------- web UI ----------

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})
