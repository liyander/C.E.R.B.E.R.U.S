"""AI watch: a scheduled analyst.

Every few minutes it checks server health and log error rates on its own. A
condition that starts is recorded as a finding, turned into an event (so the
normal correlation opens an incident), written up by the model, and announced
in the app and by email. A condition that stops is marked recovered. Once a
day it emails a digest.

The checks themselves are plain thresholds; the model only explains what was
found. Monitoring keeps working when no model is connected.
"""
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from . import accounts, ai, grafana, mailer, store, wazuh
from .db import audit, db, get_integration, get_setting, iso, now, set_integration, set_setting

log = logging.getLogger("cerberus.watch")

DEFAULTS = {
    "enabled": False,
    "interval_minutes": 5,
    "tz_offset": 0,                 # minutes from UTC, captured from the admin's browser
    "checks": {"targets": True, "probes": True, "disk": True, "memory": True, "cpu": True, "load": True, "log_errors": True, "tools": True},
    "disk_pct": 90,
    "memory_pct": 90,
    "cpu_pct": 90,
    "load_factor": 1.0,             # load is high when it exceeds CPU cores x this
    "log_errors_5m": 200,           # error-level lines from one host in five minutes
    "notify_in_app": True,
    "notify_email": True,
    "email_min_severity": 7,
    "renotify_hours": 6,            # a condition that keeps flapping is announced at most this often
    "ai_writeup": True,
    "digest_enabled": True,
    "digest_hour": 8,               # local hour of the daily digest
}
CHECK_NAMES = {"targets": "Scrape targets down", "probes": "Web checks down", "disk": "Disk usage", "memory": "Memory usage",
               "cpu": "CPU usage", "load": "System load", "log_errors": "Error lines in logs", "tools": "Security tools reporting"}
ERROR_LEVELS = "error|err|critical|crit|fatal|emerg|alert|panic"
POLL_SECONDS = 20
KEEP_RUNS = 200

_lock = threading.Lock()
_started = False


def settings(conn) -> dict:
    saved = get_integration(conn, "watch")
    merged = {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS}}
    merged["checks"] = {**DEFAULTS["checks"], **(saved.get("checks") or {})}
    return merged


def save_settings(conn, changes: dict) -> dict:
    current = settings(conn)
    current.update({k: v for k, v in changes.items() if k in DEFAULTS and k != "checks"})
    if isinstance(changes.get("checks"), dict):
        current["checks"].update({k: bool(v) for k, v in changes["checks"].items() if k in DEFAULTS["checks"]})
    set_integration(conn, "watch", current)
    return current


def _bare(instance: str) -> str:
    """'10.0.0.5:9100' or 'http://host:1554/' -> the host part, used as the asset name."""
    instance = str(instance)
    if "://" in instance:
        return urlparse(instance).hostname or instance
    return instance.rsplit(":", 1)[0] if instance.count(":") == 1 else instance


def collect(cfg: dict, s: dict) -> list[dict]:
    """Run the enabled checks and return the conditions that are true right now."""
    health = grafana.server_health(cfg)
    checks, found = s["checks"], []

    def add(kind, subject, severity, title, detail, **extra):
        found.append({"key": f"{kind}:{subject}", "kind": kind, "asset": _bare(subject), "severity": severity,
                      "title": title, "detail": detail, **extra})

    if checks["targets"]:
        for t in health["scrape_targets"]:
            if not t["up"]:
                add("target", t["instance"], 8, f"{_bare(t['instance'])} is not answering Prometheus",
                    f"Scrape target {t['instance']} (job {t['job']}) is down, so its metrics are not being collected.")
    if checks["probes"]:
        for p in health["http_probes"]:
            if not p["up"]:
                add("probe", p["target"], 8, f"Web check \"{p['job'] or p['target']}\" is failing",
                    f"The HTTP check for {p['target']} is failing"
                    + (f" (last attempt took {p['response_seconds']} s)." if p.get("response_seconds") is not None else "."))
    for host in health["hosts"]:
        name, inst = _bare(host["instance"]), host["instance"]
        for check, field, label, limit in (("disk", "disk_pct", "Disk", s["disk_pct"]), ("memory", "mem_pct", "Memory", s["memory_pct"]),
                                           ("cpu", "cpu_pct", "CPU", s["cpu_pct"])):
            value = host.get(field)
            if checks[check] and value is not None and value >= limit:
                add(check, inst, 9 if value >= min(99, limit + 7) else 7, f"{label} at {value:.0f}% on {name}",
                    f"{label} usage on {inst} is {value:.1f}%, at or above the {limit}% limit.", metric=check, value=value)
        cores, load = host.get("cpu_cores"), host.get("load1")
        if checks["load"] and cores and load is not None and load >= cores * s["load_factor"]:
            add("load", inst, 7, f"Load {load:g} on {name} ({cores} cores)",
                f"The 1-minute load on {inst} is {load:g}, above its {cores} CPU cores, so work is queueing.", metric="load", value=load)
    if checks["log_errors"] and cfg.get("loki_uid"):
        try:
            for host, count in grafana.loki_error_counts(cfg, ERROR_LEVELS, 5).items():
                if count >= s["log_errors_5m"]:
                    add("logerr", host, 6, f"{count} error lines in 5 minutes on {host}",
                        f"{host} logged {count} error-level lines in the last five minutes (limit {s['log_errors_5m']}).", value=count)
        except grafana.GrafanaError as exc:
            log.warning("log error check skipped: %s", exc)
    if checks.get("tools", True):
        _tool_health(cfg, add)
    return found


# ---------- are the security tools themselves working? ----------

def _tool_health(cfg: dict, add) -> None:
    """Sensors, agents and log shipping that have gone quiet or are failing. Each check stands alone."""
    from . import openappsec, snort
    from .db import get_setting

    def guarded(name, check):
        try:
            check()
        except Exception as exc:  # one source failing must not hide the others
            log.warning("tool health check %s skipped: %s", name, exc)

    def snort_sensors():
        day = {g["host"]: n for g, n in snort.counts(cfg, ("host",), 1440, keep=300)}
        recent = {g["host"]: n for g, n in snort.counts(cfg, ("host",), 20, keep=60)}
        for host, n in day.items():
            if host and not recent.get(host):
                add("sensor", f"snort:{host}", 7, f"Snort on {host} stopped reporting",
                    f"The Snort sensor on {host} sent {n:,} alerts in the last 24 hours but none in the last 20 minutes. "
                    "Snort may have stopped, or its alerts are no longer being copied to the log shipper.")

    def waf_agents():
        live = openappsec.live_agents(cfg)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        for agent_id, a in live.items():
            seen = datetime.strptime(a["seen"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc) if a.get("seen") else None
            if seen and seen < datetime.now(timezone.utc) - timedelta(hours=6):
                add("sensor", f"waf:{agent_id}", 7, f"open-appsec agent on {a['host']} has gone quiet",
                    f"The open-appsec agent {agent_id[:8]} on {a['host']} last wrote anything at {a['seen']}. It may have stopped.")
        loads: dict[str, int] = {}
        for e in openappsec.agent_events(cfg):
            if "Policy Loaded" in e["name"] and e["time"] and e["time"][:19] >= cutoff.strftime("%Y-%m-%dT%H:%M:%S"):
                loads[e["host"]] = loads.get(e["host"], 0) + 1
        for host, n in loads.items():
            if n >= 50:
                add("sensor", f"waf-policy:{host}", 6, f"open-appsec agent on {host} keeps reloading its policy",
                    f"The agent on {host} reloaded its policy {n} times in 24 hours. That usually means a policy update keeps failing "
                    "(check `open-appsec-ctl --status` on the agent for 'Policy load status: Error').")

    def waf_cloud_only():
        with db() as conn:
            recorded = openappsec.inventory(conn)
        if not recorded["assets"]:
            return
        reporting = {e["asset"] for e in openappsec.requests(cfg, 24)}
        through_gateway = {e["asset"] for e in openappsec.all_requests(cfg, 24, recorded) if e.get("via") == "gateway"}
        for name in sorted(through_gateway - reporting):
            add("sensor", f"waf-cloud:{name}", 5, f"{name}: firewall events go to the cloud only",
                f"The web firewall is blocking requests for {name}, but its detailed events are not in the agent's output, so CERBERUS only sees "
                "the web server's 403s. In the open-appsec portal, give its log trigger agent logging as well.")

    def wazuh_health():
        from . import wazuh
        with db() as conn:
            w = wazuh.settings(conn)
            last_ok, last = get_setting(conn, "wazuh_last_ok"), get_setting(conn, "wazuh_last_result")
        if not wazuh.is_ready(w):
            return
        if w.get("enabled") and last_ok == "0":
            add("sensor", "wazuh:pull", 7, "CERBERUS cannot pull alerts from Wazuh", f"The last pull from Wazuh failed: {last}")
        client = wazuh._Client(w)
        try:
            for a in wazuh._agent_rows(client):
                if a.get("id") != "000" and a.get("status") not in ("active", None):
                    add("sensor", f"wazuh-agent:{a['name']}", 7, f"Wazuh agent {a['name']} is {str(a['status']).replace('_', ' ')}",
                        f"The Wazuh agent on {a['name']} ({a.get('ip', '')}) is {a['status']}, so that machine is not being monitored. Last seen {a.get('last_seen', 'unknown')}.")
        finally:
            client.close()

    def log_shipping():
        uid = cfg.get("loki_uid")
        if not uid:
            return
        ask = lambda window: {r["metric"].get("host", ""): float(r["value"][1]) for r in (grafana._get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query", {
            "query": f'sum by (host) (count_over_time({{host=~".+"}}[{window}]))', "time": int(time.time())}) or {}).get("data", {}).get("result", [])}
        before, recent = ask("3h"), ask("10m")
        for host, n in before.items():
            if host and n > 100 and not recent.get(host):
                add("sensor", f"logs:{host}", 7, f"Logs from {host} stopped arriving",
                    f"{host} sent {int(n):,} log lines in the last 3 hours but none in the last 10 minutes. Its log shipper may have stopped.")

    for name, check in (("snort", snort_sensors), ("waf", waf_agents), ("waf-cloud", waf_cloud_only), ("wazuh", wazuh_health), ("logs", log_shipping)):
        guarded(name, check)


def _writeup(conn, new: list[dict], tz_minutes: int) -> str:
    """Ask the analyst to explain the new findings. Returns '' when no model is available."""
    provider = ai.active_provider(conn)
    if not provider:
        return ""
    listing = "\n".join(f"- {f['title']}: {f['detail']}" for f in new[:8])
    question = ("The scheduled watch just found these new conditions:\n" + listing + "\n\n"
                "Write one bullet per condition, in the same order, and nothing else. Each bullet: the host in bold, since "
                "when it has been the case (use the metric history; if it was already so when the look-back window "
                "opened, say 'for more than 24 hours'), the most likely cause only if the evidence shows one, and one "
                "concrete next step. Two sentences per bullet at most. Do not propose response actions.")
    try:
        with ai.usage("watch", "ai-watch"):
            return ai.investigate(conn, provider, [{"role": "user", "content": question}], "ai-watch", tz_minutes)["reply"]
    except ai.AIError as exc:
        log.warning("watch write-up failed: %s", exc)
        return ""


def _notify(conn, s: dict, new: list[dict], recovered: list[dict], writeup: str) -> None:
    worst = max((f["severity"] for f in new), default=0)
    if new:
        title = new[0]["title"] if len(new) == 1 else f"{len(new)} new conditions need attention"
        body = "\n".join(f"- **{f['title']}**: {f['detail']}" for f in new)
        if writeup:
            body += "\n\n**AI analyst**\n\n" + writeup
        if s["notify_in_app"]:
            conn.execute(
                "INSERT INTO notifications (title, body, level, audience, in_app, emailed, created_by, created_at) "
                "VALUES (?, ?, ?, 'all', 1, 0, 'AI watch', ?)",
                (title[:120], body[:5000], "critical" if worst >= 9 else "warning" if worst >= 7 else "info", now()))
        if s["notify_email"] and worst >= s["email_min_severity"]:
            try:
                mailer.send(conn, "watch", accounts.admin_emails(conn),
                            mailer.watch_email(new, writeup, worst, mailer.config(conn).get("app_url", "")))
            except mailer.MailError as exc:
                log.warning("watch email not sent: %s", exc)
    if recovered and s["notify_in_app"]:
        conn.execute(
            "INSERT INTO notifications (title, body, level, audience, in_app, emailed, created_by, created_at) "
            "VALUES (?, ?, 'info', 'all', 1, 0, 'AI watch', ?)",
            (("Recovered: " + recovered[0]["title"] if len(recovered) == 1 else f"{len(recovered)} conditions recovered")[:120],
             "\n".join(f"- {f['title']} (had been the case since {f['first_seen']})" for f in recovered)[:5000], now()))


def run(trigger: str = "schedule", tz_offset: int | None = None) -> dict:
    """One watch pass. Safe to call from the scheduler or from the API; only one pass runs at a time."""
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "A check is already running"}
    started = time.monotonic()
    summary = {"ok": True, "trigger": trigger, "firing": 0, "new": 0, "recovered": 0, "error": ""}
    try:
        with db() as conn:
            s = settings(conn)
            if tz_offset is not None and tz_offset != s["tz_offset"]:
                s = save_settings(conn, {"tz_offset": tz_offset})
            cfg = get_integration(conn, "grafana")
            try:
                found = collect(cfg, s)
            except grafana.GrafanaError as exc:
                summary.update(ok=False, error=str(exc)[:300])
                found = None
            if found is not None:
                stamp = now()
                known = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM watch_findings")}
                quiet_after = store.ago(hours=s["renotify_hours"])
                new = []
                for f in found:
                    prior = known.get(f["key"])
                    # Still true and already known. A dismissed finding stays dismissed while its condition lasts.
                    if prior and prior["status"] in ("firing", "dismissed"):
                        conn.execute("UPDATE watch_findings SET last_seen = ?, title = ?, detail = ?, severity = ? WHERE key = ?",
                                     (stamp, f["title"], f["detail"], f["severity"], f["key"]))
                        continue
                    result = store.ingest_event(conn, {
                        "source": "watch", "source_event_id": f"{f['key']}:{stamp}", "asset": f["asset"],
                        "event_type": f"watch_{f['kind']}", "severity": f["severity"], "timestamp": stamp, "rule_id": f["key"],
                        "title": f["title"], "message": f["detail"], "evidence_ref": {"backend": "prometheus", "check": f["kind"]}})
                    conn.execute(
                        "INSERT INTO watch_findings (key, kind, asset, title, detail, severity, status, first_seen, last_seen, incident_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, 'firing', ?, ?, ?) ON CONFLICT(key) DO UPDATE SET status = 'firing', title = excluded.title, "
                        "detail = excluded.detail, severity = excluded.severity, first_seen = excluded.first_seen, last_seen = excluded.last_seen, "
                        "incident_id = excluded.incident_id",
                        (f["key"], f["kind"], f["asset"], f["title"], f["detail"], f["severity"], stamp, stamp, result["incident_id"]))
                    f["incident_id"] = result["incident_id"]
                    # A condition that flaps is tracked every time but announced only once per quiet period.
                    if not (prior and prior["last_notified"] and prior["last_notified"] >= quiet_after):
                        new.append(f)
                current_keys = {f["key"] for f in found}
                gone = [k for k in known.values() if k["status"] in ("firing", "dismissed") and k["key"] not in current_keys]
                recovered = [k for k in gone if k["status"] == "firing"]  # a dismissed finding recovers quietly
                for k in gone:
                    conn.execute("UPDATE watch_findings SET status = 'recovered', last_seen = ? WHERE key = ?", (stamp, k["key"]))
                    store.ingest_event(conn, {"source": "watch", "source_event_id": f"{k['key']}:recovered:{stamp}", "asset": k["asset"],
                                              "event_type": "alert_resolved", "severity": 1, "timestamp": stamp, "rule_id": k["key"],
                                              "title": f"Recovered: {k['title']}", "message": "The condition is no longer true."})
                    if k["incident_id"]:
                        conn.execute("UPDATE incidents SET status = 'resolved' WHERE id = ? AND rule_id = ? AND status = 'open'",
                                     (k["incident_id"], k["key"]))
                writeup = _writeup(conn, new, s["tz_offset"]) if new and s["ai_writeup"] else ""
                for f in new:
                    # A newly announced finding gets the fresh note; one that merely flapped keeps its earlier note.
                    conn.execute("UPDATE watch_findings SET ai_note = ? WHERE key = ?", (writeup, f["key"]))
                    if writeup and f.get("incident_id"):
                        conn.execute("UPDATE incidents SET summary = ?, summary_meta = ? WHERE id = ? AND summary = ''",
                                     (writeup, f"AI watch · {stamp}", f["incident_id"]))
                if new:
                    conn.execute(f"UPDATE watch_findings SET last_notified = ? WHERE key IN ({','.join('?' * len(new))})",
                                 [stamp, *[f["key"] for f in new]])
                _notify(conn, s, new, recovered, writeup)
                dismissed = {k["key"] for k in known.values() if k["status"] == "dismissed"}
                summary.update(firing=len([f for f in found if f["key"] not in dismissed]), new=len(new), recovered=len(recovered))
            summary["seconds"] = round(time.monotonic() - started, 1)
            conn.execute("INSERT INTO watch_runs (ts, reason, ok, firing, fresh, recovered, error, seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (now(), trigger, int(summary["ok"]), summary["firing"], summary["new"], summary["recovered"],
                          summary["error"], summary["seconds"]))
            conn.execute("DELETE FROM watch_runs WHERE id NOT IN (SELECT id FROM watch_runs ORDER BY id DESC LIMIT ?)", (KEEP_RUNS,))
            set_setting(conn, "watch_last_run", now())
            if summary["new"] or summary["recovered"] or not summary["ok"]:
                audit(conn, "ai-watch", "watch.run", {k: summary[k] for k in ("trigger", "firing", "new", "recovered", "error")})
    finally:
        _lock.release()
    return summary


def set_dismissed(conn, key: str, dismissed: bool, actor: str) -> int:
    """Dismiss a finding (hide it and stop counting it while its condition lasts) or bring it back. key '*' means all."""
    before, after = ("firing", "dismissed") if dismissed else ("dismissed", "firing")
    if key == "*":
        changed = conn.execute("UPDATE watch_findings SET status = ? WHERE status = ?", (after, before)).rowcount
    else:
        changed = conn.execute("UPDATE watch_findings SET status = ? WHERE key = ? AND status = ?", (after, key, before)).rowcount
    if changed:
        audit(conn, actor, "watch.dismissed" if dismissed else "watch.restored", {"finding": key, "count": changed})
    return changed


def send_digest(conn, s: dict) -> bool:
    """Daily summary for the admins: what is wrong now, what happened in the last 24 hours."""
    firing = [dict(r) for r in conn.execute("SELECT title, detail, severity, first_seen FROM watch_findings WHERE status = 'firing' ORDER BY severity DESC")]
    day = store.ago(hours=24)
    recovered = [dict(r) for r in conn.execute("SELECT title, first_seen, last_seen FROM watch_findings WHERE status = 'recovered' AND last_seen >= ?", (day,))]
    snapshot = {"conditions_true_now": firing, "recovered_in_last_24h": recovered,
                "active_incidents": store.query_incidents(conn, status="active", limit=12),
                "events_last_24h": {k: v for k, v in store.event_stats(conn, hours=24).items() if k != "hourly"}}
    provider, text = ai.active_provider(conn), ""
    if provider:
        try:
            with ai.usage("digest", "ai-watch"):
                text = ai.brief(provider, "overview", json.dumps(snapshot, default=str), grafana.tz_label(s["tz_offset"]))
        except ai.AIError as exc:
            log.warning("digest write-up failed: %s", exc)
    if not text:
        text = ("**Needs attention now**\n\n" + ("\n".join(f"- {f['title']}" for f in firing) or "- Nothing") +
                "\n\n**Recovered in the last 24 hours**\n\n" + ("\n".join(f"- {f['title']}" for f in recovered) or "- Nothing"))
    try:
        mailer.send(conn, "digest", accounts.admin_emails(conn),
                    mailer.digest_email(text, len(firing), mailer.config(conn).get("app_url", "")))
    except mailer.MailError as exc:
        log.warning("digest not sent: %s", exc)
        return False
    return True


def _tick() -> None:
    with db() as conn:
        s = settings(conn)
        last = get_setting(conn, "watch_last_run")
        last_digest = get_setting(conn, "watch_last_digest")
    if not s["enabled"]:
        return
    if not last or last <= store.ago(minutes=s["interval_minutes"]):
        run("schedule")
    local = datetime.now(timezone.utc) + timedelta(minutes=s["tz_offset"])
    today = local.strftime("%Y-%m-%d")
    if s["digest_enabled"] and local.hour >= s["digest_hour"] and last_digest != today:
        with db() as conn:
            set_setting(conn, "watch_last_digest", today)  # set first so a failure cannot cause a mail loop
            send_digest(conn, s)


def _loop() -> None:
    while True:
        time.sleep(POLL_SECONDS)
        from . import alerting, backups, dashboard, detections, login_detection, patches, predict, reports, triage
        for job in (backups.tick, wazuh.tick, detections.tick, login_detection.tick, predict.tick, triage.tick, alerting.tick, dashboard.tick, patches.tick, reports.tick, _tick):
            try:
                job()
            except Exception:  # the scheduler must survive any single bad pass
                log.exception("background job %s failed", job.__module__)


def start() -> None:
    """Start the background scheduler once per process."""
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, name="cerberus-watch", daemon=True).start()


def status(conn) -> dict:
    s = settings(conn)
    last = get_setting(conn, "watch_last_run")
    next_run = ""
    if s["enabled"]:
        base = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if last else datetime.now(timezone.utc)
        next_run = iso(max(base + timedelta(minutes=s["interval_minutes"]), datetime.now(timezone.utc)))
    findings = [dict(r) for r in conn.execute(
        "SELECT * FROM watch_findings WHERE status IN ('firing', 'dismissed') OR last_seen >= ? "
        "ORDER BY (status = 'firing') DESC, severity DESC, first_seen DESC",
        (store.ago(hours=24),))]
    runs = [dict(r) for r in conn.execute("SELECT * FROM watch_runs ORDER BY id DESC LIMIT 15")]
    grafana_cfg = get_integration(conn, "grafana")
    return {"settings": s, "check_names": CHECK_NAMES, "last_run": last, "next_run": next_run, "findings": findings, "runs": runs,
            "metrics_connected": bool(grafana_cfg.get("url") and grafana_cfg.get("prometheus_uid")),
            "logs_connected": bool(grafana_cfg.get("url") and grafana_cfg.get("loki_uid")),
            "email_ready": mailer.is_configured(mailer.config(conn)) and bool(accounts.admin_emails(conn)),
            "ai_ready": bool(ai.active_provider(conn))}
