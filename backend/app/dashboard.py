"""The main dashboard: the vital signs of every connected application on one screen, and one threat level.

Each panel says whether its application is healthy, what matters in its numbers right now, and links to
the full view. The threat level (0-100) is the single number the threat alerts compare with a threshold:
the highest of the attack forecast's likelihood, serious incidents opened today, attacks that got past the
web firewall, and the riskiest machine's score. Everything is read in parallel and remembered for a minute.
"""
import time
from datetime import datetime, timezone

from . import grafana, insights, openappsec, predict, snort, store, wazuh
from .db import now

LEVELS = ((85, "Critical", "critical"), (70, "High", "high"), (50, "Elevated", "medium"), (25, "Guarded", "low"), (0, "Low", "ok"))


def level_name(value: int) -> tuple[str, str]:
    return next((name, tone) for floor, name, tone in LEVELS if value >= floor)


def threat(conn, machines: list[dict] | None = None, waf_through: int | None = None) -> dict:
    """The overall threat level and what drives it. Cheap: database reads plus cached lookups."""
    drivers = []
    top = conn.execute("SELECT title, likelihood FROM forecasts WHERE status = 'active' ORDER BY likelihood DESC LIMIT 1").fetchone()
    if top:
        drivers.append((top["likelihood"], f"Attack forecast: {top['title']} ({top['likelihood']}% likely)", "#/forecast"))
    since = store.ago(hours=24)
    for floor, value, label in ((9, 90, "critical"), (7, 72, "high-severity")):
        n = conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating') AND severity >= ? AND first_seen >= ? AND demo = 0",
                         (floor, since)).fetchone()[0]
        if n:
            drivers.append((value, f"{n} {label} incident{'s' if n != 1 else ''} opened in the last 24 hours", "#/incidents"))
            break
    if waf_through:
        drivers.append((75, f"{waf_through} web attack{'s' if waf_through != 1 else ''} got past the firewall in the last hour (detect-only mode)", "#/app/openappsec/events"))
    if machines is None:
        try:
            machines, _ = insights.machines(conn)
        except Exception:
            machines = []
    if machines:
        worst = max(machines, key=lambda m: m.get("risk", 0))
        if worst.get("risk"):
            drivers.append((round(worst["risk"] * 0.8), f"Riskiest machine: {', '.join(worst['names'][:1]) or worst['ip']} scores {worst['risk']}/100", "#/risk"))
    drivers.sort(key=lambda d: -d[0])
    value = int(min(100, drivers[0][0])) if drivers else 5
    name, tone = level_name(value)
    return {"value": value, "label": name, "tone": tone, "drivers": [{"value": v, "text": t, "href": h} for v, t, h in drivers[:4]],
            "forecast_max": top["likelihood"] if top else 0, "risk_max": max((m.get("risk", 0) for m in machines), default=0)}


def _wazuh(w: dict) -> dict:
    client = wazuh._Client(w)
    try:
        agents = [a for a in wazuh._agent_rows(client) if a.get("id") != "000"]
        r = client.search({"size": 0, "track_total_hits": True, "query": {"range": {"timestamp": {"gte": "now-24h"}}}, "aggs": {
            "lv": {"range": {"field": "rule.level", "ranges": [{"key": "low", "to": 7}, {"key": "medium", "from": 7, "to": 10}, {"key": "high", "from": 10, "to": 13}, {"key": "critical", "from": 13}]}},
            "hour": {"filter": {"range": {"timestamp": {"gte": "now-1h"}}}},
            "rule": {"terms": {"field": "rule.description", "size": 1}, "aggs": {"lv": {"max": {"field": "rule.level"}}}}}})
    finally:
        client.close()
    a = r.get("aggregations", {})
    levels = {b["key"]: b["doc_count"] for b in a.get("lv", {}).get("buckets", [])}
    top = (a.get("rule", {}).get("buckets") or [{}])[0]
    return {"agents": len(agents), "active": sum(1 for x in agents if x.get("status") == "active"), "down": [x["name"] for x in agents if x.get("status") != "active"],
            "alerts": (r.get("hits", {}).get("total") or {}).get("value", 0), "levels": levels, "hour": a.get("hour", {}).get("doc_count", 0),
            "top_rule": top.get("key", ""), "top_rule_count": top.get("doc_count", 0)}


def _panel(app, name, status, tiles, note="", href="", logo="", icon=""):
    return {"app": app, "name": name, "status": status, "tiles": tiles, "note": note, "href": href, "logo": logo, "icon": icon}


def _t(label, value, tone="", hint=""):
    return {"label": label, "value": value, "tone": tone, "hint": hint}


def vitals(conn) -> dict:
    def load():
        started = time.time()
        c = insights._configs(conn)
        g, w = c["grafana"], c["wazuh"]
        jobs = {}
        if c["wazuh_ready"]:
            jobs["wazuh"] = lambda: _wazuh(w)
        if g.get("url") and g.get("prometheus_uid"):
            jobs["health"] = lambda: grafana.server_health(g)
        if c["loki"]:
            jobs["waf"] = lambda: openappsec.all_requests(g, 24, c["inventory"])
            jobs["waf_agents"] = lambda: openappsec.live_agents(g)
            jobs["snort_day"] = lambda: snort.counts(g, ("prio",), 1440, keep=120)
            jobs["snort_hour"] = lambda: snort.counts(g, ("prio",), 60, keep=60)
            jobs["snort_top"] = lambda: snort.counts(g, ("msg",), 1440, 1, keep=300)
            jobs["sensors_day"] = lambda: snort.counts(g, ("host",), 1440, keep=600)
            jobs["sensors_now"] = lambda: snort.counts(g, ("host",), 20, keep=60)
        q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
        since = store.ago(hours=24)
        active = "status IN ('open', 'investigating') AND demo = 0"
        db = {"open": q(f"SELECT COUNT(*) FROM incidents WHERE {active}"), "critical": q(f"SELECT COUNT(*) FROM incidents WHERE {active} AND severity >= 9"),
              "new": q("SELECT COUNT(*) FROM incidents WHERE first_seen >= ? AND demo = 0", since),
              "approvals": q("SELECT COUNT(*) FROM approvals WHERE status = 'pending'") + q("SELECT COUNT(*) FROM server_commands WHERE status = 'pending' AND expires_at >= ?", now()),
              "events": q("SELECT COUNT(*) FROM events WHERE ts >= ?", since),
              "ai_calls": q("SELECT COUNT(*) FROM ai_usage WHERE ts >= ?", since), "ai_tokens": q("SELECT COALESCE(SUM(total_tokens), 0) FROM ai_usage WHERE ts >= ?", since),
              "ai_failed": q("SELECT COUNT(*) FROM ai_usage WHERE ts >= ? AND ok = 0", since),
              "findings": q("SELECT COUNT(*) FROM watch_findings WHERE status = 'firing'" + (" AND dismissed = 0" if _has(conn, "watch_findings", "dismissed") else "")),
              "forecasts": predict.active(conn, 5), "provider": (conn.execute("SELECT name, model FROM ai_providers WHERE is_active = 1").fetchone() or None)}
        try:
            machines, _ = insights.machines(conn)
        except Exception:
            machines = []
        try:
            vulns, _, _ = insights._vuln_base(conn)
        except Exception:
            vulns = []
        patch = _patch_summary(conn)
        found, problems = insights._parallel(jobs)
        panels = []

        if "wazuh" in found:
            x = found["wazuh"]
            lv = x["levels"]
            status = "critical" if lv.get("critical") or x["down"] else "warn" if lv.get("high") else "ok"
            panels.append(_panel("wazuh", "Wazuh", status, [
                _t("Agents reporting", f"{x['active']}/{x['agents']}", "critical" if x["down"] else "ok"),
                _t("Alerts (24 h)", x["alerts"]), _t("High or critical", lv.get("high", 0) + lv.get("critical", 0), "high" if lv.get("high") or lv.get("critical") else ""),
                _t("Last hour", x["hour"])],
                (f"Not reporting: {', '.join(x['down'])}. " if x["down"] else "") + (f"Busiest rule: {x['top_rule']} ({x['top_rule_count']:,})" if x["top_rule"] else ""),
                "#/app/wazuh/overview", "/static/logos/wazuh.svg"))
        else:
            panels.append(_off("wazuh", "Wazuh", problems, "wazuh", "/static/logos/wazuh.svg"))

        if "health" in found:
            h = found["health"]
            down = [t["instance"] for t in h["scrape_targets"] if not t["up"]]
            probes_down = [p["target"] for p in h["http_probes"] if not p["up"]]
            hottest = max(h["hosts"], key=lambda x: max(x.get("cpu_pct", 0), x.get("mem_pct", 0), x.get("disk_pct", 0)), default=None)
            peak = max(hottest.get("cpu_pct", 0), hottest.get("mem_pct", 0), hottest.get("disk_pct", 0)) if hottest else 0
            disk = max((x.get("disk_pct", 0) for x in h["hosts"]), default=0)
            status = "critical" if probes_down or disk >= 95 else "warn" if down or peak >= 85 else "ok"
            panels.append(_panel("grafana", "Grafana · servers", status, [
                _t("Targets up", f"{len(h['scrape_targets']) - len(down)}/{len(h['scrape_targets'])}", "high" if down else "ok"),
                _t("Web checks failing", len(probes_down), "critical" if probes_down else "ok"),
                _t("Fullest disk", f"{disk:.0f}%", "critical" if disk >= 95 else "high" if disk >= 85 else ""),
                _t("Busiest host", f"{peak:.0f}%", "high" if peak >= 85 else "", hottest["instance"] if hottest else "")],
                ("Failing: " + ", ".join(probes_down[:3]) + ". ") * bool(probes_down) + ("Down: " + ", ".join(down[:3])) * bool(down),
                "#/infrastructure", "/static/logos/grafana.svg"))
        else:
            panels.append(_off("grafana", "Grafana · servers", problems, "health", "/static/logos/grafana.svg"))

        through_hour = 0
        if "waf" in found:
            reqs = found["waf"]
            hour = time.time() * 1e9 - 3600e9
            blocked = sum(1 for e in reqs if e["action"] == "Prevent")
            through = sum(1 for e in reqs if e["action"] == "Detect")
            through_hour = sum(1 for e in reqs if e["action"] == "Detect" and e["ns"] >= hour)
            types: dict[str, int] = {}
            for e in reqs:
                types[e["type"]] = types.get(e["type"], 0) + 1
            top = max(types.items(), key=lambda kv: kv[1]) if types else ("", 0)
            agents = found.get("waf_agents") or {}
            panels.append(_panel("openappsec", "Web firewall", "critical" if through_hour else "warn" if through else "ok", [
                _t("Requests judged (24 h)", len(reqs)), _t("Blocked", blocked, "ok" if blocked else ""), _t("Let through", through, "critical" if through else "ok"),
                _t("Agents reporting", len(agents))], f"Most common: {top[0]} ({top[1]:,})" if top[1] else "No attacks in the last 24 hours.",
                "#/app/openappsec/overview", "/static/logos/openappsec.png"))
        else:
            panels.append(_off("openappsec", "Web firewall", problems, "waf", "/static/logos/openappsec.png"))

        if "snort_day" in found:
            day = {g_["prio"]: n for g_, n in found["snort_day"]}
            hour_n = sum(n for _, n in found.get("snort_hour", []))
            sensors = {g_["host"] for g_, _ in found.get("sensors_day", [])}
            quiet = sorted(sensors - {g_["host"] for g_, _ in found.get("sensors_now", [])})
            top = (found.get("snort_top") or [({"msg": ""}, 0)])[0]
            panels.append(_panel("snort", "Snort", "warn" if quiet or day.get("1", 0) else "ok", [
                _t("Alerts (24 h)", sum(day.values())), _t("Priority 1", day.get("1", 0), "high" if day.get("1") else ""), _t("Last hour", hour_n),
                _t("Sensors reporting", f"{len(sensors) - len(quiet)}/{len(sensors)}", "high" if quiet else "ok")],
                (f"Quiet: {', '.join(quiet)}. " if quiet else "") + (f"Top signature: {top[0]['msg'][:70]} ({top[1]:,})" if top[1] else ""),
                "#/app/snort/overview", "/static/logos/snort.png"))
        else:
            panels.append(_off("snort", "Snort", problems, "snort_day", "/static/logos/snort.png"))

        fc = db["forecasts"]
        kev = sum(1 for v in vulns if v.get("kev"))
        panels.append(_panel("cerberus", "Incidents and forecast", "critical" if db["critical"] or (fc and fc[0]["likelihood"] >= 85) else "warn" if db["open"] or fc else "ok", [
            _t("Open incidents", db["open"], "high" if db["open"] else "ok"), _t("Critical", db["critical"], "critical" if db["critical"] else "ok"),
            _t("Highest forecast", f"{fc[0]['likelihood']}%" if fc else "—", level_name(fc[0]["likelihood"])[1] if fc else ""),
            _t("Waiting approval", db["approvals"], "high" if db["approvals"] else "")],
            (f"Most likely: {fc[0]['title']}" if fc else "No attack is building up right now.") + f" · {db['new']} incident{'s' if db['new'] != 1 else ''} opened today",
            "#/forecast", icon="shield"))
        worst = max(machines, key=lambda m: m.get("risk", 0)) if machines else None
        panels.append(_panel("exposure", "Exposure and patching", "critical" if patch.get("overdue") and kev else "warn" if patch.get("overdue") or (worst and worst["risk"] >= 60) else "ok", [
            _t("Riskiest machine", f"{worst['risk']}" if worst else "—", "critical" if worst and worst["risk"] >= 70 else "high" if worst and worst["risk"] >= 50 else "", (worst["names"] or [worst["ip"]])[0] if worst else ""),
            _t("Exploited CVEs", kev, "critical" if kev else "ok"), _t("Patches available", patch.get("available", "—")), _t("Overdue", patch.get("overdue", "—"), "critical" if patch.get("overdue") else "")],
            patch.get("note", ""), "#/patches", icon="tool"))
        prov = db["provider"]
        panels.append(_panel("ai", "AI analyst", "critical" if not prov else "warn" if db["ai_failed"] else "ok", [
            _t("Model calls (24 h)", db["ai_calls"]), _t("Tokens", db["ai_tokens"]), _t("Failed calls", db["ai_failed"], "high" if db["ai_failed"] else "ok"),
            _t("Watch conditions", db["findings"], "high" if db["findings"] else "ok")],
            f"Model: {prov['model']}" if prov else "No AI provider is active.", "#/ai-usage", icon="spark"))

        level = threat(conn, machines, through_hour)
        return {"threat": level, "panels": panels, "events_24h": db["events"], "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "seconds": round(time.time() - started, 1)}
    return insights._cached(("dashboard",), 60, load)


def _has(conn, table: str, column: str) -> bool:
    return any(r[1] == column for r in conn.execute(f"PRAGMA table_info({table})"))


def _off(app, name, problems, job, logo):
    why = next((p for p in problems if p.startswith(job)), "")
    return _panel(app, name, "error" if why else "off", [], why.split(": ", 1)[-1][:160] if why else "Not connected. An admin can connect it under Integrations.", "#/integrations", logo)


def _patch_summary(conn) -> dict:
    from . import patches
    def load():
        try:
            p = patches.plan(conn)
        except Exception:
            return {}
        items = p["items"]
        return {"available": sum(1 for i in items if i["status"] == "available"), "overdue": sum(1 for i in items if i["overdue"]),
                "note": f"{len([m for m in p['machines'] if m['upgrade']])} machine(s) have upgrades waiting." if p["machines"] else ""}
    return insights._cached(("dash-patches",), 600, load)


_last_warm = 0.0


def tick() -> None:
    """Called by the background scheduler: keep the dashboard fresh so opening it never waits on a cold lookup."""
    global _last_warm
    if time.time() - _last_warm < 50:
        return
    _last_warm = time.time()
    from .db import db
    with db() as conn:
        vitals(conn)
