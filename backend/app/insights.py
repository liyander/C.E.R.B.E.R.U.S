"""Views that cut across every connected source: one IP address, risk per machine, which
vulnerabilities to fix first, and how much the AI is being used.

Each view returns the same page description the application workspaces use (tiles, bars, tables,
filters), so the web app draws them with the same code. Everything here is read-only. A source
that is not connected, or that fails, is skipped and named in a note; it never breaks the page.
"""
import ipaddress
import json
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx

from . import grafana, openappsec, snort, store, wazuh
from .apps import badge, bars, link, search_box, segments, select, stamp, table, tile
from .db import DATA_DIR, get_integration, get_setting, now

PERIODS = (("24", "Last 24 hours"), ("168", "Last 7 days"))
_cache: dict[tuple, tuple[float, object]] = {}
_lock = threading.Lock()


def _cached(key: tuple, seconds: int, load):
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < seconds:
            return hit[1]
    value = load()
    with _lock:
        _cache[key] = (time.monotonic(), value)
    return value


def _parallel(jobs: dict) -> tuple[dict, list[str]]:
    """Run lookups at once. Returns (results, problems); a failed lookup becomes a problem, not an error."""
    def run(job):
        try:
            return job(), ""
        except Exception as exc:
            return None, str(exc)[:160]
    with ThreadPoolExecutor(max_workers=8) as pool:
        done = dict(zip(jobs, pool.map(run, jobs.values())))
    return {k: v for k, (v, err) in done.items() if not err}, [f"{k}: {err}" for k, (v, err) in done.items() if err]


def is_public(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_multicast or address.is_link_local or address.is_reserved)


def _hours(q: dict) -> int:
    return 168 if q.get("hours") == "168" else 24


def _configs(conn) -> dict:
    g, w = get_integration(conn, "grafana"), wazuh.settings(conn)
    return {"grafana": g, "wazuh": w, "loki": bool(g.get("url") and g.get("loki_uid")), "wazuh_ready": wazuh.is_ready(w),
            "inventory": openappsec.inventory(conn)}



_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
_FAILED = re.compile(r"(?:Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port|Invalid user (\S*) from (\S+))")


LOG_HOURS = 6


def _loki_lines(cfg: dict, logql: str, hours: int, limit: int) -> list[tuple[int, str, dict]]:
    uid = store.text(cfg.get("loki_uid"), 80)
    end = int(time.time()) + 60
    try:
        with grafana._client(cfg) as client:
            resp = client.get(f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query_range", timeout=45, params={
                "query": logql, "start": (end - hours * 3600) * 10**9, "end": end * 10**9, "limit": limit, "direction": "backward"})
    except httpx.HTTPError as exc:
        raise grafana.GrafanaError(f"Loki did not answer in time ({exc.__class__.__name__})") from exc
    if resp.status_code >= 400:
        raise grafana.GrafanaError(f"Loki returned HTTP {resp.status_code}: {resp.text[:160]}")
    data = (resp.json() or {}).get("data") or {}
    return sorted(((int(ns), line, s.get("stream") or {}) for s in data.get("result", []) for ns, line in s.get("values", [])), reverse=True)


def ip_profile(conn, q: dict) -> dict:
    """Everything every source knows about one address."""
    ip = store.text(q.get("ip"), 60).strip()
    hours = _hours(q)
    filters = [search_box("ip", "IP address", ip, 200), select("hours", "Period", str(hours), PERIODS)]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"title": "IP lookup", "subtitle": "Type an address to see what every connected source knows about it.", "filters": filters,
                "blocks": [table("Recent attackers", (("ip", "Address", "mono"), ("sources", "Seen by", "text"), ("hits", "Sightings", "num")), _recent_attackers(conn),
                                 empty="No external addresses have shown up in the last 24 hours.")]}
    c = _configs(conn)
    g, quoted = c["grafana"], '"' + ip.replace('"', "") + '"'
    local = (store.query_events(conn, q=ip, limit=100),
             [dict(r) for r in conn.execute("SELECT id, title, status, severity, first_seen, last_seen FROM incidents WHERE source_ip = ? ORDER BY last_seen DESC LIMIT 20", (ip,))])
    jobs = {}
    if c["wazuh_ready"]:
        jobs["Wazuh"] = lambda: wazuh.search_alerts(c["wazuh"], source_ip=ip, hours=hours, limit=30)
    if c["loki"]:
        jobs["Snort"] = lambda: [a for a in snort.latest(g, LOG_HOURS * 60, 400, text=ip) if ip in (a["source"], a["target"])]
        jobs["WAF"] = lambda: [e for e in openappsec.all_requests(g, hours, c["inventory"]) if e["source"] == ip]
        jobs["Logins"] = lambda: _loki_lines(g, f'{{job="loki.source.journal.system"}} |= {quoted} |~ "Accepted |Failed |Invalid user "', LOG_HOURS, 1000)
        jobs["Logs"] = lambda: _loki_lines(g, f'{{host=~".+", job!="loki.source.journal.system"}} |= {quoted}', LOG_HOURS, 60)
    found, problems = _parallel(jobs)
    timeline, logins = [], {}
    events, incidents = local
    for e in events:
        timeline.append({"time": e.get("ts"), "source": "CERBERUS", "what": e.get("title", ""), "where": e.get("asset_name") or "", "tone": "info"})
    for a in (found.get("Wazuh") or {}).get("alerts", []):
        level = int(a.get("level") or 0)
        timeline.append({"time": stamp(a.get("time")), "source": "Wazuh", "what": f"{a.get('description', '')} (level {level})", "where": a.get("agent", ""),
                         "tone": "critical" if level >= 12 else "high" if level >= 10 else "medium" if level >= 7 else "low", "detail": a.get("log", "")})
    for a in found.get("Snort") or []:
        direction = "from" if a["source"] == ip else "to"
        timeline.append({"time": a["time"], "source": "Snort", "what": f"{a['message']} ({direction} this address)", "where": a["sensor"],
                         "tone": {"1": "critical", "2": "high", "3": "medium"}.get(a["priority"], "low"),
                         "detail": f"{a['protocol']} {a['source']}:{a['source_port']} -> {a['target']}:{a['target_port']} · priority {a['priority']} · {a['kind']}"})
    for e in found.get("WAF") or []:
        timeline.append({"time": e["time"], "source": "WAF", "what": f"{'Blocked' if e['action'] == 'Prevent' else 'Detected'}: {e['type']} on {e['method']} {e['path']}"[:200],
                         "where": e["asset"], "tone": "critical" if e["severity"] == "Critical" else "high", "detail": e.get("matched") or e.get("browser", "")})
    for ns, line, labels in found.get("Logins") or []:
        ok, bad = _ACCEPTED.search(line), _FAILED.search(line)
        if ok and ok.group(3) == ip:
            who, outcome = ok.group(2), "accepted"
        elif bad and ip in (bad.group(3), bad.group(5)):
            who, outcome = bad.group(2) or bad.group(4) or "?", "failed"
        else:
            continue
        server = labels.get("host", "")
        row = logins.setdefault((server, who, outcome), {"count": 0, "last": ns})
        row["count"] += 1
        timeline.append({"time": stamp(time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ns / 1e9)) + "Z"), "source": "Logins",
                         "what": f"SSH login {outcome} as {who}", "where": server, "tone": "critical" if outcome == "accepted" and is_public(ip) else "medium"})
    for ns, line, labels in found.get("Logs") or []:
        timeline.append({"time": stamp(time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ns / 1e9)) + "Z"), "source": "Logs", "what": line[:180],
                         "where": " · ".join(filter(None, [labels.get("host"), labels.get("service_name")])), "tone": "low", "detail": line[:2000]})
    timeline.sort(key=lambda t: t.get("time") or "", reverse=True)
    per_source = {}
    for t in timeline:
        per_source[t["source"]] = per_source.get(t["source"], 0) + 1
    if found.get("Wazuh"):
        per_source["Wazuh"] = max(per_source.get("Wazuh", 0), found["Wazuh"].get("total_matching", 0))
    accepted = [k for k in logins if k[2] == "accepted"]
    times = [t["time"] for t in timeline if t.get("time")]
    kind = "External" if is_public(ip) else "Internal"
    rep = None
    if kind == "External":
        try:
            from . import intel
            if intel.enabled(conn):
                rep = intel.lookup(conn, ip)
        except Exception as exc:
            problems.append(f"Reputation: {str(exc)[:80]}")
    rep_block = []
    rep_tile = None
    if rep and rep.get("verdict"):
        v = rep["verdict"]
        gn, ab = rep.get("greynoise") or {}, rep.get("abuseipdb") or {}
        rep_tile = tile("Reputation", v["label"], v["tone"])
        rows = []
        if ab:
            rows += [{"k": "AbuseIPDB score", "v": f"{ab.get('score', 0)}/100 ({ab.get('total_reports', 0)} reports)"},
                     {"k": "Country / network", "v": " · ".join(filter(None, [ab.get("country"), ab.get("isp"), ab.get("usage")]))},
                     {"k": "Last reported", "v": ab.get("last_reported", "") or "—"}]
        if gn:
            rows += [{"k": "GreyNoise", "v": (gn.get("classification") or ("benign service (RIOT)" if gn.get("riot") else "internet scanner" if gn.get("noise") else "seen" if gn.get("seen") else "not seen")) + (f" — {gn['name']}" if gn.get("name") else "")}]
        rep_block = [table(f"Reputation · {v['label']}", (("k", "Source", "text"), ("v", "Finding", "wrap")), rows,
                           note=v["text"] + (" Cached." if rep.get("cached") else "") + ("  Could not reach: " + "; ".join(rep["errors"]) if rep.get("errors") else ""),
                           empty="No reputation data for this address.")]
    return {
        "title": f"IP {ip}", "subtitle": "Everything the connected sources have recorded about this address. Ask the AI for a verdict.",
        "filters": filters,
        "tiles": [tile("Address", kind, "high" if kind == "External" and timeline else ""), tile("Seen by sources", len(per_source), "critical" if len(per_source) >= 3 else "high" if len(per_source) == 2 else ""),
                  tile("Sightings", sum(per_source.values())),
                  rep_tile or tile("Successful logins", sum(logins[k]["count"] for k in accepted), "critical" if accepted and is_public(ip) else "")],
        "blocks": rep_block + [
            bars("Sightings by source", [{"label": k, "value": v} for k, v in sorted(per_source.items(), key=lambda kv: -kv[1])], empty="No source has seen this address in the period."),
            bars("Where it was seen", [{"label": k, "value": v} for k, v in _count(t["where"] for t in timeline if t["where"])[:8]], empty="Nowhere in the period."),
            table("SSH logins from this address", (("server", "Server", "text"), ("user", "Account", "mono"), ("outcome", "Outcome", "badge"), ("count", "Times", "num")), [
                {"server": k[0], "user": k[1], "outcome": badge(k[2], "critical" if k[2] == "accepted" else "medium"), "count": v["count"]} for k, v in sorted(logins.items(), key=lambda kv: -kv[1]["count"])],
                empty="No SSH logins from this address."),
            table("Open incidents involving it", (("ref", "Incident", "text"), ("status", "Status", "badge"), ("severity", "Severity", "num"), ("last", "Last seen", "time")), [
                {"ref": f"INC-{i['id']:04d} {i['title']}", "status": badge(i["status"], "high" if i["status"] == "open" else ""), "severity": i["severity"], "last": i["last_seen"],
                 "_href": f"#/incidents/{i['id']}"} for i in incidents], empty="No incident names this address."),
            table(f"Timeline{f' · newest {min(len(timeline), 200)} of {len(timeline)}' if len(timeline) > 200 else ''}",
                  (("time", "Time", "time"), ("source", "Source", "badge"), ("what", "What happened", "wrap"), ("where", "Where", "text")), [
                      {"time": t["time"], "source": badge(t["source"], t["tone"]), "what": t["what"], "where": t["where"], **({"_detail": t["detail"]} if t.get("detail") else {})}
                      for t in timeline[:200]],
                  note=" ".join(filter(None, [f"First seen {min(times)}, last seen {max(times)}." if times else "",
                                              f"Wazuh, the WAF and CERBERUS cover the chosen period; Snort, logins and other logs the last {LOG_HOURS} hours.",
                                              "Could not read: " + "; ".join(problems) if problems else ""])),
                  empty="No source recorded this address in the period."),
        ]}


def _count(values) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def _recent_attackers(conn) -> list[dict]:
    """External addresses CERBERUS recorded in the last day, with how many sources saw them."""
    rows = conn.execute("SELECT source_ip, GROUP_CONCAT(DISTINCT source) AS sources, COUNT(*) AS n FROM events WHERE source_ip != '' AND ts >= ? "
                        "GROUP BY source_ip ORDER BY COUNT(DISTINCT source) DESC, n DESC LIMIT 60", (store.ago(hours=24),)).fetchall()
    return [{"ip": r["source_ip"], "sources": r["sources"], "hits": r["n"], "_href": f"#/ip?ip={r['source_ip']}"} for r in rows if is_public(r["source_ip"])][:25]



def _name_to_ip(c: dict, agents: list[dict]) -> dict[str, str]:
    names = {a["name"]: a["ip"] for a in agents if a.get("name") and a.get("ip") and a["ip"] != "127.0.0.1"}
    if c["loki"]:
        try:
            uid = c["grafana"]["loki_uid"]
            result = (grafana._get(c["grafana"], f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query",
                                   {"query": 'sum by (host, ip) (count_over_time({host=~".+", ip=~".+"}[30m]))', "time": int(time.time())}) or {}).get("data", {}).get("result", [])
            names.update({r["metric"]["host"]: r["metric"]["ip"] for r in result if r.get("metric", {}).get("host") and r["metric"].get("ip")})
        except Exception:
            pass
    return names


def machines(conn) -> tuple[list[dict], list[str]]:
    """Every server CERBERUS can see, merged by IP address, with what each source says about it. Remembered for five minutes."""
    def load():
        c = _configs(conn)
        g, w = c["grafana"], c["wazuh"]
        jobs = {}
        if c["wazuh_ready"]:
            def from_wazuh():
                client = wazuh._Client(w)
                try:
                    agents = [a for a in wazuh._agent_rows(client) if a.get("id") != "000"]
                    scores = {}
                    for a in agents:
                        try:
                            policies = client.api(f"/sca/{a['id']}").get("affected_items", [])
                            if policies:
                                scores[a["name"]] = min(int(p.get("score") or 0) for p in policies)
                        except wazuh.WazuhError:
                            pass
                    vulns = client.search({"size": 0, "aggs": {"a": {"terms": {"field": "agent.name", "size": 100}, "aggs": {"s": {"terms": {"field": "vulnerability.severity", "size": 6}}}}}},
                                          index="wazuh-states-vulnerabilities-*")
                    alerts = client.search({"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-24h"}}}, {"range": {"rule.level": {"gte": 12}}}]}},
                                            "aggs": {"a": {"terms": {"field": "agent.name", "size": 100}}}})
                    public = client.search({"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-24h"}}}, {"exists": {"field": "data.srcip"}}],
                                                                           "must_not": [{"prefix": {"data.srcip": p}} for p in ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "192.168.", "127.")]}},
                                            "aggs": {"a": {"terms": {"field": "agent.name", "size": 100}}}})
                finally:
                    client.close()
                bucket = lambda d: {b["key"]: b for b in d.get("aggregations", {}).get("a", {}).get("buckets", [])}
                return agents, scores, {k: {s["key"]: s["doc_count"] for s in v["s"]["buckets"]} for k, v in bucket(vulns).items()}, \
                    {k: v["doc_count"] for k, v in bucket(alerts).items()}, {k: v["doc_count"] for k, v in bucket(public).items()}
            jobs["wazuh"] = from_wazuh
        if g.get("url") and g.get("prometheus_uid"):
            jobs["health"] = lambda: grafana.server_health(g)
        if c["loki"]:
            jobs["snort_to"] = lambda: snort.counts(g, ("dst",), 1440, 200, priority="1")
            jobs["snort_from_public"] = lambda: snort.counts(g, ("dst",), 1440, 200, public_source=True)
            jobs["sensors"] = lambda: snort.counts(g, ("host",), 1440, keep=600)
            jobs["waf"] = lambda: openappsec.all_requests(g, 24, c["inventory"])
            jobs["waf_agents"] = lambda: openappsec.live_agents(g)
        try:
            cves = _vuln_base(conn)
        except Exception as exc:
            cves = ([], [str(exc)[:120]], "")
        found, problems = _parallel(jobs)
        agents, scores, vulns, alerts, public_alerts = found.get("wazuh", ([], {}, {}, {}, {}))
        names = _name_to_ip(c, agents)
        resolve = lambda name: name if _looks_ip(name) else names.get(name, "")
        box: dict[str, dict] = {}

        def machine(ip: str, name: str = "") -> dict:
            m = box.setdefault(ip, {"ip": ip, "names": set(), "sources": set(), "status": "", "os": "", "sca": None, "vulns": {}, "wazuh_alerts": 0,
                                    "public_alerts": 0, "snort_p1": 0, "snort_public": 0, "waf_attacks": 0, "waf_through": 0, "waf_assets": set(), "incidents": 0, "kev": 0, "epss_hot": 0,
                                    "cpu": None, "mem": None, "disk": None, "up": None})
            if name and name != ip:
                m["names"].add(name)
            return m
        for a in agents:
            m = machine(a["ip"] if a.get("ip") and a["ip"] != "127.0.0.1" else a["name"], a["name"])
            m["sources"].add("Wazuh"); m["status"], m["os"] = a.get("status", ""), a.get("os", "")
            m["sca"] = scores.get(a["name"]); m["vulns"] = vulns.get(a["name"], {})
            hot = [r for r in cves[0] if a["name"] in r["agents"]]
            m["kev"], m["epss_hot"] = sum(1 for r in hot if r["kev"]), sum(1 for r in hot if (r["epss"] or 0) >= 0.1)
            m["wazuh_alerts"], m["public_alerts"] = alerts.get(a["name"], 0), public_alerts.get(a["name"], 0)
        for h in (found.get("health") or {}).get("hosts", []):
            ip = h["instance"].rsplit(":", 1)[0]
            m = machine(resolve(ip) or ip); m["sources"].add("Prometheus")
            m["cpu"], m["mem"], m["disk"] = h.get("cpu_pct"), h.get("mem_pct"), h.get("disk_pct")
        for t in (found.get("health") or {}).get("scrape_targets", []):
            ip = t["instance"].rsplit(":", 1)[0]
            if ip in box and t.get("job") == "linux-servers":
                box[ip]["up"] = t.get("up")
        for labels, n in found.get("snort_to") or []:
            if labels["dst"] in box:
                box[labels["dst"]]["snort_p1"] += n
        for labels, n in found.get("snort_from_public") or []:
            if labels["dst"] in box:
                box[labels["dst"]]["snort_public"] += n
        for labels, _ in found.get("sensors") or []:
            ip = resolve(labels["host"])
            if ip:
                machine(ip, labels["host"])["sources"].add("Snort")
        for agent in (found.get("waf_agents") or {}).values():
            ip = resolve(agent["host"])
            if ip:
                machine(ip, agent["host"])["sources"].add("open-appsec")
        hosts = {}
        for a in c["inventory"]["agents"]:
            live = (found.get("waf_agents") or {}).get(a["id"])
            if live:
                hosts[a.get("profile", "")] = resolve(live["host"])
        asset_ip = {a["name"]: hosts.get(a.get("profile", ""), "") for a in c["inventory"]["assets"]}
        for e in found.get("waf") or []:
            ip = asset_ip.get(e["asset"]) or resolve(e["host"])
            if ip in box:
                box[ip]["waf_attacks"] += 1; box[ip]["waf_assets"].add(e["asset"])
                box[ip]["waf_through"] += e["action"] == "Detect"
        for a in c["inventory"]["assets"]:
            if asset_ip.get(a["name"]) in box:
                box[asset_ip[a["name"]]]["waf_assets"].add(a["name"])
        for r in conn.execute("SELECT a.name, COUNT(*) AS n FROM incidents i JOIN assets a ON a.id = i.asset_id WHERE i.status IN ('open', 'investigating') AND i.severity >= 8 GROUP BY a.name"):
            ip = r["name"] if r["name"] in box else resolve(r["name"])
            if ip in box:
                box[ip]["incidents"] += r["n"]
        out = []
        for m in box.values():
            m["exposure"] = "internet-facing" if (m["waf_assets"] or m["public_alerts"] or m["snort_public"]) else "internal"
            m.update(_risk(m))
            m["names"], m["sources"], m["waf_assets"] = sorted(m["names"]), sorted(m["sources"]), sorted(m["waf_assets"])
            out.append(m)
        return sorted(out, key=lambda m: -m["risk"]), problems
    return _cached(("machines",), 300, load)


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _risk(m: dict) -> dict:
    """0-100, from five parts that each have a ceiling, so no single source can dominate.

    Raw counts are misleading (every Linux host carries hundreds of CVEs and thousands of routine alerts),
    so each part weighs evidence of real danger: exploited or likely-exploited CVEs, the most serious
    alerts, attacks that got through, and serious incidents still open.
    """
    critical = m["vulns"].get("Critical", 0)
    parts = {
        "Vulnerabilities": min(30.0, 12 * m["kev"] + 1.0 * m["epss_hot"] + 2 * math.log10(1 + critical)),
        "Configuration": round((100 - m["sca"]) * 0.15, 1) if m["sca"] is not None else 0.0,
        "Recent attacks": min(25.0, 3 * math.log10(1 + m["wazuh_alerts"]) + 3 * math.log10(1 + m["snort_p1"]) + 6 * math.log10(1 + m["waf_through"])),
        "Exposure": 15.0 if m["exposure"] == "internet-facing" else 0.0,
        "Open incidents": min(15.0, 4 * math.log2(1 + m["incidents"])),
    }
    return {"risk": round(min(100, sum(parts.values()))), "risk_parts": {k: round(v, 1) for k, v in parts.items()}}


def risk_page(conn, q: dict) -> dict:
    rows, problems = machines(conn)
    sort = q.get("sort") if q.get("sort") in ("risk", "vulns", "attacks") else "risk"
    key = {"risk": lambda m: -m["risk"], "vulns": lambda m: -(m["vulns"].get("Critical", 0) * 100 + m["vulns"].get("High", 0)),
           "attacks": lambda m: -(m["wazuh_alerts"] + m["snort_p1"] + m["waf_attacks"])}[sort]
    tone = lambda r: "critical" if r >= 60 else "high" if r >= 40 else "medium" if r >= 20 else "ok"
    return {
        "title": "Asset risk", "subtitle": "Every server CERBERUS can see, merged across Wazuh, Prometheus, Snort and the WAF, scored 0-100. Click a row for how the score is made up.",
        "filters": [select("sort", "Order by", sort, (("risk", "Risk score"), ("vulns", "Critical vulnerabilities"), ("attacks", "Recent attacks")))],
        "tiles": [tile("Machines", len(rows)), tile("High risk (60+)", sum(1 for m in rows if m["risk"] >= 60), "critical" if any(m["risk"] >= 60 for m in rows) else ""),
                  tile("Internet-facing", sum(1 for m in rows if m["exposure"] == "internet-facing"), "high" if any(m["exposure"] == "internet-facing" for m in rows) else ""),
                  tile("Riskiest", (rows[0]["names"] or [rows[0]["ip"]])[0] if rows else "—", tone(rows[0]["risk"]) if rows else "")],
        "blocks": [
            bars("Risk score", [{"label": ", ".join(m["names"][:2]) or m["ip"], "value": m["risk"], "tone": tone(m["risk"]) if m["risk"] >= 40 else ""} for m in rows[:10]]),
            table("Machines", (("machine", "Machine", "text"), ("ip", "IP", "mono"), ("risk", "Risk", "badge"), ("exposure", "Exposure", "badge"), ("crit", "Critical CVEs", "num"),
                               ("high", "High CVEs", "num"), ("sca", "Config score", "text"), ("attacks", "Attacks, 24 h", "num"), ("incidents", "Open incidents", "num"), ("sources", "Seen by", "text")), [
                {"machine": ", ".join(m["names"]) or m["ip"], "ip": m["ip"], "risk": badge(m["risk"], tone(m["risk"])),
                 "exposure": badge(m["exposure"], "high" if m["exposure"] == "internet-facing" else "low"), "crit": m["vulns"].get("Critical", 0), "high": m["vulns"].get("High", 0),
                 "sca": f"{m['sca']}%" if m["sca"] is not None else "—", "attacks": m["wazuh_alerts"] + m["snort_p1"] + m["waf_attacks"], "incidents": m["incidents"],
                 "sources": ", ".join(m["sources"]),
                 "_detail": "How the score is made up:\n" + "\n".join(f"  {k}: {v}" for k, v in m["risk_parts"].items())
                            + f"\n\nExploited CVEs (CISA): {m['kev']}\nCVEs likely to be exploited soon (EPSS 10%+): {m['epss_hot']}\nCritical CVEs: {m['vulns'].get('Critical', 0)}"
                            + f"\nWazuh alerts level 12+ (24 h): {m['wazuh_alerts']}\nSnort priority 1 alerts against it (24 h): {m['snort_p1']}"
                            + f"\nWAF attacks on its sites (24 h): {m['waf_attacks']}, of which let through (detected only): {m['waf_through']}\nSerious open incidents: {m['incidents']}"
                            + (f"\nSites behind its firewall: {', '.join(m['waf_assets'])}" if m["waf_assets"] else "")
                            + (f"\nResources now: CPU {m['cpu']}%, memory {m['mem']}%, disk {m['disk']}%" if m["cpu"] is not None else "")
                            + (f"\nOperating system: {m['os']}" if m["os"] else "")}
                for m in sorted(rows, key=key)],
                note=" ".join(filter(None, ["Score parts: vulnerabilities up to 30 (exploited and likely-exploited CVEs count most), configuration up to 15, serious recent attacks up to 25, "
                                            "internet exposure 15, serious open incidents up to 15.",
                                            "Could not read: " + "; ".join(problems) if problems else ""])), empty="No machines found."),
        ]}



KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TIERS = (("now", "Fix now", "critical"), ("soon", "Fix soon", "high"), ("plan", "Plan", "medium"), ("low", "Low", "low"))


def _kev() -> tuple[dict, str]:
    """CISA's list of vulnerabilities known to be exploited in the wild. Downloaded once a day and kept on disk."""
    path = DATA_DIR / "kev.json"
    try:
        fresh = path.exists() and time.time() - path.stat().st_mtime < 86400
        if not fresh:
            resp = httpx.get(KEV_URL, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            path.write_bytes(resp.content)
        data = json.loads(path.read_text(encoding="utf-8"))
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}, data.get("dateReleased", "")
    except Exception as exc:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return {v["cveID"]: v for v in data.get("vulnerabilities", [])}, data.get("dateReleased", "") + " (could not refresh)"
        raise RuntimeError(f"Could not download the CISA known-exploited list: {exc}") from exc


def _epss(cves: list[str]) -> dict[str, float]:
    """FIRST's EPSS: the chance a vulnerability is exploited in the next 30 days. Kept on disk for a day."""
    path = DATA_DIR / "epss.json"
    try:
        kept = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError:
        kept = {}
    day = time.strftime("%Y-%m-%d")
    wanted = [c for c in cves if not (c in kept and kept[c][1] == day)]
    for i in range(0, min(len(wanted), 1000), 100):
        try:
            resp = httpx.get(EPSS_URL, params={"cve": ",".join(wanted[i:i + 100])}, timeout=20)
            for row in resp.json().get("data", []):
                kept[row["cve"]] = [float(row.get("epss") or 0), day]
            for c in wanted[i:i + 100]:
                kept.setdefault(c, [0.0, day])
        except Exception:
            break
    try:
        path.write_text(json.dumps(kept), encoding="utf-8")
    except OSError:
        pass
    return {c: v[0] for c, v in kept.items()}


def _vuln_base(conn) -> tuple[list[dict], list[str], str]:
    """Each CVE on the agents with CISA and EPSS evidence, before exposure is considered. Remembered for ten minutes."""
    def load():
        c = _configs(conn)
        if not c["wazuh_ready"]:
            return [], ["Wazuh is not connected"], ""
        client = wazuh._Client(c["wazuh"])
        try:
            data = client.search({"size": 0, "aggs": {"cve": {"terms": {"field": "vulnerability.id", "size": 5000}, "aggs": {
                "sev": {"terms": {"field": "vulnerability.severity", "size": 1}}, "score": {"max": {"field": "vulnerability.score.base"}},
                "agents": {"terms": {"field": "agent.name", "size": 20}}, "pkg": {"terms": {"field": "package.name", "size": 3}}}}}}, index="wazuh-states-vulnerabilities-*")
        finally:
            client.close()
        problems, kev, kev_date = [], {}, ""
        try:
            kev, kev_date = _kev()
        except RuntimeError as exc:
            problems.append(str(exc))
        rows = []
        for b in data.get("aggregations", {}).get("cve", {}).get("buckets", []):
            sev = ((b.get("sev") or {}).get("buckets") or [{"key": ""}])[0]["key"]
            rows.append({"cve": b["key"], "severity": sev, "cvss": (b.get("score") or {}).get("value"), "count": b["doc_count"],
                         "agents": [a["key"] for a in b["agents"]["buckets"]], "packages": [p["key"] for p in b["pkg"]["buckets"]], "kev": kev.get(b["key"])})
        ranked = sorted(rows, key=lambda r: (not r["kev"], -(r["cvss"] or 0)))
        epss = _epss([r["cve"] for r in ranked if r["cve"].startswith("CVE-")][:800])
        for r in rows:
            r["epss"] = epss.get(r["cve"])
            r["cvss"] = round(r["cvss"], 1) if r["cvss"] else None
        if not epss:
            problems.append("Could not reach FIRST for exploit-likelihood (EPSS) scores")
        return rows, problems, kev_date
    return _cached(("vuln-base",), 600, load)


def vulnerabilities(conn) -> tuple[list[dict], list[str], str]:
    """Each CVE on the agents, with exploitation evidence and exposure. Remembered for ten minutes."""
    def load():
        base, problems, kev_date = _vuln_base(conn)
        rows = [dict(r) for r in base]
        exposed = set()
        try:
            for m in machines(conn)[0]:
                if m["exposure"] == "internet-facing":
                    exposed.update(m["names"])
        except Exception:
            pass
        for r in rows:
            r["exposed"] = [a for a in r["agents"] if a in exposed]
            cvss = r["cvss"] or 0
            r["tier"] = ("now" if r["kev"] else "soon" if (r["epss"] or 0) >= 0.1 or (cvss >= 9 and r["exposed"])
                         else "plan" if cvss >= 7 or r["severity"] in ("Critical", "High") else "low")
        order = {t[0]: i for i, t in enumerate(TIERS)}
        rows.sort(key=lambda r: (order[r["tier"]], -(r["epss"] or 0), -(r["cvss"] or 0), -len(r["exposed"])))
        return rows, problems, kev_date
    return _cached(("vulns",), 600, load)


def vulns_page(conn, q: dict) -> dict:
    rows, problems, kev_date = vulnerabilities(conn)
    tier = q.get("tier") if q.get("tier") in {t[0] for t in TIERS} else ""
    agent = store.text(q.get("agent"), 120)
    words = store.text(q.get("text"), 80).lower()
    agents = sorted({a for r in rows for a in r["agents"]})
    shown = [r for r in rows if (not tier or r["tier"] == tier) and (not agent or agent in r["agents"])
             and (not words or words in r["cve"].lower() or any(words in p.lower() for p in r["packages"]))]
    count = {t[0]: sum(1 for r in rows if r["tier"] == t[0]) for t in TIERS}
    names = {t[0]: (t[1], t[2]) for t in TIERS}
    return {
        "title": "Vulnerability priority", "subtitle": "Every CVE on your agents, ranked by whether it is being exploited in the wild, how likely that is soon, and whether the machine faces the internet.",
        "filters": [select("tier", "Priority", tier, [("", "All priorities")] + [(t[0], t[1]) for t in TIERS]),
                    select("agent", "Agent", agent, [("", "All agents")] + [(a, a) for a in agents]), search_box("text", "Search CVE or package", words, 220)],
        "tiles": [tile(t[1], count[t[0]], t[2] if count[t[0]] and t[0] in ("now", "soon") else "", href=link("#/vulns", {"agent": agent}, tier=t[0])) for t in TIERS],
        "blocks": [
            segments("By priority", [{"label": t[1], "value": count[t[0]], "tone": t[2]} for t in TIERS]),
            table(f"CVEs{f' · first 300 of {len(shown):,}' if len(shown) > 300 else ''}",
                  (("cve", "CVE", "mono"), ("tier", "Priority", "badge"), ("kev", "Exploited in the wild", "badge"), ("epss", "Chance of exploit (30 days)", "text"),
                   ("cvss", "CVSS", "num"), ("agents", "Machines", "wrap"), ("package", "Package", "text")), [
                      {"cve": r["cve"], "tier": badge(names[r["tier"]][0], names[r["tier"]][1]), "kev": badge("yes", "critical") if r["kev"] else "",
                       "epss": f"{r['epss'] * 100:.1f}%" if r["epss"] is not None else "—", "cvss": r["cvss"] or "",
                       "agents": ", ".join(r["agents"][:4]) + (f" +{len(r['agents']) - 4}" if len(r["agents"]) > 4 else "") + (" (internet-facing)" if r["exposed"] else ""),
                       "package": ", ".join(r["packages"][:2]), "_url": f"https://nvd.nist.gov/vuln/detail/{r['cve']}",
                       "_detail": "\n".join(filter(None, [
                           f"Known exploited (CISA, added {r['kev'].get('dateAdded')}): {r['kev'].get('vulnerabilityName', '')}" if r["kev"] else "",
                           f"CISA required action: {r['kev'].get('requiredAction', '')}" if r["kev"] else "",
                           f"Severity {r['severity'] or 'unrated'}, CVSS {r['cvss'] or 'n/a'}", f"Packages: {', '.join(r['packages'])}",
                           f"On: {', '.join(r['agents'])}", f"Internet-facing machines among them: {', '.join(r['exposed'])}" if r["exposed"] else ""]))}
                      for r in shown[:300]],
                  note=" ".join(filter(None, [
                      "Fix now: CISA lists it as exploited in the wild. Fix soon: at least 10% chance of exploitation in the next 30 days (FIRST EPSS), or critical on an internet-facing machine. "
                      "Plan: high or critical otherwise.", f"CISA list dated {kev_date}." if kev_date else "", "Could not read: " + "; ".join(problems) if problems else ""])),
                  empty="No vulnerabilities match."),
        ]}



def usage_page(conn, q: dict) -> dict:
    hours = {"24": 24, "168": 168, "720": 720}.get(q.get("hours"), 24)
    since = store.ago(hours=hours)
    rows = [dict(r) for r in conn.execute("SELECT * FROM ai_usage WHERE ts >= ? ORDER BY id DESC", (since,))]
    tools = conn.execute("SELECT detail FROM audit_logs WHERE action = 'ai.tool_call' AND ts >= ?", (since,)).fetchall()
    from .ai import PURPOSES
    total_in, total_out = sum(r["prompt_tokens"] for r in rows), sum(r["completion_tokens"] for r in rows)
    failures = sum(1 for r in rows if not r["ok"])
    runs = len({r["run_id"] for r in rows if r["run_id"]})
    step = 3600 if hours <= 24 else 21600 if hours <= 168 else 86400
    end = int(time.time()) // step * step + step
    start = end - hours * 3600
    slots = (end - start) // step
    series = {"Prompt tokens": [0] * slots, "Answer tokens": [0] * slots}
    for r in rows:
        t = datetime.strptime(r["ts"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        i = int((t - start) // step)
        if 0 <= i < slots:
            series["Prompt tokens"][i] += r["prompt_tokens"]; series["Answer tokens"][i] += r["completion_tokens"]
    group = lambda key: _sum_by(rows, key)
    per_tool: dict[str, list[int]] = {}
    for t in tools:
        try:
            d = json.loads(t["detail"] or "{}")
        except ValueError:
            continue
        stats = per_tool.setdefault(d.get("tool", "?"), [0, 0])
        stats[0] += 1; stats[1] += 1 if d.get("error") else 0
    latency = sorted(r["ms"] for r in rows if r["ok"])
    from .ai import active_provider
    current = active_provider(conn)
    return {
        "title": "AI usage", "subtitle": "Every call CERBERUS made to an AI model: what for, who asked, how many tokens, how long it took.",
        "filters": [select("hours", "Period", str(hours), (("24", "Last 24 hours"), ("168", "Last 7 days"), ("720", "Last 30 days")))],
        "tiles": [tile("Model calls", len(rows), hint=f"{runs} agent runs"), tile("Tokens used", total_in + total_out, hint=f"{total_in:,} in · {total_out:,} out"),
                  tile("Typical wait", f"{latency[len(latency) // 2] / 1000:.1f} s" if latency else "—", hint="median per call"),
                  tile("Failed calls", failures, "critical" if failures and failures >= len(rows) / 4 else "high" if failures else "ok" if rows else "")],
        "blocks": [
            {"type": "lines", "title": "Tokens over time", "unit": "", "wide": True, "start": start * 1000, "step": step * 1000, "note": "",
             "series": [{"name": k, "v": v} for k, v in series.items()] if rows else []},
            bars("Tokens by purpose", [{"label": PURPOSES.get(k, k), "value": v["tokens"]} for k, v in group("purpose")]),
            bars("Agent runs by purpose", [{"label": PURPOSES.get(k, k), "value": len(v["runs"])} for k, v in group("purpose")]),
            bars("Tokens by person", [{"label": k or "system", "value": v["tokens"]} for k, v in group("actor")[:8]]),
            bars("Tokens by model", [{"label": k, "value": v["tokens"]} for k, v in group("model")[:8]]),
            table("Lookups the analyst ran", (("tool", "Lookup", "text"), ("calls", "Times run", "num"), ("errors", "Failed", "num")), [
                {"tool": k, "calls": v[0], "errors": v[1]} for k, v in sorted(per_tool.items(), key=lambda kv: -kv[1][0])], empty="The analyst ran no lookups in this period."),
            table("Recent model calls", (("time", "Time", "time"), ("purpose", "For", "text"), ("actor", "Asked by", "text"), ("model", "Model", "text"),
                                         ("tin", "Tokens in", "num"), ("tout", "Tokens out", "num"), ("secs", "Seconds", "num"), ("ok", "Result", "badge")), [
                {"time": r["ts"], "purpose": PURPOSES.get(r["purpose"], r["purpose"]), "actor": r["actor"] or "system", "model": r["model"], "tin": r["prompt_tokens"],
                 "tout": r["completion_tokens"], "secs": round(r["ms"] / 1000, 1), "ok": badge("ok" if r["ok"] else "failed", "ok" if r["ok"] else "critical"),
                 **({"_detail": r["error"]} if r["error"] else {})} for r in rows[:100]],
                note=" ".join(filter(None, [f"Active model: {current['model']}." if current else "No AI provider is active.",
                                            "Token counts marked as estimates come from providers that do not report usage." if any(r["estimated"] for r in rows) else "",
                                            "Counting started when this feature was installed."])),
                empty="No model calls in this period."),
        ]}


def _sum_by(rows: list[dict], key: str) -> list[tuple[str, dict]]:
    out: dict[str, dict] = {}
    for r in rows:
        v = out.setdefault(r[key], {"tokens": 0, "runs": set()})
        v["tokens"] += r["total_tokens"]; v["runs"].add(r["run_id"])
    return sorted(out.items(), key=lambda kv: -kv[1]["tokens"])


def _patch_page(conn, q):
    from . import patches
    return patches.page(conn, q)


def _forecast_page(conn, q):
    from . import predict
    return predict.page(conn, q)


PAGES = {"patches": _patch_page, "forecast": _forecast_page, "ip": ip_profile, "risk": risk_page, "vulns": vulns_page, "ai-usage": usage_page}
