"""Wazuh integration: CERBERUS pulls detections from Wazuh; nothing is installed on the Wazuh server.

Alerts are read from the Wazuh indexer, either directly (port 9200) or through the Wazuh
dashboard's query proxy when only the dashboard is reachable. A busy Wazuh raises thousands
of near-identical alerts an hour, so they are not copied one by one: each poll groups them by
agent, rule and source IP for the current hour and keeps ONE event per group with a running
count. The normal correlation then turns those into incidents.
"""
import hashlib
import logging
import threading
from datetime import datetime, timedelta, timezone

import httpx

from . import store
from .db import db, get_integration, get_setting, now, set_setting

log = logging.getLogger("cerberus.wazuh")

DEFAULTS = {"enabled": False, "url": "", "username": "", "password": "", "verify_tls": True, "mode": "",
            "min_level": 7, "exclude_rules": "", "poll_minutes": 2}
INDEX = "wazuh-alerts-*"
MAX_GROUPS = 500
EVENT_TYPES = (
    ("vulnerability-detector", "vulnerability"),
    ("authentication_failed", "authentication_failure"),
    ("authentication_failures", "authentication_failure"),
    ("authentication_success", "authentication_success"),
    ("syscheck", "file_integrity"),
    ("rootcheck", "rootkit_check"),
    ("attack", "web_attack"),
    ("web", "web_attack"),
    ("ids", "network_ids"),
    ("sudo", "privilege_use"),
)
_lock = threading.Lock()


class WazuhError(Exception):
    pass


def settings(conn) -> dict:
    return {**DEFAULTS, **{k: v for k, v in get_integration(conn, "wazuh").items() if k in DEFAULTS}}


def is_ready(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("username") and cfg.get("password"))


def severity(level) -> int:
    """Wazuh levels run 0-15; CERBERUS uses 1-10 (4+ can open an incident, 7+ is high, 9+ critical)."""
    try:
        return max(1, min(10, round(float(level) * 10 / 15)))
    except (TypeError, ValueError):
        return 5


def event_type(groups) -> str:
    groups = groups or []
    return next((mapped for group, mapped in EVENT_TYPES if group in groups), groups[0] if groups else "alert")


class _Client:
    """One signed-in connection to the indexer, direct or through the dashboard."""

    def __init__(self, cfg: dict):
        if not is_ready(cfg):
            raise WazuhError("Wazuh is not configured")
        self.cfg = cfg
        self.base = str(cfg["url"]).rstrip("/")
        if not self.base.startswith(("http://", "https://")):
            raise WazuhError("The Wazuh address must start with http:// or https://")
        self.http = httpx.Client(verify=cfg.get("verify_tls", True), timeout=40, headers={"osd-xsrf": "true"})
        self.api_host = None
        self.mode = cfg.get("mode") or self._detect()
        if self.mode == "dashboard":
            self._call("POST", "/auth/login", json={"username": cfg["username"], "password": cfg["password"]}, what="sign-in")

    def _call(self, method, path, what="request", **kwargs):
        try:
            resp = self.http.request(method, self.base + path, **kwargs)
        except httpx.HTTPError as exc:
            hint = " If it uses a self-signed certificate, turn off certificate verification." if "CERTIFICATE" in str(exc).upper() else ""
            raise WazuhError(f"Could not reach Wazuh at {self.base}: {exc}.{hint}"[:400]) from exc
        if resp.status_code == 401:
            raise WazuhError("Wazuh rejected the username or password")
        if resp.status_code >= 400:
            raise WazuhError(f"Wazuh {what} failed with HTTP {resp.status_code}: {resp.text[:200]}")
        return resp

    def _detect(self) -> str:
        """The dashboard announces itself with an osd-name header; anything else is treated as the indexer."""
        try:
            resp = self.http.get(self.base + "/", follow_redirects=False)
        except httpx.HTTPError as exc:
            hint = " If it uses a self-signed certificate, turn off certificate verification." if "CERTIFICATE" in str(exc).upper() else ""
            raise WazuhError(f"Could not reach Wazuh at {self.base}: {exc}.{hint}"[:400]) from exc
        return "dashboard" if "osd-name" in resp.headers else "indexer"

    def search(self, body: dict, index: str = INDEX) -> dict:
        if self.mode == "dashboard":
            resp = self._call("POST", "/api/console/proxy", params={"path": f"{index}/_search", "method": "POST"}, json=body, what="search")
        else:
            resp = self._call("POST", f"/{index}/_search", json=body, auth=(self.cfg["username"], self.cfg["password"]), what="search")
        try:
            return resp.json()
        except ValueError as exc:
            raise WazuhError("Wazuh returned something that is not JSON; check the address") from exc

    def api(self, path: str, params: dict | None = None) -> dict:
        """GET on the Wazuh manager API, relayed by the dashboard (the API port itself is rarely reachable)."""
        if self.mode != "dashboard":
            raise WazuhError("Agent and configuration-assessment data comes from the Wazuh manager API, which is only "
                             "reachable when CERBERUS is connected to the Wazuh dashboard address.")
        if self.api_host is None:
            try:
                hosts = self._call("GET", "/hosts/apis", what="API lookup").json()
                self.api_host = str(hosts[0]["id"])
            except (ValueError, LookupError, TypeError) as exc:
                raise WazuhError("The Wazuh dashboard has no manager API configured") from exc
            self._call("POST", "/api/login", json={"idHost": self.api_host, "force": False}, what="API sign-in")
        resp = self._call("POST", "/api/request", what="API request",
                          json={"method": "GET", "path": path, "body": {"params": params or {}}, "id": self.api_host})
        try:
            return resp.json().get("data") or {}
        except (ValueError, AttributeError) as exc:
            raise WazuhError("Wazuh returned something that is not JSON; check the address") from exc

    def close(self):
        self.http.close()


def _filters(cfg: dict, start: str, end: str | None = None) -> tuple[list[dict], list[dict]]:
    """(filters, exclusions) for alerts at or above the configured level in a time range."""
    time_range = {"gte": start, **({"lt": end} if end else {})}
    filters = [{"range": {"timestamp": time_range}}, {"range": {"rule.level": {"gte": int(cfg.get("min_level", 7))}}}]
    excluded = [r.strip() for r in str(cfg.get("exclude_rules", "")).replace(";", ",").split(",") if r.strip().isdigit()]
    return filters, ([{"terms": {"rule.id": excluded}}] if excluded else [])


def _hour_groups(client: _Client, cfg: dict, hour: datetime) -> list[dict]:
    """Alerts of one clock hour, grouped by agent, rule and source IP."""
    start, end = hour.strftime("%Y-%m-%dT%H:00:00.000Z"), (hour + timedelta(hours=1)).strftime("%Y-%m-%dT%H:00:00.000Z")
    filters, excluded = _filters(cfg, start, end)
    data = client.search({
        "size": 0, "query": {"bool": {"filter": filters, "must_not": excluded}},
        "aggs": {"groups": {
            "composite": {"size": MAX_GROUPS, "sources": [
                {"agent": {"terms": {"field": "agent.name"}}}, {"rule": {"terms": {"field": "rule.id"}}},
                {"ip": {"terms": {"field": "data.srcip", "missing_bucket": True}}}]},
            "aggs": {"level": {"max": {"field": "rule.level"}}, "last": {"max": {"field": "timestamp"}},
                     "sample": {"top_hits": {"size": 1, "sort": [{"timestamp": "desc"}], "_source": [
                         "rule.description", "rule.groups", "agent.ip", "full_log", "data.dstuser", "data.srcuser", "data.url", "id"]}}}}}})
    return data.get("aggregations", {}).get("groups", {}).get("buckets", [])


def _store_group(conn, bucket: dict, hour: datetime) -> str:
    """Create or refresh the one event that stands for this agent + rule + IP in this hour."""
    key = bucket["key"]
    agent, rule_id, source_ip = key.get("agent") or "", str(key.get("rule") or ""), key.get("ip") or ""
    sample = ((bucket.get("sample", {}).get("hits", {}).get("hits") or [{}])[0]).get("_source", {})
    rule, data = sample.get("rule") or {}, sample.get("data") or {}
    count = bucket["doc_count"]
    last = (bucket.get("last") or {}).get("value_as_string") or now()
    title = (rule.get("description") or f"Wazuh rule {rule_id}") + (f" (x{count:,})" if count > 1 else "")
    message = (f"{count:,} Wazuh alert{'s' if count != 1 else ''} this hour for rule {rule_id}"
               + (f" from {source_ip}" if source_ip else "") + f" on {agent}. Latest at {last}."
               + (f"\nRequested: {data['url']}" if data.get("url") else "")
               + (f"\nLatest log: {sample['full_log'][:1500]}" if sample.get("full_log") else ""))
    digest = hashlib.sha1(f"{agent}|{rule_id}|{source_ip}".encode()).hexdigest()[:16]
    event = {
        "source": "wazuh", "source_event_id": f"{digest}:{hour.strftime('%Y%m%d%H')}", "asset": agent,
        "asset_ip": (sample.get("agent") or {}).get("ip") or "", "event_type": event_type(rule.get("groups")),
        "severity": severity((bucket.get("level") or {}).get("value")), "timestamp": last, "source_ip": source_ip,
        "username": data.get("dstuser") or data.get("srcuser") or "", "rule_id": rule_id, "title": title, "message": message,
        "evidence_ref": {"backend": "wazuh", "index": INDEX,
                         "query": f"rule.id:{rule_id} AND agent.name:\"{agent}\"" + (f" AND data.srcip:{source_ip}" if source_ip else "")},
    }
    result = store.ingest_event(conn, event)
    if not result["duplicate"]:
        return "new"
    stamp = store.parse_ts(last)
    conn.execute("UPDATE events SET title = ?, message = ?, ts = ?, severity = MAX(severity, ?) WHERE id = ?",
                 (title[:200], message[:4000], stamp, event["severity"], result["event_id"]))
    if result["incident_id"]:
        conn.execute("UPDATE incidents SET last_seen = MAX(last_seen, ?), severity = MAX(severity, ?) WHERE id = ?",
                     (stamp, event["severity"], result["incident_id"]))
    return "updated"


def sync(reason: str = "schedule") -> dict:
    """Pull the current hour (and the previous one just after the hour turns) into events."""
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "A sync is already running"}
    summary = {"ok": True, "reason": reason, "groups": 0, "new": 0, "updated": 0, "error": ""}
    try:
        with db() as conn:
            cfg = settings(conn)
            try:
                client = _Client(cfg)
                try:
                    current = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
                    hours = [current] + ([current - timedelta(hours=1)] if datetime.now(timezone.utc).minute < 6 else [])
                    for hour in hours:
                        for bucket in _hour_groups(client, cfg, hour):
                            summary["groups"] += 1
                            summary[_store_group(conn, bucket, hour)] += 1
                finally:
                    client.close()
            except WazuhError as exc:
                summary.update(ok=False, error=str(exc)[:400])
            set_setting(conn, "wazuh_last_sync", now())
            set_setting(conn, "wazuh_last_result", f"{summary['groups']} groups, {summary['new']} new" if summary["ok"] else summary["error"])
            set_setting(conn, "wazuh_last_ok", "1" if summary["ok"] else "0")
    finally:
        _lock.release()
    return summary


def tick() -> None:
    """Called by the background scheduler every few seconds; syncs when one is due."""
    with db() as conn:
        cfg = settings(conn)
        last = get_setting(conn, "wazuh_last_sync")
        failed = get_setting(conn, "wazuh_last_ok") == "0"
    every = min(2, int(cfg["poll_minutes"])) if failed else int(cfg["poll_minutes"])
    if cfg["enabled"] and is_ready(cfg) and (not last or last <= store.ago(minutes=max(1, every))):
        result = sync("schedule")
        if not result["ok"]:
            log.warning("wazuh sync failed: %s", result["error"])


def test(cfg: dict) -> dict:
    """Sign in and report what the last 24 hours look like at the chosen level."""
    client = _Client(cfg)
    try:
        filters, excluded = _filters(cfg, "now-24h")
        data = client.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filters, "must_not": excluded}},
                              "aggs": {"agents": {"terms": {"field": "agent.name", "size": 20}}}})
    finally:
        client.close()
    return {"ok": True, "mode": client.mode, "alerts_24h": data.get("hits", {}).get("total", {}).get("value", 0),
            "agents": [{"name": b["key"], "alerts": b["doc_count"]} for b in data.get("aggregations", {}).get("agents", {}).get("buckets", [])]}



def search_alerts(cfg: dict, *, agent="", rule_id="", source_ip="", text="", min_level=1, hours=24, limit=20) -> dict:
    """Recent individual alerts straight from Wazuh, for detail the grouped events do not carry."""
    filters = [{"range": {"timestamp": {"gte": f"now-{store.clamp(hours, 1, 720, 24)}h"}}},
               {"range": {"rule.level": {"gte": store.clamp(min_level, 0, 15, 1)}}}]
    for field, value in (("agent.name", agent), ("rule.id", rule_id), ("data.srcip", source_ip)):
        if store.text(value, 120):
            filters.append({"term": {field: store.text(value, 120)}})
    words = store.text(text, 200).replace("*", " ").replace("?", " ").strip()
    must = [{"bool": {"minimum_should_match": 1, "should": [
        {"wildcard": {"rule.description": {"value": f"*{words}*", "case_insensitive": True}}},
        {"match_phrase": {"full_log": words}}]}}] if words else []
    client = _Client(cfg)
    try:
        data = client.search({"size": store.clamp(limit, 1, 30, 20), "sort": [{"timestamp": "desc"}], "track_total_hits": True,
                              "query": {"bool": {"filter": filters, "must": must}},
                              "_source": ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "rule.groups",
                                          "data.srcip", "data.dstuser", "data.srcuser", "data.url", "full_log"]})
    finally:
        client.close()
    alerts = []
    for hit in data.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        rule, d = s.get("rule") or {}, s.get("data") or {}
        alerts.append({k: v for k, v in {
            "time": s.get("timestamp"), "agent": (s.get("agent") or {}).get("name"), "rule_id": rule.get("id"), "level": rule.get("level"),
            "description": rule.get("description"), "source_ip": d.get("srcip"), "user": d.get("dstuser") or d.get("srcuser"),
            "url": d.get("url"), "log": (s.get("full_log") or "")[:400]}.items() if v not in (None, "")})
    return {"backend": "wazuh", "total_matching": data.get("hits", {}).get("total", {}).get("value", 0), "alerts": alerts}


def summary(cfg: dict, *, hours=24, agent="") -> dict:
    """Totals for a period: by level band, top rules, agents and source IPs."""
    filters = [{"range": {"timestamp": {"gte": f"now-{store.clamp(hours, 1, 720, 24)}h"}}}]
    if store.text(agent, 120):
        filters.append({"term": {"agent.name": store.text(agent, 120)}})
    client = _Client(cfg)
    try:
        data = client.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filters}}, "aggs": {
            "levels": {"range": {"field": "rule.level", "ranges": [{"key": "low (0-6)", "to": 7}, {"key": "medium (7-9)", "from": 7, "to": 10},
                                                                   {"key": "high (10-12)", "from": 10, "to": 13}, {"key": "critical (13+)", "from": 13}]}},
            "rules": {"terms": {"field": "rule.id", "size": 10}, "aggs": {"name": {"terms": {"field": "rule.description", "size": 1}},
                                                                         "level": {"max": {"field": "rule.level"}}}},
            "agents": {"terms": {"field": "agent.name", "size": 10}},
            "source_ips": {"terms": {"field": "data.srcip", "size": 10}}}})
    finally:
        client.close()
    aggs = data.get("aggregations", {})
    pairs = lambda name: [{"name": b["key"], "alerts": b["doc_count"]} for b in aggs.get(name, {}).get("buckets", [])]
    return {"backend": "wazuh", "window_hours": store.clamp(hours, 1, 720, 24), "total_alerts": data.get("hits", {}).get("total", {}).get("value", 0),
            "by_level": pairs("levels"), "top_agents": pairs("agents"), "top_source_ips": pairs("source_ips"),
            "top_rules": [{"rule_id": b["key"], "alerts": b["doc_count"], "level": int((b.get("level") or {}).get("value") or 0),
                           "description": ((b.get("name") or {}).get("buckets") or [{"key": ""}])[0]["key"]} for b in aggs.get("rules", {}).get("buckets", [])]}


def _agent_rows(client: _Client, params: dict | None = None) -> list[dict]:
    items = client.api("/agents", {"select": "id,name,ip,status,os.name,os.version,version,lastKeepAlive", "limit": 200,
                                   **(params or {})}).get("affected_items", [])
    return [{k: v for k, v in {
        "id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "status": a.get("status"),
        "os": " ".join(filter(None, [(a.get("os") or {}).get("name"), (a.get("os") or {}).get("version")])),
        "wazuh_version": a.get("version"),
        "last_seen": None if a.get("id") == "000" else a.get("lastKeepAlive")}.items() if v not in (None, "")} for a in items]


def agents(cfg: dict) -> dict:
    """Every machine enrolled in Wazuh and whether it is reporting."""
    client = _Client(cfg)
    try:
        rows = _agent_rows(client)
    finally:
        client.close()
    return {"backend": "wazuh", "total": len(rows), "agents": rows}


def _find_agent(client: _Client, wanted: str) -> dict:
    rows = _agent_rows(client)
    key = wanted.lower()
    match = ([a for a in rows if key in (a.get("name", "").lower(), a.get("id"), a.get("ip"))]
             or [a for a in rows if key in a.get("name", "").lower()])
    if len(match) != 1:
        names = ", ".join(f"{a.get('name')} ({a.get('id')})" for a in rows)
        raise WazuhError(f"{'No' if not match else 'More than one'} Wazuh agent matches '{wanted}'. Agents: {names}")
    return match[0]


def configuration_assessment(cfg: dict, *, agent="", result="failed", text="", limit=25, offset=0) -> dict:
    """Security Configuration Assessment (SCA) for one agent: the score of each benchmark and its checks."""
    wanted = store.text(agent, 120)
    if not wanted:
        raise WazuhError("Give the agent name; wazuh_agents lists them")
    result = result if result in ("failed", "passed", "not applicable", "all") else "failed"
    client = _Client(cfg)
    try:
        found = _find_agent(client, wanted)
        policies = []
        for p in client.api(f"/sca/{found['id']}").get("affected_items", []):
            params = {"limit": store.clamp(limit, 1, 60, 25), "offset": store.clamp(offset, 0, 5000, 0), "sort": "+id"}
            if result != "all":
                params["result"] = result
            if store.text(text, 120):
                params["search"] = store.text(text, 120)
            checks = client.api(f"/sca/{found['id']}/checks/{p.get('policy_id')}", params)
            policies.append({
                "benchmark": p.get("name"), "policy_id": p.get("policy_id"), "score_percent": p.get("score"),
                "passed": p.get("pass"), "failed": p.get("fail"), "not_applicable": p.get("invalid"),
                "total_checks": p.get("total_checks"), "last_scan": p.get("end_scan"),
                "checks_shown": result + (f" matching '{store.text(text, 120)}'" if store.text(text, 120) else ""),
                "checks_matching": checks.get("total_affected_items", 0),
                "checks": [{k: v for k, v in {
                    "id": c.get("id"), "title": c.get("title"), "result": c.get("result") or c.get("status"),
                    "reason": (c.get("reason") or "")[:200],
                    "remediation": (c.get("remediation") or "")[:320]}.items() if v not in (None, "")}
                    for c in checks.get("affected_items", [])]})
    finally:
        client.close()
    if not policies:
        return {"backend": "wazuh", "agent": found, "policies": [],
                "note": "Wazuh has no configuration assessment for this agent: no scan has run or the module is off."}
    return {"backend": "wazuh", "agent": found, "policies": policies}


def status(conn) -> dict:
    cfg = settings(conn)
    password = cfg.pop("password", "")
    return {"settings": {**cfg, "has_password": bool(password)}, "last_sync": get_setting(conn, "wazuh_last_sync"),
            "last_result": get_setting(conn, "wazuh_last_result"), "last_ok": get_setting(conn, "wazuh_last_ok") != "0",
            "events": conn.execute("SELECT COUNT(*) FROM events WHERE source = 'wazuh'").fetchone()[0]}
