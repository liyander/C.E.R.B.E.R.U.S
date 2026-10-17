"""open-appsec (web application firewall): read its decisions from the agents' own event stream.

Each open-appsec agent writes one JSON line per event to its output: every request it blocked or
flagged, plus policy loads and restarts. Where the agent containers' output is shipped to Loki,
CERBERUS reads it there through Grafana, so nothing is installed on the agents and no cloud
portal key is needed. Everything here is read-only.

A firewall judges far fewer requests than it sees, so a period's events are fetched in one
query and counted here, which is much faster than asking Loki to parse and group them.
"""
import json
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from . import grafana, store

SELECTOR = '{service_name="appsec-agent"}'
REQUEST = "Web Request"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
ACTIONS = ("Prevent", "Detect")
LIMIT = 5000
_cache: dict[tuple, tuple[float, list[dict]]] = {}
_lock = threading.Lock()
_requests: dict[str, dict] = {}
_requests_lock = threading.Lock()


def is_ready(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("loki_uid"))


def _lines(cfg: dict, logql: str, start: int, end: int) -> list[tuple[int, str, dict]]:
    """Log lines between two moments (seconds), newest first."""
    uid = store.text(cfg.get("loki_uid"), 80)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", uid):
        raise grafana.GrafanaError("No Loki data source is configured")
    data = (grafana._get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query_range", {
        "query": logql, "start": int(start) * 10**9, "end": int(end) * 10**9, "limit": LIMIT, "direction": "backward"}) or {}).get("data") or {}
    out = [(int(ns), line, stream.get("stream") or {}) for stream in data.get("result", []) for ns, line in stream.get("values", [])]
    return sorted(out, key=lambda item: item[0], reverse=True)[:LIMIT]


def _cached(key: tuple, seconds: int, load) -> list[dict]:
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < seconds:
            return hit[1]
    value = load()
    with _lock:
        _cache[key] = (time.monotonic(), value)
        for old in [k for k, v in _cache.items() if time.monotonic() - v[0] > 600]:
            _cache.pop(old, None)
    return value


def _request_events(cfg: dict, start: int, end: int) -> list[dict]:
    events = []
    for ns, line, labels in _lines(cfg, f'{SELECTOR} |= "{REQUEST}"', start, end):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or e.get("eventName") != REQUEST:
            continue
        d = e.get("eventData") or {}
        events.append({
            "ns": ns, "host": labels.get("host", ""), "time": str(e.get("eventTime", "")) + "Z" if e.get("eventTime") else None,
            "action": d.get("securityAction", ""), "severity": e.get("eventSeverity", ""), "type": d.get("waapIncidentType", ""),
            "method": d.get("httpMethod", ""), "path": d.get("httpUriPath", ""), "query": d.get("httpUriQuery", ""), "site": d.get("httpHostName", ""),
            "source": d.get("httpSourceId") or d.get("sourceIP", ""), "asset": d.get("assetName", ""), "matched": d.get("matchedSample", ""),
            "found_in": d.get("matchedLocation", ""), "parameter": d.get("matchedParameter", ""), "indicators": d.get("waapFoundIndicators", ""),
            "confidence": d.get("eventConfidence", ""), "reputation": d.get("waapUserReputation", ""), "practice": d.get("practiceName", ""),
            "reference": d.get("eventReferenceId", ""), "_text": line.lower()})
    return events


def requests(cfg: dict, hours: int) -> list[dict]:
    """Every request the firewall judged in the period, newest first.

    Searching a week of logs is slow, so what has been read is kept in memory: each call only
    fetches what is newer than the last one, or older than anything read so far.
    """
    now = int(time.time())
    want = now - int(hours) * 3600
    with _requests_lock:
        kept = _requests.get(cfg.get("url"))
        if not kept:
            kept = _requests[cfg.get("url")] = {"from": want, "to": now, "events": _request_events(cfg, want, now + 60)}
        else:
            if now - kept["to"] > 10:
                seen = {(e["ns"], e["host"]) for e in kept["events"][:400]}
                fresh = [e for e in _request_events(cfg, kept["to"] - 10, now + 60) if (e["ns"], e["host"]) not in seen]
                kept["events"], kept["to"] = fresh + kept["events"], now
            if want < kept["from"]:
                kept["events"] += _request_events(cfg, want, kept["from"])
                kept["from"] = want
            horizon = (now - 31 * 86400) * 10**9
            kept["events"] = [e for e in kept["events"] if e["ns"] >= horizon]
        return [e for e in kept["events"] if e["ns"] >= want * 10**9]


def agent_events(cfg: dict, hours: int = 168) -> list[dict]:
    """Everything else the agents wrote (policy loads, restarts), newest first. Remembered for five minutes."""
    def load():
        events = []
        for ns, line, labels in _lines(cfg, f'{SELECTOR} != "{REQUEST}"', int(time.time()) - int(hours) * 3600, int(time.time()) + 60):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict):
                source = e.get("eventSource") or {}
                events.append({"ns": ns, "host": labels.get("host", ""), "time": str(e.get("eventTime", "")) + "Z" if e.get("eventTime") else None,
                               "name": e.get("eventName", ""), "agent": source.get("agentId", ""), "version": source.get("issuingEngineVersion", "")})
        return events
    return _cached((cfg.get("url"), "agent", int(hours)), 300, load)


def pick(events: list[dict], *, host="", action="", severity="", text="") -> list[dict]:
    words = store.text(text, 120).lower()
    return [e for e in events if (not host or e["host"] == host) and (action not in ACTIONS or e["action"] == action)
            and (severity not in SEVERITIES or e["severity"] == severity) and (not words or words in e["_text"])]


def tally(events: list[dict], key: str) -> list[tuple[str, int]]:
    return Counter(e[key] for e in events).most_common()


def attack_types(events: list[dict]) -> dict[str, dict[str, int]]:
    """open-appsec names several attack types on one request ("Path Traversal, Remote Code Execution"); count each on its own."""
    out: dict[str, dict[str, int]] = {}
    for e in events:
        for name in [t.strip() for t in str(e["type"]).split(",") if t.strip()] or ["Unclassified"]:
            bucket = out.setdefault(name, {"total": 0, "Prevent": 0, "Detect": 0})
            bucket["total"] += 1
            if e["action"] in ACTIONS:
                bucket[e["action"]] += 1
    return dict(sorted(out.items(), key=lambda kv: kv[1]["total"], reverse=True))


def over_time(events: list[dict], hours: int, step: int) -> tuple[int, dict[str, list[int]]]:
    """Requests per time step, split by what the firewall did: (start in seconds, {action: counts})."""
    end = int(time.time()) // step * step + step
    start = end - int(hours) * 3600
    slots = (end - start) // step
    out = {action: [0] * slots for action in ACTIONS}
    for e in events:
        index = int((e["ns"] / 1e9 - start) // step)
        if 0 <= index < slots and e["action"] in out:
            out[e["action"]][index] += 1
    return start, out


def brief(e: dict) -> dict:
    keys = ("time", "host", "action", "severity", "type", "method", "site", "path", "source", "asset", "found_in", "confidence", "reputation")
    return {**{k: e[k] for k in keys if e.get(k)}, **({"query": e["query"][:200]} if e["query"] else {}), **({"matched": e["matched"][:200]} if e["matched"] else {})}


def summary(cfg: dict, *, hours=24, action="", text="", limit=15, recorded: dict | None = None) -> dict:
    """For the AI analyst: what the firewall judged in a period, and the newest requests behind it."""
    hours = store.clamp(hours, 1, 720, 24)
    everything = all_requests(cfg, hours, recorded)
    events = pick(everything, action=action, text=text)
    return {
        "backend": "open-appsec (web application firewall)", "window_hours": hours, "requests_judged": len(events),
        "blocked": sum(1 for e in events if e["action"] == "Prevent"), "detected_not_blocked": sum(1 for e in events if e["action"] == "Detect"),
        "by_severity": dict(tally(events, "severity")),
        "attack_types": [{"type": name, "requests": c["total"], "blocked": c["Prevent"], "detected_only": c["Detect"]} for name, c in list(attack_types(events).items())[:12]],
        "top_paths": [{"path": k, "requests": n} for k, n in tally(events, "path")[:10]],
        "top_sources": [{"source": k, "requests": n} for k, n in tally(events, "source")[:10]],
        "protected_assets": [{"asset": k, "requests": n} for k, n in tally(events, "asset")[:10]],
        "agent_hosts": [{"host": k, "requests": n} for k, n in tally(events, "host")],
        "latest_requests": [brief(e) for e in events[:store.clamp(limit, 1, 40, 15)]],
        "note": "Prevent = blocked. Detect = seen and allowed through. A private source address (172.x, 10.x) is a proxy or container in front of the agent, "
                "not the real client. Requests of type '" + UNCLASSIFIED + "' come from the web server's access log for assets whose detailed events go to the cloud only."}



ASSET_FIELDS = ("name", "address", "profile")
AGENT_FIELDS = ("id", "profile", "kind", "installed")


def parse_lines(text_block: str, fields: tuple) -> list[dict]:
    """'a | b | c' per line -> [{field: value}]; blank lines and lines without a first value are skipped."""
    rows = []
    for line in str(text_block or "").splitlines()[:200]:
        parts = [store.text(p, 160) for p in line.split("|")]
        if parts and parts[0]:
            rows.append({f: (parts[i] if i < len(parts) else "") for i, f in enumerate(fields)})
    return rows


def format_lines(rows: list[dict], fields: tuple) -> str:
    return "\n".join(" | ".join(str(r.get(f, "")) for f in fields).rstrip(" |") for r in rows)


def inventory(conn) -> dict:
    from .db import get_integration
    saved = get_integration(conn, "openappsec")
    return {"assets": [a for a in saved.get("assets", []) if isinstance(a, dict) and a.get("name")],
            "agents": [a for a in saved.get("agents", []) if isinstance(a, dict) and a.get("id")]}


def live_agents(cfg: dict) -> dict[str, dict]:
    """Agents seen in the event stream in the last 7 days, by agent ID: server, version, restarts, last policy load."""
    agents: dict[str, dict] = {}
    for e in agent_events(cfg):
        if not e["agent"]:
            continue
        row = agents.setdefault(e["agent"], {"host": e["host"], "version": e["version"], "starts": 0, "policy": None, "seen": e["time"]})
        row["starts"] += "started" in e["name"]
        if "Policy Loaded" in e["name"] and not row["policy"]:
            row["policy"] = e["time"]
    return agents



GATEWAY = '{service_name="appsec-nginx"}'
_ACCESS = ' |~ "HTTP/[0-9.]+\\" [0-9]{3} "'


def gateway_traffic(cfg: dict, hours: int) -> dict[str, dict]:
    """Per agent server: requests seen, how many were uptime probes, how many were blocked. Remembered for five minutes."""
    def load():
        uid = store.text(cfg.get("loki_uid"), 80)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", uid):
            raise grafana.GrafanaError("No Loki data source is configured")

        def count(extra: str) -> dict[str, int]:
            data = (grafana._get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query", {
                "time": int(time.time()), "query": f"sum by (host) (count_over_time({GATEWAY}{_ACCESS}{extra} [{int(hours)}h]))"}) or {}).get("data") or {}
            return {(r.get("metric") or {}).get("host", ""): int(float(r["value"][1])) for r in data.get("result", [])}
        with ThreadPoolExecutor(max_workers=3) as pool:
            total, probes, blocked = pool.map(count, ("", ' |= "Blackbox-Exporter"', ' |~ "HTTP/[0-9.]+\\" 403 "'))
        return [{host: {"requests": n, "probes": probes.get(host, 0), "visitors": max(0, n - probes.get(host, 0)), "blocked": blocked.get(host, 0)}
                 for host, n in total.items()}]
    return _cached((cfg.get("url"), "gateway", int(hours)), 300, load)[0]


_ACCESS_LINE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
UNCLASSIFIED = "Blocked at the gateway (type not reported)"


def gateway_blocked(cfg: dict, hours: int) -> list[dict]:
    """Requests the gateways answered with 403, from their access logs, newest first. Remembered briefly, so a new block shows within seconds."""
    def load():
        now = int(time.time())
        rows = []
        for ns, line, labels in _lines(cfg, GATEWAY + ' |~ "HTTP/[0-9.]+\\" 403 "', now - int(hours) * 3600, now + 60):
            found = _ACCESS_LINE.match(line)
            if found and found.group(4) == "403":
                path, _, query = found.group(3).partition("?")
                rows.append({"ns": ns, "host": labels.get("host", ""), "source": found.group(1), "method": found.group(2), "path": path, "query": query,
                             "browser": found.group(5), "_text": line.lower()})
        return rows
    return _cached((cfg.get("url"), "gateway403", int(hours)), 15 if int(hours) <= 24 else 60, load)


def all_requests(cfg: dict, hours: int, recorded: dict | None = None) -> list[dict]:
    """The agents' own events, plus blocked requests that only the gateway log shows.

    An asset whose log trigger sends events to the cloud only leaves nothing in the agent's output,
    but its web server still logs each blocked request. Those are added here, attributed to an asset
    when that can be known: the asset is alone behind that server, or it is the one asset there that
    does not report (anything the others reported is matched by time and path and left out).
    """
    events = requests(cfg, hours)
    recorded = recorded or {"assets": [], "agents": []}
    if not recorded["assets"]:
        return events
    try:
        blocked, live = gateway_blocked(cfg, hours), live_agents(cfg)
    except grafana.GrafanaError:
        return events
    servers: dict[str, list[str]] = {}
    profile_server = {a["profile"]: live[a["id"]]["host"] for a in recorded["agents"] if a.get("profile") and a["id"] in live}
    for asset in recorded["assets"]:
        server = profile_server.get(asset.get("profile", ""))
        if server:
            servers.setdefault(server, []).append(asset["name"])
    reporting = {e["asset"] for e in events}
    seen = {(e["host"], int(e["ns"] // 10**9) + d, e["path"]) for e in events for d in (-2, -1, 0, 1, 2)}
    address = {a["name"]: a.get("address", "") for a in recorded["assets"]}
    extra = []
    for b in blocked:
        behind = servers.get(b["host"], [])
        if (b["host"], int(b["ns"] // 10**9), b["path"]) in seen:
            continue
        silent = [name for name in behind if name not in reporting]
        asset = behind[0] if len(behind) == 1 else silent[0] if len(silent) == 1 else ""
        if not asset:
            continue
        extra.append({
            "ns": b["ns"], "host": b["host"], "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(b["ns"] / 1e9)) + "Z", "action": "Prevent", "severity": "",
            "type": UNCLASSIFIED, "method": b["method"], "path": b["path"], "query": b["query"], "site": address.get(asset, ""), "source": b["source"], "asset": asset,
            "matched": "", "found_in": "", "parameter": "", "indicators": "", "confidence": "", "reputation": "", "practice": "", "reference": "",
            "browser": b["browser"], "via": "gateway", "_text": b["_text"] + " " + asset.lower() + " " + UNCLASSIFIED.lower()})
    return sorted(events + extra, key=lambda e: e["ns"], reverse=True) if extra else events

