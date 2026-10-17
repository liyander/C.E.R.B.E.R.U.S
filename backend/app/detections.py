"""Turn firewall and network-sensor detections into CERBERUS events, so they correlate into incidents.

Wazuh already feeds the incident pipeline. This does the same for Snort and the open-appsec WAF,
behind noise controls an admin chooses, and adds one cross-source rule: an internet address seen by
two or more sources within the hour. Like the Wazuh pull, detections are grouped: one event per
source address, target and rule per clock hour, with a running count in the title.
"""
import hashlib
import logging
import threading
from datetime import datetime, timedelta, timezone

from . import grafana, openappsec, snort, store
from .db import db, get_integration, get_setting, now, set_integration, set_setting
from .insights import is_public

log = logging.getLogger("cerberus.detections")

DEFAULTS = {
    "enabled": True,
    "interval_minutes": 5,
    "snort": True,
    "snort_priority": 1,
    "waf": True,
    "waf_mode": "detected",
    "multi_source": True,
    "multi_min": 2,
}
WAF_MODES = ("detected", "critical", "all")
SNORT_SEVERITY = {"1": 8, "2": 6, "3": 4, "4": 3}
WAF_SEVERITY = {"Critical": 8, "High": 7, "Medium": 5, "Low": 3, "Info": 2}
_lock = threading.Lock()


def settings(conn) -> dict:
    saved = get_integration(conn, "detections")
    merged = {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS}}
    merged["snort_priority"] = store.clamp(merged["snort_priority"], 1, 3, 1)
    merged["multi_min"] = store.clamp(merged["multi_min"], 2, 4, 2)
    merged["waf_mode"] = merged["waf_mode"] if merged["waf_mode"] in WAF_MODES else "detected"
    return merged


def save_settings(conn, changes: dict) -> dict:
    merged = {**settings(conn), **{k: v for k, v in changes.items() if k in DEFAULTS}}
    set_integration(conn, "detections", merged)
    return settings(conn)


def _upsert(conn, event: dict, count: int) -> str:
    """Create or refresh the one event that stands for this group in this hour."""
    title = event["title"][:180] + (f" (x{count:,})" if count > 1 else "")
    result = store.ingest_event(conn, {**event, "title": title})
    if not result["duplicate"]:
        return "new"
    stamp = store.parse_ts(event["timestamp"])
    conn.execute("UPDATE events SET title = ?, message = ?, ts = ?, severity = MAX(severity, ?) WHERE id = ?",
                 (title, event["message"][:4000], stamp, event["severity"], result["event_id"]))
    if result["incident_id"]:
        conn.execute("UPDATE incidents SET last_seen = MAX(last_seen, ?), severity = MAX(severity, ?) WHERE id = ?",
                     (stamp, event["severity"], result["incident_id"]))
    return "updated"


def _key(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _machine_names(conn) -> dict[str, str]:
    """IP -> the name CERBERUS already uses for that machine, so detections land on the right asset."""
    names = {}
    for r in conn.execute("SELECT name, ip FROM assets WHERE ip != ''"):
        names.setdefault(r["ip"], r["name"])
    return names


def run(reason: str = "schedule") -> dict:
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "A pass is already running"}
    summary = {"ok": True, "reason": reason, "snort": 0, "waf": 0, "multi": 0, "new": 0, "updated": 0, "error": ""}
    try:
        with db() as conn:
            s, cfg = settings(conn), get_integration(conn, "grafana")
            if not snort.is_ready(cfg):
                summary.update(ok=False, error="Loki (through Grafana) is not connected")
            else:
                names = _machine_names(conn)
                now_utc = datetime.now(timezone.utc)
                hour = now_utc.replace(minute=0, second=0, microsecond=0)
                minutes = max(1, int((now_utc - hour).total_seconds() // 60))
                hour_key, stamp = hour.strftime("%Y%m%d%H"), now()
                problems = []
                if s["snort"]:
                    for priority in range(1, s["snort_priority"] + 1):
                        try:
                            rows = snort.counts(cfg, ("src", "dst", "sig", "msg", "host"), minutes, 500, keep=1, priority=str(priority))
                        except grafana.GrafanaError as exc:
                            problems.append(f"Snort: {exc}")
                            break
                        groups: dict[tuple, dict] = {}
                        for g, n in rows:
                            item = groups.setdefault((g["dst"], g["sig"]), {"msg": g["msg"], "host": g["host"], "total": 0, "sources": {}})
                            item["total"] += n
                            item["sources"][g["src"]] = item["sources"].get(g["src"], 0) + n
                        for (dst, sig), item in groups.items():
                            top = sorted(item["sources"].items(), key=lambda kv: -kv[1])
                            listed = ", ".join(f"{ip} ({n})" for ip, n in top[:6]) + (f" and {len(top) - 6} more" if len(top) > 6 else "")
                            event = {"source": "snort", "source_event_id": f"{_key(dst, sig)}:{hour_key}", "asset": names.get(dst, dst), "asset_ip": dst,
                                     "event_type": "network_ids", "severity": SNORT_SEVERITY.get(str(priority), 4), "timestamp": stamp,
                                     "source_ip": top[0][0] if len(top) == 1 else "", "rule_id": f"snort:{sig}",
                                     "title": f"{item['msg'] or 'Snort signature ' + sig} against {names.get(dst, dst)} from {len(top)} source{'s' if len(top) != 1 else ''}",
                                     "message": f"{item['total']:,} Snort alert{'s' if item['total'] != 1 else ''} this hour (priority {priority}, signature {sig}) against {dst}, "
                                                f"seen by the sensor on {item['host']}. Sources: {listed}.",
                                     "evidence_ref": {"backend": "loki", "query": f"snort signature {sig} to {dst}"}}
                            summary[_upsert(conn, event, item["total"])] += 1
                            summary["snort"] += 1
                if s["waf"]:
                    try:
                        cutoff = hour.timestamp() * 1e9
                        wanted = {"detected": lambda e: e["action"] == "Detect",
                                  "critical": lambda e: e["action"] == "Detect" or e["severity"] == "Critical",
                                  "all": lambda e: True}[s["waf_mode"]]
                        groups: dict[tuple, list] = {}
                        for e in openappsec.requests(cfg, 2):
                            if e["ns"] >= cutoff and wanted(e):
                                groups.setdefault((e["source"], e["asset"], e["type"]), []).append(e)
                        for (source, asset, kind), items in groups.items():
                            worst = max(items, key=lambda e: WAF_SEVERITY.get(e["severity"], 0))
                            through = sum(1 for e in items if e["action"] == "Detect")
                            event = {"source": "openappsec", "source_event_id": f"{_key(source, asset, kind)}:{hour_key}", "asset": asset or "web firewall",
                                     "event_type": "web_attack", "severity": min(10, WAF_SEVERITY.get(worst["severity"], 5) + (1 if through else 0)),
                                     "timestamp": stamp, "source_ip": source, "rule_id": kind[:60],
                                     "title": f"{'Web attack let through' if through else 'Web attack blocked'}: {kind} on {asset}",
                                     "message": f"{len(items)} request{'s' if len(items) != 1 else ''} this hour from {source} against {asset}: {kind}. "
                                                f"{through} let through (detect mode), {len(items) - through} blocked. Example: {worst['method']} {worst['path'][:200]}",
                                     "evidence_ref": {"backend": "openappsec", "reference": worst.get("reference", "")}}
                            summary[_upsert(conn, event, len(items))] += 1
                            summary["waf"] += 1
                    except grafana.GrafanaError as exc:
                        problems.append(f"WAF: {exc}")
                if s["multi_source"]:
                    seen: dict[str, set] = {}
                    try:
                        for g, _ in snort.counts(cfg, ("src",), 60, 300, keep=1):
                            if is_public(g["src"]):
                                seen.setdefault(g["src"], set()).add("Snort")
                    except grafana.GrafanaError as exc:
                        problems.append(f"Snort: {exc}")
                    try:
                        for e in openappsec.requests(cfg, 1):
                            if is_public(e["source"]):
                                seen.setdefault(e["source"], set()).add("WAF")
                    except grafana.GrafanaError as exc:
                        problems.append(f"WAF: {exc}")
                    for r in conn.execute("SELECT DISTINCT source_ip, source FROM events WHERE ts >= ? AND source_ip != '' AND source IN ('wazuh', 'grafana')",
                                          (store.ago(hours=1),)):
                        if is_public(r["source_ip"]):
                            seen.setdefault(r["source_ip"], set()).add("Wazuh" if r["source"] == "wazuh" else "Grafana")
                    for ip, sources in seen.items():
                        if len(sources) >= s["multi_min"]:
                            listed = ", ".join(sorted(sources))
                            event = {"source": "cerberus", "source_event_id": f"multi:{ip}:{hour_key}", "asset": "multiple sources", "event_type": "multi_source",
                                     "severity": 8 if len(sources) >= 3 else 7, "timestamp": stamp, "source_ip": ip, "rule_id": "multi_source",
                                     "title": f"{ip} seen by {len(sources)} sources: {listed}",
                                     "message": f"The internet address {ip} was seen by {listed} within the last hour. Open the IP view for everything recorded about it.",
                                     "evidence_ref": {"backend": "cerberus", "view": f"#/ip?ip={ip}"}}
                            summary[_upsert(conn, event, 1)] += 1
                            summary["multi"] += 1
                if problems:
                    summary["error"] = "; ".join(problems)[:300]
            set_setting(conn, "detections_last_run", now())
            set_setting(conn, "detections_last_result", summary["error"] or f"{summary['snort']} Snort, {summary['waf']} WAF, {summary['multi']} multi-source groups; {summary['new']} new")
            set_setting(conn, "detections_last_ok", "0" if summary["error"] or not summary["ok"] else "1")
    finally:
        _lock.release()
    return summary


def tick() -> None:
    """Called by the background scheduler; runs a pass when one is due."""
    with db() as conn:
        s = settings(conn)
        last = get_setting(conn, "detections_last_run")
    if s["enabled"] and (not last or last <= store.ago(minutes=s["interval_minutes"])):
        result = run("schedule")
        if result.get("error"):
            log.warning("detections pass: %s", result["error"])


def status(conn) -> dict:
    return {"settings": settings(conn), "last_run": get_setting(conn, "detections_last_run"), "last_result": get_setting(conn, "detections_last_result"),
            "last_ok": get_setting(conn, "detections_last_ok") != "0",
            "events": {r["source"]: r["n"] for r in conn.execute("SELECT source, COUNT(*) AS n FROM events WHERE source IN ('snort', 'openappsec', 'cerberus') GROUP BY source")}}
