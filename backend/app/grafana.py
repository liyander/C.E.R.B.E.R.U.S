"""Grafana integration.

Inbound: alerting webhook contact point -> normalised events.
Outbound: service-account token -> health, datasource discovery, and bounded
Prometheus / Loki queries through Grafana's datasource proxy.
"""
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .store import clamp, text

SEVERITY_MAP = {
    "critical": 9, "crit": 9, "page": 9, "emergency": 10, "high": 8, "error": 8, "major": 8,
    "warning": 6, "warn": 6, "medium": 5, "minor": 4, "low": 3, "info": 2, "none": 2,
}
ASSET_LABELS = ("instance", "host", "hostname", "nodename", "node", "agent_name", "job")


class GrafanaError(Exception):
    pass


def _host_only(value: str) -> str:
    """'10.0.0.5:9100' or 'http://host:9100/metrics' -> bare host."""
    value = text(value, 200)
    if "://" in value:
        return urlparse(value).hostname or value
    if value.count(":") == 1:
        return value.split(":")[0]
    return value


def normalize_webhook(payload: dict) -> list[dict]:
    """Translate a Grafana (or Alertmanager-compatible) webhook body into events."""
    events = []
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        return events
    for alert in alerts[:200]:
        if not isinstance(alert, dict):
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
        ann = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}
        name = text(labels.get("alertname") or "Grafana alert", 120)
        resolved = alert.get("status") == "resolved"
        asset = next((_host_only(labels[k]) for k in ASSET_LABELS if labels.get(k)), "")
        started = alert.get("startsAt")
        fingerprint = text(alert.get("fingerprint"), 80) or name
        summary = text(ann.get("summary") or ann.get("description") or ann.get("message"), 1500)
        values = alert.get("valueString") or alert.get("values")
        events.append({
            "source": "grafana",
            # One event per firing and one per resolution of the same alert instance.
            "source_event_id": f"{fingerprint}:{started}:{'resolved' if resolved else 'firing'}",
            "event_type": "alert_resolved" if resolved else "grafana_alert",
            "severity": 1 if resolved else SEVERITY_MAP.get(str(labels.get("severity", "")).lower(), 5),
            "timestamp": alert.get("endsAt") if resolved else started,
            "asset": asset,
            "source_ip": text(labels.get("source_ip") or labels.get("src_ip"), 64),
            "rule_id": name,
            "title": f"{name} resolved" if resolved else name,
            "message": "\n".join(p for p in (summary, f"values: {values}" if values else "",
                                             f"labels: {labels}") if p),
            "evidence_ref": {
                "backend": "grafana",
                "fingerprint": fingerprint,
                "generator_url": text(alert.get("generatorURL"), 500),
                "dashboard_url": text(alert.get("dashboardURL"), 500),
                "panel_url": text(alert.get("panelURL"), 500),
            },
        })
    return events


def _client(cfg: dict) -> httpx.Client:
    url = text(cfg.get("url"), 300).rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise GrafanaError("Grafana URL is not configured")
    headers = {"Authorization": f"Bearer {cfg['token']}"} if cfg.get("token") else {}
    return httpx.Client(base_url=url, headers=headers, timeout=15, verify=cfg.get("verify_tls", True))


def _get(cfg: dict, path: str, params: dict | None = None):
    try:
        with _client(cfg) as client:
            resp = client.get(path, params=params)
    except httpx.HTTPError as exc:
        raise GrafanaError(f"Could not reach Grafana: {exc}") from exc
    if resp.status_code >= 400:
        raise GrafanaError(f"Grafana returned HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        return resp.json()
    except ValueError as exc:
        raise GrafanaError("Grafana returned a non-JSON response (is the URL correct?)") from exc


def test_connection(cfg: dict) -> dict:
    health = _get(cfg, "/api/health")
    result = {"ok": True, "version": health.get("version", "unknown"), "datasources": [], "warning": ""}
    try:
        result["datasources"] = [
            {"uid": d.get("uid"), "name": d.get("name"), "type": d.get("type")}
            for d in _get(cfg, "/api/datasources")
        ]
    except GrafanaError as exc:
        result["warning"] = f"Grafana is reachable, but the token could not list datasources. {exc}"
    return result


_REAL_FS = '{fstype!~"tmpfs|overlay|squashfs|ramfs|devtmpfs"}'
# Standard node_exporter / blackbox_exporter metrics; anything a setup lacks simply comes back empty.
HEALTH_QUERIES = {
    "up": "up",
    "cpu_pct": '100 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100',
    "mem_pct": "(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100",
    "disk_pct": f"max by (instance) ((1 - node_filesystem_avail_bytes{_REAL_FS} / node_filesystem_size_bytes{_REAL_FS}) * 100)",
    "load1": "node_load1",
    "uptime_days": "(time() - node_boot_time_seconds) / 86400",
    "cpu_cores": 'count by (instance) (node_cpu_seconds_total{mode="idle"})',
    "probe_up": "probe_success",
    "probe_seconds": "probe_duration_seconds",
}


def _instant(cfg: dict, uid: str, promql: str) -> list[tuple[dict, float]]:
    data = _get(cfg, f"/api/datasources/proxy/uid/{uid}/api/v1/query", {"query": promql})
    out = []
    for item in (data.get("data", {}).get("result") or [])[:200]:
        try:
            out.append((item.get("metric", {}), float(item["value"][1])))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return out


def server_health(cfg: dict) -> dict:
    """One-call overview: scrape targets up/down, per-host resource use, HTTP probe results."""
    uid = text(cfg.get("prometheus_uid"), 80)
    if not uid:
        raise GrafanaError("No Prometheus datasource UID configured")
    results, errors = {}, []
    for key, promql in HEALTH_QUERIES.items():
        try:
            results[key] = _instant(cfg, uid, promql)
        except GrafanaError as exc:
            results[key] = []
            errors.append(f"{key}: {exc}"[:200])
    if len(errors) == len(HEALTH_QUERIES):
        raise GrafanaError(errors[0])

    hosts: dict[str, dict] = {}
    for key in ("cpu_pct", "mem_pct", "disk_pct", "load1", "uptime_days", "cpu_cores"):
        for metric, value in results[key]:
            name = metric.get("instance", "unknown")
            hosts.setdefault(name, {"instance": name})[key] = int(value) if key == "cpu_cores" else round(value, 1)
    probes: dict[str, dict] = {}
    for metric, value in results["probe_up"]:
        name = metric.get("instance", "unknown")
        probes[name] = {"target": name, "job": metric.get("job", ""), "up": value == 1}
    for metric, value in results["probe_seconds"]:
        if metric.get("instance") in probes:
            probes[metric["instance"]]["response_seconds"] = round(value, 3)
    return {
        "backend": "prometheus",
        "scrape_targets": [{"instance": m.get("instance", ""), "job": m.get("job", ""), "up": v == 1}
                           for m, v in results["up"]][:100],
        "hosts": list(hosts.values())[:100],
        "http_probes": list(probes.values())[:100],
        "query_errors": errors,
    }


def _loki_base(cfg: dict) -> str:
    uid = text(cfg.get("loki_uid"), 80)
    if not uid:
        raise GrafanaError("No Loki datasource is configured. An admin can add it under Integrations.")
    return f"/api/datasources/proxy/uid/{uid}/loki/api/v1"


def _ns_to_iso(ns) -> str:
    return datetime.fromtimestamp(int(ns) / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


LOG_LEVELS = ("error", "warn", "info", "debug", "other")
_LEVEL_ALIASES = {"critical": "error", "crit": "error", "fatal": "error", "emerg": "error", "alert": "error", "err": "error",
                  "error": "error", "panic": "error", "warning": "warn", "warn": "warn", "notice": "info", "info": "info",
                  "informational": "info", "debug": "debug", "trace": "debug"}


def log_level(value) -> str:
    return _LEVEL_ALIASES.get(str(value or "").lower(), "other")


def loki_error_counts(cfg: dict, levels: str, minutes: int = 5) -> dict[str, int]:
    """Error-level lines per host over the last few minutes. The level is matched in the pipeline,
    which works whether Loki keeps it as a label or as structured metadata."""
    data = _get(cfg, f"{_loki_base(cfg)}/query", {
        "query": f'sum by (host) (count_over_time({{job=~".+"}} | detected_level=~"{levels}" [{clamp(minutes, 1, 60, 5)}m]))',
        "time": time.time_ns()})
    return {str((item.get("metric") or {}).get("host") or "unknown host"): int(float(item["value"][1]))
            for item in data.get("data", {}).get("result") or []}


def loki_label_values(cfg: dict, name: str) -> list[str]:
    """Values of one stream label (job, host, program...), for the filter pickers."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,60}", name or ""):
        raise GrafanaError("Invalid label name")
    data = _get(cfg, f"{_loki_base(cfg)}/label/{name}/values")
    return sorted(str(v) for v in (data.get("data") or []))[:300]


def _iso_to_ns(value: str) -> int:
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 10**9)
    except ValueError as exc:
        raise GrafanaError("Invalid time") from exc


def _stream_lines(data: dict) -> list[dict]:
    lines = []
    for stream in data.get("data", {}).get("result") or []:
        labels = {str(k): str(v)[:120] for k, v in (stream.get("stream") or {}).items()}
        level = log_level(labels.get("detected_level") or labels.get("level"))
        for ts, line in stream.get("values", []):
            lines.append({"ts": _ns_to_iso(ts), "ns": str(ts), "labels": labels, "level": level, "line": str(line)[:4000]})
    return lines


def loki_explore(cfg: dict, logql: str, minutes: int = 60, limit: int = 200, start: str = "", end: str = "") -> dict:
    """Recent log lines for a LogQL query plus line counts over time, by level, for a volume chart.

    With `start` and `end` (ISO times) the search covers exactly that window instead of the last `minutes`.
    """
    base = _loki_base(cfg)
    logql = text(logql, 1000) or '{job=~".+"}'
    limit = clamp(limit, 10, 500, 200)
    if start and end:
        start_ns, end_ns = _iso_to_ns(start), _iso_to_ns(end)
        if not 0 < end_ns - start_ns <= 7 * 86400 * 10**9:
            raise GrafanaError("The time window must be between one second and seven days")
        minutes = max(1, (end_ns - start_ns) // (60 * 10**9))
    else:
        minutes = clamp(minutes, 5, 10080, 60)
        end_ns = time.time_ns()
        start_ns = end_ns - minutes * 60 * 10**9
    data = _get(cfg, f"{base}/query_range", {"query": logql, "start": start_ns, "end": end_ns, "limit": limit, "direction": "backward"})
    if data.get("data", {}).get("resultType") not in (None, "streams"):
        raise GrafanaError("That is a metric query. Enter a log query such as {job=\"varlogs\"} |= \"error\".")
    lines = sorted(_stream_lines(data), key=lambda item: int(item["ns"]), reverse=True)[:limit]
    step = max(1, (end_ns - start_ns) // 10**9 // 60)
    volume, warning = [], ""
    try:
        counted = _get(cfg, f"{base}/query_range", {
            "query": f"sum by (detected_level) (count_over_time({logql} [{step}s]))", "start": start_ns, "end": end_ns, "step": step})
        first = (start_ns // 10**9) // step * step + step
        slots = {t: dict.fromkeys(LOG_LEVELS, 0) for t in range(first, end_ns // 10**9 + 1, step)}
        for series in counted.get("data", {}).get("result") or []:
            level = log_level((series.get("metric") or {}).get("detected_level"))
            for ts, value in series.get("values", []):
                if int(float(ts)) in slots:
                    slots[int(float(ts))][level] += int(float(value))
        volume = [{"ts": datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **counts}
                  for t, counts in slots.items()]
    except GrafanaError as exc:
        warning = f"The volume chart is unavailable for this query. {exc}"[:300]
    return {"query": logql, "minutes": minutes, "step": step, "lines": lines, "volume": volume,
            "total": sum(sum(v[k] for k in LOG_LEVELS) for v in volume), "warning": warning}


def loki_context(cfg: dict, labels: dict, ns: str, count: int = 15) -> dict:
    """Lines just before and after one log line, from the same stream (same host, program...)."""
    base = _loki_base(cfg)
    parts = []
    for key, value in (labels or {}).items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,60}", str(key)) and value not in (None, "") and key != "detected_level":
            escaped = str(value)[:200].replace("\\", "\\\\").replace('"', '\\"')
            parts.append(f'{key}="{escaped}"')
    if not parts or not str(ns).isdigit():
        raise GrafanaError("That line cannot be located")
    selector, at, count, hour = "{" + ", ".join(parts[:6]) + "}", int(ns), clamp(count, 1, 50, 15), 3600 * 10**9
    before = _get(cfg, f"{base}/query_range", {"query": selector, "start": at - hour, "end": at, "limit": count, "direction": "backward"})
    after = _get(cfg, f"{base}/query_range", {"query": selector, "start": at, "end": at + hour, "limit": count + 1, "direction": "forward"})
    lines = {item["ns"] + item["line"]: item for item in _stream_lines(before) + _stream_lines(after)}
    ordered = sorted(lines.values(), key=lambda item: int(item["ns"]))
    for item in ordered:
        item["current"] = item["ns"] == str(ns)
    return {"selector": selector, "lines": ordered}


def log_patterns(lines: list[dict], top: int = 15) -> list[dict]:
    """Group similar lines by replacing the parts that vary (addresses, ids, numbers)."""
    groups: dict[str, dict] = {}
    for item in lines:
        shape = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", item["line"])
        shape = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<id>", shape)
        shape = re.sub(r"\d+", "<n>", shape)[:180]
        entry = groups.setdefault(shape, {"pattern": shape, "count": 0, "example": item["line"][:300],
                                          "host": item["labels"].get("host", ""), "program": item["labels"].get("program", "")})
        entry["count"] += 1
    return sorted(groups.values(), key=lambda e: e["count"], reverse=True)[:top]


# metric -> (PromQL template with {sel} / {and_sel}, unit, fixed "high" threshold or None)
HISTORY_METRICS = {
    "load": ("node_load1{{{sel}}}", "", None),
    "cpu": ('100 - avg by (instance) (rate(node_cpu_seconds_total{{mode="idle"{and_sel}}}[5m])) * 100', "%", 80.0),
    "memory": ("(1 - node_memory_MemAvailable_bytes{{{sel}}} / node_memory_MemTotal_bytes{{{sel}}}) * 100", "%", 85.0),
    "disk": ("max by (instance) ((1 - node_filesystem_avail_bytes{{" + _REAL_FS[1:-1] + "{and_sel}}} / "
             "node_filesystem_size_bytes{{" + _REAL_FS[1:-1] + "{and_sel}}}) * 100)", "%", 90.0),
    "response_time": ("probe_duration_seconds{{{sel}}}", "s", 1.0),
}


def tz_label(minutes: int) -> str:
    sign = "+" if minutes >= 0 else "-"
    return f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def metric_history(cfg: dict, metric: str, host: str = "", hours: int = 24, tz_minutes: int = 0) -> dict:
    """How one metric moved over time: timeline, peak, and the periods it was high. Answers "when" questions."""
    uid = text(cfg.get("prometheus_uid"), 80)
    if not uid:
        raise GrafanaError("No Prometheus datasource UID configured")
    if metric not in HISTORY_METRICS:
        raise GrafanaError(f"metric must be one of {sorted(HISTORY_METRICS)}")
    host = text(host, 120)
    if host and not re.fullmatch(r"[A-Za-z0-9_.:/-]+", host):
        raise GrafanaError("host may only contain letters, digits and . : / _ -")
    hours = clamp(hours, 1, 168, 24)
    sel = 'instance=~".*{}.*"'.format(host.replace(".", "\\\\.")) if host else ""
    template, unit, fixed = HISTORY_METRICS[metric]
    promql = template.format(sel=sel, and_sel=("," + sel) if sel else "")
    end = int(time.time())
    step = max(60, hours * 3600 // 120)
    data = _get(cfg, f"/api/datasources/proxy/uid/{uid}/api/v1/query_range",
                {"query": promql, "start": end - hours * 3600, "end": end, "step": step})
    cores = {}
    if metric == "load":
        try:
            cores = {m.get("instance"): v for m, v in _instant(
                cfg, uid, 'count by (instance) (node_cpu_seconds_total{{mode="idle"{}}})'.format(("," + sel) if sel else ""))}
        except GrafanaError:
            cores = {}
    offset = tz_minutes * 60
    fmt = "%d %b %H:%M" if hours > 20 else "%H:%M"
    local = lambda ts: datetime.fromtimestamp(ts + offset, tz=timezone.utc).strftime(fmt)
    series = []
    for item in (data.get("data", {}).get("result") or [])[:6]:
        points = [(int(float(ts)), float(v)) for ts, v in item.get("values", []) if v not in ("NaN", "+Inf", "-Inf")]
        if not points:
            continue
        instance = (item.get("metric") or {}).get("instance", "")
        values = [v for _, v in points]
        peak_ts, peak = max(points, key=lambda p: p[1])
        threshold = fixed if fixed is not None else float(cores.get(instance) or max(1.0, round(0.8 * peak, 2)))
        periods, current = [], None
        for ts, value in points:
            if value >= threshold:
                current = current or {"start": ts, "end": ts, "peak": value}
                current["end"], current["peak"] = ts, max(current["peak"], value)
            elif current:
                periods.append(current)
                current = None
        if current:
            periods.append(current)
        chunk = max(1, len(points) // 24)
        timeline = [{"time": local(points[i][0]), "avg": round(sum(v for _, v in points[i:i + chunk]) / len(points[i:i + chunk]), 2),
                     "max": round(max(v for _, v in points[i:i + chunk]), 2)} for i in range(0, len(points), chunk)]
        series.append({
            "instance": instance, **({"cpu_cores": int(cores[instance])} if instance in cores else {}),
            "latest": round(values[-1], 2), "min": round(min(values), 2), "avg": round(sum(values) / len(values), 2),
            "peak": {"value": round(peak, 2), "time": local(peak_ts)},
            "high_threshold": round(threshold, 2),
            # A period already under way when the window opens has no known start: say so, never invent one.
            "high_periods": [{"from": ("before " + local(p["start"])) if p["start"] == points[0][0] else local(p["start"]),
                              "to": "now (still high)" if p["end"] == points[-1][0] else local(p["end"] + step),
                              "peak": round(p["peak"], 2), "minutes": (p["end"] - p["start"] + step) // 60,
                              **({"started_before_window": True} if p["start"] == points[0][0] else {})} for p in periods[-10:]],
            "high_for_whole_window": len(periods) == 1 and periods[0]["start"] == points[0][0] and periods[0]["end"] == points[-1][0],
            "minutes_high": sum((p["end"] - p["start"] + step) // 60 for p in periods),
            "still_high_now": bool(periods) and periods[-1]["end"] == points[-1][0],
            "timeline": timeline,
        })
    return {"backend": "prometheus", "metric": metric, "unit": unit, "window_hours": hours, "times_are_in": tz_label(tz_minutes),
            "note": "high_threshold for load is the number of CPU cores when known" if metric == "load" else "",
            "series": series}


def query_prometheus(cfg: dict, promql: str, minutes: int = 60) -> dict:
    uid = text(cfg.get("prometheus_uid"), 80)
    if not uid:
        raise GrafanaError("No Prometheus datasource UID configured")
    minutes = clamp(minutes, 1, 1440, 60)
    end = int(time.time())
    data = _get(cfg, f"/api/datasources/proxy/uid/{uid}/api/v1/query_range", {
        "query": text(promql, 1000), "start": end - minutes * 60, "end": end,
        "step": max(15, minutes * 60 // 120),
    })
    series = []
    for item in (data.get("data", {}).get("result") or [])[:20]:
        vals = [float(v[1]) for v in item.get("values", []) if v[1] not in ("NaN", "+Inf", "-Inf")]
        if vals:
            series.append({"metric": item.get("metric", {}), "samples": len(vals), "min": min(vals),
                           "max": max(vals), "avg": sum(vals) / len(vals), "last": vals[-1]})
    return {"backend": "prometheus", "query": promql, "window_minutes": minutes, "series": series}


def query_loki(cfg: dict, logql: str, minutes: int = 60, limit: int = 30) -> dict:
    uid = text(cfg.get("loki_uid"), 80)
    if not uid:
        raise GrafanaError("No Loki datasource UID configured")
    minutes = clamp(minutes, 1, 1440, 60)
    end = time.time_ns()
    data = _get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query_range", {
        "query": text(logql, 1000), "start": end - minutes * 60 * 10**9, "end": end,
        "limit": clamp(limit, 1, 50, 30), "direction": "backward",
    })
    lines = []
    for stream in data.get("data", {}).get("result") or []:
        for ts, line in stream.get("values", []):
            lines.append({"ts_ns": ts, "labels": stream.get("stream", {}), "line": str(line)[:400]})
    lines.sort(key=lambda item: item["ts_ns"], reverse=True)
    return {"backend": "loki", "query": logql, "window_minutes": minutes, "lines": lines[:clamp(limit, 1, 50, 30)]}
