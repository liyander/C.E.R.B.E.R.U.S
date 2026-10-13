"""Grafana integration.

Inbound: alerting webhook contact point -> normalised events.
Outbound: service-account token -> health, datasource discovery, and bounded
Prometheus / Loki queries through Grafana's datasource proxy.
"""
import time
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
    for key in ("cpu_pct", "mem_pct", "disk_pct", "load1", "uptime_days"):
        for metric, value in results[key]:
            name = metric.get("instance", "unknown")
            hosts.setdefault(name, {"instance": name})[key] = round(value, 1)
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
