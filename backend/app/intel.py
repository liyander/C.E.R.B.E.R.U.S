"""IP threat-intelligence enrichment.

Looks up an address against external reputation sources and caches the result:
  - GreyNoise Community — whether an address is internet-wide "noise" (a mass scanner) or part of a
    known benign service (RIOT). No API key needed (community tier, rate-limited).
  - AbuseIPDB — an abuse confidence score, country, network owner and recent report count. Needs a
    free API key, pasted under Integrations.

Results are cached for 12 hours. Nothing here blocks the hot path; the IP page and triage read the
cache, and a lookup refreshes it in the background. Enrichment is enrichment only — it informs the
analyst and nudges priority, but never acts.
"""
import json
import ipaddress
import logging
import time
from datetime import datetime, timezone

import httpx

from .db import db, get_integration, now, set_integration

log = logging.getLogger("cerberus.intel")

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_cache (
    ip TEXT PRIMARY KEY,
    data TEXT NOT NULL DEFAULT '{}',
    fetched_at TEXT NOT NULL
);
"""
TTL_SECONDS = 12 * 3600
GREYNOISE = "https://api.greynoise.io/v3/community/{ip}"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"


def settings(conn) -> dict:
    s = get_integration(conn, "intel")
    return {"greynoise_enabled": bool(s.get("greynoise_enabled", True)),
            "abuseipdb_enabled": bool(s.get("abuseipdb_enabled", False)),
            "abuseipdb_key": s.get("abuseipdb_key", "")}


def public_view(conn) -> dict:
    s = settings(conn)
    return {"greynoise_enabled": s["greynoise_enabled"], "abuseipdb_enabled": s["abuseipdb_enabled"],
            "has_abuseipdb_key": bool(s["abuseipdb_key"])}


def save_settings(conn, body: dict, actor: str) -> dict:
    s = settings(conn)
    key = body.get("abuseipdb_key")
    merged = {"greynoise_enabled": bool(body.get("greynoise_enabled", True)),
              "abuseipdb_enabled": bool(body.get("abuseipdb_enabled", False)),
              "abuseipdb_key": (key if key else s["abuseipdb_key"])}
    set_integration(conn, "intel", merged)
    return public_view(conn)


def _greynoise(client: httpx.Client, ip: str) -> dict | None:
    r = client.get(GREYNOISE.format(ip=ip), timeout=6)
    if r.status_code == 404:
        return {"seen": False, "note": "GreyNoise has not seen this address."}
    if r.status_code != 200:
        raise httpx.HTTPStatusError(f"GreyNoise returned HTTP {r.status_code}", request=r.request, response=r)
    d = r.json()
    return {"seen": d.get("seen", False), "classification": d.get("classification", ""), "name": d.get("name", ""),
            "noise": d.get("noise", False), "riot": d.get("riot", False), "last_seen": d.get("last_seen", "")}


def _abuseipdb(client: httpx.Client, ip: str, key: str) -> dict | None:
    r = client.get(ABUSEIPDB, headers={"Key": key, "Accept": "application/json"},
                   params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=6)
    if r.status_code != 200:
        raise httpx.HTTPStatusError(f"AbuseIPDB returned HTTP {r.status_code}", request=r.request, response=r)
    d = r.json().get("data", {})
    return {"score": d.get("abuseConfidenceScore", 0), "country": d.get("countryCode", ""), "isp": d.get("isp", ""),
            "domain": d.get("domain", ""), "usage": d.get("usageType", ""), "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", ""), "tor": d.get("isTor", False), "whitelisted": d.get("isWhitelisted", False)}


def _verdict(data: dict) -> dict:
    """A short reputation summary for a tile and for the analyst."""
    gn, ab = data.get("greynoise") or {}, data.get("abuseipdb") or {}
    score = ab.get("score", 0)
    if ab.get("whitelisted") or gn.get("riot"):
        return {"label": "Known benign", "tone": "low", "text": gn.get("name") or "A known legitimate service."}
    if score >= 75 or gn.get("classification") == "malicious":
        return {"label": "Malicious reputation", "tone": "critical",
                "text": (f"AbuseIPDB score {score}/100, {ab.get('total_reports', 0)} reports. " if score else "") + ("GreyNoise: malicious. " if gn.get("classification") == "malicious" else "")}
    if gn.get("noise") or (25 <= score < 75):
        return {"label": "Scanner / suspicious", "tone": "high",
                "text": ("Seen scanning the internet widely (GreyNoise noise). " if gn.get("noise") else "") + (f"AbuseIPDB score {score}/100. " if score else "")}
    if gn.get("seen") is False and not ab:
        return {"label": "No reputation data", "tone": "", "text": "Not seen by the configured sources."}
    return {"label": "Low / unknown", "tone": "", "text": f"AbuseIPDB score {score}/100." if ab else "No strong signal."}


def lookup(conn, ip: str, force: bool = False) -> dict:
    """Cached reputation for one address. Fetches from the network only when stale or forced."""
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {"ip": ip, "greynoise": None, "abuseipdb": None, "errors": [],
                "verdict": {"label": "Private or reserved address", "tone": "", "text": "External reputation lookup is unavailable for this address."},
                "cached": True}
    row = conn.execute("SELECT data, fetched_at FROM intel_cache WHERE ip = ?", (ip,)).fetchone()
    if row and not force:
        try:
            age = time.time() - datetime.strptime(row["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if age < TTL_SECONDS:
                return {**json.loads(row["data"]), "cached": True}
        except (ValueError, KeyError):
            pass
    s = settings(conn)
    data = {"ip": ip, "greynoise": None, "abuseipdb": None, "errors": []}
    with httpx.Client(headers={"User-Agent": "CERBERUS"}, follow_redirects=True) as client:
        if s["greynoise_enabled"] and address.version == 4:
            try:
                data["greynoise"] = _greynoise(client, ip)
            except httpx.HTTPError as exc:
                data["errors"].append(f"GreyNoise: {exc.__class__.__name__}")
        if s["abuseipdb_enabled"] and s["abuseipdb_key"]:
            try:
                data["abuseipdb"] = _abuseipdb(client, ip, s["abuseipdb_key"])
            except httpx.HTTPError as exc:
                data["errors"].append(f"AbuseIPDB: {exc.__class__.__name__}")
    data["verdict"] = _verdict(data)
    data["fetched_at"] = now()
    conn.execute("INSERT INTO intel_cache (ip, data, fetched_at) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at",
                 (ip, json.dumps(data), data["fetched_at"]))
    return {**data, "cached": False}


def cached(conn, ip: str) -> dict | None:
    row = conn.execute("SELECT data FROM intel_cache WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["data"])
    except ValueError:
        return None


def enabled(conn) -> bool:
    s = settings(conn)
    return s["greynoise_enabled"] or (s["abuseipdb_enabled"] and bool(s["abuseipdb_key"]))
