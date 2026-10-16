"""Detect first seen successful SSH logins from Loki auth logs."""
import hashlib
import logging
import time
from datetime import datetime, timezone

from . import grafana, store
from .db import db, get_integration, get_setting, now, set_setting

log = logging.getLogger("cerberus.logins")
SCHEMA = """
CREATE TABLE IF NOT EXISTS login_seen (
    host TEXT NOT NULL, username TEXT NOT NULL, source_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY(host, username, source_ip)
);
CREATE INDEX IF NOT EXISTS idx_login_seen_host_user ON login_seen(host, username);
"""
INTERVAL_SECONDS = 300


def tick():
    with db() as conn:
        cfg = get_integration(conn, "grafana")
        last = get_setting(conn, "login_detection_last_run")
        if not cfg.get("loki_uid") or (last and time.time() - datetime.fromisoformat(last.replace("Z", "+00:00")).timestamp() < INTERVAL_SECONDS):
            return
        uid = cfg["loki_uid"]
        end = int(time.time()) + 60
        try:
            result = grafana._get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query_range", {
                "query": '{host=~".+"} |= "Accepted " |= " for "',
                "start": (end - 15 * 60) * 10**9, "end": end * 10**9,
                "limit": 5000, "direction": "forward"}).get("data") or {}
        except grafana.GrafanaError as exc:
            log.warning("Unusual-login check skipped: %s", exc)
            return
        baseline = get_setting(conn, "login_detection_baselined") == "1"
        matches = []
        for stream in result.get("result", []):
            host = str((stream.get("stream") or {}).get("host", ""))[:120]
            for ns, line in stream.get("values", []):
                match = grafana._ACCEPTED.search(line)
                if match and host:
                    method, username, source = match.groups()
                    matches.append((int(ns), host, username[:120], source[:64], method[:40]))
        for ns, host, username, source, method in sorted(matches):
            stamp = datetime.fromtimestamp(ns / 1e9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            seen = conn.execute("SELECT 1 FROM login_seen WHERE host=? AND username=? AND source_ip=?", (host, username, source)).fetchone()
            account_seen = conn.execute("SELECT 1 FROM login_seen WHERE host=? AND username=?", (host, username)).fetchone()
            conn.execute("INSERT INTO login_seen(host,username,source_ip,first_seen,last_seen) VALUES(?,?,?,?,?) "
                         "ON CONFLICT(host,username,source_ip) DO UPDATE SET last_seen=excluded.last_seen",
                         (host, username, source, stamp, stamp))
            if seen or not baseline:
                continue
            kind = "new_address" if account_seen else "new_account"
            event_id = hashlib.sha256(f"{host}|{username}|{source}|{stamp}".encode()).hexdigest()[:32]
            store.ingest_event(conn, {"source": "cerberus", "source_event_id": f"login:{event_id}",
                "asset": host, "event_type": "unusual_login", "severity": 7,
                "timestamp": stamp, "source_ip": source, "username": username,
                "rule_id": kind,
                "title": f"Successful SSH login from {'new address' if account_seen else 'new account'}: {username} on {host}",
                "message": f"{username} signed in to {host} from {source} using {method}. This host/account/address combination was not previously observed.",
                "evidence_ref": {"backend": "loki", "host": host, "timestamp": stamp}})
        if not baseline:
            set_setting(conn, "login_detection_baselined", "1")
        set_setting(conn, "login_detection_last_run", now())
