#!/usr/bin/env python3
"""Wazuh -> CERBERUS integration.

Wazuh's integrator daemon runs this once per matching alert:
    custom-cerberus.py <alert file> <api key> <hook url>
It converts the alert to a CERBERUS event and posts it to the intake address.
Only the Python standard library is used, so it runs on any Wazuh manager.

Install: see README.md next to this file.
"""
import json
import ssl
import sys
import urllib.error
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"
# Wazuh rule groups -> CERBERUS event types. First match wins; anything else uses the first group.
EVENT_TYPES = (
    ("vulnerability-detector", "vulnerability"),   # inventory finding: stored, never opens an incident
    ("authentication_failed", "authentication_failure"),
    ("authentication_failures", "authentication_failure"),
    ("authentication_success", "authentication_success"),
    ("syscheck", "file_integrity"),
    ("rootcheck", "rootkit_check"),
    ("web", "web_attack"),
    ("ids", "network_ids"),
    ("sudo", "privilege_use"),
)


def log(message):
    try:
        with open(LOG_FILE, "a") as handle:
            handle.write("custom-cerberus: %s\n" % message)
    except OSError:
        sys.stderr.write(message + "\n")


def severity(level):
    """Wazuh levels run 0-15; CERBERUS uses 1-10 (4+ opens an incident, 7+ is high, 9+ critical)."""
    try:
        return max(1, min(10, round(int(level) * 10 / 15)))
    except (TypeError, ValueError):
        return 5


def to_event(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    groups = rule.get("groups") or []
    event_type = next((mapped for group, mapped in EVENT_TYPES if group in groups), groups[0] if groups else "alert")
    win = (data.get("win") or {}).get("eventdata") or {}
    return {
        "source": "wazuh",
        "source_event_id": str(alert.get("id") or alert.get("timestamp") or ""),
        "asset": agent.get("name") or (alert.get("manager") or {}).get("name") or "",
        "asset_ip": agent.get("ip") or "",
        "event_type": event_type,
        "severity": severity(rule.get("level")),
        "timestamp": alert.get("timestamp") or "",
        "source_ip": data.get("srcip") or win.get("ipAddress") or "",
        "username": data.get("dstuser") or data.get("srcuser") or win.get("targetUserName") or "",
        "rule_id": str(rule.get("id") or ""),
        "title": rule.get("description") or "Wazuh alert",
        "message": alert.get("full_log") or json.dumps(data)[:3000],
        "evidence_ref": {
            "backend": "wazuh-indexer",
            "index": "wazuh-alerts-*",
            "document_id": str(alert.get("id") or ""),
            "query": "rule.id:%s AND agent.name:%s" % (rule.get("id", ""), agent.get("name", "")),
        },
    }


def main(argv):
    if len(argv) < 4:
        log("usage: custom-cerberus.py <alert file> <api key> <hook url>")
        return 2
    alert_file, token, url = argv[1], argv[2], argv[3]
    try:
        with open(alert_file) as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log("could not read alert %s: %s" % (alert_file, exc))
        return 1
    event = to_event(alert)
    if not event["source_event_id"]:
        log("alert without an id skipped")
        return 0
    request = urllib.request.Request(
        url, data=json.dumps({"events": [event]}).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(request, timeout=10, context=ssl.create_default_context()) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        log("CERBERUS answered HTTP %s for rule %s: %s" % (exc.code, event["rule_id"], exc.read()[:200]))
        return 1
    except (urllib.error.URLError, OSError) as exc:
        log("could not reach %s: %s" % (url, exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
