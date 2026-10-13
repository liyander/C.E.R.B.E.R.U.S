"""Application workspaces: each connected product gets its own menu and pages inside CERBERUS.

The navbar switcher lists what `catalog` returns. Choosing an application swaps the sidebar for
that application's menu, and every page in it is described here as plain data (tiles, bars,
tables, filters) that one generic screen in the web app draws. Everything is read-only.

To add an application: write its page functions, then add one entry to APPS.
"""
import re
import time
from urllib.parse import urlencode, urlsplit

from . import grafana, store, wazuh
from .db import get_integration


class NotConnected(Exception):
    pass


# ---------- building blocks of a page ----------

def tile(label, value, tone="", hint="", href="") -> dict:
    return {"label": label, "value": value, "tone": tone, "hint": hint, "href": href}


def bars(title, items, empty="Nothing in this period") -> dict:
    return {"type": "bars", "title": title, "items": items, "empty": empty}


def table(title, columns, rows, note="", empty="Nothing to show") -> dict:
    """columns: (key, label, kind) with kind text | num | time | mono | badge | wrap."""
    return {"type": "table", "title": title, "note": note, "empty": empty, "rows": rows,
            "columns": [{"key": k, "label": label, "kind": kind} for k, label, kind in columns]}


def trend(title, points) -> dict:
    return {"type": "trend", "title": title, "points": points}


def select(name, label, value, options) -> dict:
    return {"kind": "select", "name": name, "label": label, "value": value, "options": [list(o) for o in options]}


def search_box(name, label, value, width=220) -> dict:
    return {"kind": "text", "name": name, "label": label, "value": value, "width": width}


def link(here: str, q: dict, **change) -> str:
    """This page again with some filters changed; blank values are dropped."""
    params = {k: v for k, v in {**q, **change}.items() if v not in (None, "")}
    return here + (f"?{urlencode(params)}" if params else "")


def stamp(value):
    """Timestamps in the one form every browser parses: 2026-10-13T09:13:52.912Z."""
    if not value:
        return None
    return re.sub(r"(\.\d{3})\d+", r"\1", str(value)).replace("+0000", "Z")


def badge(text, tone="") -> dict:
    return {"text": str(text), "tone": tone}


# ---------- Wazuh ----------

HOURS = (("1", "Last hour"), ("6", "Last 6 hours"), ("24", "Last 24 hours"), ("168", "Last 7 days"))
STEP = {"1": "5m", "6": "15m", "24": "1h", "168": "6h"}
LEVELS = (("", "All levels"), ("7", "Level 7 +"), ("10", "Level 10 +"), ("13", "Level 13 +"))
STATE_TONE = {"active": "ok", "disconnected": "critical", "never_connected": "low", "pending": "medium"}
RESULT_TONE = {"failed": "critical", "passed": "ok", "not applicable": "low"}
VULN_TONE = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
COMPLIANCE = {"pci-dss": ("rule.pci_dss", "PCI DSS"), "gdpr": ("rule.gdpr", "GDPR"), "hipaa": ("rule.hipaa", "HIPAA"),
              "nist": ("rule.nist_800_53", "NIST 800-53"), "tsc": ("rule.tsc", "TSC")}
_agent_cache: dict[str, tuple[float, list[dict]]] = {}


def level_tone(level) -> str:
    level = int(level or 0)
    return "critical" if level >= 13 else "high" if level >= 10 else "medium" if level >= 7 else "low"


def _hours(q: dict) -> str:
    return q.get("hours") if q.get("hours") in STEP else "24"


def _agents(client) -> list[dict]:
    """Enrolled agents, remembered for two minutes so every page does not ask again."""
    hit = _agent_cache.get(client.base)
    if hit and time.monotonic() - hit[0] < 120:
        return hit[1]
    try:
        rows = wazuh._agent_rows(client)
    except wazuh.WazuhError:
        rows = []  # connected straight to the indexer: no manager API
    _agent_cache[client.base] = (time.monotonic(), rows)
    return rows


def _agent_select(client, value) -> dict:
    return select("agent", "Agent", value, [("", "All agents")] + [(a["name"], a["name"]) for a in _agents(client) if a.get("name")])


def _buckets(data: dict, name: str) -> list[dict]:
    return data.get("aggregations", {}).get(name, {}).get("buckets", [])


def _total(data: dict) -> int:
    return data.get("hits", {}).get("total", {}).get("value", 0)


def _alert_row(s: dict) -> dict:
    rule, d = s.get("rule") or {}, s.get("data") or {}
    return {"time": stamp(s.get("timestamp")), "agent": (s.get("agent") or {}).get("name", ""),
            "level": badge(rule.get("level", ""), level_tone(rule.get("level"))), "rule": rule.get("id", ""),
            "description": rule.get("description", ""), "source_ip": d.get("srcip", ""),
            "_detail": (s.get("full_log") or "")[:1500]}


ALERT_COLUMNS = (("time", "Time", "time"), ("agent", "Agent", "text"), ("level", "Level", "badge"), ("rule", "Rule", "mono"),
                 ("description", "Description", "wrap"), ("source_ip", "Source IP", "mono"))
ALERT_SOURCE = ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "data.srcip", "full_log"]


def _fim_row(s: dict) -> dict:
    check, rule = s.get("syscheck") or {}, s.get("rule") or {}
    changed = ", ".join(check.get("changed_attributes") or [])
    detail = "\n".join(f"{label}: {check[key]}" for key, label in (
        ("uname_after", "Owner"), ("gname_after", "Group"), ("perm_after", "Permissions"), ("size_after", "Size"),
        ("mtime_after", "Modified"), ("sha256_after", "SHA-256"), ("mode", "Detected by")) if check.get(key))
    return {"time": stamp(s.get("timestamp")), "agent": (s.get("agent") or {}).get("name", ""), "path": check.get("path", ""),
            "action": badge(check.get("event", ""), {"added": "info", "deleted": "critical", "modified": "medium"}.get(check.get("event"), "")),
            "changed": changed, "description": rule.get("description", ""), "_detail": detail}


FIM_COLUMNS = (("time", "Time", "time"), ("agent", "Agent", "text"), ("path", "File", "mono"), ("action", "Action", "badge"),
               ("changed", "What changed", "text"), ("description", "Rule", "wrap"))


def _alert_page(ctx, *, title, about, groups=None, row=_alert_row, columns=ALERT_COLUMNS, source=ALERT_SOURCE, empty="", start_level="") -> dict:
    """Any page that is 'the alerts of one Wazuh module': volume over time, top rules and agents, latest alerts."""
    q, here = ctx["q"], ctx["here"]
    hours = _hours(q)
    agent, rule = store.text(q.get("agent"), 120), store.text(q.get("rule"), 20)
    level = q.get("level") if q.get("level") in ("0", "7", "10", "13") else start_level
    words = store.text(q.get("text"), 200).replace("*", " ").replace("?", " ").strip()
    keep = {"agent": agent, "hours": "" if hours == "24" else hours, "level": "" if level == start_level else level, "rule": rule, "text": words}
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}]
    filters += [{"term": {"agent.name": agent}}] if agent else []
    filters += [{"term": {"rule.id": rule}}] if rule else []
    filters += [{"terms": {"rule.groups": list(groups)}}] if groups else []
    filters += [{"range": {"rule.level": {"gte": int(level)}}}] if level not in ("", "0") else []
    must = [{"bool": {"minimum_should_match": 1, "should": [
        {"wildcard": {"rule.description": {"value": f"*{words}*", "case_insensitive": True}}},
        {"match_phrase": {"full_log": words}}]}}] if words else []
    levels = [("0" if start_level else "", "All levels")] + list(LEVELS[1:])
    client = wazuh._Client(ctx["cfg"])
    try:
        agent_filter = _agent_select(client, agent)
        data = client.search({
            "size": 60, "sort": [{"timestamp": "desc"}], "track_total_hits": True, "_source": source,
            "query": {"bool": {"filter": filters, "must": must}},
            "aggs": {"time": {"date_histogram": {"field": "timestamp", "fixed_interval": STEP[hours], "min_doc_count": 0}},
                     "rules": {"terms": {"field": "rule.id", "size": 8}, "aggs": {"name": {"terms": {"field": "rule.description", "size": 1}}}},
                     "agents": {"terms": {"field": "agent.name", "size": 8}},
                     "rule_count": {"cardinality": {"field": "rule.id"}}, "top": {"max": {"field": "rule.level"}}}})
    finally:
        client.close()
    aggs = data.get("aggregations", {})
    total, top = _total(data), int((aggs.get("top") or {}).get("value") or 0)
    rows = [row(hit.get("_source", {})) for hit in data.get("hits", {}).get("hits", [])]
    return {
        "title": title, "subtitle": about,
        "filters": [agent_filter, select("hours", "Period", hours, HOURS), select("level", "Level", level, levels),
                    search_box("text", "Search description or log", words), search_box("rule", "Rule ID", rule, 110)],
        "tiles": [tile("Alerts", total), tile("Agents affected", len(_buckets(data, "agents"))),
                  tile("Rules triggered", int((aggs.get("rule_count") or {}).get("value") or 0)),
                  tile("Highest level", top, level_tone(top) if total else "")],
        "blocks": [
            trend("Alerts over time", [{"t": stamp(b.get("key_as_string")), "v": b["doc_count"]} for b in _buckets(data, "time")]),
            bars("Top rules", [{"label": f"{b['key']} · {((b.get('name') or {}).get('buckets') or [{'key': ''}])[0]['key']}", "value": b["doc_count"],
                               "href": link(here, keep, rule=b["key"])} for b in _buckets(data, "rules")]),
            bars("By agent", [{"label": b["key"], "value": b["doc_count"], "href": link(here, keep, agent=b["key"])} for b in _buckets(data, "agents")]),
            table(f"Latest alerts{f' · showing {len(rows)} of {total:,}' if total > len(rows) else ''}", columns, rows,
                  empty=empty or "No alerts match in this period."),
        ]}


def wz_overview(ctx) -> dict:
    q, here = ctx["q"], ctx["here"]
    hours = _hours(q)
    agent = store.text(q.get("agent"), 120)
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}] + ([{"term": {"agent.name": agent}}] if agent else [])
    client = wazuh._Client(ctx["cfg"])
    try:
        agent_filter = _agent_select(client, agent)
        agents = _agents(client)
        data = client.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filters}}, "aggs": {
            "time": {"date_histogram": {"field": "timestamp", "fixed_interval": STEP[hours], "min_doc_count": 0}},
            "levels": {"range": {"field": "rule.level", "ranges": [{"key": "Low (0-6)", "to": 7}, {"key": "Medium (7-9)", "from": 7, "to": 10},
                                                                   {"key": "High (10-12)", "from": 10, "to": 13}, {"key": "Critical (13+)", "from": 13}]}},
            "rules": {"terms": {"field": "rule.id", "size": 10}, "aggs": {"name": {"terms": {"field": "rule.description", "size": 1}},
                                                                         "level": {"max": {"field": "rule.level"}}}},
            "agents": {"terms": {"field": "agent.name", "size": 8}}, "ips": {"terms": {"field": "data.srcip", "size": 8}},
            "tactics": {"terms": {"field": "rule.mitre.tactic", "size": 8}}}})
    finally:
        client.close()
    levels = {b["key"]: b["doc_count"] for b in _buckets(data, "levels")}
    active = sum(1 for a in agents if a.get("status") == "active" and a.get("id") != "000")
    enrolled = sum(1 for a in agents if a.get("id") != "000")
    tones = {"Low (0-6)": "low", "Medium (7-9)": "medium", "High (10-12)": "high", "Critical (13+)": "critical"}
    alerts = "#/app/wazuh/discover"
    period = {"hours": "" if hours == "24" else hours, "agent": agent}
    return {
        "title": "Wazuh overview", "subtitle": "What Wazuh has detected across your enrolled machines.",
        "filters": [agent_filter, select("hours", "Period", hours, HOURS)],
        "tiles": [tile("Agents reporting", f"{active} / {enrolled}" if agents else "—", "" if active == enrolled else "high", href="#/app/wazuh/agents"),
                  tile("Alerts", _total(data), href=link(alerts, period)),
                  tile("High (10-12)", levels.get("High (10-12)", 0), "high" if levels.get("High (10-12)") else "", href=link(alerts, period, level="10")),
                  tile("Critical (13+)", levels.get("Critical (13+)", 0), "critical" if levels.get("Critical (13+)") else "", href=link(alerts, period, level="13"))],
        "blocks": [
            trend("Alerts over time", [{"t": stamp(b.get("key_as_string")), "v": b["doc_count"]} for b in _buckets(data, "time")]),
            bars("By level", [{"label": k, "value": levels.get(k, 0), "tone": tone} for k, tone in tones.items()]),
            bars("MITRE ATT&CK tactics", [{"label": b["key"], "value": b["doc_count"], "href": "#/app/wazuh/mitre"} for b in _buckets(data, "tactics")]),
            bars("Busiest agents", [{"label": b["key"], "value": b["doc_count"], "href": link(here, period, agent=b["key"])} for b in _buckets(data, "agents")]),
            bars("Top source IPs", [{"label": b["key"], "value": b["doc_count"], "href": link(alerts, period, text=b["key"])} for b in _buckets(data, "ips")]),
            table("Top rules", (("rule", "Rule", "mono"), ("description", "Description", "wrap"), ("level", "Level", "badge"), ("alerts", "Alerts", "num")), [
                {"rule": b["key"], "description": ((b.get("name") or {}).get("buckets") or [{"key": ""}])[0]["key"],
                 "level": badge(int((b.get("level") or {}).get("value") or 0), level_tone((b.get("level") or {}).get("value"))),
                 "alerts": b["doc_count"], "_href": link(alerts, period, rule=b["key"])} for b in _buckets(data, "rules")]),
        ]}


def wz_discover(ctx):
    return _alert_page(ctx, title="Discover", about="Every alert Wazuh has raised, newest first. Filter it down, or click a bar.")


def wz_hunting(ctx):
    return _alert_page(ctx, title="Threat hunting", start_level="7",
                       about="The alerts worth a closer look: level 7 and above. Narrow them by agent, rule or text to follow a lead.")


def wz_malware(ctx):
    return _alert_page(ctx, title="Malware detection", groups=("rootcheck", "virustotal", "yara", "clamd"),
                       about="Rootkit checks, VirusTotal lookups and antivirus findings.",
                       empty="No malware or rootkit findings in this period.")


def wz_fim(ctx):
    return _alert_page(ctx, title="File integrity monitoring", groups=("syscheck",), row=_fim_row, columns=FIM_COLUMNS,
                       source=["timestamp", "agent.name", "rule.id", "rule.description", "syscheck"],
                       about="Files that were added, changed or deleted on monitored paths.",
                       empty="No file changes were recorded in this period.")


def wz_docker(ctx):
    return _alert_page(ctx, title="Docker", groups=("docker",), about="Container activity reported by the Wazuh Docker listener.",
                       empty="No Docker alerts in this period. The Docker listener may not be enabled on your agents.")


def wz_aws(ctx):
    return _alert_page(ctx, title="Amazon Web Services", groups=("amazon", "aws"), about="Findings from AWS services such as CloudTrail and GuardDuty.",
                       empty="No AWS alerts in this period. The AWS module may not be set up in Wazuh.")


def wz_github(ctx):
    return _alert_page(ctx, title="GitHub", groups=("github",), about="Audit events from your GitHub organisations.",
                       empty="No GitHub alerts in this period. The GitHub module may not be set up in Wazuh.")


def wz_sca(ctx) -> dict:
    q, here = ctx["q"], ctx["here"]
    result = q.get("result") if q.get("result") in ("failed", "passed", "not applicable", "all") else "failed"
    words = store.text(q.get("text"), 120)
    client = wazuh._Client(ctx["cfg"])
    try:
        agents = [a for a in wazuh._agent_rows(client) if a.get("name")]
        chosen = next((a for a in agents if a["name"] == q.get("agent")), None) or next((a for a in agents if a.get("id") != "000"), None) or (agents or [None])[0]
        if not chosen:
            return {"title": "Configuration assessment", "subtitle": "No agents are enrolled in Wazuh yet.", "blocks": []}
        policies = client.api(f"/sca/{chosen['id']}").get("affected_items", [])
        checks = {}
        for p in policies:
            params = {"limit": 500, "sort": "+id", **({"result": result} if result != "all" else {}), **({"search": words} if words else {})}
            checks[p.get("policy_id")] = client.api(f"/sca/{chosen['id']}/checks/{p.get('policy_id')}", params)
    finally:
        client.close()
    keep = {"agent": chosen["name"], "text": words}
    page = {
        "title": "Configuration assessment", "subtitle": f"How {chosen['name']} measures up against its hardening benchmark.",
        "filters": [select("agent", "Agent", chosen["name"], [(a["name"], a["name"]) for a in agents]),
                    select("result", "Checks", result, (("failed", "Failed"), ("passed", "Passed"), ("not applicable", "Not applicable"), ("all", "All checks"))),
                    search_box("text", "Search checks, e.g. ssh", words)],
        "tiles": [], "blocks": []}
    if not policies:
        page["blocks"].append(table("Checks", (("title", "Check", "wrap"),), [],
                                    empty="Wazuh has no configuration assessment for this agent: no scan has run yet, or the module is off."))
    for p in policies:
        if not page["tiles"]:
            score = p.get("score") or 0
            page["tiles"] = [tile("Score", f"{score}%", "ok" if score >= 80 else "high" if score >= 50 else "critical", hint=p.get("name", "")),
                             tile("Passed", p.get("pass", 0), "ok", href=link(here, keep, result="passed")),
                             tile("Failed", p.get("fail", 0), "critical" if p.get("fail") else "", href=link(here, keep)),
                             tile("Not applicable", p.get("invalid", 0), href=link(here, keep, result="not applicable"))]
        found = checks.get(p.get("policy_id"), {})
        rows = [{"id": c.get("id"), "title": c.get("title", ""), "result": badge(c.get("result") or c.get("status") or "", RESULT_TONE.get(c.get("result"), "")),
                 "_detail": "\n\n".join(f"{label}\n{c[key]}" for key, label in (("rationale", "Why it matters"), ("remediation", "How to fix"),
                                                                              ("reason", "Why not applicable")) if c.get(key))}
                for c in found.get("affected_items", [])]
        page["blocks"].append(table(
            f"{(p.get('name') or '').rstrip('.')} · {found.get('total_affected_items', len(rows))} {'checks' if result == 'all' else result}",
            (("id", "ID", "mono"), ("title", "Check", "wrap"), ("result", "Result", "badge")), rows,
            empty="No checks match."))
        page["blocks"][-1].update(note_label="Last scan", note_time=p.get("end_scan") or "")
    return page


def wz_vulnerabilities(ctx) -> dict:
    q, here = ctx["q"], ctx["here"]
    agent, words = store.text(q.get("agent"), 120), store.text(q.get("text"), 80).replace("*", "").replace("?", "").strip()
    severity = q.get("severity") if q.get("severity") in VULN_TONE else ""
    filters = ([{"term": {"agent.name": agent}}] if agent else []) + ([{"term": {"vulnerability.severity": severity}}] if severity else [])
    must = [{"bool": {"minimum_should_match": 1, "should": [
        {"wildcard": {"vulnerability.id": {"value": f"*{words}*", "case_insensitive": True}}},
        {"wildcard": {"package.name": {"value": f"*{words}*", "case_insensitive": True}}}]}}] if words else []
    client = wazuh._Client(ctx["cfg"])
    try:
        agent_filter = _agent_select(client, agent)
        data = client.search({
            "size": 100, "track_total_hits": True, "query": {"bool": {"filter": filters, "must": must}},
            "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float", "missing": "_last"}}],
            "_source": ["agent.name", "package.name", "package.version", "vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
                        "vulnerability.detected_at", "vulnerability.description", "vulnerability.reference"],
            "aggs": {"severity": {"terms": {"field": "vulnerability.severity", "size": 6}}, "agents": {"terms": {"field": "agent.name", "size": 8}},
                     "packages": {"terms": {"field": "package.name", "size": 8}}}}, index="wazuh-states-vulnerabilities-*")
    finally:
        client.close()
    counts = {b["key"]: b["doc_count"] for b in _buckets(data, "severity")}
    keep = {"agent": agent, "severity": severity, "text": words}
    rows = []
    for hit in data.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        v, pkg = s.get("vulnerability") or {}, s.get("package") or {}
        reference = str(v.get("reference") or "").split(",")[0].strip()
        rows.append({"cve": v.get("id", ""), "severity": badge(v.get("severity") or "-", VULN_TONE.get(v.get("severity"), "")),
                     "score": (v.get("score") or {}).get("base") or "", "package": pkg.get("name", ""), "version": pkg.get("version", ""),
                     "agent": (s.get("agent") or {}).get("name", ""), "detected": stamp(v.get("detected_at")),
                     "_detail": v.get("description") or "", "_url": reference if reference.startswith("https://") else ""})
    total = _total(data)
    return {
        "title": "Vulnerability detection", "subtitle": "Known vulnerabilities in the software installed on your agents, worst first.",
        "filters": [agent_filter, select("severity", "Severity", severity, [("", "All severities")] + [(k, k) for k in VULN_TONE]),
                    search_box("text", "Search CVE or package", words)],
        "tiles": [tile(name, counts.get(name, 0), tone if counts.get(name) and name in ("Critical", "High") else "", href=link(here, keep, severity=name))
                  for name, tone in VULN_TONE.items()],
        "blocks": [
            bars("Most affected packages", [{"label": b["key"], "value": b["doc_count"], "href": link(here, keep, text=b["key"])} for b in _buckets(data, "packages")]),
            bars("By agent", [{"label": b["key"], "value": b["doc_count"], "href": link(here, keep, agent=b["key"])} for b in _buckets(data, "agents")]),
            table(f"Vulnerabilities{f' · showing the {len(rows)} highest scores of {total:,}' if total > len(rows) else ''}",
                  (("cve", "CVE", "mono"), ("severity", "Severity", "badge"), ("score", "Score", "num"), ("package", "Package", "text"),
                   ("version", "Version", "mono"), ("agent", "Agent", "text"), ("detected", "Detected", "time")), rows,
                  empty="No vulnerabilities match. The vulnerability detector may be off in Wazuh."),
        ]}


def wz_mitre(ctx) -> dict:
    q, here = ctx["q"], ctx["here"]
    hours, agent = _hours(q), store.text(q.get("agent"), 120)
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}, {"exists": {"field": "rule.mitre.id"}}] + ([{"term": {"agent.name": agent}}] if agent else [])
    client = wazuh._Client(ctx["cfg"])
    try:
        agent_filter = _agent_select(client, agent)
        data = client.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filters}}, "aggs": {
            "tactics": {"terms": {"field": "rule.mitre.tactic", "size": 14}}, "agents": {"terms": {"field": "agent.name", "size": 8}},
            "techniques": {"terms": {"field": "rule.mitre.id", "size": 30}, "aggs": {
                "name": {"terms": {"field": "rule.mitre.technique", "size": 1}}, "rule": {"terms": {"field": "rule.description", "size": 1}},
                "agents": {"cardinality": {"field": "agent.name"}}}}}})
    finally:
        client.close()
    period = {"hours": "" if hours == "24" else hours, "agent": agent}
    first = lambda b, name: ((b.get(name) or {}).get("buckets") or [{"key": ""}])[0]["key"]
    return {
        "title": "MITRE ATT&CK", "subtitle": "Wazuh alerts mapped to the attacker tactics and techniques they indicate.",
        "filters": [agent_filter, select("hours", "Period", hours, HOURS)],
        "tiles": [tile("Mapped alerts", _total(data)), tile("Tactics seen", len(_buckets(data, "tactics"))), tile("Techniques seen", len(_buckets(data, "techniques")))],
        "blocks": [
            bars("Tactics", [{"label": b["key"], "value": b["doc_count"]} for b in _buckets(data, "tactics")]),
            bars("By agent", [{"label": b["key"], "value": b["doc_count"], "href": link(here, period, agent=b["key"])} for b in _buckets(data, "agents")]),
            table("Techniques", (("id", "ID", "mono"), ("technique", "Technique", "text"), ("rule", "Most common rule", "wrap"), ("agents", "Agents", "num"), ("alerts", "Alerts", "num")), [
                {"id": b["key"], "technique": first(b, "name"), "rule": first(b, "rule"), "agents": int((b.get("agents") or {}).get("value") or 0), "alerts": b["doc_count"],
                 "_url": f"https://attack.mitre.org/techniques/{str(b['key']).replace('.', '/')}/"} for b in _buckets(data, "techniques")],
                  empty="No alerts carried a MITRE mapping in this period."),
        ]}


def _compliance(standard: str):
    field, name = COMPLIANCE[standard]

    def page(ctx) -> dict:
        q, here = ctx["q"], ctx["here"]
        hours, agent = _hours(q), store.text(q.get("agent"), 120)
        filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}, {"exists": {"field": field}}] + ([{"term": {"agent.name": agent}}] if agent else [])
        client = wazuh._Client(ctx["cfg"])
        try:
            agent_filter = _agent_select(client, agent)
            data = client.search({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filters}}, "aggs": {
                "agents": {"terms": {"field": "agent.name", "size": 8}},
                "requirements": {"terms": {"field": field, "size": 60}, "aggs": {
                    "rule": {"terms": {"field": "rule.description", "size": 1}}, "level": {"max": {"field": "rule.level"}},
                    "agents": {"cardinality": {"field": "agent.name"}}}}}})
        finally:
            client.close()
        period = {"hours": "" if hours == "24" else hours, "agent": agent}
        reqs = _buckets(data, "requirements")
        return {
            "title": name, "subtitle": f"Wazuh alerts that relate to {name} requirements. Alerts show activity to review, not a pass or fail.",
            "filters": [agent_filter, select("hours", "Period", hours, HOURS)],
            "tiles": [tile("Related alerts", _total(data)), tile("Requirements touched", len(reqs)), tile("Agents involved", len(_buckets(data, "agents")))],
            "blocks": [
                bars("Requirements with the most alerts", [{"label": b["key"], "value": b["doc_count"]} for b in reqs[:8]]),
                bars("By agent", [{"label": b["key"], "value": b["doc_count"], "href": link(here, period, agent=b["key"])} for b in _buckets(data, "agents")]),
                table("Requirements", (("requirement", "Requirement", "mono"), ("rule", "Most common rule", "wrap"), ("level", "Highest level", "badge"),
                                       ("agents", "Agents", "num"), ("alerts", "Alerts", "num")), [
                    {"requirement": b["key"], "rule": ((b.get("rule") or {}).get("buckets") or [{"key": ""}])[0]["key"],
                     "level": badge(int((b.get("level") or {}).get("value") or 0), level_tone((b.get("level") or {}).get("value"))),
                     "agents": int((b.get("agents") or {}).get("value") or 0), "alerts": b["doc_count"]} for b in reqs],
                      empty=f"No alerts carried a {name} mapping in this period."),
            ]}
    return page


def wz_agents(ctx) -> dict:
    client = wazuh._Client(ctx["cfg"])
    try:
        rows = wazuh._agent_rows(client)
    finally:
        client.close()
    _agent_cache[client.base] = (time.monotonic(), rows)
    count = lambda state: sum(1 for a in rows if a.get("status") == state and a.get("id") != "000")
    return {
        "title": "Agents", "subtitle": "Every machine enrolled in Wazuh. Click one to see its configuration assessment.",
        "tiles": [tile("Active", count("active"), "ok" if count("active") else ""), tile("Disconnected", count("disconnected"), "critical" if count("disconnected") else ""),
                  tile("Pending", count("pending")), tile("Never connected", count("never_connected"))],
        "blocks": [table("Agents", (("id", "ID", "mono"), ("name", "Name", "text"), ("ip", "IP address", "mono"), ("os", "Operating system", "text"),
                                    ("version", "Wazuh", "text"), ("status", "Status", "badge"), ("last_seen", "Last seen", "time")), [
            {"id": a.get("id"), "name": a.get("name", "") + (" (manager)" if a.get("id") == "000" else ""), "ip": a.get("ip", ""), "os": a.get("os", ""),
             "version": str(a.get("wazuh_version", "")).replace("Wazuh ", ""), "status": badge(str(a.get("status", "")).replace("_", " "), STATE_TONE.get(a.get("status"), "")),
             "last_seen": a.get("last_seen"), "_href": f"#/app/wazuh/sca?{urlencode({'agent': a.get('name', '')})}"} for a in rows])]}


def wz_server(ctx) -> dict:
    client = wazuh._Client(ctx["cfg"])
    try:
        daemons = (client.api("/manager/status").get("affected_items") or [{}])[0]
        info = (client.api("/manager/info").get("affected_items") or [{}])[0]
    finally:
        client.close()
    running = sum(1 for state in daemons.values() if state == "running")
    return {
        "title": "Server status", "subtitle": "The Wazuh manager and the services it runs.",
        "tiles": [tile("Version", str(info.get("version", "—")).lstrip("v")), tile("Services running", running, "ok" if running else "critical"),
                  tile("Services stopped", len(daemons) - running), tile("Agent limit", str(info.get("max_agents", "—")).capitalize())],
        "blocks": [table("Services", (("name", "Service", "mono"), ("state", "State", "badge")), [
            {"name": name, "state": badge(state, "ok" if state == "running" else "low")} for name, state in sorted(daemons.items())],
            note="Stopped services such as wazuh-maild or wazuh-agentlessd are optional features that are simply not in use.")]}


# ---------- Grafana ----------

def _g(cfg, path, params=None):
    """(data, error): one Grafana call that may be refused without losing the rest of the page."""
    try:
        return grafana._get(cfg, path, params), ""
    except grafana.GrafanaError as exc:
        text = str(exc)
        return None, ("The Grafana token is not allowed to read this." if "HTTP 403" in text or "HTTP 401" in text else text[:200])


def _datasources(cfg) -> list[dict]:
    return grafana._get(cfg, "/api/datasources") or []


def _alert_sources(cfg, kind: str) -> list[tuple[str, str]]:
    """Grafana's own alerting plus every datasource of one type: (name, uid)."""
    found, _ = _g(cfg, "/api/datasources")
    return [("Grafana", "grafana")] + [(d.get("name", ""), d.get("uid", "")) for d in found or [] if d.get("type") == kind and d.get("uid")]


def _rules(cfg) -> tuple[list[dict], list[str]]:
    rows, problems = [], []
    for name, uid in _alert_sources(cfg, "prometheus"):
        data, err = _g(cfg, f"/api/prometheus/{uid}/api/v1/rules")
        if err:
            problems.append(f"{name}: {err}")
            continue
        for group in (data or {}).get("data", {}).get("groups", []):
            for r in group.get("rules", []):
                if r.get("type") == "recording":
                    continue
                notes = r.get("annotations") or {}
                state = r.get("state", "")
                rows.append({"name": r.get("name", ""), "state": badge(state or "unknown", {"firing": "critical", "pending": "medium", "inactive": "ok"}.get(state, "")),
                             "severity": (r.get("labels") or {}).get("severity", ""), "group": group.get("name", ""), "source": name,
                             "health": badge(r.get("health", ""), "ok" if r.get("health") == "ok" else "critical" if r.get("health") in ("err", "error") else ""),
                             "evaluated": stamp(r.get("lastEvaluation")) if str(r.get("lastEvaluation", "")).startswith("2") else None, "_state": state,
                             "_detail": "\n\n".join(filter(None, [notes.get("summary", ""), notes.get("description", ""), f"Query\n{r.get('query', '')}" if r.get("query") else "",
                                                                 f"Error\n{r['lastError']}" if r.get("lastError") else ""]))})
    order = {"firing": 0, "pending": 1}
    return sorted(rows, key=lambda r: (order.get(r["_state"], 2), r["name"].lower())), problems


def _am(cfg, what: str) -> tuple[list[tuple[str, dict]], list[str]]:
    items, problems = [], []
    for name, uid in _alert_sources(cfg, "alertmanager"):
        data, err = _g(cfg, f"/api/alertmanager/{uid}/api/v2/{what}")
        if err:
            problems.append(f"{name}: {err}")
        items += [(name, item) for item in data or []]
    return items, problems


def _host(url: str) -> str:
    """Only the host of a notification address: the rest often carries a secret token."""
    try:
        return urlsplit(str(url)).hostname or ""
    except ValueError:
        return ""


def gf_home(ctx) -> dict:
    cfg = ctx["cfg"]
    health = grafana._get(cfg, "/api/health")
    dashboards, d_err = _g(cfg, "/api/search", {"type": "dash-db", "limit": 1000})
    sources, s_err = _g(cfg, "/api/datasources")
    rules, _ = _rules(cfg)
    firing = sum(1 for r in rules if r["_state"] == "firing")
    recent = sorted(dashboards or [], key=lambda d: d.get("sortMeta", 0), reverse=True)[:8]
    return {
        "title": "Grafana", "subtitle": "Your Grafana at a glance: dashboards, alerting and the data behind them.",
        "tiles": [tile("Version", health.get("version", "—")), tile("Dashboards", len(dashboards or []), href="#/app/grafana/dashboards"),
                  tile("Data sources", len(sources or []), href="#/app/grafana/datasources"),
                  tile("Alerts firing", firing, "critical" if firing else "ok" if rules else "", hint=f"of {len(rules)} rules", href="#/app/grafana/alert-rules")],
        "blocks": [
            table("Dashboards", (("title", "Dashboard", "text"), ("folder", "Folder", "text"), ("tags", "Tags", "text")), [
                {"title": d.get("title", ""), "folder": d.get("folderTitle") or "General", "tags": ", ".join(d.get("tags") or []),
                 "_url": cfg["url"].rstrip("/") + d.get("url", "")} for d in recent], note=d_err, empty="No dashboards yet."),
            table("Data sources", (("name", "Name", "text"), ("type", "Type", "text"), ("default", "", "badge")), [
                {"name": s.get("name", ""), "type": s.get("typeName") or s.get("type", ""), "default": badge("default", "info") if s.get("isDefault") else ""}
                for s in sources or []], note=s_err, empty="No data sources yet."),
        ]}


def gf_dashboards(ctx) -> dict:
    cfg, q = ctx["cfg"], ctx["q"]
    words = store.text(q.get("text"), 80)
    found = grafana._get(cfg, "/api/search", {"type": "dash-db", "limit": 1000, **({"query": words} if words else {})})
    folders = sorted({d.get("folderTitle") or "General" for d in found})
    return {
        "title": "Dashboards", "subtitle": "Every dashboard in Grafana. Click one to open it there.",
        "filters": [search_box("text", "Search dashboards", words)],
        "tiles": [tile("Dashboards", len(found)), tile("Folders", len(folders)), tile("Starred", sum(1 for d in found if d.get("isStarred")))],
        "blocks": [table("Dashboards", (("title", "Dashboard", "text"), ("folder", "Folder", "text"), ("tags", "Tags", "wrap")), [
            {"title": d.get("title", ""), "folder": d.get("folderTitle") or "General", "tags": ", ".join(d.get("tags") or []),
             "_url": cfg["url"].rstrip("/") + d.get("url", "")} for d in sorted(found, key=lambda d: d.get("title", "").lower())],
            empty="No dashboards match.")]}


def gf_rules(ctx) -> dict:
    rows, problems = _rules(ctx["cfg"])
    count = lambda state: sum(1 for r in rows if r["_state"] == state)
    broken = sum(1 for r in rows if r["health"] and r["health"]["tone"] == "critical")
    return {
        "title": "Alert rules", "subtitle": "The rules Grafana and Prometheus evaluate, with the ones firing first.",
        "tiles": [tile("Rules", len(rows)), tile("Firing", count("firing"), "critical" if count("firing") else ""),
                  tile("Pending", count("pending"), "medium" if count("pending") else ""), tile("Failing to evaluate", broken, "high" if broken else "")],
        "blocks": [table("Rules", (("name", "Rule", "text"), ("state", "State", "badge"), ("severity", "Severity", "text"), ("group", "Group", "text"),
                                   ("source", "Source", "text"), ("health", "Health", "badge"), ("evaluated", "Last checked", "time")), rows,
                         note=" · ".join(problems), empty="No alert rules are defined.")]}


def gf_active(ctx) -> dict:
    items, problems = _am(ctx["cfg"], "alerts")
    rows = []
    for source, a in items:
        labels, notes, state = a.get("labels") or {}, a.get("annotations") or {}, (a.get("status") or {}).get("state", "")
        rows.append({"alert": labels.get("alertname", ""), "state": badge(state, {"active": "critical", "suppressed": "low"}.get(state, "")),
                     "severity": labels.get("severity", ""), "instance": labels.get("instance") or labels.get("job", ""), "since": a.get("startsAt"),
                     "source": source, "_state": state,
                     "_detail": "\n\n".join(filter(None, [notes.get("summary", ""), notes.get("description", ""),
                                                         "Labels\n" + ", ".join(f"{k}={v}" for k, v in sorted(labels.items()))]))})
    active = sum(1 for r in rows if r["_state"] == "active")
    return {
        "title": "Active notifications", "subtitle": "Alerts that are firing right now and being routed to your contact points.",
        "tiles": [tile("Firing", active, "critical" if active else "ok"), tile("Silenced", len(rows) - active)],
        "blocks": [table("Alerts", (("alert", "Alert", "text"), ("state", "State", "badge"), ("severity", "Severity", "text"), ("instance", "Instance", "mono"),
                                    ("since", "Firing since", "time"), ("source", "Source", "text")), rows,
                         note=" · ".join(problems), empty="Nothing is firing.")]}


def gf_silences(ctx) -> dict:
    items, problems = _am(ctx["cfg"], "silences")
    rows = []
    for source, s in items:
        state = (s.get("status") or {}).get("state", "")
        rows.append({"matchers": ", ".join(f"{m.get('name')}{'=~' if m.get('isRegex') else '='}{m.get('value')}" for m in s.get("matchers") or []),
                     "state": badge(state, {"active": "medium", "pending": "info", "expired": "low"}.get(state, "")), "by": s.get("createdBy", ""),
                     "ends": s.get("endsAt"), "source": source, "_state": state, "_detail": s.get("comment") or ""})
    rows.sort(key=lambda r: r["_state"] == "expired")
    return {
        "title": "Silences", "subtitle": "Alerts that have been muted for a while, and who muted them.",
        "tiles": [tile("Active", sum(1 for r in rows if r["_state"] == "active")), tile("Expired", sum(1 for r in rows if r["_state"] == "expired"))],
        "blocks": [table("Silences", (("matchers", "Applies to", "mono"), ("state", "State", "badge"), ("by", "Created by", "text"),
                                      ("ends", "Ends", "time"), ("source", "Source", "text")), rows,
                         note=" · ".join(problems), empty="No silences.")]}


def gf_contacts(ctx) -> dict:
    cfg = ctx["cfg"]
    points, p_err = _g(cfg, "/api/v1/provisioning/contact-points")
    policy, _ = _g(cfg, "/api/v1/provisioning/policies")
    rows = []
    for p in points or []:
        settings = p.get("settings") or {}
        target = settings.get("addresses") or _host(settings.get("url")) or settings.get("recipient") or ""
        rows.append({"name": p.get("name", ""), "type": p.get("type", ""), "target": target,
                     "resolved": badge("no", "low") if p.get("disableResolveMessage") else badge("yes", "ok")})
    blocks = [table("Contact points", (("name", "Name", "text"), ("type", "Type", "text"), ("target", "Sends to", "mono"), ("resolved", "Tells you when resolved", "badge")),
                    rows, note=p_err or "Only the host of each address is shown, because the full address often contains a secret.", empty="No contact points.")]
    if policy:
        routes = policy.get("routes") or []
        blocks.append(table("Notification policy", (("match", "Alerts matching", "mono"), ("receiver", "Go to", "text"), ("group", "Grouped by", "text")), [
            {"match": "everything else (default)", "receiver": policy.get("receiver", ""), "group": ", ".join(policy.get("group_by") or [])}] + [
            {"match": ", ".join(" ".join(map(str, m)) for m in r.get("object_matchers") or []) or "—", "receiver": r.get("receiver", ""),
             "group": ", ".join(r.get("group_by") or [])} for r in routes]))
    return {"title": "Notification configuration", "subtitle": "Where Grafana sends alerts, and which alerts go where.",
            "tiles": [tile("Contact points", len(rows)), tile("Routing rules", len((policy or {}).get("routes") or []) + (1 if policy else 0))], "blocks": blocks}


def gf_datasources(ctx) -> dict:
    found = _datasources(ctx["cfg"])
    kinds = sorted({s.get("typeName") or s.get("type", "") for s in found})
    return {
        "title": "Data sources", "subtitle": "The systems Grafana reads from. CERBERUS queries Prometheus and Loki through these.",
        "tiles": [tile("Data sources", len(found)), tile("Types", len(kinds))],
        "blocks": [table("Data sources", (("name", "Name", "text"), ("type", "Type", "text"), ("url", "Address", "mono"), ("uid", "UID", "mono"), ("default", "", "badge")), [
            {"name": s.get("name", ""), "type": s.get("typeName") or s.get("type", ""), "url": s.get("url", ""), "uid": s.get("uid", ""),
             "default": badge("default", "info") if s.get("isDefault") else ""} for s in sorted(found, key=lambda s: s.get("name", "").lower())],
            empty="No data sources.")]}


# ---------- the catalogue ----------

def _page(page_id, label, icon, handler, external="") -> dict:
    return {"id": page_id, "label": label, "icon": icon, "handler": handler, "external": external}


def _route(route, label, icon) -> dict:
    """A menu entry that opens an existing CERBERUS screen instead of an application page."""
    return {"route": route, "label": label, "icon": icon}


APPS = [
    {"id": "wazuh", "name": "Wazuh", "about": "Endpoint detection and compliance",
     "ready": lambda conn: wazuh.is_ready(wazuh.settings(conn)), "config": lambda conn: wazuh.settings(conn),
     "errors": (wazuh.WazuhError,), "open": lambda cfg, path: str(cfg.get("url", "")).rstrip("/") if cfg.get("mode") == "dashboard" else "",
     "menu": [
         ("", [_page("overview", "Home", "home", wz_overview)]),
         ("Explore", [_page("discover", "Discover", "search", wz_discover), _route("#/events?source=wazuh", "Events in CERBERUS", "list")]),
         ("Endpoint security", [_page("sca", "Configuration assessment", "check", wz_sca), _page("malware", "Malware detection", "alert", wz_malware),
                                _page("fim", "File integrity monitoring", "edit", wz_fim)]),
         ("Threat intelligence", [_page("hunting", "Threat hunting", "eye", wz_hunting), _page("vulnerabilities", "Vulnerability detection", "shield", wz_vulnerabilities),
                                  _page("mitre", "MITRE ATT&CK", "grid", wz_mitre)]),
         ("Security operations", [_page(key, name, "check", _compliance(key)) for key, (_, name) in COMPLIANCE.items()]),
         ("Cloud security", [_page("docker", "Docker", "layers", wz_docker), _page("aws", "Amazon Web Services", "cloud", wz_aws), _page("github", "GitHub", "cloud", wz_github)]),
         ("Agents management", [_page("agents", "Summary", "users", wz_agents)]),
         ("Server management", [_page("server", "Status", "server", wz_server)]),
     ]},
    {"id": "grafana", "name": "Grafana", "about": "Metrics, logs and alerting",
     "ready": lambda conn: bool(get_integration(conn, "grafana").get("url")), "config": lambda conn: get_integration(conn, "grafana"),
     "errors": (grafana.GrafanaError,), "open": lambda cfg, path: str(cfg.get("url", "")).rstrip("/") + path,
     "menu": [
         ("", [_page("overview", "Home", "home", gf_home, "/")]),
         ("Dashboards", [_page("dashboards", "Browse", "grid", gf_dashboards, "/dashboards")]),
         ("Explore", [_route("#/logs", "Logs", "terminal"), _route("#/infrastructure", "Metrics and health", "activity")]),
         ("Alerting", [_page("alert-rules", "Alert rules", "bell", gf_rules, "/alerting/list"),
                       _page("contact-points", "Notification configuration", "mail", gf_contacts, "/alerting/notifications"),
                       _page("silences", "Silences", "moon", gf_silences, "/alerting/silences"),
                       _page("active", "Active notifications", "alert", gf_active, "/alerting/groups")]),
         ("Connections", [_page("datasources", "Data sources", "plug", gf_datasources, "/connections/datasources")]),
     ]},
]


def catalog(conn) -> list[dict]:
    """What the application switcher shows: each application, whether it is connected, and its menu."""
    return [{"id": a["id"], "name": a["name"], "about": a["about"], "connected": a["ready"](conn),
             "menu": [{"label": label, "items": [{k: v for k, v in item.items() if k in ("id", "route", "label", "icon")} for item in items]}
                      for label, items in a["menu"]]} for a in APPS]


def render(conn, app_id: str, page_id: str, q: dict) -> dict:
    """One application page as data. Raises KeyError for an unknown page and NotConnected when the application is not set up."""
    found = next(a for a in APPS if a["id"] == app_id) if any(a["id"] == app_id for a in APPS) else None
    item = found and next((i for _, items in found["menu"] for i in items if i.get("id") == page_id), None)
    if not item:
        raise KeyError(page_id)
    if not found["ready"](conn):
        raise NotConnected(found["name"])
    cfg = found["config"](conn)
    q = {k: str(v)[:200] for k, v in q.items()}
    page = item["handler"]({"cfg": cfg, "q": q, "here": f"#/app/{app_id}/{page_id}"})
    opened = found["open"](cfg, item["external"])
    return {"app": app_id, "app_name": found["name"], "page": page_id, "label": item["label"], "tiles": [], "filters": [], "blocks": [],
            **page, "external": {"label": f"Open in {found['name']}", "url": opened} if opened else None}


def errors() -> tuple:
    return tuple(e for a in APPS for e in a["errors"])
