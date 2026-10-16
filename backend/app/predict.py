"""Attack forecasting: early warnings from the patterns that usually come before an intrusion.

Nothing here can know the future. What it can do is notice an attack that is building up, the way an
analyst would: an address that scanned a server and is now sending exploits at it, password guessing that
is speeding up against real accounts, attacks aimed at a machine with flaws known to be exploited, or a
sudden surge of hostile traffic. Each pattern gets a likelihood (0-100) that an intrusion follows unless
someone acts, the stage the attack has reached, what usually happens next, and what to do now. The AI
writes the warning; admins are alerted in the app, by email and with an incident.
"""
import json
import logging
import math
import threading
from collections import Counter
from datetime import datetime, timezone

from . import accounts, ai, grafana, insights, mailer, openappsec, snort, store
from .apps import badge, bars, table, tile
from .db import db, get_integration, get_setting, now, set_integration, set_setting

log = logging.getLogger("cerberus.predict")

DEFAULTS = {
    "enabled": True,
    "interval_minutes": 10,
    "alert_min": 70,        # alert admins when a warning's likelihood reaches this
    "notify_in_app": True,
    "email": True,
    "incident": True,       # also open an incident for each alerted warning
    "ai": True,             # let the AI write the warning
}

# Snort classifications, by the stage of an attack they point to.
RECON = {"Detection of a Network Scan", "Attempted Information Leak", "Potentially Bad Traffic", "Misc activity",
         "Detection of a non-standard protocol or event", "Generic Protocol Command Decode", "Information Leak"}
EXPLOIT = {"Executable code was detected", "Attempted Administrator Privilege Gain", "Attempted User Privilege Gain", "Web Application Attack",
           "Misc Attack", "Attempted Denial of Service", "Unsuccessful User Privilege Gain", "Denial of Service", "Attempted Login"}
COMPROMISE = {"Successful Administrator Privilege Gain", "Successful User Privilege Gain", "A Network Trojan was detected",
              "Successful Credential Theft Detected", "Large Scale Information Leak", "Successful Information Leak"}
# open-appsec attack types that try to run something, as opposed to looking around.
WAF_EXPLOIT = ("Remote Code Execution", "SQL Injection", "Path Traversal", "Cross Site Scripting", "Command Injection", "LDAP Injection",
               "XML External Entity", "Server Side Request Forgery", "Local File Inclusion", "Remote File Inclusion", "Evasion Techniques")
BASE_MINUTES = 360  # the "normal" level is the last six hours; a day of every log line is too slow to count
STAGES = ("Reconnaissance", "Credential attack", "Exploitation attempt", "Possible intrusion")

JOURNAL = '{job="loki.source.journal.system"}'
FAILED_REAL = '|= "Failed password for " != "invalid user"'
FAILED_ANY = '|~ "Failed password for |Invalid user "'
FROM_IP = r'| regexp `from (?P<ip>\d+\.\d+\.\d+\.\d+) port`'
FAILED_USER = r'| regexp `Failed \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port`'
ACCEPTED = r'|= "Accepted " | regexp `Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port`'

SCHEMA = """
CREATE TABLE IF NOT EXISTS forecasts (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    likelihood INTEGER NOT NULL,
    peak INTEGER NOT NULL DEFAULT 0,
    stage TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ended_at TEXT NOT NULL DEFAULT '',
    alerted_at TEXT NOT NULL DEFAULT '',
    alerted_likelihood INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_forecasts_status ON forecasts(status, last_seen);
"""
_lock = threading.Lock()


def settings(conn) -> dict:
    saved = get_integration(conn, "forecast")
    merged = {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS}}
    merged["alert_min"] = store.clamp(merged["alert_min"], 40, 95, 70)
    merged["interval_minutes"] = store.clamp(merged["interval_minutes"], 5, 60, 10)
    return merged


def save_settings(conn, changes: dict) -> dict:
    set_integration(conn, "forecast", {**settings(conn), **{k: v for k, v in changes.items() if k in DEFAULTS}})
    return settings(conn)


# ---------- reading the sources ----------

def _metric(cfg: dict, logql: str) -> list[tuple[dict, int]]:
    uid = store.text(cfg.get("loki_uid"), 80)
    data = grafana._get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/query", {"query": logql, "time": int(datetime.now(timezone.utc).timestamp())})
    return [(r.get("metric") or {}, int(float(r["value"][1]))) for r in (data or {}).get("data", {}).get("result", [])]


def _ssh(cfg: dict, filt: str, parse: str, by: str, minutes: int) -> list[tuple[dict, int]]:
    return _metric(cfg, f"topk(400, sum by ({by}) (count_over_time({JOURNAL} {filt} {parse} [{int(minutes)}m])))")


def _collect(conn) -> tuple[dict, list[str]]:
    """Everything the patterns look at. Database reads happen here, on the caller's thread; network reads run in parallel."""
    c = insights._configs(conn)
    g = c["grafana"]
    try:
        machines, problems = insights.machines(conn)
    except Exception as exc:  # the forecast still works without vulnerability context
        machines, problems = [], [f"Machine inventory: {str(exc)[:120]}"]
    wazuh_recent = [dict(r) for r in conn.execute(
        "SELECT source_ip, COUNT(*) AS n, MAX(severity) AS worst FROM events WHERE ts >= ? AND source = 'wazuh' AND source_ip != '' GROUP BY source_ip",
        (store.ago(hours=1),))]
    jobs = {}
    if c["loki"]:
        jobs["snort_now"] = lambda: snort.counts(g, ("src", "dst", "kind", "msg"), 60, 500, keep=1, public_source=True)
        jobs["snort_dst_now"] = lambda: snort.counts(g, ("dst",), 60, 200, keep=1, public_source=True)
        jobs["snort_dst_day"] = lambda: snort.counts(g, ("dst",), 1440, 200, keep=300, public_source=True)
        jobs["fail_real"] = lambda: _ssh(g, FAILED_REAL, FAILED_USER, "host, user, ip", 60)
        jobs["fail_any"] = lambda: _ssh(g, FAILED_ANY, FROM_IP, "host, ip", 60)
        jobs["fail_15"] = lambda: _ssh(g, FAILED_ANY, "", "host", 15)
        jobs["fail_base"] = lambda: _ssh(g, FAILED_ANY, "", "host", BASE_MINUTES)
        jobs["fail_ip_base"] = lambda: _ssh(g, FAILED_ANY, FROM_IP, "host, ip", BASE_MINUTES)
        jobs["accepted"] = lambda: _ssh(g, "", ACCEPTED, "host, method, user, ip", BASE_MINUTES)
        jobs["waf"] = lambda: openappsec.requests(g, 24)
    found, failed = insights._parallel(jobs)
    found.update(machines=machines, wazuh=wazuh_recent)
    return found, problems + failed


# ---------- the patterns ----------

def _name_of(machines: list[dict]) -> dict:
    """IP or name -> the machine record, so any address or host name resolves to one machine."""
    index = {}
    for m in machines:
        index[m["ip"]] = m
        for n in m["names"]:
            index[n] = m
    return index


def _label(m: dict | None, fallback: str) -> str:
    return (m["names"][0] if m and m["names"] else fallback) or fallback


def _vulnerable(m: dict | None) -> bool:
    return bool(m and (m.get("kev") or m.get("epss_hot")))


def _ssh_signature(g: dict) -> bool:
    """Snort's SSH shellcode/overflow signatures fire on ordinary SSH brute-force traffic; they are part of the password attack, not an exploit."""
    return "ssh" in g.get("msg", "").lower()


def _forecast(key, kind, title, target, likelihood, stage, next_step, action, evidence, attackers=(), **extra) -> dict:
    return {"key": key, "kind": kind, "title": title, "target": target, "likelihood": int(max(1, min(99, round(likelihood)))), "stage": stage,
            "next": next_step, "action": action, "evidence": [e for e in evidence if e], "attackers": list(attackers)[:8], **extra}


def _password_guessing(d: dict, index: dict) -> list[dict]:
    """Password guessing that is heavy, speeding up, aimed at real accounts, or has already let someone in."""
    out = []
    per_host: dict[str, dict] = {}
    for m, n in d.get("fail_any", []):
        h = per_host.setdefault(m.get("host", ""), {"total": 0, "sources": Counter(), "real": 0, "users": Counter()})
        h["total"] += n
        h["sources"][m.get("ip", "")] += n
    for m, n in d.get("fail_real", []):
        h = per_host.setdefault(m.get("host", ""), {"total": 0, "sources": Counter(), "real": 0, "users": Counter()})
        h["real"] += n
        h["users"][m.get("user", "")] += n
    last15 = {m.get("host", ""): n for m, n in d.get("fail_15", [])}
    known_base = "fail_base" in d
    day = {m.get("host", ""): n for m, n in d.get("fail_base", [])}
    failed_day = {(m.get("host", ""), m.get("ip", "")): n for m, n in d.get("fail_ip_base", [])}
    password_ok = {m.get("host", "") for m, _ in d.get("accepted", []) if m.get("method") == "password"}
    # Someone who failed many times and then got in: this may already have happened.
    for m, n in d.get("accepted", []):
        host, ip, user = m.get("host", ""), m.get("ip", ""), m.get("user", "")
        fails = failed_day.get((host, ip), 0)
        if fails >= 10 and not insights.is_public(ip):
            # Behind a gateway every connection shares one address, so this login cannot be tied to the attackers.
            out.append(_forecast(
                f"ssh-in:{host}:{ip}:{user}", "credential", f"{user} logged in to {host} through the address the password guessing comes from", host, 62, STAGES[1],
                "If this login was not one of your team, an attacker has guessed the password for this account.",
                f"Confirm the {m.get('method', '')} login as {user} on {host} was expected. If nobody recognises it, change that password and check what ran after it.",
                [f"{n} successful {m.get('method', '')} login(s) as {user} from {ip}, which also sent {fails:,} failed logins in the last 6 hours.",
                 f"{ip} is an internal address (a gateway or proxy), so legitimate users and attackers share it; this may well be a normal login."],
                [ip], host=host))
        elif fails >= 10:
            out.append(_forecast(
                f"ssh-in:{host}:{ip}:{user}", "credential", f"{ip} logged in to {host} as {user} after failing {fails:,} times", host, 93, STAGES[3],
                "The attacker is already on the machine: next comes running tools, adding a backdoor or moving to other servers.",
                f"Check now whether this login was expected. If not: disconnect it, change the password of {user}, look at what ran after the login "
                f"(the IP lookup page shows the timeline), and block {ip}.",
                [f"{fails:,} failed SSH logins from {ip} on {host} in the last 6 hours, then {n} successful {m.get('method', '')} login(s) as {user}.",
                 "" if insights.is_public(ip) else f"{ip} is an internal address: a gateway or proxy may be forwarding the real attacker."],
                [ip], host=host))
    for host, h in per_host.items():
        if not host or h["total"] < 30:
            continue
        base = max(1.0, (day.get(host, 0) - h["total"]) / 5) if known_base else 0
        surge = h["total"] / base if base else 0
        speeding = last15.get(host, 0) * 4 / max(1, h["total"])
        m = index.get(host)
        exposed = bool(m and m.get("exposure") == "internet-facing")
        score = (25 + min(22, 7 * math.log10(1 + h["total"])) + (15 if h["real"] >= 10 else 0) + (10 if speeding >= 1.5 or surge >= 3 else 0)
                 + (10 if exposed else 0) + (10 if host in password_ok else 0))
        top = h["sources"].most_common(5)
        hidden = [ip for ip, _ in top if ip and not insights.is_public(ip)]
        users = [u for u, _ in h["users"].most_common(5) if u]
        out.append(_forecast(
            f"ssh:{host}", "credential", f"SSH password guessing against {host} could succeed", host, score, STAGES[1],
            "If any account has a weak password, the attacker logs in over SSH and has a shell on the server.",
            "Turn off SSH password logins (PasswordAuthentication no) and use keys; check that fail2ban is running; block the top sources"
            + (f"; make sure {', '.join(users[:3])} have strong passwords or are disabled" if users else "") + ".",
            [f"{h['total']:,} failed SSH logins in the last hour from {len(h['sources'])} address(es)" + (f"; the hours before averaged {base:,.0f}." if base else "."),
             f"{h['real']:,} of them were for accounts that exist on the server: {', '.join(users)}." if h["real"] >= 10 else "",
             f"It is speeding up: {last15.get(host, 0):,} in the last 15 minutes." if speeding >= 1.5 else "",
             f"This server accepts password logins (seen in the last 6 hours)." if host in password_ok else "",
             f"{host} faces the internet." if exposed else "",
             f"Some sources are internal addresses ({', '.join(hidden)}): a gateway or proxy is forwarding the real attackers." if hidden else ""],
            [ip for ip, _ in top], host=host, attempts=h["total"], accounts=users))
    return out


def _attack_chains(d: dict, index: dict) -> list[dict]:
    """One internet address moving through the stages of an attack: looking, guessing, exploiting."""
    cutoff = (datetime.now(timezone.utc).timestamp() - 3600) * 1e9
    who: dict[str, dict] = {}
    def entry(ip):
        return who.setdefault(ip, {"stages": set(), "sources": set(), "targets": Counter(), "count": 0, "kinds": Counter(), "through": 0})
    for g, n in d.get("snort_now", []):
        e = entry(g["src"])
        kind = g.get("kind", "")
        ssh_noise = _ssh_signature(g)
        e["stages"].add("credential" if ssh_noise else "compromise" if kind in COMPROMISE else "exploit" if kind in EXPLOIT else "recon")
        e["sources"].add("Snort")
        e["targets"][g["dst"]] += n
        e["kinds"][("SSH attack traffic (Snort: " + g.get("msg", "")[:40] + ")") if ssh_noise else kind or "unclassified"] += n
        e["count"] += n
    for r in d.get("waf", []):
        if r["ns"] < cutoff or not insights.is_public(r["source"]):
            continue
        e = entry(r["source"])
        e["stages"].add("exploit" if r["type"] in WAF_EXPLOIT else "recon")
        e["sources"].add("WAF")
        e["targets"][r["asset"] or "web"] += 1
        e["kinds"][r["type"] or "web attack"] += 1
        e["count"] += 1
        e["through"] += r["action"] == "Detect"
    for m, n in d.get("fail_any", []):
        if insights.is_public(m.get("ip", "")) and n >= 10:
            e = entry(m["ip"])
            e["stages"].add("credential")
            e["sources"].add("SSH logs")
            e["targets"][m.get("host", "")] += n
            e["kinds"]["SSH password guessing"] += n
            e["count"] += n
    for r in d.get("wazuh", []):
        if insights.is_public(r["source_ip"]) and r["source_ip"] in who:
            who[r["source_ip"]]["sources"].add("Wazuh")
    out = []
    for ip, e in who.items():
        steps = e["stages"] & {"recon", "credential", "exploit"}
        if "compromise" not in e["stages"] and (len(steps) < 2 and not ("exploit" in steps and len(e["sources"]) >= 2)):
            continue
        target_key, hits = e["targets"].most_common(1)[0]
        m = index.get(target_key)
        target = _label(m, target_key)
        score = (30 + 15 * (len(steps) - 1) + (10 if len(e["sources"]) >= 2 else 0) + (15 if _vulnerable(m) else 0)
                 + (10 if e["through"] else 0) + min(10, 3 * math.log10(1 + e["count"])))
        if "compromise" in e["stages"]:
            score, stage = max(score, 90), STAGES[3]
        else:
            stage = STAGES[2] if "exploit" in steps else STAGES[1]
        order = [s for s in ("recon", "credential", "exploit", "compromise") if s in e["stages"]]
        words = {"recon": "scanning", "credential": "password guessing", "exploit": "exploit attempts", "compromise": "signs of a successful attack"}
        out.append(_forecast(
            f"chain:{ip}", "chain", f"{ip} has moved from {words[order[0]]} to {words[order[-1]]} against {target}", target, score, stage,
            "Attackers who have mapped a server and started firing exploits keep trying until one works; this address is past the looking stage.",
            f"Block {ip} at the firewall now"
            + (f", and patch {target}'s known-exploited vulnerabilities (Vulnerability priority page)" if _vulnerable(m) else "")
            + ". Open the IP lookup page for its full timeline.",
            [f"In the last hour: {', '.join(f'{k} ({v:,})' for k, v in e['kinds'].most_common(4))}.",
             f"Seen by {', '.join(sorted(e['sources']))}." if len(e["sources"]) >= 2 else "",
             f"{e['through']} web attack(s) got past the firewall (it is in detect-only mode for that site)." if e["through"] else "",
             f"{target} has {m['kev']} vulnerability(ies) known to be exploited in the wild." if m and m.get("kev") else ""],
            [ip], ip=ip, events=e["count"]))
    return sorted(out, key=lambda f: -f["likelihood"])[:8]


def _exposed_and_attacked(d: dict, index: dict, machines: list[dict]) -> list[dict]:
    """A machine with flaws known to be exploited, facing the internet, receiving exploit attempts right now."""
    cutoff = (datetime.now(timezone.utc).timestamp() - 3600) * 1e9
    out = []
    for m in machines:
        if not _vulnerable(m) or m.get("exposure") != "internet-facing":
            continue
        snort_hits = sum(n for g, n in d.get("snort_now", []) if g["dst"] == m["ip"] and g.get("kind") in EXPLOIT | COMPROMISE and not _ssh_signature(g))
        waf_hits = sum(1 for r in d.get("waf", []) if r["ns"] >= cutoff and r["asset"] in m.get("waf_assets", []) and r["type"] in WAF_EXPLOIT)
        if snort_hits + waf_hits < 5:
            continue
        name = _label(m, m["ip"])
        score = 45 + (20 if m.get("kev") else 0) + (10 if m.get("epss_hot") else 0) + min(15, 5 * math.log10(1 + snort_hits + waf_hits)) + (10 if m.get("waf_through") else 0)
        out.append(_forecast(
            f"vuln:{m['ip']}", "vulnerable", f"{name} is being attacked and has vulnerabilities attackers already use", name, score, STAGES[2],
            "Attackers try known exploits until one matches an unpatched flaw; this machine has such flaws and is receiving exploit traffic now.",
            f"Patch the 'Fix now' CVEs on {name} first (Vulnerability priority page); until then limit who can reach it from the internet.",
            [f"{snort_hits:,} Snort exploit alert(s) and {waf_hits:,} web exploit attempt(s) against it in the last hour.",
             f"{m['kev']} vulnerability(ies) on it are in CISA's list of flaws exploited in the wild." if m.get("kev") else "",
             f"{m['epss_hot']} more are likely to be exploited within 30 days (EPSS 10% or more)." if m.get("epss_hot") else "",
             f"Risk score {m.get('risk', '?')}/100."],
            host=name, ip=m["ip"]))
    return out


def _surges(d: dict, index: dict) -> list[dict]:
    """Hostile traffic against one target far above its normal level: a campaign building up."""
    day = {g["dst"]: n for g, n in d.get("snort_dst_day", [])}
    sources = Counter(g["dst"] for g, _ in d.get("snort_now", []))
    out = []
    for g, n in d.get("snort_dst_now", []):
        normal = max(1.0, (day.get(g["dst"], 0) - n) / 23)
        ratio = n / normal
        if n < 200 or ratio < 4:
            continue
        m = index.get(g["dst"])
        name = _label(m, g["dst"])
        score = 40 + min(25, 10 * math.log2(ratio / 2)) + (10 if _vulnerable(m) else 0) + (5 if sources[g["dst"]] >= 10 else 0)
        out.append(_forecast(
            f"surge:{g['dst']}", "surge", f"Attack traffic against {name} is {ratio:.0f}x its normal level", name, score, STAGES[0],
            "A sudden surge usually means a campaign has picked this target; exploitation attempts against what it found tend to follow.",
            f"Watch {name} closely for the next hours, block the busiest sources, and check its exposed services are patched.",
            [f"{n:,} Snort alerts from internet addresses in the last hour; a normal hour has about {normal:,.0f}.",
             f"{sources[g['dst']]} different source address(es) involved." if sources[g["dst"]] else ""],
            host=name, ip=g["dst"]))
    return out


def _unblocked(d: dict) -> list[dict]:
    """Serious web attacks that the firewall only logged, because the site is in detect-only mode."""
    groups: dict[str, list] = {}
    for r in d.get("waf", []):
        if r["action"] == "Detect" and r["severity"] in ("High", "Critical"):
            groups.setdefault(r["asset"] or "web", []).append(r)
    out = []
    for asset, items in groups.items():
        critical = sum(1 for r in items if r["severity"] == "Critical")
        kinds = Counter(r["type"] for r in items)
        out.append(_forecast(
            f"through:{asset}", "unblocked", f"Serious web attacks are reaching {asset} without being blocked", asset,
            60 + (10 if critical else 0) + min(15, 6 * math.log10(1 + len(items))), STAGES[2],
            "These requests reached the application. If one of them matches a flaw in the site, it succeeds.",
            f"Switch {asset}'s practice to Prevent in the open-appsec portal, then check the application logs for what these requests did.",
            [f"{len(items)} high or critical web attack(s) let through in the last 24 hours ({critical} critical): {', '.join(f'{k} ({v})' for k, v in kinds.most_common(3))}."],
            sorted({r["source"] for r in items})))
    return out


def forecasts(d: dict) -> list[dict]:
    machines = d.get("machines", [])
    index = _name_of(machines)
    found = _password_guessing(d, index) + _attack_chains(d, index) + _exposed_and_attacked(d, index, machines) + _surges(d, index) + _unblocked(d)
    return sorted(found, key=lambda f: -f["likelihood"])


# ---------- running, remembering, alerting ----------

def _store(conn, found: list[dict], s: dict) -> list[dict]:
    """Save this pass. A warning ends only when two passes in a row no longer see it, so it does not flicker."""
    stamp = now()
    for f in found:
        conn.execute(
            "INSERT INTO forecasts (key, kind, title, target, likelihood, peak, stage, detail, status, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?) ON CONFLICT(key) DO UPDATE SET title = excluded.title, target = excluded.target, "
            "likelihood = excluded.likelihood, peak = MAX(forecasts.peak, excluded.likelihood), stage = excluded.stage, detail = excluded.detail, "
            "first_seen = CASE WHEN forecasts.status = 'active' THEN forecasts.first_seen ELSE excluded.first_seen END, "
            "alerted_at = CASE WHEN forecasts.status = 'active' THEN forecasts.alerted_at ELSE '' END, "
            "alerted_likelihood = CASE WHEN forecasts.status = 'active' THEN forecasts.alerted_likelihood ELSE 0 END, "
            "status = 'active', ended_at = '', last_seen = excluded.last_seen",
            (f["key"], f["kind"], f["title"][:200], f["target"][:120], f["likelihood"], f["likelihood"], f["stage"], json.dumps(f, default=str), stamp, stamp))
    conn.execute("UPDATE forecasts SET status = 'ended', ended_at = ? WHERE status = 'active' AND last_seen < ?",
                 (stamp, store.ago(minutes=2 * s["interval_minutes"] + 5)))
    due = []
    for r in conn.execute("SELECT * FROM forecasts WHERE status = 'active' AND last_seen = ? AND likelihood >= ?", (stamp, s["alert_min"])):
        if not r["alerted_at"] or r["likelihood"] >= r["alerted_likelihood"] + 15 or r["alerted_at"] < store.ago(hours=24):
            due.append(json.loads(r["detail"]))
    return due


def _email(due: list[dict], assessment: str, app_url: str) -> tuple[str, str, str]:
    worst = due[0]
    listing = "\n".join(f"- **{f['likelihood']}% · {f['title']}** ({f['stage']}). Expected next: {f['next']} **Do now:** {f['action']}" for f in due)
    body = mailer.md_to_html(listing)
    if assessment:
        body += (f'<p style="margin:26px 0 8px;font-size:13px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:{mailer.QUIET}">'
                 "AI analyst</p>" + mailer.md_to_html(assessment))
    critical = worst["likelihood"] >= 85
    subject = f"[CERBERUS forecast] {worst['likelihood']}% likely: {worst['title']}" + (f" and {len(due) - 1} more" if len(due) > 1 else "")
    html_body = mailer.layout(
        banner="watch-critical" if critical else "watch", accent="#b91c1c" if critical else "#b45309",
        headline=worst["title"] if len(due) == 1 else f"[[{len(due)} attacks]] may be about to succeed",
        lead="CERBERUS sees the pattern that usually comes before an intrusion. Acting now can stop it.",
        button=("Open the attack forecast", f"{app_url}/#/forecast") if app_url else None, body_html=body,
        note="You receive this as a CERBERUS admin. The alert threshold can be changed under Integrations, Attack forecasting.", preheader=worst["title"])
    text = subject + "\n\n" + "\n".join(f"- {f['likelihood']}% {f['title']}: {f['action']}" for f in due) + (f"\n\nAI analyst:\n{assessment}" if assessment else "")
    return subject, html_body, text


def _alert(conn, due: list[dict], s: dict, assessment: str) -> None:
    worst = due[0]["likelihood"]
    title = due[0]["title"] if len(due) == 1 else f"{len(due)} attacks may be about to succeed"
    body = "\n".join(f"- **{f['likelihood']}%** {f['title']}. Do now: {f['action']}" for f in due) + (f"\n\n**AI analyst**\n\n{assessment}" if assessment else "")
    if s["notify_in_app"]:
        conn.execute("INSERT INTO notifications (title, body, level, audience, in_app, emailed, created_by, created_at) VALUES (?, ?, ?, 'admins', 1, 0, 'Attack forecast', ?)",
                     (("Forecast: " + title)[:120], body[:5000], "critical" if worst >= 85 else "warning", now()))
    if s["email"]:
        try:
            mailer.send(conn, "forecast", accounts.admin_emails(conn), _email(due, assessment, mailer.config(conn).get("app_url", "")))
        except mailer.MailError as exc:
            log.warning("forecast email not sent: %s", exc)
    if s["incident"]:
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        for f in due:
            ip = next((a for a in f["attackers"] if insights.is_public(a)), "")
            store.ingest_event(conn, {
                "source": "cerberus", "source_event_id": f"forecast:{f['key']}:{day}", "asset": f["target"] or "multiple", "event_type": "predicted_attack",
                "severity": 9 if f["likelihood"] >= 90 else 8 if f["likelihood"] >= 80 else 7, "timestamp": now(), "source_ip": ip, "rule_id": f"forecast:{f['kind']}",
                "title": f"Predicted ({f['likelihood']}%): {f['title']}"[:200],
                "message": f"Stage: {f['stage']}. Expected next: {f['next']} Do now: {f['action']} Evidence: {' '.join(f['evidence'])}"[:4000],
                "evidence_ref": {"backend": "cerberus", "view": "#/forecast"}})
    stamp = now()
    for f in due:
        conn.execute("UPDATE forecasts SET alerted_at = ?, alerted_likelihood = ? WHERE key = ?", (stamp, f["likelihood"], f["key"]))


def run(reason: str = "schedule") -> dict:
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "A forecast is already running"}
    try:
        with db() as conn:
            s = settings(conn)
            data, problems = _collect(conn)
        found = forecasts(data)
        with db() as conn:
            due = _store(conn, found, s)
            provider = ai.active_provider(conn) if s["ai"] and due else None
        assessment = ""
        if provider:
            try:
                with ai.usage("forecast", "attack forecast"):
                    assessment = ai.brief(provider, "forecast", json.dumps({"warnings": due, "other_active": [f["title"] for f in found if f not in due][:10]}, default=str), "UTC")
            except ai.AIError as exc:
                problems.append(f"AI: {exc}")
        with db() as conn:
            if due:
                _alert(conn, due, s, assessment)
                set_setting(conn, "forecast_assessment", assessment)
                set_setting(conn, "forecast_assessment_at", now())
            set_setting(conn, "forecast_last_run", now())
            set_setting(conn, "forecast_last_result", f"{len(found)} warning(s), {len(due)} alerted" + (f"; skipped: {'; '.join(problems)[:200]}" if problems else ""))
        return {"ok": True, "reason": reason, "warnings": len(found), "alerted": len(due), "problems": problems}
    finally:
        _lock.release()


def tick() -> None:
    with db() as conn:
        s = settings(conn)
        last = get_setting(conn, "forecast_last_run")
    if s["enabled"] and (not last or last <= store.ago(minutes=s["interval_minutes"])):
        result = run("schedule")
        if result.get("problems"):
            log.warning("forecast pass: %s", result["problems"])


def status(conn) -> dict:
    return {"settings": settings(conn), "last_run": get_setting(conn, "forecast_last_run"), "last_result": get_setting(conn, "forecast_last_result"),
            "active": conn.execute("SELECT COUNT(*) FROM forecasts WHERE status = 'active'").fetchone()[0]}


def active(conn, limit: int = 20) -> list[dict]:
    rows = conn.execute("SELECT * FROM forecasts WHERE status = 'active' ORDER BY likelihood DESC, last_seen DESC LIMIT ?", (limit,)).fetchall()
    return [{**json.loads(r["detail"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"], "peak": r["peak"], "alerted_at": r["alerted_at"]} for r in rows]


# ---------- the page ----------

def _tone(p: int) -> str:
    return "critical" if p >= 85 else "high" if p >= 70 else "medium" if p >= 50 else "low"


def page(conn, q: dict) -> dict:
    s = settings(conn)
    live = active(conn, 50)
    ended = conn.execute("SELECT * FROM forecasts WHERE status = 'ended' AND ended_at >= ? ORDER BY ended_at DESC LIMIT 20", (store.ago(hours=48),)).fetchall()
    last, result = get_setting(conn, "forecast_last_run"), get_setting(conn, "forecast_last_result")
    assessment, said_at = get_setting(conn, "forecast_assessment"), get_setting(conn, "forecast_assessment_at")
    high = [f for f in live if f["likelihood"] >= s["alert_min"]]
    detail = lambda f: "\n".join([f"Stage reached: {f['stage']}", f"What usually happens next: {f['next']}", f"What to do now: {f['action']}", "", "Evidence:"]
                                 + [f"  - {e}" for e in f["evidence"]] + ([f"Addresses: {', '.join(f['attackers'])}"] if f["attackers"] else [])
                                 + [f"First seen {f['first_seen']}, highest likelihood {f['peak']}%" + (f", admins alerted {f['alerted_at']}" if f["alerted_at"] else "")])
    blocks = []
    if assessment and said_at >= store.ago(hours=24):
        blocks.append({"type": "text", "title": "Latest AI warning", "text": assessment, "note_time": said_at, "note_label": "Written"})
    if live:
        blocks.append(bars("Likelihood of an intrusion (%)", [{"label": f["title"][:70], "value": f["likelihood"], "tone": _tone(f["likelihood"])} for f in live[:10]]))
    blocks.append(table(
        "Early warnings", (("p", "Likelihood", "badge"), ("title", "Warning", "wrap"), ("stage", "Stage", "badge"), ("target", "Target", "text"),
                           ("who", "From", "mono"), ("since", "Since", "time")),
        [{"p": badge(f"{f['likelihood']}%", _tone(f["likelihood"])), "title": f["title"], "stage": badge(f["stage"], "critical" if f["stage"] == STAGES[3] else "high" if f["stage"] == STAGES[2] else "medium" if f["stage"] == STAGES[1] else "low"),
          "target": f["target"], "who": ", ".join(f["attackers"][:2]) + (f" +{len(f['attackers']) - 2}" if len(f["attackers"]) > 2 else ""), "since": f["first_seen"], "_detail": detail(f)} for f in live],
        empty="No attack is building up right now. CERBERUS keeps checking every few minutes.",
        note="Likelihood is CERBERUS's estimate that an intrusion follows if nobody acts, from the stage the attack has reached, how hard it is pushing, and how exposed and vulnerable the target is. Click a row for the evidence and what to do."))
    if ended:
        blocks.append(table("Ended in the last 48 hours", (("title", "Warning", "wrap"), ("peak", "Highest", "num"), ("ended", "Ended", "time")),
                            [{"title": r["title"], "peak": r["peak"], "ended": r["ended_at"]} for r in ended], empty=""))
    return {
        "title": "Attack forecast", "subtitle": "Early warnings: attacks that are building up and the intrusion they are likely to lead to, so you can act before it happens.",
        "filters": [],
        "tiles": [tile("Active warnings", len(live), "high" if live else ""), tile(f"Likely ({s['alert_min']}%+)", len(high), "critical" if high else ""),
                  tile("Highest likelihood", f"{live[0]['likelihood']}%" if live else "—", _tone(live[0]["likelihood"]) if live else ""),
                  tile("Last check", (last or "never").replace("T", " ")[:16], "" if s["enabled"] else "medium")],
        "blocks": blocks, "action": {"id": "forecast-run", "label": "Check now", "admin": True},
        "note": result or "",
    }
