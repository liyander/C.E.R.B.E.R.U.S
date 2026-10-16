"""Patch availability and fix-by dates for every vulnerability Wazuh finds.

For each vulnerable package on each machine, CERBERUS asks two public sources:
  - Launchpad (Ubuntu's archive): which source package it comes from and the newest version Ubuntu ships
    for that release (Security and Updates pockets, never Proposed);
  - OSV.dev (Ubuntu's own security data): which CVEs affect the installed version and which still affect
    the newest version.
A CVE that affects the installed version but not the newest one has a patch: upgrading fixes it. One that
still affects the newest version has no patch yet. For those, Ubuntu Pro (ESM) fixes are looked up too.

Every vulnerability then gets a fix-by date from a published policy (exploited in the wild, likely to be
exploited, severity, internet exposure, and whether the machine is under attack right now), counted from
when Wazuh first found it. Lookups run in the background and are remembered for a day.
"""
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx

from . import insights, store, wazuh
from .apps import badge, segments, select, search_box, table, tile
from .db import DATA_DIR, db, get_setting, now, set_setting

log = logging.getLogger("cerberus.patches")

LP = "https://api.launchpad.net/1.0/ubuntu"
OSV = "https://api.osv.dev/v1"
CACHE = os.path.join(DATA_DIR, "patches.json")
TTL_HOURS = 20
KERNEL = re.compile(r"^linux-(image|modules|headers|tools|cloud-tools|buildinfo|hwe|objects)")

# Fix-by policy: (label, days, why). The first rule that applies wins.
POLICY = (
    ("kev_exposed", 2, "Exploited in the wild and the machine faces the internet"),
    ("attacked", 2, "The machine is under attack now (Attack forecast) and the flaw is serious"),
    ("kev", 7, "Exploited in the wild (CISA list)"),
    ("epss", 7, "Likely to be exploited within 30 days (EPSS 10% or more)"),
    ("critical_exposed", 7, "Critical and internet-facing"),
    ("critical", 15, "Critical severity"),
    ("high_exposed", 15, "High severity and internet-facing"),
    ("high", 30, "High severity"),
    ("medium", 90, "Medium severity"),
    ("low", 180, "Low or unrated severity: next maintenance window"),
)
URGENCY = (("today", "Fix now (due or overdue)", "critical"), ("week", "This week", "high"), ("month", "This month", "medium"),
           ("quarter", "This quarter", "low"), ("later", "Next maintenance", "info"))
STATUS = {"available": ("Patch available", "ok"), "reboot": ("Fixed after a reboot", "ok"), "unused": ("Kernel not in use", "low"),
          "foreign": ("Not from Ubuntu", "medium"), "pro": ("Fix with Ubuntu Pro", "medium"), "none": ("No patch yet", "critical"),
          "unknown": ("Not checked yet", "")}

_lock = threading.Lock()
_running = threading.Event()
_progress = {"done": 0, "total": 0, "started": 0.0, "error": ""}


# ---------- the cache ----------

def _load() -> dict:
    try:
        with open(CACHE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"packages": {}, "pro": {}}


def _save(cache: dict) -> None:
    tmp = CACHE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cache, fh)
    os.replace(tmp, CACHE)


def _fresh(entry: dict | None) -> bool:
    return bool(entry) and entry.get("checked", 0) > time.time() - TTL_HOURS * 3600 and (not entry.get("lang") or entry.get("v") == 2)


# ---------- what Wazuh says is installed and vulnerable ----------

def _release(os_full: str) -> tuple[str, str]:
    """'Ubuntu 22.04.5 LTS (Jammy Jellyfish)' -> ('jammy', 'Ubuntu:22.04:LTS')."""
    m = re.search(r"Ubuntu (\d+\.\d+)(?:\.\d+)?( LTS)? \((\w+)", os_full or "")
    if not m:
        return "", ""
    return m.group(3).lower(), f"Ubuntu:{m.group(1)}" + (":LTS" if m.group(2) else "")


def inventory(conn) -> tuple[list[dict], list[str]]:
    """Every (machine, package, installed version) with its CVEs. Remembered for ten minutes."""
    def load():
        w = wazuh.settings(conn)
        if not wazuh.is_ready(w):
            return [], ["Wazuh is not connected"]
        client = wazuh._Client(w)
        try:
            r = client.search({"size": 0, "aggs": {"agent": {"terms": {"field": "agent.name", "size": 100}, "aggs": {
                "os": {"terms": {"field": "host.os.full", "size": 1}},
                "kernel": {"terms": {"field": "host.os.kernel", "size": 1}},
                "pkg": {"terms": {"field": "package.name", "size": 500}, "aggs": {
                    "ver": {"terms": {"field": "package.version", "size": 3}},
                    "type": {"terms": {"field": "package.type", "size": 1}},
                    "cve": {"terms": {"field": "vulnerability.id", "size": 6000}, "aggs": {
                        "sev": {"terms": {"field": "vulnerability.severity", "size": 1}},
                        "found": {"min": {"field": "vulnerability.detected_at"}},
                        "score": {"max": {"field": "vulnerability.score.base"}}}}}}}}}}, index="wazuh-states-vulnerabilities-*")
        finally:
            client.close()
        rows = []
        for a in r.get("aggregations", {}).get("agent", {}).get("buckets", []):
            os_full = (a["os"]["buckets"] or [{"key": ""}])[0]["key"]
            series, eco = _release(os_full)
            for p in a["pkg"]["buckets"]:
                rows.append({"agent": a["key"], "os": os_full, "series": series, "eco": eco, "package": p["key"],
                             "type": (p["type"]["buckets"] or [{"key": "deb"}])[0]["key"], "running": (a["kernel"]["buckets"] or [{"key": ""}])[0]["key"],
                             "version": (p["ver"]["buckets"] or [{"key": ""}])[0]["key"],
                             "cves": [{"cve": c["key"], "severity": (c["sev"]["buckets"] or [{"key": "-"}])[0]["key"],
                                       "found": c["found"].get("value_as_string") or "", "score": c["score"].get("value")} for c in p["cve"]["buckets"]]})
        return rows, []
    return insights._cached(("patch-inventory",), 600, load)


# ---------- asking Ubuntu and OSV ----------

def _lp(client: httpx.Client, params: dict) -> list[dict]:
    r = client.get(f"{LP}/+archive/primary", params={**params, "ws.size": 50, "order_by_date": "true"})
    r.raise_for_status()
    return r.json().get("entries", [])


def _osv_ids(client: httpx.Client, name: str, eco: str, version: str) -> set[str]:
    """Every CVE OSV says affects this source package version (all pages)."""
    found, token = set(), None
    for _ in range(12):
        query = {"package": {"name": name, "ecosystem": eco}, "version": version, **({"page_token": token} if token else {})}
        r = client.post(f"{OSV}/querybatch", json={"queries": [query]}, timeout=90)
        r.raise_for_status()
        result = (r.json().get("results") or [{}])[0]
        found |= {re.sub(r"^UBUNTU-", "", v["id"]) for v in result.get("vulns", []) if "CVE-" in v["id"]}
        token = result.get("next_page_token")
        if not token:
            break
    return found


def _check_package(client: httpx.Client, series: str, eco: str, binary: str, version: str) -> dict:
    """Source package, newest shipped version, and which CVEs the installed and newest versions still have."""
    entries = _lp(client, {"ws.op": "getPublishedBinaries", "binary_name": binary, "exact_match": "true",
                           "distro_arch_series": f"{LP}/{series}/amd64"})
    if not entries:  # architecture-independent packages are published under 'all' on amd64 too, but try without the filter
        entries = [e for e in _lp(client, {"ws.op": "getPublishedBinaries", "binary_name": binary, "exact_match": "true"})
                   if e["distro_arch_series_link"].split("/")[-2] == series]
    if not entries:
        return {"checked": time.time(), "error": "not in Ubuntu's archive (third-party or locally built)"}
    if not any(e["binary_package_version"] == version or e["binary_package_version"].endswith(":" + version) for e in entries):
        return {"checked": time.time(), "error": f"version {version} did not come from Ubuntu's archive (a PPA, a vendor repository or built locally)"}
    source = entries[0]["source_package_name"]
    exact = next((e["binary_package_version"] for e in entries if e["binary_package_version"] == version or e["binary_package_version"].endswith(":" + version)), version)
    sources = [e for e in _lp(client, {"ws.op": "getPublishedSources", "source_name": source, "exact_match": "true",
                                        "distro_series": f"{LP}/{series}", "status": "Published"}) if e["pocket"] in ("Security", "Updates", "Release")]
    latest = sources[0]["source_package_version"] if sources else exact
    osv_name = re.sub(r"^linux-signed(-|$)", lambda m: "linux" + m.group(1), source)  # signed kernels share the kernel's security data
    now_cves = _osv_ids(client, osv_name, eco, exact)
    after = _osv_ids(client, osv_name, eco, latest) if latest != exact else now_cves
    return {"checked": time.time(), "source": source, "osv": osv_name, "installed": exact, "latest": latest,
            "latest_pocket": sources[0]["pocket"] if sources else "", "affected_now": sorted(now_cves), "affected_latest": sorted(after)}


LANG = {"pypi": ("PyPI", "pip install --upgrade"), "npm": ("npm", "npm install -g"), "gem": ("RubyGems", "gem update"), "cargo": ("crates.io", "cargo install"),
        "go": ("Go", "go get -u"), "maven": ("Maven", "update the dependency to"), "nuget": ("NuGet", "dotnet add package"), "composer": ("Packagist", "composer require")}


def _vkey(version: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", version or "0")[:6])


def _check_lang(client: httpx.Client, kind: str, name: str, version: str) -> dict:
    """A package installed with pip, npm and so on: its CVEs and the version that fixes each, from OSV."""
    eco = LANG[kind][0]
    r = client.post(f"{OSV}/querybatch", json={"queries": [{"package": {"name": name, "ecosystem": eco}, "version": version}]}, timeout=60)
    r.raise_for_status()
    ids = [v["id"] for v in ((r.json().get("results") or [{}])[0].get("vulns") or [])][:60]
    fixes, open_ = {}, set()
    for vid in ids:
        d = client.get(f"{OSV}/vulns/{vid}", timeout=30)
        if d.status_code != 200:
            continue
        d = d.json()
        cves = [a for a in [d["id"], *d.get("aliases", [])] if a.startswith("CVE-")]
        fixed = [e["fixed"] for a in d.get("affected", []) if a["package"]["name"].lower() == name.lower() and a["package"]["ecosystem"] == eco
                 for rg in a.get("ranges", []) for e in rg.get("events", []) if e.get("fixed") and _vkey(e["fixed"]) > _vkey(version)]
        final = [v for v in fixed if not re.search(r"(rc|a|b|dev|alpha|beta|pre)\.?\d*$", v, re.I)] or fixed  # prefer final releases
        for cve in cves:
            if fixed:
                fixes[cve] = min(final, key=_vkey)
            else:
                open_.add(cve)
    latest = max(fixes.values(), key=_vkey) if fixes else version
    return {"checked": time.time(), "v": 2, "source": name, "osv": name, "lang": kind, "installed": version, "latest": latest, "fixes": fixes,
            "affected_now": sorted(set(fixes) | open_), "affected_latest": sorted(open_ - set(fixes))}


def _check_pro(client: httpx.Client, cve: str, eco: str, source: str) -> str:
    """A fixed version available only through Ubuntu Pro (ESM), or ''."""
    r = client.get(f"{OSV}/vulns/UBUNTU-{cve}", timeout=30)
    if r.status_code != 200:
        return ""
    pro_eco = eco.replace("Ubuntu:", "Ubuntu:Pro:")
    for a in r.json().get("affected", []):
        if a["package"]["ecosystem"] == pro_eco and a["package"]["name"] == source:
            return next((e["fixed"] for rg in a.get("ranges", []) for e in rg.get("events", []) if e.get("fixed")), "")
    return ""


def refresh(force: bool = False) -> None:
    """Look up every package not checked in the last day. Runs in the background; one at a time."""
    if _running.is_set():
        return
    _running.set()
    try:
        with db() as conn:
            rows, problems = inventory(conn)
        cache = _load()
        todo = {}
        for r in rows:
            if r["series"]:
                key = f"{r['series']}|{r['package']}|{r['version']}"
                if force or not _fresh(cache["packages"].get(key)):
                    todo[key] = r
        # Small packages first so most of the page fills in quickly; kernels (thousands of CVEs) last.
        order = sorted(todo.items(), key=lambda kv: (bool(KERNEL.match(kv[1]["package"])), len(kv[1]["cves"])))
        _progress.update(done=0, total=len(order), started=time.time(), error="; ".join(problems))
        with httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": "CERBERUS patch check"}) as client:
            def one(item):
                key, r = item
                try:
                    if r["type"] in LANG:
                        return key, _check_lang(client, r["type"], r["package"], r["version"])
                    if r["type"] != "deb":
                        return key, {"checked": time.time(), "error": f"{r['type']} packages are not looked up"}
                    return key, _check_package(client, r["series"], r["eco"], r["package"], r["version"])
                except (httpx.HTTPError, ValueError, KeyError) as exc:
                    return key, {"checked": time.time() - (TTL_HOURS - 1) * 3600, "error": f"lookup failed: {exc.__class__.__name__}"}
            with ThreadPoolExecutor(4) as pool:
                for key, result in pool.map(one, order):
                    with _lock:
                        cache["packages"][key] = result
                        _progress["done"] += 1
                        if _progress["done"] % 5 == 0:
                            _save(cache)
            # Ubuntu Pro fixes for the CVEs that have no free patch (not for kernels: Pro kernel fixes come as Livepatch).
            for r in rows:
                entry = cache["packages"].get(f"{r['series']}|{r['package']}|{r['version']}") or {}
                if not entry.get("source") or entry.get("lang") or KERNEL.match(r["package"]):
                    continue
                for c in r["cves"]:
                    pro_key = f"{r['eco']}|{entry['osv']}|{c['cve']}"
                    if c["cve"] in entry.get("affected_latest", []) and pro_key not in cache["pro"]:
                        try:
                            cache["pro"][pro_key] = _check_pro(client, c["cve"], r["eco"], entry["osv"])
                        except httpx.HTTPError:
                            pass
        with _lock:
            _save(cache)
        with db() as conn:
            set_setting(conn, "patches_last_check", now())
    except Exception as exc:  # a background job must never take the server down
        log.warning("patch check failed: %s", exc)
        _progress["error"] = str(exc)[:200]
    finally:
        _running.clear()


def ensure_fresh() -> None:
    """Start a background check if anything is stale. Returns immediately."""
    if not _running.is_set():
        threading.Thread(target=refresh, name="cerberus-patches", daemon=True).start()


def tick() -> None:
    """Called by the scheduler: re-check once the day's results are stale."""
    with db() as conn:
        last = get_setting(conn, "patches_last_check")
    if not last or last <= store.ago(hours=TTL_HOURS):
        ensure_fresh()


# ---------- deadlines ----------

def _rule(c: dict, exposed: bool, attacked: bool) -> tuple[str, int, str]:
    sev = c["severity"]
    serious = sev in ("Critical", "High") or (c.get("score") or 0) >= 7
    for key, days, why in POLICY:
        if (key == "kev_exposed" and c.get("kev") and exposed) or (key == "attacked" and attacked and serious) or (key == "kev" and c.get("kev")) \
                or (key == "epss" and (c.get("epss") or 0) >= 0.1) or (key == "critical_exposed" and sev == "Critical" and exposed) \
                or (key == "critical" and sev == "Critical") or (key == "high_exposed" and sev == "High" and exposed) or (key == "high" and sev == "High") \
                or (key == "medium" and sev == "Medium") or key == "low":
            return key, days, why
    return "low", 180, POLICY[-1][2]


def _urgency(due: datetime, now_: datetime) -> str:
    left = (due - now_).days
    return "today" if left <= 1 else "week" if left <= 7 else "month" if left <= 31 else "quarter" if left <= 92 else "later"


def plan(conn) -> dict:
    """Every vulnerability with its patch status, fix-by date and urgency, plus a per-machine action list."""
    rows, problems = inventory(conn)
    cache = _load()
    base, base_problems, _ = insights._vuln_base(conn)
    facts = {r["cve"]: r for r in base}
    try:
        machines, _ = insights.machines(conn)
    except Exception:
        machines = []
    exposed = {n for m in machines if m.get("exposure") == "internet-facing" for n in m["names"]}
    attacked = {}
    for r in conn.execute("SELECT target, MIN(first_seen) AS since FROM forecasts WHERE status = 'active' AND likelihood >= 70 GROUP BY target"):
        attacked[r["target"]] = datetime.fromisoformat(r["since"].replace("Z", "+00:00"))
    now_ = datetime.now(timezone.utc)
    items, per_machine = [], {}
    for r in rows:
        entry = cache["packages"].get(f"{r['series']}|{r['package']}|{r['version']}") or {}
        kernel = bool(KERNEL.match(r["package"])) and r["type"] == "deb"
        unused = kernel and r["running"] and r["running"] not in r["package"]
        m = per_machine.setdefault(r["agent"], {"agent": r["agent"], "os": r["os"], "upgrade": {}, "lang": {}, "reboot": False, "fixed": 0, "nopatch": 0, "pro": 0,
                                                "earliest": None, "overdue": 0, "old_kernels": set(), "running": r["running"], "newer_installed": False})
        if unused:
            m["old_kernels"].add(r["package"])
            if _vkey(r["package"].split("linux-image-")[-1]) > _vkey(r["running"]):
                m["newer_installed"] = True
        for c in r["cves"]:
            f = facts.get(c["cve"], {})
            c = {**c, "kev": f.get("kev"), "epss": f.get("epss")}
            if unused:
                newer = _vkey(r["package"].split("linux-image-")[-1]) > _vkey(r["running"])
                status, fixed = ("unused", "") if not newer else ("unused", "")
            elif entry.get("error") and "did not come from" in entry["error"]:
                status, fixed = "foreign", ""
            elif entry.get("lang"):
                status, fixed = ("available", entry["fixes"][c["cve"]]) if c["cve"] in entry.get("fixes", {}) else ("none", "")
            elif not entry.get("source"):
                status, fixed = "unknown", ""
            elif c["cve"] in entry.get("affected_latest", []):
                pro = cache["pro"].get(f"{r['eco']}|{entry['osv']}|{c['cve']}", "")
                status, fixed = ("pro", pro) if pro else ("none", "")
            elif c["cve"] in entry.get("affected_now", []) or entry.get("latest") != entry.get("installed"):
                status, fixed = "available", entry.get("latest", "")
            else:
                status, fixed = "none", ""  # Wazuh and Ubuntu's data disagree and no newer version exists: treat as unpatched
            key, days, why = _rule(c, r["agent"] in exposed, r["agent"] in attacked)
            try:
                found = datetime.fromisoformat(c["found"].replace("Z", "+00:00")) if c["found"] else now_
            except ValueError:
                found = now_
            # The clock starts when the reason for the deadline began: CISA listing it, or the attack starting; otherwise when Wazuh found it.
            start = found
            if key in ("kev", "kev_exposed") and (c.get("kev") or {}).get("dateAdded"):
                try:
                    start = max(found, datetime.fromisoformat(c["kev"]["dateAdded"]).replace(tzinfo=timezone.utc))
                except ValueError:
                    pass
            elif key == "attacked":
                start = max(found, attacked[r["agent"]])
            due = start + timedelta(days=days)
            if status == "unused":  # not exploitable while the machine runs another kernel
                key, why, due = "unused", "Kernel installed but not running: remove it when convenient", max(due, now_ + timedelta(days=90))
            urgency = _urgency(due, now_)
            items.append({"cve": c["cve"], "agent": r["agent"], "package": r["package"], "installed": r["version"], "fixed": fixed, "status": status,
                          "severity": c["severity"], "kev": bool(c.get("kev")), "epss": c.get("epss"), "rule": key, "why": why, "due": due, "urgency": urgency,
                          "overdue": due < now_ and status != "unused", "found": found, "kernel": kernel, "lang": entry.get("lang", ""), "kev_action": (c.get("kev") or {}).get("requiredAction", "") if c.get("kev") else ""})
            if status == "available" and entry.get("lang"):
                m["lang"][(r["type"], r["package"])] = max(fixed, m["lang"].get((r["type"], r["package"]), "0"), key=_vkey)
                m["fixed"] += 1
                m["earliest"] = min(m["earliest"] or due, due)
                m["overdue"] += due < now_
            elif status == "available":
                m["upgrade"].setdefault(r["package"], fixed)
                m["fixed"] += 1
                m["reboot"] = m["reboot"] or kernel
                m["earliest"] = min(m["earliest"] or due, due)
                m["overdue"] += due < now_
            elif status == "pro":
                m["pro"] += 1
            elif status == "none":
                m["nopatch"] += 1
    total = sum(len(r["cves"]) for r in rows)
    checked = sum(1 for r in rows if (cache["packages"].get(f"{r['series']}|{r['package']}|{r['version']}") or {}).get("checked"))
    return {"items": items, "machines": list(per_machine.values()), "problems": problems + base_problems, "packages": len(rows), "checked": checked, "total": total}


def _mitigation(i: dict) -> str:
    if i["kev_action"]:
        return f"CISA: {i['kev_action']}"
    if i["kernel"]:
        return ("Kernel flaw with no released fix: most need local access, so limit who can log in and run code on this machine, keep SSH key-only, "
                "and install the kernel update as soon as Ubuntu releases it (kernel updates come roughly every three weeks).")
    return (f"No fix for {i['package']} yet: if it is a network service, restrict who can reach it (firewall, WAF) or turn it off if unused; "
            "if it is a library, check whether anything exposed uses it. Re-check here daily; the fix appears as soon as Ubuntu ships it.")


def runnable(conn, agent: str) -> list[str]:
    """The patch plan for one machine as separate, non-interactive commands, each to be approved on its own."""
    m = next((m for m in plan(conn)["machines"] if m["agent"] == agent), None)
    if not m:
        return []
    kernel = [p for p in m["upgrade"] if KERNEL.match(p)]
    other = sorted(p for p in m["upgrade"] if not KERNEL.match(p))
    commands = ["sudo apt-get update"]
    if other:
        commands.append("sudo apt-get install -y --only-upgrade " + " ".join(other))
    if kernel:
        commands.append("sudo apt-get -y full-upgrade")
    for (kind, name), version in sorted(m.get("lang", {}).items()):
        if kind == "npm":
            commands.append(f"sudo npm install -g {name}@{version}")
        elif kind == "pypi":
            commands.append(f"pip install --upgrade '{name}>={version}'")
    if kernel or m.get("newer_installed"):
        commands.append("sudo reboot")
    return commands if len(commands) > 1 else []


def _command(m: dict) -> str:
    kernel = [p for p in m["upgrade"] if KERNEL.match(p)]
    other = sorted(p for p in m["upgrade"] if not KERNEL.match(p))
    parts = ["sudo apt update"]
    if m.get("newer_installed") and not kernel:
        parts.append(f"sudo reboot   # a newer kernel is already installed; this machine still runs {m['running']}")
    if other:
        parts.append("sudo apt install --only-upgrade " + " ".join(other))
    if kernel:
        parts.append("sudo apt full-upgrade   # installs the newest kernel")
        parts.append("sudo reboot   # the new kernel only protects you after a reboot")
    for (kind, name), version in sorted(m.get("lang", {}).items()):
        tool = LANG[kind][1]
        parts.append(f"{tool} {name}@{version}" if kind == "npm" else f"{tool} '{name}>={version}'" if kind == "pypi" else f"{tool} {name}  # to {version} or later")
    if m.get("old_kernels"):
        parts.append("sudo apt autoremove --purge   # after the reboot: removes kernels that are installed but not in use (now: " + ", ".join(sorted(k.replace("linux-image-", "") for k in m["old_kernels"])) + ")")
    return "\n".join(parts)


# ---------- the page ----------

def page(conn, q: dict) -> dict:
    ensure_fresh()
    p = plan(conn)
    items = p["items"]
    status_f, urgency_f, agent_f, words = q.get("status", ""), q.get("urgency", ""), q.get("agent", ""), q.get("text", "").strip().lower()
    by_status = {k: sum(1 for i in items if i["status"] == k) for k in STATUS}
    by_urgency = {k: sum(1 for i in items if i["urgency"] == k and i["status"] != "unknown") for k, _, _ in URGENCY}
    overdue = sum(1 for i in items if i["overdue"])
    now_ = datetime.now(timezone.utc)
    shown = [i for i in items if (not status_f or i["status"] == status_f) and (not urgency_f or i["urgency"] == urgency_f) and (not agent_f or i["agent"] == agent_f)
             and (not words or words in i["cve"].lower() or words in i["package"].lower())]
    order = {k: n for n, (k, _, _) in enumerate(URGENCY)}
    first = {k: n for n, k in enumerate(("available", "reboot", "pro", "none", "foreign", "unknown", "unused"))}
    shown.sort(key=lambda i: (order[i["urgency"]], first.get(i["status"], 9), not i["kev"], i["due"], -(i["epss"] or 0)))
    progress = ""
    if _running.is_set():
        progress = f"Checking patch availability with Ubuntu and OSV: {_progress['done']} of {_progress['total']} packages done. Results fill in as they arrive."
    elif p["checked"] < p["packages"]:
        progress = f"{p['packages'] - p['checked']} package(s) not checked yet."
    when_text = lambda due, overdue: f"{due:%d %b %Y}" + (f" ({(now_ - due).days} d overdue)" if overdue and (now_ - due).days >= 1 else " (today)" if overdue else "")
    days_left = lambda i: (f"{-(i['due'] - now_).days} days overdue" if i["overdue"] else "due today" if (i["due"] - now_).days < 1 else f"{(i['due'] - now_).days} days left")
    machine_rows = []
    for m in sorted(p["machines"], key=lambda m: (m["earliest"] or now_ + timedelta(days=9999))):
        if not m["upgrade"] and not m["lang"] and not m["nopatch"] and not m["pro"] and not m["old_kernels"]:
            continue
        machine_rows.append({
            "machine": m["agent"], "os": m["os"].split(" (")[0], "fixed": m["fixed"], "pkgs": len(m["upgrade"]) + len(m["lang"]),
            "reboot": badge("reboot needed", "medium") if m["reboot"] or m["newer_installed"] else "",
            "due": when_text(m["earliest"], m["earliest"] < now_) if m["earliest"] else "—", "overdue": m["overdue"], "nopatch": m["nopatch"] + m["pro"],
            "_detail": "Run on " + m["agent"] + ":\n\n" + _command(m) + "\n\nUpgrades:\n" + "\n".join([f"  {k} -> {v or 'newest'}" for k, v in sorted(m["upgrade"].items())] + [f"  {n} ({k}) -> {v}" for (k, n), v in sorted(m["lang"].items())])
                       + (f"\n\nIt runs kernel {m['running']} although a newer one is installed: reboot to use it." if m["newer_installed"] else "")
                       + (f"\n\nKernels installed but not running ({len(m['old_kernels'])}): their vulnerabilities only matter if the machine boots them. Remove the unused ones after the reboot." if m["old_kernels"] else "")
                       + (f"\n\n{m['pro']} more can be fixed with Ubuntu Pro (free for up to 5 machines: sudo pro attach <token>, then sudo apt upgrade)." if m["pro"] else "")
                       + (f"\n\n{m['nopatch']} have no patch yet; see the mitigation in each row below." if m["nopatch"] else "")})
    vuln_rows = []
    for i in shown[:400]:
        status_text, tone = STATUS[i["status"]]
        detail = [f"{i['cve']} in {i['package']} {i['installed']} on {i['agent']}", "",
                  f"Patch: {status_text}" + (f", fixed in {i['fixed']}" if i["fixed"] else "") + (" (kernel: reboot after upgrading)" if i["kernel"] and i["status"] == "available" else ""),
                  f"Fix by {i['due']:%d %b %Y} ({days_left(i)}): {i['why']}." + (f" Wazuh first found it {i['found']:%d %b %Y}." if i["found"] else "")]
        if i["status"] == "available" and i["lang"]:
            detail.append(f"How: {LANG[i['lang']][1]} {i['package']} (to {i['fixed']} or later). It was installed with {i['lang']}, not apt.")
        elif i["status"] == "available":
            detail.append(f"How: sudo apt update && " + ("sudo apt full-upgrade && sudo reboot" if i["kernel"] else f"sudo apt install --only-upgrade {i['package']}"))
        elif i["status"] == "unused":
            detail.append("This kernel is installed but the machine is not running it, so the flaw cannot be used unless it is booted. Remove it: sudo apt autoremove --purge")
        elif i["status"] == "foreign":
            detail.append("This version was not installed from Ubuntu's archive (a PPA, a vendor repository, or built locally). Update it from where it came from.")
        elif i["status"] == "pro":
            detail.append(f"How: the fix ({i['fixed']}) is in Ubuntu Pro (ESM). Attach the machine (sudo pro attach <token>; free for up to 5 machines), then sudo apt upgrade.")
        else:
            detail.append("Until it can be patched: " + _mitigation(i))
        if i["kev"]:
            detail.append("This flaw is in CISA's list of vulnerabilities exploited in the wild.")
        vuln_rows.append({"cve": i["cve"], "machine": i["agent"], "package": i["package"], "patch": badge(status_text + (f" ({i['fixed'][:24]})" if i["status"] == "available" and i["fixed"] else ""), tone),
                          "fixby": when_text(i["due"], i["overdue"]), "when": badge(dict((k, t) for k, t, _ in URGENCY)[i["urgency"]] if not i["overdue"] else "Overdue", dict((k, c) for k, _, c in URGENCY)[i["urgency"]]),
                          "why": i["why"], "_detail": "\n".join(detail)})
    groups: dict[tuple, dict] = {}
    for i in shown:
        if i["status"] == "unused":
            continue
        g = groups.setdefault((i["agent"], i["package"], i["status"]), {"items": [], "due": i["due"], "urgency": i["urgency"], "overdue": False, "fixed": ""})
        g["items"].append(i)
        g["fixed"] = max(g["fixed"], i["fixed"] or "", key=_vkey) if i["lang"] else g["fixed"] or i["fixed"]  # one upgrade to the highest fix covers all
        if i["due"] < g["due"]:
            g["due"], g["urgency"] = i["due"], i["urgency"]
        g["overdue"] = g["overdue"] or i["overdue"]
    group_rows = []
    for (agent, package, status), g in sorted(groups.items(), key=lambda kv: (order[kv[1]["urgency"]], first.get(kv[0][2], 9), kv[1]["due"], -len(kv[1]["items"])))[:120]:
        its = sorted(g["items"], key=lambda i: (not i["kev"], i["due"]))
        sample, fixed = its[0], g["fixed"]
        status_text, tone = STATUS[status]
        how = (f"{LANG[sample['lang']][1]} {package} (to {fixed} or later)" if sample["lang"] else
               "sudo apt update && sudo apt full-upgrade && sudo reboot" if sample["kernel"] else f"sudo apt update && sudo apt install --only-upgrade {package}") if status == "available" else               (f"Attach Ubuntu Pro (sudo pro attach <token>, free for 5 machines), then sudo apt upgrade" if status == "pro" else "Until it can be patched: " + _mitigation(sample))
        group_rows.append({
            "machine": agent, "package": package, "patch": badge(status_text + (f" ({fixed[:24]})" if fixed and status == "available" else ""), tone),
            "cves": len(its), "crit": sum(1 for i in its if i["severity"] == "Critical"), "kev": sum(1 for i in its if i["kev"]),
            "when": badge("Overdue" if g["overdue"] else dict((k, t) for k, t, _ in URGENCY)[g["urgency"]], dict((k, c) for k, _, c in URGENCY)[g["urgency"]]),
            "fixby": when_text(g["due"], g["overdue"]),
            "_detail": "\n\n".join([f"{package} on {agent}: {len(its)} vulnerabilit{'y' if len(its) == 1 else 'ies'}.", how, f"Deadline: {sample['why']}.", ""])
                       + "CVEs (most urgent first): " + ", ".join(i["cve"] + (" [exploited in the wild]" if i["kev"] else "") for i in its[:25]) + (f" and {len(its) - 25} more" if len(its) > 25 else "")})
    agents = sorted({i["agent"] for i in items})
    return {
        "title": "Patch plan",
        "subtitle": "For every vulnerability: is a patch available, by when it should be fixed, and the exact command to fix it on each machine.",
        "filters": [select("urgency", "When", urgency_f, [("", "Any time")] + [(k, t) for k, t, _ in URGENCY]),
                    select("status", "Patch", status_f, [("", "Any status")] + [(k, v[0]) for k, v in STATUS.items()]),
                    select("agent", "Machine", agent_f, [("", "All machines")] + [(a, a) for a in agents]), search_box("text", "CVE or package", q.get("text", ""), 200)],
        "tiles": [tile("Patch available", by_status["available"] + by_status["reboot"], "ok" if by_status["available"] else ""), tile("No patch yet", by_status["none"], "high" if by_status["none"] else ""),
                  tile("Overdue", overdue, "critical" if overdue else ""), tile("Fix this week", by_urgency["today"] + by_urgency["week"], "high" if by_urgency["today"] + by_urgency["week"] else "")],
        "note": " ".join(filter(None, [progress, "; ".join(p["problems"])[:200]])),
        "blocks": [
            segments("When to fix", [{"label": t, "value": by_urgency[k], "tone": c} for k, t, c in URGENCY]),
            segments("Patch status", [{"label": STATUS[k][0], "value": by_status[k], "tone": STATUS[k][1] or "info"} for k in ("available", "pro", "none", "unused", "foreign", "unknown") if by_status[k]]),
            table("What to run on each machine", (("machine", "Machine", "text"), ("os", "System", "text"), ("pkgs", "Packages to upgrade", "num"), ("fixed", "Fixes", "num"),
                                                   ("overdue", "Overdue", "num"), ("due", "First due", "text"), ("reboot", "Reboot", "badge"), ("nopatch", "Not patchable yet", "num")),
                  machine_rows, note="Click a machine for the exact commands. One upgrade fixes many CVEs at once.", empty="Nothing to patch, or patch availability is still being checked."),
            table(f"Fixes by package{f' · first 120 of {len(groups):,}' if len(groups) > 120 else ''}",
                  (("machine", "Machine", "text"), ("package", "Package", "mono"), ("patch", "Patch", "badge"), ("cves", "CVEs", "num"), ("crit", "Critical", "num"),
                   ("kev", "Exploited", "num"), ("when", "When", "badge"), ("fixby", "Fix by", "text")), group_rows,
                  note="One upgrade fixes every CVE in its row. Kernels that are installed but not running are left out. Click a row for the command and the CVEs.",
                  empty="Nothing to fix for this selection."),
            table(f"Every vulnerability by deadline{f' · first 400 of {len(shown):,}' if len(shown) > 400 else ''}",
                  (("cve", "CVE", "mono"), ("machine", "Machine", "text"), ("package", "Package", "mono"), ("patch", "Patch", "badge"), ("when", "When", "badge"),
                   ("fixby", "Fix by", "text"), ("why", "Why this deadline", "wrap")), vuln_rows,
                  note="Fix-by dates follow the policy below, counted from when Wazuh first found the flaw. Click a row for the fix or, if there is no patch, how to reduce the risk until there is.",
                  empty="No vulnerability matches."),
            table("Deadline policy", (("rule", "When", "wrap"), ("days", "Fix within (days)", "num")),
                  [{"rule": why, "days": days} for _, days, why in POLICY], note="The first rule that applies sets the deadline."),
        ],
    }


def summary_for_ai(conn, agent: str = "", cve: str = "") -> dict:
    """Compact patch status for the analyst tool."""
    p = plan(conn)
    items = [i for i in p["items"] if (not agent or agent.lower() in i["agent"].lower()) and (not cve or i["cve"].upper() == cve.upper())]
    count = lambda k, v: sum(1 for i in items if i[k] == v)
    items.sort(key=lambda i: (i["due"], not i["kev"]))
    return {"checked_packages": f"{p['checked']} of {p['packages']}", "available": count("status", "available"), "no_patch": count("status", "none"), "ubuntu_pro_only": count("status", "pro"),
            "overdue": sum(1 for i in items if i["overdue"]), "policy": [f"{why}: {days} days" for _, days, why in POLICY],
            "machines": [{"machine": m["agent"], "packages_to_upgrade": sorted(m["upgrade"]), "fixes": m["fixed"], "reboot_needed": m["reboot"], "command": _command(m)}
                         for m in p["machines"] if m["upgrade"] and (not agent or agent.lower() in m["agent"].lower())],
            "most_urgent": [{"cve": i["cve"], "machine": i["agent"], "package": i["package"], "patch": STATUS[i["status"]][0], "fixed_version": i["fixed"],
                             "fix_by": i["due"].strftime("%Y-%m-%d"), "overdue": i["overdue"], "why": i["why"]} for i in items[:25]]}
