"""Snort (network intrusion detection): read its alerts from Loki.

Snort writes one line per alert ("alert_fast"). Where those lines are copied into a
server's system journal and shipped to Loki, CERBERUS reads them through Grafana. A sensor raises several alerts a second, most
of them routine, so totals and rankings are counted by Loki itself and only the newest alerts are
fetched as lines. Everything here is read-only.
"""
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import grafana, store

# Alerts arrive through each server's system journal, and they are found in two places:
#  - where the log shipper labels the program, a small stream of its own (fast to read);
#  - where it does not, somewhere in that server's whole journal, recognised by the shape of the line.
# Every lookup asks both and adds the answers together.
SOURCES = (('{program="snort"', ""), ('{job="loki.source.journal.system", program=""', ' |= "[**] [" |= "[Priority: "'))
# 10/14-09:02:40.59 [**] [1:1917:16] "message" [**] [Classification: x] [Priority: 3] {UDP} 1.2.3.4:55 -> 5.6.7.8:1900
PARSE = ('regexp `\\[(?P<sig>\\d+:\\d+):\\d+\\] "(?P<msg>[^"]*)" \\[\\*\\*\\] (\\[Classification: (?P<kind>[^\\]]*)\\] )?\\[Priority: (?P<prio>\\d)\\] '
         '\\{(?P<proto>[\\w-]+)\\} (?P<src>\\d+\\.\\d+\\.\\d+\\.\\d+)(:\\d+)? -> (?P<dst>\\d+\\.\\d+\\.\\d+\\.\\d+)(:(?P<dport>\\d+))?`')
LINE = re.compile(r'\[(\d+:\d+):\d+\] "([^"]*)" \[\*\*\] (?:\[Classification: ([^\]]*)\] )?\[Priority: (\d)\] \{([\w-]+)\} (\S+?)(?::(\d+))? -> (\S+?)(?::(\d+))?$')
PRIORITIES = {"1": "High", "2": "Medium", "3": "Low", "4": "Very low"}
_cache: dict[tuple, tuple[float, object]] = {}
_lock = threading.Lock()


def is_ready(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("loki_uid"))


def _cached(key: tuple, seconds: int, load):
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < seconds:
            return hit[1]
    value = load()
    with _lock:
        _cache[key] = (time.monotonic(), value)
        for old in [k for k, v in _cache.items() if time.monotonic() - v[0] > 900]:
            _cache.pop(old, None)
    return value


def _loki(cfg: dict, path: str, params: dict) -> dict:
    uid = store.text(cfg.get("loki_uid"), 80)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", uid):
        raise grafana.GrafanaError("No Loki data source is configured")
    return (grafana._get(cfg, f"/api/datasources/proxy/uid/{uid}/loki/api/v1/{path}", params) or {}).get("data") or {}


def _quote(value) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _streams(*, host="", priority="", text="") -> list[str]:
    """The LogQL that selects raw alert lines, one per place they can be."""
    words = store.text(text, 120)
    return [opening + (f", host={_quote(host)}" if host else "") + "}" + mark + (f" |= {_quote(words)}" if words else "")
            + (f' |= "[Priority: {priority}]"' if priority in PRIORITIES else "") for opening, mark in SOURCES]


def _both(run, queries: list[str]) -> list:
    """Ask each place at once. One of them failing or timing out does not lose the other."""
    def safe(query):
        try:
            return run(query)
        except grafana.GrafanaError as exc:
            return exc
    with ThreadPoolExecutor(max_workers=len(queries)) as pool:
        results = list(pool.map(safe, queries))
    good = [r for r in results if not isinstance(r, Exception)]
    if not good:
        raise results[0]
    return good


def counts(cfg: dict, by: tuple, minutes: int, top: int = 50, keep: int = 60, public_source: bool = False, **filters) -> list[tuple[dict, int]]:
    """How many alerts per value of the given fields, largest first. Remembered for a minute."""
    def load():
        # Counting per sensor needs no parsing, which keeps the long look-back cheap.
        parse = "" if by == ("host",) and not public_source else " | " + PARSE + ' | prio != ""'
        if public_source:  # only alerts whose source address is on the internet
            parse += ' | src !~ `10\\..*|127\\..*|172\\.(1[6-9]|2[0-9]|3[01])\\..*|192\\.168\\..*|22[4-9]\\..*|23[0-9]\\..*|255\\..*`'
        def run(raw):
            query = f"topk({int(top)}, sum by ({', '.join(by)}) (count_over_time({raw}{parse} [{int(minutes)}m])))"
            return _loki(cfg, "query", {"time": int(time.time()), "query": query}).get("result", [])
        totals: dict[tuple, int] = {}
        for result in _both(run, _streams(**filters)):
            for r in result:
                key = tuple((r.get("metric") or {}).get(b, "") for b in by)
                totals[key] = totals.get(key, 0) + int(float(r["value"][1]))
        rows = [(dict(zip(by, key)), n) for key, n in totals.items()]
        return sorted(rows, key=lambda r: r[1], reverse=True)[:top]
    return _cached((cfg.get("url"), "counts", by, int(minutes), top, public_source, tuple(sorted(filters.items()))), keep, load)


def over_time(cfg: dict, minutes: int, step: int, **filters) -> tuple[int, dict[str, list[int]]]:
    """Alerts per time step for each priority: (start in seconds, {priority: counts})."""
    def load():
        end = int(time.time()) // step * step + step
        start = end - int(minutes) * 60
        slots = (end - start) // step
        def run(raw):
            return _loki(cfg, "query_range", {"start": start * 10**9, "end": end * 10**9, "step": step,
                                              "query": f'sum by (prio) (count_over_time({raw} | {PARSE} | prio != "" [{step}s]))'}).get("result", [])
        out: dict[str, list[int]] = {}
        for result in _both(run, _streams(**filters)):
            for r in result:
                values = out.setdefault((r.get("metric") or {}).get("prio", ""), [0] * slots)
                for t, v in r.get("values", []):
                    index = int((float(t) - start) // step) - 1
                    if 0 <= index < slots:
                        values[index] += int(float(v))
        return start, out
    return _cached((cfg.get("url"), "time", int(minutes), step, tuple(sorted(filters.items()))), 60, load)


def latest(cfg: dict, minutes: int, limit: int = 150, *, host="", priority="", text="") -> list[dict]:
    """The newest alerts themselves, parsed, newest first. Remembered for fifteen seconds."""
    def load():
        end = int(time.time()) + 60
        def run(raw):
            return _loki(cfg, "query_range", {"query": raw, "start": (end - int(minutes) * 60) * 10**9, "end": end * 10**9,
                                              "limit": store.clamp(limit, 1, 1000, 150), "direction": "backward"}).get("result", [])
        alerts = []
        for result in _both(run, _streams(host=host, priority=priority, text=text)):
            for s in result:
                sensor = (s.get("stream") or {}).get("host", "")
                for ns, line in s.get("values", []):
                    found = LINE.search(line)
                    if found:
                        sig, msg, kind, prio, proto, src, sport, dst, dport = found.groups()
                        alerts.append({"ns": int(ns), "sensor": sensor, "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(ns) / 1e9)) + "Z", "sig": sig, "message": msg,
                                       "kind": kind or "", "priority": prio, "protocol": proto, "source": src, "source_port": sport or "", "target": dst, "target_port": dport or ""})
        return sorted(alerts, key=lambda a: a["ns"], reverse=True)[:limit]
    return _cached((cfg.get("url"), "latest", int(minutes), limit, host, priority, text), 15, load)


def gather(jobs: dict) -> dict:
    """Run several lookups at once; the first failure is raised."""
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {name: pool.submit(job) for name, job in jobs.items()}
        return {name: f.result() for name, f in futures.items()}


def summary(cfg: dict, *, hours=1, priority="", text="", limit=15) -> dict:
    """For the AI analyst: what Snort alerted on in a period, and the newest alerts."""
    hours = store.clamp(hours, 1, 24, 1)
    minutes = hours * 60
    f = {"priority": priority if priority in PRIORITIES else "", "text": text}
    found = gather({
        "prio": lambda: counts(cfg, ("prio",), minutes, **f),
        "sigs": lambda: counts(cfg, ("sig", "msg", "kind", "prio"), minutes, 15, **f),
        "src": lambda: counts(cfg, ("src",), minutes, 10, **f),
        "dst": lambda: counts(cfg, ("dst",), minutes, 10, **f),
        "sensors": lambda: counts(cfg, ("host",), minutes, **f),
        "latest": lambda: latest(cfg, minutes, store.clamp(limit, 1, 40, 15), **f)})
    return {
        "backend": "snort (network intrusion detection)", "window_hours": hours, "alerts": sum(n for _, n in found["prio"]),
        "by_priority": {f"{labels['prio']} ({PRIORITIES.get(labels['prio'], 'other')})": n for labels, n in found["prio"]},
        "top_signatures": [{"id": l["sig"], "message": l["msg"], "classification": l["kind"], "priority": l["prio"], "alerts": n} for l, n in found["sigs"]],
        "top_sources": [{"address": l["src"], "alerts": n} for l, n in found["src"]],
        "top_targets": [{"address": l["dst"], "alerts": n} for l, n in found["dst"]],
        "sensors": [{"server": l["host"], "alerts": n} for l, n in found["sensors"]],
        "latest_alerts": [{k: v for k, v in a.items() if k != "ns" and v != ""} for a in found["latest"]],
        "note": "Snort priority 1 is the most serious. Snort only detects; it does not block. Much of the volume is routine network chatter "
                "(UPnP discovery, ICMP unreachable), so judge by signature and priority, not by count."}
