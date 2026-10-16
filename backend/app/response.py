"""Response actions and playbooks for an incident.

Actions that touch a machine (block an attacking IP at the firewall, collect evidence) are built here as
exact shell commands and routed through the server-command approval system: nothing runs until an admin
approves it, dangerous commands are still refused, and everything is audited. Each blocking action records
its own undo, so it can be reversed with one more approval.

Playbooks are ordered checklists per incident type. Each step is either a read-only check or a proposed
command; the analyst approves each one. Nothing is automatic.

Actions we cannot safely run from here (disabling a directory account, isolating a host) are offered as a
recorded recommendation with instructions, not executed.
"""
import ipaddress
import json
import re

from . import insights, remote, store
from .db import audit

# action -> how to present and build it. "build" returns (command, undo_command) given ip/asset.
FIREWALL_COMMENT = "CERBERUS"


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _block_cmds(ip: str, incident_ref: str) -> tuple[str, str]:
    tag = f"{FIREWALL_COMMENT} {incident_ref}"
    return (f"sudo ufw insert 1 deny from {ip} to any comment '{tag}'",
            f"sudo ufw delete deny from {ip} to any")


def _forensics_cmd(ip: str) -> str:
    # Read-only: what this address has been doing on the box right now.
    return (f"echo '== current connections =='; sudo ss -tnp | grep {ip} || echo none; "
            f"echo '== recent auth log =='; sudo grep -F {ip} /var/log/auth.log 2>/dev/null | tail -n 40 || echo none")


ACTIONS = {
    "block_ip": {"label": "Block this IP at the firewall", "needs": "ip", "needs_server": True, "executable": True,
                 "about": "Adds a deny rule for the address on the chosen server's firewall (ufw). Reversible."},
    "unblock_ip": {"label": "Unblock this IP", "needs": "ip", "needs_server": True, "executable": True,
                   "about": "Removes the deny rule for the address."},
    "collect_evidence": {"label": "Collect evidence (read-only)", "needs": "ip", "needs_server": True, "executable": True,
                         "about": "Reads current connections and recent auth-log lines for the address. Changes nothing."},
    "disable_account": {"label": "Disable the account", "needs": "user", "needs_server": False, "executable": False,
                        "about": "CERBERUS does not change accounts itself. This records the recommendation and how to do it."},
    "isolate_host": {"label": "Isolate the host", "needs": "", "needs_server": False, "executable": False,
                     "about": "Cutting a host off the network can lock you out and is site-specific, so this is a recommendation, not an action."},
}


def available(conn, inc: dict) -> dict:
    """Which actions make sense for this incident, with the registered servers that could run them."""
    servers = [s for s in remote.public_view(conn)["servers"] if s["enabled"]]
    change_servers = [s for s in servers if s["allow_changes"] and s["host_key"]]
    read_servers = [s for s in servers if s["host_key"]]
    ip = inc.get("source_ip") or ""
    external = ip and insights.is_public(ip)
    # Has this IP already been blocked (a done/approved block command for it)?
    blocked = bool(ip) and bool(conn.execute(
        "SELECT 1 FROM server_commands WHERE action = 'block_ip' AND status IN ('done', 'approved', 'running') AND command LIKE ? LIMIT 1",
        (f"%deny from {ip} %",)).fetchone())
    out = []
    if external and not blocked:
        out.append({"action": "block_ip", **ACTIONS["block_ip"], "servers": change_servers})
    if external and blocked:
        out.append({"action": "unblock_ip", **ACTIONS["unblock_ip"], "servers": change_servers})
    if ip:
        out.append({"action": "collect_evidence", **ACTIONS["collect_evidence"], "servers": read_servers})
    out.append({"action": "disable_account", **ACTIONS["disable_account"], "servers": []})
    out.append({"action": "isolate_host", **ACTIONS["isolate_host"], "servers": []})
    return {"actions": out, "blocked": blocked, "enabled": remote.settings(conn)["enabled"],
            "has_servers": bool(servers)}


def run_action(conn, incident_id: int, action: str, server: str, actor: str) -> dict:
    inc = store.get_incident(conn, incident_id)
    if not inc:
        raise ValueError("No such incident")
    spec = ACTIONS.get(action)
    if not spec:
        raise ValueError("Unknown action")
    ip = inc.get("source_ip") or ""
    if spec["needs"] == "ip" and not _valid_ip(ip):
        raise ValueError("This incident has no valid source IP to act on")

    if not spec["executable"]:
        # Record the recommendation and leave it to the operator.
        how = {"disable_account": "On the identity source (AD, LDAP or the host): disable or lock the account, then force a password reset.",
               "isolate_host": "On your network: move the host to a quarantine VLAN or apply a restrictive firewall policy, keeping your own management access."}
        from . import triage
        triage._note(conn, incident_id, "action", actor, f"**Recommended: {spec['label']}.** {how.get(action, '')}")
        audit(conn, actor, "incident.action_recommended", {"incident_id": incident_id, "action": action})
        return {"recorded": True, "executable": False, "note": "Recommendation recorded on the incident."}

    if action == "collect_evidence":
        command, undo = _forensics_cmd(ip), ""
        reason = f"Collect read-only evidence for {ip} (incident {inc['ref']})"
    elif action == "block_ip":
        command, undo = _block_cmds(ip, inc["ref"])
        reason = f"Block attacking address {ip} at the firewall (incident {inc['ref']})"
    elif action == "unblock_ip":
        _, command = _block_cmds(ip, inc["ref"])
        undo = ""
        reason = f"Unblock {ip} (incident {inc['ref']})"
    else:
        raise ValueError("Unknown action")

    result = remote.propose(conn, server, command, reason, f"{actor} (incident {inc['ref']})",
                            origin="plan", incident_id=incident_id, undo_command=undo, action=action)
    if "error" in result:
        raise ValueError(result["error"])
    from . import triage
    triage._note(conn, incident_id, "action", actor,
                 f"Proposed **{spec['label']}** on {result['server']} (command #{result['id']}, awaiting approval):\n\n`{command}`")
    audit(conn, actor, "incident.action_proposed", {"incident_id": incident_id, "action": action, "command_id": result["id"]})
    return {"recorded": True, "executable": True, "command_id": result["id"], "server": result["server"], "risk": result["risk"]}


def incident_commands(conn, incident_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT id, server, command, action, risk, status, decided_by, exit_code, created_at FROM server_commands WHERE incident_id = ? ORDER BY id DESC",
        (incident_id,))]


# ---------- playbooks ----------

PLAYBOOKS = {
    "ssh_bruteforce": {
        "name": "SSH brute force / password guessing",
        "match": lambda inc: bool(re.search(r"brute|password|failed login|non.?existent user|invalid user|ssh", (inc.get("title") or ""), re.I))
                              or (inc.get("rule_id") or "").startswith("forecast:credential"),
        "steps": [
            {"text": "Check fail2ban is running and see who it has already banned.", "command": "sudo fail2ban-client status sshd 2>/dev/null || systemctl status fail2ban --no-pager | head", "risk": "read-only"},
            {"text": "Block the attacking address at the firewall.", "action": "block_ip"},
            {"text": "Confirm SSH password logins are off (keys only).", "command": "sudo sshd -T 2>/dev/null | grep -i passwordauthentication", "risk": "read-only"},
            {"text": "Check whether the address ever logged in successfully.", "command": "sudo grep -F 'Accepted' /var/log/auth.log 2>/dev/null | tail -n 20 || echo none", "risk": "read-only"},
        ],
    },
    "web_attack": {
        "name": "Web application attack",
        "match": lambda inc: bool(re.search(r"sql injection|xss|rce|remote code|traversal|web attack|webapp|shellshock|lfi|rfi", (inc.get("title") or ""), re.I)),
        "steps": [
            {"text": "Block the source address at the firewall.", "action": "block_ip"},
            {"text": "Check the web server for what this address requested.", "command": "sudo tail -n 100 /var/log/nginx/access.log 2>/dev/null || sudo tail -n 100 /var/log/apache2/access.log 2>/dev/null || echo 'no web log found'", "risk": "read-only"},
            {"text": "Recommendation: switch the site's firewall profile to Prevent in the open-appsec portal if attacks are only being detected.", "note": True},
        ],
    },
    "network_scan": {
        "name": "Network scan / reconnaissance",
        "match": lambda inc: bool(re.search(r"scan|recon|sweep|probe|port", (inc.get("title") or ""), re.I)),
        "steps": [
            {"text": "See what services are listening (what the scanner can reach).", "command": "sudo ss -tlnp", "risk": "read-only"},
            {"text": "Block the scanning address if it is hostile and internet-facing.", "action": "block_ip"},
        ],
    },
    "generic": {
        "name": "General triage",
        "match": lambda inc: True,
        "steps": [
            {"text": "Collect read-only evidence about the source address.", "action": "collect_evidence"},
            {"text": "Ask the AI analyst to investigate this incident.", "link": "investigate"},
        ],
    },
}


def playbook_for(inc: dict) -> dict:
    for key, pb in PLAYBOOKS.items():
        if key != "generic" and pb["match"](inc):
            return {"key": key, "name": pb["name"], "steps": pb["steps"]}
    return {"key": "generic", "name": PLAYBOOKS["generic"]["name"], "steps": PLAYBOOKS["generic"]["steps"]}
