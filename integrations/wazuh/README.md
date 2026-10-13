# Wazuh → CERBERUS

Sends Wazuh alerts to CERBERUS as events, where they are correlated into incidents.
Run these steps on the **Wazuh manager** (for a Docker install, inside the manager container).

## 1. Install the script

```bash
# copy custom-cerberus.py from this folder to the manager, then:
sudo cp custom-cerberus.py /var/ossec/integrations/custom-cerberus.py
# Wazuh starts integrations through a small wrapper; reuse the one it ships for Slack
sudo cp /var/ossec/integrations/slack /var/ossec/integrations/custom-cerberus
sudo chown root:wazuh /var/ossec/integrations/custom-cerberus /var/ossec/integrations/custom-cerberus.py
sudo chmod 750 /var/ossec/integrations/custom-cerberus /var/ossec/integrations/custom-cerberus.py
```

## 2. Tell Wazuh to use it

Add this inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-cerberus</name>
  <hook_url>https://YOUR-CERBERUS-ADDRESS/api/v1/ingest/events</hook_url>
  <api_key>THE-BEARER-TOKEN-FROM-CERBERUS-INTEGRATIONS-PAGE</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

`<level>7</level>` forwards alerts of level 7 and above. Lower it to send more, raise it to send less.

## 3. Restart and check

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/integrations.log     # errors from this script appear here
```

In CERBERUS, open **Events** and choose the source **wazuh**.

## What gets mapped

| Wazuh | CERBERUS |
| --- | --- |
| `agent.name`, `agent.ip` | asset |
| `rule.level` 0–15 | severity 1–10 (level 6+ can open an incident, 10+ is high, 13+ critical) |
| `rule.id`, `rule.description` | rule, title |
| `rule.groups` | event type (`vulnerability-detector` is stored but never opens an incident) |
| `data.srcip`, `data.dstuser` / `data.srcuser` | source IP, user |
| `full_log` | message |
| `id` | used to ignore duplicates |

The manager must be able to reach the CERBERUS address over the network.
