# CERBERUS

**AI-assisted security operations console.** CERBERUS pulls telemetry from the security tools
you already run, correlates it into incidents, and puts an AI SOC analyst on top: it triages,
prioritises, forecasts attacks, and proposes responses — while a human approves anything that
touches a machine. Everything the AI does is bounded and audited.

Single Python process, no Node, Docker or database server required. The web UI is vanilla
JavaScript served by the same process.

---

## Table of contents

- [What it does](#what-it-does)
- [Feature tour](#feature-tour)
- [Tech stack](#tech-stack)
- [Architecture](#architecture)
- [Module map](#module-map)
- [Integrations](#integrations)
- [Install and run](#install-and-run)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Data and storage](#data-and-storage)
- [Roadmap](#roadmap)

---

## What it does

1. **Collects** events from Wazuh, Grafana (Prometheus + Loki), the open-appsec web firewall,
   and Snort — plus a generic webhook/intake for anything else.
2. **Correlates** events into incidents (one case per asset + source address per window).
3. **Understands** them with an AI analyst that runs read-only, audited queries against your
   data, triages each incident (verdict + MITRE technique), and forecasts attacks before they
   land.
4. **Prioritises** a work queue so analysts handle the most important case first, not the newest.
5. **Responds** with admin-approved actions over SSH (block an IP, collect evidence, run a
   patch plan) and per-incident playbooks.
6. **Reports and alerts**: a live dashboard, scheduled PDF reports, and threshold-based threat
   alerts by email.

---

## Feature tour

### Dashboard & monitoring
- **Main dashboard** — one screen with the vital signs of every connected application (Wazuh,
  Grafana/servers, web firewall, Snort, incidents/forecast, exposure/patching, AI), plus a single
  **threat level (0–100)** with a "why" breakdown. Refreshes every minute.
- **AI watch** — a scheduled analyst that checks servers, logs and the security tools themselves
  (sensors gone quiet, agents down, logs stopped, policy-reload loops) and alerts on new findings.
- **Infrastructure / Logs / Events / Assets** — live views over Prometheus, Loki and the
  normalised event store.

### Investigation
- **Enforcer console** — chat with the AI analyst. It runs bounded tool calls (search events,
  query Prometheus/Loki, read Wazuh, Snort, the WAF, SSH logins, patch status, the forecast) and
  cites its evidence. `@source` mentions focus a question on one source.
- **Incidents + Queue** — incidents correlated from events, and a **priority-ranked queue** with
  an AI verdict on each (malicious / suspicious / benign / noise), owner, status and response
  deadline.
- **IP lookup** — everything every source knows about one address, with a timeline and an AI
  verdict (malicious / suspicious / benign / internal noise).
- **Tag & discuss** — tag any row (log line, event, alert) and discuss it with the AI in a drawer.

### Triage, prioritisation & response workflow
- **AI auto-triage** — every new incident gets a verdict, a confidence, a plain-language reason
  and a MITRE ATT&CK technique, written automatically in the background.
- **Priority score (0–100)** — severity, asset importance, internet exposure, exploited
  vulnerabilities, attack-forecast likelihood and the AI verdict, with a visible breakdown.
- **Workflow** — assign to an analyst, status with reason, response deadlines (SLA) by priority,
  escalation of overdue cases, notes/timeline per incident, auto-close of stale incidents, and
  time-to-acknowledge / time-to-resolve metrics.
- **Response actions** — block/unblock an IP at a server's firewall, collect read-only evidence,
  or record a recommendation (disable account / isolate host). Blocking records its own undo.
- **Playbooks** — ordered checklists per incident type (SSH brute force, web attack, network
  scan, generic); each step is a one-click proposed command.
- **AI closure report** — a short *what happened / impact / root cause / what was done /
  recommendation* record, filed in the incident's notes.

### Prediction & posture
- **Attack forecast** — early warnings from the patterns that precede an intrusion (scanning
  turning into exploit attempts, accelerating password guessing against real accounts, a
  vulnerable internet-facing host under attack, traffic surges, a login after many failures).
  Each warning has a likelihood, the stage reached, evidence, what usually comes next, and what
  to do. Alerts admins in-app, by email and as an incident.
- **Asset risk** — every machine scored 0–100 across Wazuh, Prometheus, Snort and the WAF.
- **Vulnerability priority** — CVEs ranked by CISA KEV (exploited in the wild), FIRST EPSS
  (likelihood of exploitation) and internet exposure.
- **Patch plan** — for every vulnerability: whether a patch exists (Ubuntu archive + OSV.dev),
  the fix-by date from a published policy, and the exact command to run on each machine. Can be
  queued for approved execution over SSH.

### Response over SSH (approval-gated)
- **Servers** — register servers; CERBERUS connects over SSH with its own key (or a password),
  pins the host key, and can run commands **only after an admin approves each one**.
- **Command policy** — commands that destroy data, stop security tools, change accounts/keys,
  hide evidence or open shells are refused outright and cannot be approved. Servers default to
  read-only until changes are explicitly allowed.
- **Approvals** — every proposed command and response action is shown in full with a risk level,
  decided by an admin, executed non-interactively with a timeout, and audited.

### Reporting & alerting
- **Scheduled reports** — daily/weekly PDF security report with an AI executive summary, emailed
  to admins and extra recipients.
- **Threat alerts** — admin-defined rules that email chosen people when a measure (overall threat
  level, forecast likelihood, machine risk, or incident severity) crosses a threshold, with a
  quiet period and test sends.
- **AI usage** — tokens, calls, cost-shaped metrics, latency and failures per purpose and per user.

### Administration
- Users & roles (admin / analyst), email-verified accounts, invitations, password reset.
- Announcements, audit log, AI provider management, all integrations in one place.
- Email (Gmail app password or SMTP) for verification, reports, watch and alerts.

---

## Tech stack

| Layer | Technology |
| --- | --- |
| Language | Python 3.11+ (developed on 3.14) |
| Web framework | FastAPI |
| Server | Uvicorn (with `--reload` in dev) |
| HTTP client | httpx |
| Database | SQLite (WAL mode), single file, no server |
| SSH | Paramiko (ed25519 key, pinned host keys) |
| PDF | fpdf2 |
| Auth | bcrypt-hashed passwords, signed session cookies |
| Front end | Vanilla JavaScript SPA (no build step), hand-rolled CSS with light/dark + accent themes |
| AI | Any OpenAI-compatible `/chat/completions` endpoint (NVIDIA NIM, Ollama, LM Studio, OpenAI, OpenRouter, Groq, vLLM, …) |
| External data | CISA KEV, FIRST EPSS, Ubuntu security tracker / Launchpad, OSV.dev |

**Dependencies** (`backend/requirements.txt`): `fastapi`, `uvicorn`, `httpx`, `fpdf2`, `paramiko`.

---

## Architecture

```
          ┌──────────── data sources ────────────┐
          │  Wazuh   Grafana(Prom/Loki)  open-appsec  Snort  webhooks │
          └───────────────────┬───────────────────┘
                              │  (read-only pulls / webhook intake)
                    ┌─────────▼──────────┐
                    │  FastAPI process   │   SQLite (data/cerberus.db)
                    │  ────────────────  │   ├─ events, incidents, notes
   browser  ◄─HTTP─►│  REST + NDJSON     │◄─►├─ approvals, server_commands
   (SPA)            │  background loop   │   ├─ ai_usage, forecasts, alerts
                    │  AI tool-loop      │   └─ settings, integrations, users
                    └─────────┬──────────┘
                              │  approved commands only
                    ┌─────────▼──────────┐
                    │  your servers (SSH) │
                    └────────────────────┘
                              │
                  AI model (OpenAI-compatible endpoint)
```

- **One process** serves the API and the static SPA, and runs a **background scheduler**
  (`watch._loop`) that ticks every 20s: pull Wazuh, run detections, forecast attacks, triage
  incidents, evaluate threat alerts, warm the dashboard, refresh patch data, send due reports, run
  AI watch.
- **The AI analyst** runs a bounded tool-calling loop (max 12 tool calls per turn) over read-only
  data tools; responses stream to the browser as NDJSON with heartbeats.
- **Everything consequential** (response actions, server commands) is proposed, approved by a
  human, then executed and audited.

---

## Module map

`backend/app/`

| Module | Responsibility |
| --- | --- |
| `main.py` | FastAPI app, all REST routes, NDJSON chat stream |
| `db.py` | SQLite schema, migrations, connection helper |
| `store.py` | Event ingest, correlation, incident/queue queries, triage stats |
| `auth.py` / `accounts.py` | Sessions, users, roles, invitations, email verification |
| `ai.py` | AI provider calls, tool loop, briefings, triage & closure prompts, usage accounting |
| `tools.py` | The read-only tools the AI analyst may call |
| `wazuh.py` | Wazuh dashboard/indexer client, alert pull, SCA, agents, vulnerabilities |
| `grafana.py` | Prometheus + Loki via the Grafana datasource proxy, server health, SSH-login parsing |
| `openappsec.py` | Web-firewall events from Loki, asset/agent inventory |
| `snort.py` | Snort alerts from Loki (two forwarder shapes), counts, summaries |
| `apps.py` | The per-application page system (Wazuh/Grafana/open-appsec/Snort views) |
| `insights.py` | Cross-source views: IP profile, asset risk, vulnerability priority, AI usage; KEV/EPSS |
| `dashboard.py` | Main dashboard vitals + overall threat level |
| `predict.py` | Attack forecasting engine |
| `triage.py` | Incident auto-triage, priority scoring, workflow, notes, metrics, closure reports |
| `response.py` | Response actions and playbooks (routed through approvals) |
| `remote.py` | SSH, server registry, command policy, approval-gated execution |
| `patches.py` | Patch availability and fix-by deadlines (Ubuntu + OSV) |
| `detections.py` | Turn Snort/WAF detections into correlated events |
| `watch.py` | Background scheduler + AI watch (scheduled analyst) |
| `alerting.py` | Threat-alert rules and evaluation |
| `reports.py` / `report_pdf.py` | Scheduled security reports and PDF rendering |
| `mailer.py` | Email delivery (Gmail/SMTP) and HTML templates |
| `demo.py` | Loadable, clearly-flagged sample scenario |

`web/`: `index.html`, `app.js` (the whole SPA), `styles.css`, `logos/`, `fonts/`.

---

## Integrations

Configured on the **Integrations** page unless noted.

| Source | Direction | How |
| --- | --- | --- |
| **AI model** | out | AI providers page; any OpenAI-compatible endpoint |
| **Grafana** | in + out | Alert webhook in; read-only service-account token out (Prometheus + Loki proxy) |
| **Wazuh** | out (pull) | Dashboard/indexer URL + credentials; nothing installed on Wazuh |
| **open-appsec** | out | Read live from the agents' output in Loki; asset/agent inventory recorded once |
| **Snort** | out | Alerts shipped to Loki (systemd-journal forwarder); read via Grafana |
| **Generic intake** | in | `POST /api/v1/ingest/events` with a bearer token |
| **Servers (SSH)** | out | Servers page; approval-gated command execution |
| **Email** | out | Gmail app password or SMTP |
| **CISA KEV / FIRST EPSS / Ubuntu / OSV** | out | Public feeds, cached locally for vuln & patch data |

---

## Install and run

Requires Python 3.11+ (no Node, Docker or database server).

```powershell
.\run.ps1                      # http://127.0.0.1:8787, this PC only
.\run.ps1 -BindHost 0.0.0.0    # reachable from the LAN (needed for Grafana on another host)
```

The script creates a virtual environment, installs `backend/requirements.txt`, and starts Uvicorn
with auto-reload. First visit asks you to create the admin account. **Overview → Load demo data**
adds a flagged sample scenario to explore before connecting anything.

> Exposing on `0.0.0.0` serves plain HTTP — keep it on a trusted network or put a TLS reverse
> proxy (or a tunnel such as Cloudflare) in front.

---

## Configuration

- **AI providers** — add an endpoint, **Load models**, pick one, **Test**. Tool-calling models
  investigate by querying; non-tool models answer from a snapshot.
- **Grafana** — paste the webhook bearer token into a Grafana contact point; add a read-only
  service-account token and the Prometheus/Loki datasource UIDs (auto-detected on save).
- **Wazuh / open-appsec / Snort** — addresses and credentials on Integrations.
- **Servers** — add CERBERUS's SSH public key to each server, press **Test connection** (pins the
  host key), and allow changes only where you want remediation.
- **Email** — Gmail app password or SMTP; needed for verification, reports, watch and threat alerts.
- **Threat alerts / Reports / Auto-triage** — thresholds, schedules and recipients in their pages.

Secrets (provider keys, Grafana/Wazuh/SSH/email passwords) are encrypted before being stored in
SQLite and never shown again after saving.

Saved integration credentials, AI API keys and authenticator secrets are encrypted with Fernet.
The key is `data/master.key` by default; keep it with any database backup or set
`CERBERUS_MASTER_KEY` to a Fernet key before startup. Losing the key makes saved credentials
unreadable. Backups are written daily to `data/backups/` and retained for 14 days. They include
the database, key file and SSH identity, so copy them to protected storage outside this machine.

On Windows, run `./service.ps1 -Action Install` after the first launch to start CERBERUS in the
background at sign-in. Use `./service.ps1 -Action Remove` to remove the startup task. This runs
under the current user's account; it does not start before that user signs in.

---

## Security model

- **Human-in-the-loop.** The AI investigates and proposes; a human approves anything that changes
  a firewall, an account, or a host. Response actions and server commands are never automatic.
- **Bounded AI.** The analyst only has read-only data tools plus the approval-gated command tool,
  a fixed tool-call budget, and audited calls. Data from your systems is treated as untrusted and
  cannot steer the model into running commands on its own.
- **Command policy.** Destructive commands, stopping security tools, account/key changes, evidence
  destruction and shell-opening are refused outright. Servers are read-only until changes are
  allowed. SSH host keys are pinned; a changed key halts execution.
- **Least privilege.** Grafana access uses a read-only service-account token; Wazuh is pulled, not
  modified; a dedicated low-privilege SSH account is recommended per server.
- **Auditing.** Proposals, approvals, executions, status changes and AI tool calls are written to
  the audit log.
- **Roles.** Admins manage integrations, servers, users and approvals; analysts investigate and
  work the queue.

---

## Data and storage

- Everything lives in **`data/`** (git-ignored): the SQLite database (`cerberus.db`), CERBERUS's
  SSH key (`ssh/`), and cached vuln/patch feeds.
- The SSH private key grants access to every server that trusts it — protect `data/` and back it
  up out of band (it is never committed). Moving the `data/` folder moves the whole install,
  including the key and all registered servers.
- SQLite runs in WAL mode; the schema self-migrates on startup.

---

## Roadmap

Delivered: dashboard & threat level, AI triage + priority queue + workflow, response actions +
playbooks + closure reports, attack forecast, asset risk, vulnerability priority, patch plan,
approval-gated SSH, scheduled reports, threat alerts, AI-usage metrics.

Delivered in Stage 3/4: IP threat intelligence (GreyNoise without a key; AbuseIPDB with an optional
key), unusual SSH-login detection, incident merge/split, encrypted saved credentials,
authenticator-app MFA, cloud-model prompt redaction, daily backups, AI-answer feedback, and a
Windows background startup task.

Unusual-login detection reads successful SSH sign-ins from Loki every five minutes. Its first
pass establishes a baseline; later first-seen accounts or source addresses create incidents.
It does not infer successful sign-ins to web applications from access logs. Cloud AI requests
redact email addresses, IP addresses and common credential patterns before sending prompts;
this can reduce an external model's ability to investigate an exact address. Local model
endpoints receive the original evidence.

See [Plan.md](Plan.md) for the original design.
