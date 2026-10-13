# CERBERUS

AI-assisted security operations console: an AI SOC analyst that investigates with
bounded, audited queries, and a human Enforcer who approves anything consequential.
This is an early version of the platform described in [Plan.md](Plan.md).

## Run it

Requires Python 3.11+ (no Node, Docker or database server needed).

```powershell
.\run.ps1                      # http://127.0.0.1:8787, this PC only
.\run.ps1 -BindHost 0.0.0.0    # reachable from the LAN (needed for Grafana on another host)
```

The first visit asks you to create the Enforcer account. **Overview → Load demo data**
adds a clearly flagged sample scenario so you can explore before connecting anything.

## Connect an AI model

**AI providers → Add a provider.** Anything that speaks the OpenAI `/chat/completions`
dialect works:

| Type | Base URL | Key |
| --- | --- | --- |
| NVIDIA NIM | `https://integrate.api.nvidia.com/v1` | `nvapi-…` from build.nvidia.com |
| Ollama (local) | `http://localhost:11434/v1` | none |
| LM Studio (local) | `http://localhost:1234/v1` | none |
| OpenAI / OpenRouter / Groq | preset | provider key |
| Custom | vLLM, llama.cpp, LiteLLM, … | optional |

Press **Load models**, pick one, save, then **Test**. Models that support tool calling
investigate by running queries; models that don't are detected automatically and answer
from a snapshot of recent incidents and events instead.

## Connect Grafana

Both directions are configured on the **Integrations** page.

1. **Alerts in (webhook).** In Grafana: *Alerting → Contact points → Add contact point →
   Webhook*. URL `http://<cerberus-host>:8787/api/v1/webhooks/grafana`, method POST,
   Authorization Header Scheme `Bearer`, Credentials = the token shown on the page. Route
   alerts to it under *Notification policies*. Labels `instance`/`host` map the alert to an
   asset; label `severity` (critical, warning, info…) sets priority.
2. **Queries out (API).** In Grafana: *Administration → Users and access → Service accounts*,
   create one with the **Viewer** role and add a token. Paste the Grafana URL and token,
   then **Save and test** – the Prometheus and Loki datasource UIDs are detected. The analyst
   then gains `query_prometheus` and `query_loki` tools.

Grafana must be able to reach CERBERUS, so if it runs on another machine start with
`-BindHost 0.0.0.0`, allow the port through Windows Firewall, and use this PC's LAN IP.

Other engines (Wazuh, Snort, WAF…) can push normalised events to
`POST /api/v1/ingest/events` with the same bearer token until they get dedicated adapters.

## Users and roles

The first account is the **admin**. Admins add people under **Users** and choose a role:

| | Admin | Analyst |
| --- | --- | --- |
| Overview, incidents, events, assets, AI console | yes | yes |
| Decide approvals | yes | view only |
| Users, announcements, AI providers, integrations, audit log | yes | no |

With email configured, a new user gets an invitation: they verify their address and choose their
own password. Without email, the admin sets an initial password. Accounts must be verified before
they can sign in; an admin can also mark one verified by hand. "Forgot your password?" on the
sign-in page emails a one-hour reset link.

## Email

**Integrations → Email** sends through Gmail by default. You need only two things:

1. Turn on 2-Step Verification for the Google account that will send the mail.
2. Create an app password at `myaccount.google.com/apppasswords` and paste its 16 letters,
   together with the Gmail address, into the form. A normal Google password is rejected.

Also set the address of this app (used for the links inside emails). **Send test email** checks
the setup; **Recent emails** shows every message and any delivery error. "Another mail server
(SMTP)" in the same form is there if you ever move off Gmail.

Email is used for: account verification, password reset and password-changed notices, analyst
reports to admins (the **Email to admins** button under any answer, or by asking the AI to "send
this to the admin as a report"), and announcements. The AI cannot choose recipients: reports
only go to admins with a verified address.

## Announcements and notifications

**Announcements** (admin) sends a notice to everyone, admins only or analysts only: as a
notification behind the bell icon, as an announcement email, or both.

## Layout

```
backend/app/
  main.py      API routes, security headers, static UI
  auth.py      accounts, roles, scrypt hashes, cookie sessions, one-time tokens
  accounts.py  sign-in, verification, reset, user management, email settings, announcements
  mailer.py    SMTP delivery, outbox log, email templates
  store.py     event intake, asset resolution, deterministic correlation
  ai.py        OpenAI-compatible client, bounded investigation loop
  tools.py     the only actions the model can take (typed, validated, audited)
  grafana.py   webhook normaliser, datasource-proxy queries
  demo.py      sample data
web/           dependency-free UI (index.html, app.js, styles.css)
data/          SQLite database, created on first run (git-ignored)
```

## Safety model

- Correlation is deterministic and runs before the model; monitoring keeps working with no AI connected.
- The model can only call the tools in `tools.py`. It cannot execute response actions – it
  queues a request, which expires after 24 h unless an Enforcer decides it.
- Investigations are capped at 12 tool calls; every call and decision is in the audit log.
- Log and alert text is treated as untrusted data in prompts and escaped in the UI.

## Not built yet

No response executor (approvals are recorded, nothing is changed on any system), no
Slack/Jira, no dedicated Wazuh/Snort/Velociraptor adapters, local accounts instead of
Keycloak, SQLite instead of PostgreSQL/Redis. API keys, tokens and the SMTP password are stored
unencrypted in `data/cerberus.db` – protect that file, and put a TLS reverse proxy in
front before exposing the app beyond a trusted network.
