Project AEGIS — Autonomous AI SOC & Human Enforcer Platform
System architecture • AI security operations • Threat investigation • Human-controlled response
I recommend building AEGIS (AI-Enhanced Guardian & Investigation System): a unified security operations platform where an AI SOC Analyst monitors and investigates activity across your security infrastructure, while a human Enforcer oversees the system, investigates incidents, issues natural-language queries, and authorizes sensitive response actions.
The goal is to go beyond a dashboard that merely aggregates alerts. You want a system that can understand events, connect evidence across tools, prioritize incidents, recommend responses, and coordinate workflows through Slack, Jira, Gmail, and your existing defense platforms.
1. The architecture
AEGIS — Unified Security Control Plane

React/Next.js • FastAPI • PostgreSQL • Redis • Realtime Events

AI SOC Analyst

24/7 alert triage, enrichment, correlation, threat hunting, investigations, incident summaries and recommendations.
Autonomous analysis


Human Enforcer

Natural-language investigation, incident supervision, approvals, response execution and policy management.
Human-controlled enforcement




AI Orchestrator + Correlation Engine
Tool routing • Evidence retrieval • Risk scoring • Policy checks • Audit trails


Security detection
Wazuh • Snort 3 • Zeek • open-appsec • auditd • osquery


Observability
Grafana • Prometheus • Loki • Tempo • Pyroscope • Netdata


Threat intelligence & DFIR
VirusTotal • AbuseIPDB • MISP • Velociraptor


Communication & tickets
Slack • Jira • Gmail • Webhooks




The two roles are deliberately different.
AI SOC Analyst acts continuously. It can discover suspicious activity, gather corroborating evidence, link related detections, create investigation cases, and recommend action. It should not independently acquire administrative privileges or execute irreversible containment operations.
Human Enforcer is a privileged human role. It can ask the AI questions about any authorized asset or incident, review the AI's evidence, approve actions, change detection policies, and manage platform integrations. Its permissions should still be scoped and audited.
2. What the finished application should look like
Conceptual UI layout
Design preview

AEGIS / Security Operations

AI SOC active


24
Assets


08
Open incidents


02
Critical


03
Pending approval




AI SOC Analyst

I correlated repeated SSH authentication failures, an unusual successful login, and elevated process activity on a monitored endpoint.
Investigation needed
3 evidence sources • Example event

Suggested action: Review endpoint session
Collect process and authentication evidence before deciding on containment.


Ask AEGIS

“Investigate all suspicious activity on sietlms over the last 24 hours and correlate Snort with Wazuh and Loki.”





Illustrative design only; the values and scenario are mock data, not live findings from your infrastructure.I would give the application these major workspaces:
Workspace	Purpose
Overview	Live security posture and risk
AI SOC	Automated investigations and agent activity
Enforcer Console	Natural-language queries and approved actions
Incident Center	Cases, evidence, timelines and ownership
Asset Intelligence	Unified endpoint, application and service view
Network Defense	Snort, Zeek, WAF and traffic analysis
Threat Intelligence	IP, domain, hash and IOC reputation
Observability	Metrics, logs, traces and performance
Digital Forensics	Velociraptor investigations
Automation	Playbooks, triggers and approvals
Integrations	Credentials, connectors and health
Reports	Incident reports, digests and SOC performance
3. What should the AI actually do?
Build the AI SOC as multiple specialized capabilities orchestrated by one central agent, rather than giving one language model unrestricted access to every API.

Detection & Triage Agent
Consumes new Wazuh, Snort, WAF and Grafana alerts. Deduplicates events, separates vulnerability inventory from active attack indicators, scores priority, and identifies which events need immediate attention.




Correlation & Investigation Agent
Searches logs, authenticates asset relationships, builds cross-platform timelines, checks process/network evidence, and proposes explanations supported by event references.




Threat Intelligence Agent
Enriches source IPs, file hashes and domains through reputation feeds; distinguishes known scanners, suspicious infrastructure and high-confidence malicious indicators.




Response Planning Agent
Prepares containment recommendations, estimates potential impact, selects approved playbooks, and generates an Enforcer approval request when necessary.




Reporting & Communications Agent
Produces incident reports, Slack updates, Jira issue drafts, Gmail summaries, handover notes and daily/weekly SOC digests without flooding recipients with duplicate alerts.



The AI should use real tools to obtain evidence, not invent findings. Every investigation result should link to the original Wazuh alert, Grafana panel, Loki query, or Velociraptor collection.
4. How each existing platform connects
Your biggest advantage is that most of the security infrastructure already exists. You do not need to replace it; you need an integration layer that translates each engine into a common evidence model.
Platform	What AEGIS retrieves	Integration method
Wazuh	Security alerts, agents, FIM, vulnerability findings, authentication events	Manager API + Indexer Search API
Snort 3	IDS signatures, source/destination IPs, ports, priorities	JSON alerts via Alloy/Loki or a dedicated ingestion service
Zeek	DNS, HTTP, TLS, connections and network metadata	JSON logs via Loki
open-appsec	Web attacks, blocked requests, WAF decisions	JSON/syslog ingestion
auditd / osquery	Process, execution, identity and system activity	Wazuh plus indexed evidence
Prometheus	CPU, memory, traffic, availability, system and application metrics	Prometheus HTTP API
Grafana / Alertmanager	Operational alerts and dashboard links	Signed webhook + Grafana API
Loki	System, application and security logs	LogQL HTTP API
Tempo	Distributed traces and request investigations	Trace API / Grafana pivot
Pyroscope	CPU and memory profiling	Grafana profiling views
Netdata	Host-health and anomaly data	Netdata API
Velociraptor	Endpoint hunts, artifacts, forensic results	Certificate-authenticated gRPC
VirusTotal / MISP	Hash, domain and IP intelligence	API / threat-intelligence feeds
Wazuh's Indexer API supports searching indexed security evidence; Grafana supports authenticated webhook notifications; Velociraptor officially exposes a gRPC automation API. Those are the key interfaces to build around. 


Wazuh indexer API · Wazuh documentation
+2



Data movement
#chatgpt-mermaid-_r_208_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(237, 237, 237);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-_r_208_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-_r_208_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-_r_208_ .error-icon{fill:rgb(48, 48, 48);}#chatgpt-mermaid-_r_208_ .error-text{fill:rgb(237, 237, 237);stroke:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-_r_208_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-_r_208_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-_r_208_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-_r_208_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-_r_208_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-_r_208_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_208_ .marker.cross{stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_208_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-_r_208_ p{margin:0;}#chatgpt-mermaid-_r_208_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ .cluster-label text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ .cluster-label span{color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-_r_208_ .label text,#chatgpt-mermaid-_r_208_ span{fill:rgb(237, 237, 237);color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ .node rect,#chatgpt-mermaid-_r_208_ .node circle,#chatgpt-mermaid-_r_208_ .node ellipse,#chatgpt-mermaid-_r_208_ .node polygon,#chatgpt-mermaid-_r_208_ .node path{fill:rgb(9, 23, 44);stroke:rgb(31, 78, 148);stroke-width:1px;}#chatgpt-mermaid-_r_208_ .rough-node .label text,#chatgpt-mermaid-_r_208_ .node .label text,#chatgpt-mermaid-_r_208_ .image-shape .label,#chatgpt-mermaid-_r_208_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-_r_208_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-_r_208_ .rough-node .label,#chatgpt-mermaid-_r_208_ .node .label,#chatgpt-mermaid-_r_208_ .image-shape .label,#chatgpt-mermaid-_r_208_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-_r_208_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-_r_208_ .root .anchor path{fill:rgb(175, 175, 175)!important;stroke-width:0;stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_208_ .arrowheadPath{fill:rgb(175, 175, 175);}#chatgpt-mermaid-_r_208_ .edgePath .path{stroke:rgb(175, 175, 175);stroke-width:1px;}#chatgpt-mermaid-_r_208_ .flowchart-link{stroke:rgb(175, 175, 175);fill:none;}#chatgpt-mermaid-_r_208_ .edgeLabel{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-_r_208_ .edgeLabel p{background-color:rgb(0, 0, 0);}#chatgpt-mermaid-_r_208_ .edgeLabel rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-_r_208_ .labelBkg{background-color:rgba(0, 0, 0, 0.5);}#chatgpt-mermaid-_r_208_ .cluster rect{fill:rgb(48, 48, 48);stroke:rgba(255, 255, 255, 0.15);stroke-width:1px;}#chatgpt-mermaid-_r_208_ .cluster text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ .cluster span{color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(48, 48, 48);border:1px solid rgba(255, 255, 255, 0.15);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-_r_208_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(237, 237, 237);}#chatgpt-mermaid-_r_208_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-_r_208_ .icon-shape,#chatgpt-mermaid-_r_208_ .image-shape{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-_r_208_ .icon-shape p,#chatgpt-mermaid-_r_208_ .image-shape p{background-color:rgb(0, 0, 0);padding:2px;}#chatgpt-mermaid-_r_208_ .icon-shape .label rect,#chatgpt-mermaid-_r_208_ .image-shape .label rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-_r_208_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-_r_208_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-_r_208_ .node .neo-node{stroke:rgb(31, 78, 148);}#chatgpt-mermaid-_r_208_ [data-look="neo"].node rect,#chatgpt-mermaid-_r_208_ [data-look="neo"].cluster rect,#chatgpt-mermaid-_r_208_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-_r_208_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_208_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-_r_208_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-_r_208_-gradient);stroke-width:1px;}#chatgpt-mermaid-_r_208_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_208_ [data-look="neo"].node .neo-line path{stroke:rgb(31, 78, 148);filter:none;}#chatgpt-mermaid-_r_208_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-_r_208_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_208_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-_r_208_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-_r_208_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_208_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-_r_208_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_208_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(153, 206, 255);}#chatgpt-mermaid-_r_208_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(153, 206, 255);}#chatgpt-mermaid-_r_208_ .node tspan[font-weight="normal"],#chatgpt-mermaid-_r_208_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-_r_208_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-width:1px;}#chatgpt-mermaid-_r_208_ .node rect,#chatgpt-mermaid-_r_208_ .node circle,#chatgpt-mermaid-_r_208_ .node ellipse,#chatgpt-mermaid-_r_208_ .node polygon,#chatgpt-mermaid-_r_208_ .node path{fill:rgb(0, 40, 77);stroke:rgba(255, 255, 255, 0.1);stroke-width:1px;}#chatgpt-mermaid-_r_208_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-_r_208_ .node.mermaid-decision .label-container{fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-dasharray:2,2;}#chatgpt-mermaid-_r_208_ .edgePaths .flowchart-link{stroke:rgb(175, 175, 175);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-_r_208_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_208_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Wazuh / Snort / Zeek / WAFEvent collectorsGrafana / AlertmanagerWebhook receiverPrometheus / Loki / TempoOn-demand query adaptersVelociraptorNormalizer and asset resolverEvent queueDeterministic correlationIncident storeAI investigation workersEvidence-backed incidentreportPolicy and approval engineSlack / Jira / GmailHuman EnforcerScoped response executor





Use two types of integration:
Push-based collection for new alerts: Wazuh, Snort, WAF, and Grafana send events to AEGIS as they happen.
Pull-based investigation for historical evidence: the AI queries Prometheus, Loki, Wazuh Indexer and Velociraptor only when needed. That prevents needless duplication of millions of log and metrics records.
5. Natural-language Enforcer Console
The Enforcer should be able to ask questions that span multiple engines, without remembering individual query languages.
Example Enforcer AI queries
Show all suspicious activity on sietlms during the last 24 hours.Did any IP blocked by our WAF successfully authenticate to another server?Why did the LMS become slow around 10:30 AM?Find suspicious files created after the SSH brute-force alert.Prepare a Jira incident and Slack update for the latest confirmed critical incident.

AEGIS execution plan
Evidence sources
Wazuh + Snort + Loki + auditd


Expected output
Timeline, source IPs, affected accounts, supporting evidence and confidence


Design this query workflow 

These should be implemented as structured tool calls, not by allowing the model to generate unrestricted shell commands or unrestricted SQL.
For instance, the AI might request:
{
  "tool": "search_security_events",
  "arguments": {
    "asset_id": "srv-001",
    "time_range": "24h",
    "min_severity": 7,
    "limit": 100
  }
}


Your backend validates the inputs, checks permissions, executes a bounded search, and returns events with source references. The AI then decides whether it needs another authorized query.
6. Communications: Slack, Jira and Gmail
Build a shared notification service. Each integration should be just another delivery channel, rather than creating separate notification logic in every security tool.









Slack — SOC collaboration
Create incident threads, send escalations, notify the on-call analyst, post evidence summaries, and update the thread when an incident changes state. Use a dedicated Slack bot with tightly scoped posting permissions.












Jira — Case tracking
Create and update incidents, map severity and affected assets, assign ownership, add findings, and link tickets back to AEGIS. Jira Cloud's REST API supports creating and modifying issues, including structured descriptions. 


developer.atlassian.com















Gmail — Email escalation and reporting
Send polished HTML incident alerts, investigation links, daily summaries, and resolved-incident reports. For the custom portal, use Gmail's OAuth-based send API rather than putting your personal app password in its code. 


developers.google.com






You can connect Gmail directly in ChatGPT for email workflows too; for AEGIS itself, implement an independent, organization-controlled integration.
Example notification workflow
Wazuh detects suspicious authentication
             ↓
AEGIS checks Snort and auditd
             ↓
Correlation engine links related evidence
             ↓
AI prepares incident assessment
             ↓
Policy engine determines priority
             ↓
Slack thread + Jira case
             ↓
Email only if escalation threshold is met
             ↓
Human Enforcer reviews suggested response


Because you previously experienced large bursts of Wazuh vulnerability emails, I would build deduplication, grouping, rate limiting, and escalation thresholds into the notification service from the beginning.
For example, 50 related vulnerability alerts should become one inventory digest, not 50 urgent emails. Repeated brute-force alerts from the same source against the same asset should normally update one incident.
7. Human approval and autonomy
The platform needs an explicit policy determining what the AI may execute and what requires Enforcer approval.
Recommended authorization matrix
Operation	Default control
Read security logs and metrics	AI allowed
Enrich indicators and correlate alerts	AI allowed
Create internal investigation cases	AI allowed
Post routine incident updates	Policy-based
Create Jira tickets or send email	Policy-based
Run non-invasive Velociraptor collections	Enforcer approval
Block an IP or disable an account	Enforcer approval
Isolate a host or delete/quarantine a file	Enforcer approval
Change firewall, Wazuh or WAF policy	Enforcer approval

A response executor must verify identity, role, asset scope, incident state, action parameters, approval validity and expiry independently of the AI's instructions. Use short-lived approvals, idempotency keys, execution deadlines and rollback plans where possible.
This is especially important for Velociraptor: its API can launch powerful endpoint operations, and its documentation specifically warns against unnecessarily privileged automation credentials. 


Digging deeper!



8. The technical stack I would choose
Layer	Technology	Reason
Frontend	Next.js + TypeScript + Tailwind	Modern admin interface and interactive investigations
Backend	FastAPI + Pydantic	Typed API endpoints and Python-based integrations
Operational database	PostgreSQL	Assets, incidents, users, workflows and audit records
Queue and background jobs	Redis + Celery initially	Asynchronous ingestion, enrichment and jobs
AI orchestration	LangGraph or a custom state machine	Multi-step investigations with durable state
Model serving	NVIDIA NIM / compatible hosted API / Ollama	Choice of inference backend
Semantic retrieval	PostgreSQL + pgvector	Relevant runbooks and prior-case retrieval
Authentication	Keycloak (OIDC)	Identity, SSO and service roles
Policy enforcement	Explicit FastAPI policy layer, optionally OPA	Separates authorization from LLM output
API gateway	Traefik or Nginx	TLS, routing, request restrictions
Observability	Your existing Grafana stack	Monitor AEGIS itself
Secrets	Docker secrets initially, Vault later	Keep service credentials out of source code
For a modest lab deployment, don't begin with Kubernetes, Kafka, Elasticsearch, multiple vector databases, and six independent AI services. That creates far more operational complexity than the MVP needs.
Start with one FastAPI backend, one AI worker, one ingestion worker, PostgreSQL and Redis. Scale individual services only when real load requires it.
Project structure
aegis/
├── apps/
│   ├── web/                     # Next.js UI
│   └── api/                     # FastAPI application
│
├── services/
│   ├── ingestion/               # Alert intake
│   ├── normalizer/              # Common event schema
│   ├── correlation/             # Deterministic detections
│   ├── ai-soc/                  # AI investigation orchestration
│   ├── notification/            # Slack, Jira, Gmail
│   └── response/                # Approved response executor
│
├── integrations/
│   ├── wazuh/
│   ├── snort/
│   ├── zeek/
│   ├── openappsec/
│   ├── prometheus/
│   ├── loki/
│   ├── grafana/
│   ├── velociraptor/
│   ├── threat_intel/
│   ├── slack/
│   ├── jira/
│   └── gmail/
│
├── shared/
│   ├── schemas/
│   ├── policy/
│   └── utilities/
│
├── infrastructure/
│   ├── compose/
│   ├── nginx/
│   └── migrations/
│
├── tests/
├── .env.example
└── README.md


Each integration should expose a typed, bounded contract. For example, wazuh.search_alerts(), loki.search_logs(), prometheus.query_metric() and velociraptor.get_client_info(). That makes adapters testable without involving the language model.
9. Database design
Your central database should be focused on operational state, not storing all raw security telemetry.
Core database relationships
Additional tables: users, memberships, asset identities, incident-event links, policies, integrations, tool executions and immutable audit records.
For each event, store at least:
{
  "event_id": "evt-example-001",
  "source": "wazuh",
  "source_event_id": "original-wazuh-id",
  "asset_id": "srv-001",
  "event_type": "authentication_failure",
  "severity": 8,
  "timestamp": "2026-10-12T09:00:00Z",
  "source_ip": "198.51.100.42",
  "username": "example-user",
  "rule_id": "example-rule",
  "evidence_ref": {
    "backend": "wazuh-indexer",
    "index": "example-index",
    "document_id": "example-document-id"
  }
}


Store asset aliases separately. An IP address alone is not a reliable permanent identifier because machines can change addresses, and public NAT can make multiple assets share an address.
For a first version, I would create 12 principal tables: assets, asset_identities, events, incidents, incident_events, evidence, investigations, tool_executions, notifications, approvals, response_actions, and audit_logs.
Add integrations, users and policies as supporting tables.
10. Build the actual AI investigation loop
The AI should be event-driven rather than repeatedly reading the entire Wazuh database.
#chatgpt-mermaid-_r_23f_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(237, 237, 237);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-_r_23f_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-_r_23f_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-_r_23f_ .error-icon{fill:rgb(48, 48, 48);}#chatgpt-mermaid-_r_23f_ .error-text{fill:rgb(237, 237, 237);stroke:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-_r_23f_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-_r_23f_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-_r_23f_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-_r_23f_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-_r_23f_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_23f_ .marker.cross{stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_23f_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-_r_23f_ p{margin:0;}#chatgpt-mermaid-_r_23f_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ .cluster-label text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ .cluster-label span{color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-_r_23f_ .label text,#chatgpt-mermaid-_r_23f_ span{fill:rgb(237, 237, 237);color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ .node rect,#chatgpt-mermaid-_r_23f_ .node circle,#chatgpt-mermaid-_r_23f_ .node ellipse,#chatgpt-mermaid-_r_23f_ .node polygon,#chatgpt-mermaid-_r_23f_ .node path{fill:rgb(9, 23, 44);stroke:rgb(31, 78, 148);stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .rough-node .label text,#chatgpt-mermaid-_r_23f_ .node .label text,#chatgpt-mermaid-_r_23f_ .image-shape .label,#chatgpt-mermaid-_r_23f_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-_r_23f_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .rough-node .label,#chatgpt-mermaid-_r_23f_ .node .label,#chatgpt-mermaid-_r_23f_ .image-shape .label,#chatgpt-mermaid-_r_23f_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-_r_23f_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-_r_23f_ .root .anchor path{fill:rgb(175, 175, 175)!important;stroke-width:0;stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_23f_ .arrowheadPath{fill:rgb(175, 175, 175);}#chatgpt-mermaid-_r_23f_ .edgePath .path{stroke:rgb(175, 175, 175);stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .flowchart-link{stroke:rgb(175, 175, 175);fill:none;}#chatgpt-mermaid-_r_23f_ .edgeLabel{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-_r_23f_ .edgeLabel p{background-color:rgb(0, 0, 0);}#chatgpt-mermaid-_r_23f_ .edgeLabel rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-_r_23f_ .labelBkg{background-color:rgba(0, 0, 0, 0.5);}#chatgpt-mermaid-_r_23f_ .cluster rect{fill:rgb(48, 48, 48);stroke:rgba(255, 255, 255, 0.15);stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .cluster text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ .cluster span{color:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(48, 48, 48);border:1px solid rgba(255, 255, 255, 0.15);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-_r_23f_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(237, 237, 237);}#chatgpt-mermaid-_r_23f_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-_r_23f_ .icon-shape,#chatgpt-mermaid-_r_23f_ .image-shape{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-_r_23f_ .icon-shape p,#chatgpt-mermaid-_r_23f_ .image-shape p{background-color:rgb(0, 0, 0);padding:2px;}#chatgpt-mermaid-_r_23f_ .icon-shape .label rect,#chatgpt-mermaid-_r_23f_ .image-shape .label rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-_r_23f_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-_r_23f_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-_r_23f_ .node .neo-node{stroke:rgb(31, 78, 148);}#chatgpt-mermaid-_r_23f_ [data-look="neo"].node rect,#chatgpt-mermaid-_r_23f_ [data-look="neo"].cluster rect,#chatgpt-mermaid-_r_23f_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-_r_23f_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_23f_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-_r_23f_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-_r_23f_-gradient);stroke-width:1px;}#chatgpt-mermaid-_r_23f_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_23f_ [data-look="neo"].node .neo-line path{stroke:rgb(31, 78, 148);filter:none;}#chatgpt-mermaid-_r_23f_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-_r_23f_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_23f_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-_r_23f_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-_r_23f_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_23f_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-_r_23f_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-_r_23f_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(153, 206, 255);}#chatgpt-mermaid-_r_23f_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(153, 206, 255);}#chatgpt-mermaid-_r_23f_ .node tspan[font-weight="normal"],#chatgpt-mermaid-_r_23f_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-_r_23f_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .node rect,#chatgpt-mermaid-_r_23f_ .node circle,#chatgpt-mermaid-_r_23f_ .node ellipse,#chatgpt-mermaid-_r_23f_ .node polygon,#chatgpt-mermaid-_r_23f_ .node path{fill:rgb(0, 40, 77);stroke:rgba(255, 255, 255, 0.1);stroke-width:1px;}#chatgpt-mermaid-_r_23f_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-_r_23f_ .node.mermaid-decision .label-container{fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-dasharray:2,2;}#chatgpt-mermaid-_r_23f_ .edgePaths .flowchart-link{stroke:rgb(175, 175, 175);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-_r_23f_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-_r_23f_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}New alert receivedNormalize + deduplicateMatch asset and correlateRequires investigation?Store / aggregate / digestCreate investigation jobAI plans bounded queriesPolicy validates tool callsRetrieve Wazuh / Snort / Loki /metricsAssemble evidence timelineEvidence sufficient?Findings + uncertainty +recommended actionsIncident policy engineNotify / create case / requestapprovalNoYesNo, within budgetYes or budget reached





There are four critical implementation requirements.
First, put correlation before the AI. Match on asset identity, source IP, authentication account, event category and a bounded time window. The LLM should help interpret correlated evidence, not be the only correlation mechanism.
Second, budget every investigation. For example, no more than 12 tool calls, 60 seconds of execution time, and a fixed token budget for an ordinary event. High-severity incidents can have a separate budget.
Third, defend against prompt injection in logs and alerts. Treat every retrieved log line, email, URL and artifact result as untrusted content, never as instructions. Strict tool schemas, output sanitization, source references and the external policy layer are mandatory.
Fourth, always report uncertainty. A malicious IP reputation match and failed SSH attempts do not by themselves prove compromise. The system should distinguish observed facts from plausible explanations.
11. Detailed implementation roadmap

Phase 1 — Foundation and authentication
Estimated 1–2 weeks
Build Next.js, FastAPI, PostgreSQL, Redis, container networking, Keycloak authentication, roles, integration health checks, backend tests, and the initial admin dashboard.
Acceptance: Enforcer can sign in, see services, and query backend health without exposing service credentials to the browser.




Phase 2 — Wazuh and asset intelligence
Estimated 1–2 weeks
Connect Wazuh Manager API and Indexer, import agents, normalize alerts, map asset identifiers, create incident detail pages and link to original Wazuh documents.
Acceptance: Open a Wazuh alert from AEGIS, view original evidence, and navigate to the affected asset.




Phase 3 — All telemetry integrations
Estimated 2–3 weeks
Integrate Snort 3 JSON, Zeek, open-appsec, Loki, Grafana webhooks, Prometheus and Netdata. Build a cross-engine event timeline and reconcile asset identities.
Acceptance: An authorized test sequence appears in one timeline with correct timestamps, sources and targets.




Phase 4 — AI SOC Analyst
Estimated 2–3 weeks
Implement model serving, tool registry, evidence search, investigation state machines, risk assessment, incident prioritization, threat intelligence and structured reports.
Acceptance: Replay known incidents and verify that the AI identifies relevant evidence, makes no unsupported claims, and stays within tool-call limits.




Phase 5 — Enforcer Console and communications
Estimated 1–2 weeks
Add natural-language investigations, follow-up questions, case notes, Jira issue management, Slack threads, Gmail reports, alert subscriptions and notification controls.
Acceptance: A critical incident results in one traceable case with correctly linked communications, rather than repeated independent emails.




Phase 6 — DFIR and approved enforcement
Estimated 2–3 weeks
Connect Velociraptor, build approval queues, action validation, scoped service credentials, audited execution, dry-run capability, rollback procedures and incident response playbooks.
Acceptance: An Enforcer can approve a limited test action; unauthorized, expired or duplicated actions are rejected.




Phase 7 — Production hardening and advanced intelligence
Estimated 2–4 weeks
Add retention policies, performance tests, HA planning, prompt-injection tests, evaluation datasets, operational dashboards, compliance exports and backup/restore exercises.
Acceptance: The system remains useful under an event burst and fails safely when a model, integration, or worker is unavailable.



These are planning estimates for a focused implementation, not guaranteed deadlines. An initial working demonstration can be delivered substantially earlier by limiting scope to Wazuh, Snort, Loki, an AI investigation worker and the Enforcer UI.
12. Advanced features worth building
After the core system is stable, these features would make AEGIS substantially more capable.









Attack-path reconstruction
Correlate network detections, authentication activity and process events to reconstruct a possible sequence of attack steps. Display observed and inferred connections differently.












Live geospatial threat visualization
Use existing Wazuh GeoLocation enrichment and Snort source addresses to display attack origins, affected assets, alert frequency and detection categories.












AI-guided digital forensics
Use Velociraptor evidence to explain suspicious processes, persistence mechanisms, executable files and relationships between endpoint activity and network detections.












Behavioral baselining and adaptive prioritization
Learn normal activity levels by asset and time period. Use statistical anomaly detection and transparent rule-based scores before adding more complex ML models.



I would also add an AI-generated daily SOC handover, a detection-rule recommendation workflow, MITRE ATT&CK coverage mapping, a searchable knowledge base of previous investigations, and replay testing using historical incident data.
13. Practical first deployment on your infrastructure
Use the central observability server (172.16.3.201) initially, provided it has enough remaining memory and CPU capacity. Keep AEGIS separate from the existing monitoring Compose stack so it can be restarted and upgraded independently.
Before installing anything, inventory the available resources:
hostname -I
free -h
df -h /
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'


Then create the project:
sudo mkdir -p /opt/aegis
sudo chown "$USER:$USER" /opt/aegis
cd /opt/aegis

mkdir -p apps/api apps/web services integrations infrastructure tests


Start with PostgreSQL and Redis:
# /opt/aegis/compose.yaml

services:
  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: aegis
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - aegis_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aegis -d aegis"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - aegis_redis:/data

secrets:
  db_password:
    file: ./secrets/db_password

volumes:
  aegis_db:
  aegis_redis:


Create a unique password locally without pasting it into this chat:
cd /opt/aegis
mkdir -p secrets
chmod 700 secrets
openssl rand -base64 36 > secrets/db_password
chmod 600 secrets/db_password

docker compose up -d
docker compose ps


This establishes the two backing services. The next task is to containerize FastAPI, implement database migrations, configure authentication, and expose a private health endpoint through your reverse proxy. Don't expose the database or Redis ports publicly.
Build the first backend API
I would define these endpoints first:
GET  /api/v1/health
GET  /api/v1/integrations
GET  /api/v1/assets
GET  /api/v1/assets/{id}
GET  /api/v1/events
GET  /api/v1/incidents
GET  /api/v1/incidents/{id}

POST /api/v1/investigations
GET  /api/v1/investigations/{id}
POST /api/v1/incidents/{id}/actions/propose

GET  /api/v1/approvals
POST /api/v1/approvals/{id}/decision

GET  /api/v1/audit


All endpoints except a minimal health endpoint should require authentication and authorization. Use /api/v1 versioning from the beginning.
Once these are built, integrate sources in this sequence:
Wazuh Indexer
    ↓
Snort 3 JSON
    ↓
Loki
    ↓
Prometheus
    ↓
Grafana webhook
    ↓
AI investigation worker
    ↓
Slack + Jira + Gmail
    ↓
Velociraptor
    ↓
Approved response


14. Test it before trusting it
I would create a repeatable test suite with these scenarios and explicit expected outcomes.
Test scenario	What AEGIS must demonstrate
50 routine CVE findings	Group into inventory reporting; no attack-alert email flood
Repeated SSH failures	Group detections and identify affected assets
SSH success after failures	Investigate whether authentication was authorized; do not automatically declare compromise
Snort + WAF evidence	Match compatible asset/IP/time details, and avoid false correlations
CPU spike during suspicious activity	Query metrics and logs; describe correlation without assuming causation
False-positive detection	Accept Enforcer feedback and preserve its reasoning and evidence
Malicious instruction embedded in a log	Treat it as data; refuse unauthorized tool execution
Unauthorized isolation request	Deny the request and record the attempt
Slack or Gmail integration unavailable	Queue retries with backoff; do not lose or multiply incidents
For evaluation, track precision of incident grouping, false-positive escalation rate, analyst time saved, evidence citation accuracy, mean time to detect, mean time to acknowledge, and mean time to respond.
One critical rule: if the AI is unavailable, the deterministic alerting and detection pipeline must keep working. Security monitoring cannot depend entirely on an LLM.
15. Recommended development milestones
Implementation checklist
Track your build progress locally
0/12



1. Infrastructure
[ ] PostgreSQL and Redis running
[ ] FastAPI and Next.js deployed
[ ] Authentication and audit logging


2. Security integrations
[ ] Wazuh alerts and assets
[ ] Snort and WAF event ingestion
[ ] Loki and Prometheus query adapters


3. AI SOC
[ ] Correlation engine
[ ] Evidence-backed AI investigation
[ ] Enforcer conversational console


4. Workflows
[ ] Slack, Jira and Gmail connectors
[ ] Incident deduplication and notification policy
[ ] Human approvals and response executor


My recommended first deliverable
Do not attempt the entire autonomous SOC immediately. Build a working AEGIS v0.1 that achieves these four outcomes:
1. Pull Wazuh and Snort alerts and show them in one interface.
2. Allow the Enforcer to ask the AI about a host, IP, incident, or time range.
3. Require the AI to retrieve real evidence and produce a source-linked investigation summary.
4. Create one structured incident, with a draft or policy-authorized Slack, Jira, or Gmail notification.
That will prove the most difficult architectural assumption: whether the AI can reliably investigate across different security engines without confusing unrelated events.
After that, connect Velociraptor, add investigation playbooks, introduce carefully controlled response actions, and progressively strengthen the system into an AI-assisted SOC capable of 24/7 operations.
One architectural decision to make before coding: I would use a hybrid AI model approach — a local model for routine classification and privacy-sensitive summaries, with an optional more capable external model for difficult investigations after applying data minimization and redaction. This keeps infrastructure costs and exposure of sensitive telemetry under control while preserving room for more advanced reasoning.
The end state is exactly your intended division of responsibilities: AI operates the analytical SOC workflow; the human Enforcer retains authority over consequential security actions.