# Recorded Future — Workflows, APIs & Ecosystem Integrations

**Reference:** `TTI-DOC-RES-003-RF-03`  
**Target Platform:** Recorded Future Intelligence Cloud  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Core Analyst Workflows

### 1.1 Threat Actor Profiling & Campaign Tracking Workflow
1. **Trigger:** A cyber threat intelligence analyst investigates a new ransomware variant observed distributing data on Telegram.
2. **Search:** The analyst queries the actor's alias or ransomware brand in the Recorded Future search portal (`VERIFIED`, [Recorded Future Platform Docs](https://docs.recordedfuture.com/)).
3. **Card Inspection:** The system opens the **Threat Actor Intelligence Card™**, displaying:
   - Real-time Risk Score (e.g., 92/99, Very Malicious).
   - Documented TTPs mapped directly to the **MITRE ATT&CK®** framework.
   - Associated malware families, C2 IP addresses, and dark-web extortion sites.
   - Sighting Timeline showing historical spikes in chatter across dark forums and Telegram channels.
4. **Reference Drill-Down:** The analyst clicks an evidence reference to view the original Telegram post snippet, author ID, and channel metadata.
5. **Export & Sharing:** The analyst exports the threat package to a STIX 2.1 bundle or creates an automated alert watchlist for future actor mentions.

### 1.2 Automated SOC Alert Triage Workflow (SecOps)
1. **Trigger:** An internal SIEM (e.g., Splunk or Microsoft Sentinel) triggers an alert on an outbound connection to an unknown external IP address.
2. **Automated API Query:** The SIEM SOAR playbook automatically queries Recorded Future's Connect API (`GET /v2/ip/{ip_address}`) passing the `X-RFToken` header (`VERIFIED`).
3. **Contextual Enrichment:** Recorded Future returns a JSON response containing:
   - `risk.score`: 85 (High Risk).
   - `risk.rules`: "Historical C2 Controller", "Associated with Lumma Stealer Telegram Distribution".
   - `evidenceDetails`: Exact dates and underground sources where the IP was detected.
4. **Automated Containment:** If the risk score exceeds 80, the SOAR playbook immediately pushes the IP to the perimeter firewall blocklist and creates a high-priority ticket in ServiceNow without human delay.

---

## 2. API Architecture & Integration Ecosystem

Recorded Future provides one of the most mature API surfaces in the commercial threat intelligence market (`VERIFIED`, [Recorded Future API Documentation](https://docs.recordedfuture.com/)):

### 2.1 Connect API Specifications
- **Base URL:** `https://api.recordedfuture.com/v2/` (and specialized `/v3/` endpoints).
- **Authentication:** HTTP header `X-RFToken: <api_key>`.
- **Entitlement Scoping:** Access to specific API endpoints (e.g., `/identity/`, `/soar/`, `/threat/`) is strictly partitioned and gated by the organization's licensed module entitlements; an API key only authorizes endpoints corresponding to contracted subscriptions.
- **Primary Endpoints:**
  - `/soar/enrichment/ip`, `/soar/enrichment/domain`, `/soar/enrichment/hash`: Lightweight endpoints designed for sub-second SOAR enrichment.
  - `/threat/actor/{id}`: Detailed threat actor profiles, aliases, and associated infrastructure.
  - `/identity/leaked-credentials`: Programmatic querying of leaked credentials and info-stealer logs.
  - `/alert/search`: Programmatic retrieval of triggered alert digests.
  - `/stix/`: Export of indicators in STIX 2.1 JSON schemas.

### 2.2 Standardized Threat Intelligence Protocols (STIX / TAXII)
- Recorded Future natively operates a **TAXII 2.1 Server** (`VERIFIED`).
- Customers can subscribe to automated TAXII collections (e.g., *High Risk Hashes*, *Recent C2 Infrastructure*, *Ransomware Indicators*) directly into OpenCTI, MISP, or commercial TIPs (ThreatConnect, Anomali).

### 2.3 Pre-Built Technology Integrations
Recorded Future maintains certified enterprise apps and technical integrations across:
- **SIEM:** Splunk, Microsoft Sentinel, IBM QRadar, Google SecOps (Chronicle), Elastic.
- **SOAR:** Palo Alto Networks Cortex XSOAR, Splunk SOAR, Torq, Tines, Swimlane.
- **Endpoint (EDR/XDR):** CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne.
- **Link Analysis (Maltego):** Official Recorded Future transforms published on the **Maltego Transform Hub**, allowing analysts to pivot directly from Maltego graph entities into Recorded Future Intelligence Cards.

---

## 3. Key Architectural Lessons & Opportunities for TTI

1. **Headless Automation as a Core Requirement (`OPP-003`, PROPOSED, NOT APPROVED):** Recorded Future demonstrates that enterprise security teams do not want to live solely inside another web portal. Exposing strong REST endpoints (`/api/v1/`) and webhook streams in TTI is critical for enterprise adoption.
2. **Standardized CTI Formats (`OPP-007`, PROPOSED, NOT APPROVED):** Rather than outputting proprietary spreadsheets like StealthMole, TTI should evaluate providing native STIX 2.1 JSON outputs to allow seamless consumption by SIEMs and threat intelligence platforms.
3. **The Chat Thread Context Trade-off (`OPP-001`, PROPOSED, NOT APPROVED):** While Recorded Future excels at broad entity resolution, it extracts only structured snippets from Telegram. TTI has a unique niche in providing **deep chronological thread reconstruction**, allowing investigators to read the human conversational context behind the threat.
