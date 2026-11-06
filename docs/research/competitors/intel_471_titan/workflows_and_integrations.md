# Intel 471 (TITAN / Verity471) — Workflows, APIs & Ecosystem Integrations

**Reference:** `TTI-DOC-RES-003-I471-03`  
**Target Platform:** Intel 471 TITAN / Verity471  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Core Analyst Workflows

### 1.1 Automated Account Takeover (ATO) Prevention Workflow
1. **Continuous Stream:** The enterprise security team connects their Identity Management system (e.g., Okta or Microsoft Entra ID) to Intel 471's Credential Intelligence stream (`VERIFIED`, [Intel 471 Credential Intelligence](https://intel471.com/)).
2. **Detection Event:** Intel 471's stealer pipeline parses an exfiltrated Lumma Stealer log; an entry matches `user@corporate-domain.com`.
3. **Webhook Trigger:** Intel 471 issues an automated webhook event containing:
   - Corporate login URL (`Host`).
   - Compromised username and plaintext password (AS IS).
   - Timestamp of infection and victim egress IP.
4. **Automated Remediative Action:** The SOAR playbook instantly:
   - Revokes all active Okta session tokens for the affected user.
   - Enforces an immediate password reset on next login.
   - Quarantines the user's registered laptop in EDR pending malware scanning.

### 1.2 Adversary Tracking & Extortion Threat Workflow
1. **Trigger:** A threat actor publishes an extortion announcement in a vetted cybercrime channel.
2. **Actor Profiling:** The analyst queries the actor's alias in the Verity471 portal.
3. **Dossier Review:** The portal returns the actor dossier, mapping:
   - Underground forum profiles across Exploit, XSS, and Telegram.
   - Known historical affiliations with ransomware syndicates.
   - Cryptocurrency wallet addresses used in previous extortion payouts.
4. **Mitigation:** The analyst exports the associated IOCs to their SIEM to detect internal scanning.

---

## 2. API Architecture & Developer Specifications

### 2.1 Modern Verity471 API Specifications
- **Base URL:** `https://api.intel471.cloud` (`VERIFIED`, [PyPI: verity471](https://pypi.org/project/verity471/)).
- **Authentication:** API Key passed via HTTP authorization headers.
- **Core Stream Endpoints:**
  - `GET /integrations/actors/v1/actors/stream`: Continuous stream of newly updated adversary profiles, forum aliases, and handles.
  - `GET /integrations/indicators/v1/indicators/stream`: High-velocity stream of newly discovered IOCs, hashes, and network infrastructure.
  - `GET /integrations/watchers/v1/alerts/stream`: Automated watcher alerts triggered by keyword and brand monitoring.
  - `GET /integrations/credentials/v1/credentials`: Queryable stealer log credential database.
- **Official Modern Python Client:** `verity471` package on PyPI (`intel471/verity471-python`).

### 2.2 Legacy TITAN REST API Specifications (Discontinuation Target)
- **Base URL:** `https://api.intel471.com/v1` (`VERIFIED`, [GitHub: titan-client-python](https://github.com/intel471/titan-client-python)).
- **Authentication:** API Key passed in request headers alongside registered user email (`api-key`, `user-email`).
- **Core Endpoints:**
  - `GET /indicators`: Retrieve tactical threat indicators and malware objects.
  - `GET /indicators/stream`: Continuous chunked stream of newly discovered indicators.
  - `GET /iocs`: Structured IOC packages with associated threat report context.
  - `GET /yara`: Download curated YARA detection signatures for active malware families.
  - `GET /cve/reports` and `GET /cve/reports/{uid}`: Vulnerability intelligence dossiers.

### 2.3 Official SDKs & Open-Source Utilities
- **`verity471` (Active):** Modern official Python library supporting `api.intel471.cloud` stream consumption.
- **`intel471/titan-client-python` (Deprecated):** Legacy OpenAPI-generated Python client providing bindings for v1 TITAN endpoints.
- **`intel471/titan-stix`:** Open-source utility converting Intel 471 indicator feeds into standardized **STIX 2.1 JSON bundles**.

---

## 3. Technology Partner Integrations

Intel 471 maintains certified commercial integrations across the enterprise security stack:
- **SIEM & SecOps:** Google SecOps (Chronicle), Microsoft Sentinel, Splunk, IBM QRadar.
- **AI Copilots:** Microsoft Security Copilot (enriching natural language prompt queries with underground threat actor intelligence).
- **SOAR:** Palo Alto Networks Cortex XSOAR, Torq, Tines, Splunk SOAR.
- **Threat Intelligence Platforms (TIP):** ThreatConnect, Anomali, OpenCTI, MISP.
- **Link Analysis:** Official **Intel 471 Transforms** available on the Maltego Transform Hub.

---

## 4. Key Architectural Lessons for TTI

1. **Streaming Ingestion Architecture (`OPP-001`, PROPOSED, NOT APPROVED):** Intel 471’s `/indicators/stream` proves that modern enterprise CTI architectures favor continuous chunked streaming over batch polling. TTI should evaluate providing streaming endpoints (SSE / WebSockets) for high-priority Telegram threat alerts.
2. **Decoupled API Versioning:** The deprecation of TITAN in favor of Verity471 highlights that TTI must maintain strict API versioning (`/api/v1/`, `/api/v2/`) with backward-compatible schemas to avoid breaking client automations.
3. **Automated Credential Revocation Focus:** Positioning credential data for automated identity remediation (Okta/Active Directory) rather than mere visual inspection provides high enterprise ROI.
