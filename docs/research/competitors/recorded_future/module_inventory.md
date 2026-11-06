# Recorded Future — Complete Module Inventory

**Reference:** `TTI-DOC-RES-003-RF-02`  
**Target Platform:** Recorded Future Intelligence Cloud  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Module Inventory Table

| Module Group | Primary Purpose | Documented Inputs / Search Syntax | Key Outputs & Detail Views | Collection Sources | StealthMole Overlap | TTI Relevance (Proposed, Not Approved) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Threat Intelligence** | Profiling cyber adversaries, malware families, campaigns, and TTPs. | Advanced search queries, entity handles, CVEs, IP/CIDR, MITRE ATT&CK IDs. | Threat Actor Intelligence Cards, TTP matrix, timeline view, Insikt reports. | Dark web, Tor, Telegram, technical sensors, malware sandboxes. | Corresponds to Darkweb Tracker PRO + Telegram Tracker. | [TTI-PROPOSED] Threat actor dossier modeling and MITRE ATT&CK association. |
| **Identity Intelligence** | Detecting corporate and VIP credentials leaked via stealer malware and breach dumps. | Corporate email domains, specific email addresses, employee IDs. | Leaked credential tables (AS IS credentials, device telemetry, infection date). | Infostealer logs (RedLine, Lumma, Vidar), combo dumps, Telegram channels. | Direct overlap with Compromised Data Set, Combo Binder, Credential Lookout, ULP Binder. | [TTI-PROPOSED] Unified credential exposure model with stealer attribution. |
| **SecOps Intelligence** | Automated indicator triage, SIEM enrichment, and dynamic risk scoring. | Hashes (MD5, SHA-1, SHA-256), IP addresses, domain names, URLs. | Dynamic Risk Lists (CSV, JSON, STIX), Risk Rules triggered, evidence snippets. | Passive DNS, malware analysis feeds, open/dark web chatter. | Overlaps with IoC search and Indicators of Leakage. | [TTI-PROPOSED] Real-time indicator risk scoring and SOAR enrichment endpoints. |
| **Attack Surface Intelligence (ASI)** | Mapping external attack surfaces, exposed services, and shadow IT. | Organization domain, apex domains, ASN numbers. | External asset inventory, certificate expirations, exposed ports, cloud buckets. | Global internet port scanning, DNS telemetry, SSL certificate transparency logs. | No direct equivalent in StealthMole (StealthMole focuses on dark web). | Outside core TTI Phase 1/2 scope; monitor as potential future integration. |
| **Vulnerability Intelligence** | Prioritizing patch remediation by monitoring active exploitation chatter. | CVE identifiers, software vendor and product names. | Vulnerability Intelligence Cards, Real-time Risk Score, proof-of-concept links. | NVD, vendor advisories, exploit forums, Telegram proof drops. | StealthMole CVE indicator (`cve:`) overlaps; RF provides dedicated scoring. | [TTI-PROPOSED] CVE tagging in exploited Telegram software chatter. |
| **Brand Intelligence** | Monitoring executive impersonation, phishing, and domain typosquatting. | Brand names, executive executive names, trademark keywords. | Typosquatted domain lists, rogue social media accounts, takedown candidate flags. | Domain registrars, social platforms, dark-web marketplace listings. | Overlaps with Defacement Alert and Leaked Monitoring. | [TTI-PROPOSED] Phishing kit and domain spoofing chatter alerts on Telegram. |
| **Payment Fraud Intelligence** | Disruption of stolen card data, ATM skimmers, and financial attacks. | Bank Identification Numbers (BINs), credit card numbers, financial domains. | Exposed card inventories, underground shop listings, skimming campaign logs. | Underground carding shops, Telegram card dumps, skimming channels. | Overlaps with `creditcard:` indicator in StealthMole. | Financial sector candidate module for Phase 3/4. |

---

## 2. Deep Dive: Telegram Collection Mechanics in Recorded Future

Recorded Future’s ingestion of Telegram data differs fundamentally from pure messaging scrapers:

### 2.1 Sourcing & Ingestion Boundary
- Ingestion occurs via automated data harvesting pipelines complemented by the **Insikt Group** (`VERIFIED`, [Recorded Future Insikt Group](https://docs.recordedfuture.com/)).
- Recorded Future monitors hundreds of thousands of Telegram channels, focusing on cybercrime marketplaces, data leak mirrors, hacktivist collectives (e.g., Killnet, Anonymous affiliates), and initial access broker forums.
- **Natural Language Processing (NLP):** Ingested messages pass through entity extraction engines that identify mentioned CVEs, Bitcoin/Monero addresses, domain names, target companies, and personal handles in multiple languages (Russian, Chinese, Arabic, Persian, English, etc.).

### 2.2 Presentation Surface: Intelligence Cards vs. Raw Threads
- **Entity Extraction:** Rather than requiring analysts to scroll through hundreds of conversational chat logs, Recorded Future extracts key findings into **Intelligence Cards™** (`VERIFIED`).
- **Evidence Strings:** A hit on an entity (e.g., an IP or company name) presents an **Evidence Snippet** showing the exact Telegram message sentence, channel name, and timestamp.
- **Raw Thread Viewing Limitation:** While snippets and context messages are visible, Recorded Future is not optimized as a real-time conversational chat client; its primary paradigm is structured entity intelligence.

---

## 3. Deep Dive: Identity Intelligence vs. StealthMole Credential Suite

A critical architectural comparison between Recorded Future's Identity Intelligence and StealthMole’s 4 credential modules:

| Dimension | Recorded Future Identity Intelligence | StealthMole (CDS, CB, CL, UB) |
| :--- | :--- | :--- |
| **Module Structure** | **Unified single pane of glass** with faceted filtering (Stealer vs. Combo vs. Breach). | **Fragmented across 4 separate modules** (Compromised Data Set, Combo Binder, Credential Lookout, ULP Binder). |
| **API Availability** | Fully accessible via REST API (`/identity/` endpoints) and automated webhooks (`VERIFIED`). | Web UI only; bulk export restricted to Excel with per-page query consumption (`VERIFIED`). |
| **Alerting** | Continuous automated alerting to SIEM/Slack/Teams when corporate domains appear in stealer logs. | Daily email digest via MoleSight blocks; no native SIEM webhooks documented. |
| **Malware Telemetry** | Correlates victim device name, stealer family, infection date, and corporate email. | Captures deep host telemetry, path, victim IP/country, plus license-gated screenshots/webcam photos. |
