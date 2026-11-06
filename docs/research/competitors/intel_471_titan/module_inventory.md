# Intel 471 (TITAN / Verity471) — Complete Module Inventory

**Reference:** `TTI-DOC-RES-003-I471-02`  
**Target Platform:** Intel 471 TITAN / Verity471  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Module Inventory Table

| Module Name | Core Purpose | Supported Inputs & Filters | Key Outputs & Detail Views | Data Sourcing | StealthMole Overlap | TTI Relevance (Proposed, Not Approved) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Adversary Intelligence** | Profiling cybercriminal actors, extortion cartels, and initial access brokers. | Actor handle, forum identity, keyword, threat group name, Telegram handle. | Detailed actor dossier, historical forum posts, chat snippets, TTPs. | Closed underground forums (XSS, Exploit), Telegram channels, dark-web sites. | Direct overlap with Telegram Tracker, Darkweb Tracker PRO, and Leaked Monitoring. | [TTI-PROPOSED] Threat actor tracking and cross-platform handle correlation. |
| **Credential Intelligence** | Monitoring compromised credentials from stealer malware to prevent ATO. | Corporate domain, email address, victim IP/country, temporal window. | Compromised host URL, login email, plaintext password AS IS, stealer family, infection date. | Infostealer malware exfiltration logs, botnet dumps, underground credential shops. | Direct overlap with Compromised Data Set, Combo Binder, and ULP Binder. | [TTI-PROPOSED] Unified credential exposure model with automated SIEM alerting. |
| **Malware Intelligence** | Tracking weaponized malware families, active C2s, and YARA rules. | Malware family (Lumma, RedLine), file hash (MD5, SHA-256), IP, domain. | Real-time C2 IP stream, configuration files, YARA signatures, IOC packages. | Malware detonation sandboxes, decrypted C2 network configs, underground chatter. | Overlaps with StealthMole `malware:`, `hash:`, and `ioc:` indicators. | [TTI-PROPOSED] Malware family tagging for Telegram-distributed payloads. |
| **Vulnerability Intelligence** | Risk-based prioritization of CVEs targeted by underground adversaries. | CVE identifier, affected software vendor, product name. | Exploit report, actor discussion threads, proof-of-concept archives. | Forum exploit broker auctions, Telegram proof drops, vulnerability feeds. | Overlaps with StealthMole `cve:` indicator. | [TTI-PROPOSED] CVE extraction from Telegram exploit discussions. |

---

## 2. Deep Dive: Telegram Collection Mechanics in Intel 471

Intel 471’s Telegram intelligence operations represent an elite tier of cyber underground monitoring (`VERIFIED`, [Google SecOps Intel 471 Integration](https://cloud.google.com/)):

### 2.1 Focus on Closed & Invite-Only Channels
- While standard scrapers harvest easily discoverable public broadcast channels, Intel 471 targets **private, vetted, and invite-only Telegram groups** where threat actors:
  - Negotiate ransomware payouts and auction corporate network access.
  - Sell stolen databases before they reach public leak blogs.
  - Recruit affiliates for malware distribution campaigns.
- **Undercover Operational Persona:** Infiltration of closed groups requires human intelligence specialists maintaining credible cybercriminal personas, bypassing bot-detection and vouching procedures.

### 2.2 Sighting & Threat Normalization
- Intel 471 normalizes ingested Telegram conversations into structured events:
  - Actor persona mapping (connecting a Telegram `@handle` to an underground forum username on Exploit or XSS).
  - IOC extraction (extracting victim IP, target domain, or crypto wallet).
  - Delivery via streaming API (`/indicators/stream`) or portal dashboards.

---

## 3. Deep Dive: Credential Intelligence vs. StealthMole

| Feature / Dimension | Intel 471 Credential Intelligence | StealthMole Credential Modules |
| :--- | :--- | :--- |
| **Streaming Ingestion** | Provides real-time streaming API (`/indicators/stream`) directly to SIEM/SOAR (`VERIFIED`). | Web portal search and manual Excel export; query deducted per exported page (`VERIFIED`). |
| **Data Normalization** | Single unified credential schema across stealer logs, botnets, and dumps. | Fragmented into 4 separate modules (CDS, CB, CL, UB). |
| **Malware Telemetry** | Correlates stealer malware family, infection timestamp, and C2 configuration. | Captures deep host telemetry (NetBIOS name, stealer path), plus license-gated screenshots/webcams. |
| **Automation Focus** | Designed for automated corporate credential revocation in Okta/Active Directory. | Designed for analyst visual inspection and case building. |
