# Cross-Platform Competitor Comparison Matrix (All 5 Platforms)

**Reference:** `TTI-DOC-RES-003-COMP`  
**Status:** Comprehensive Comparative Analysis (Audited Baseline)  
**Date:** 2026-10-28  
**Platforms Compared:**
1. **StealthMole** (v3.3 Baseline; Primary Manual Audit `TTI-DOC-RES-002`)
2. **Recorded Future** (Intelligence Cloud / Intelligence Graph®)
3. **Maltego** (Maltego Graph / Maltego Evidence / Transform Hub)
4. **Intel 471** (TITAN Cyber Intelligence Platform / Verity471)
5. **ShadowDragon** (Horizon® / SocialNet® / MalNet™)

---

## 1. Master Cross-Platform Architectural Matrix

| Architectural Dimension | StealthMole (v3.3 Baseline) | Recorded Future | Maltego | Intel 471 (TITAN / Verity) | ShadowDragon (Horizon / SocialNet) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Platform Philosophy** | Closed CTI search portal with 14 specialized query tables and visual canvas. | Automated internet-scale CTI knowledge graph with real-time risk scores. | Analytical link-analysis and visualization engine powered by external transforms. | Adversary-centric CTI fusing automated bots with undercover HUMINT specialists. | OSINT identity resolution and footprint mapping across hundreds of platforms and 140+ jurisdictions. |
| **Telegram Ingestion Model** | Sourced via OSINT specialists; 1 query consumed per 10 msgs scrolled (`Slide 51`). | Automated harvesting + Insikt research; entities extracted to Intelligence Cards. | No native crawler; queries executed on demand via partner transforms. | Infiltration of closed/vetted cybercrime groups by undercover specialists. | Ingestion of public/semi-public channels and profiles for alias attribution. |
| **Search & Query Grammar** | 40+ indicators; Boolean capped at 3 `OR` and 5 total operators (`Slide 49`). | Advanced lucene-like search, entity lookups, rule filters, watchlists. | Entity-based transform execution, graph search, degree-of-separation filters. | Entity search (actor, handle, hash, IP, CVE) across structured portal feeds. | Search by handle, phone, email, avatar across hundreds of social networks, 140+ jurisdictions, and Telegram. |
| **Visual Link Graph Analysis** | Visual Canvas (`Slides 8–9`): Physics, Hierarchical, Preset layouts; custom edges. | Visual link analysis in portal; official transforms on Maltego Transform Hub. | Industry-standard graph engine: Organic, Circular, Hierarchical layouts (`.mtgx`). | Dedicated actor network mapping; official transforms on Maltego Transform Hub. | Horizon Investigate: Interactive node-link graph with temporal event timeline. |
| **Geospatial Mapping** | Dark Map (`Slides 10–11`): Geocoded layers (IP, Image, Telegram), radius query. | Geopolitical intelligence mapping; physical threat event clustering. | OpenStreetMap plotting via transforms; geofenced monitoring in Maltego Monitor. | Geocoding of victim infrastructure and threat actor geographical hubs. | Horizon Map: Integrated geographic plotting of social and threat observables. |
| **Credential / Stealer Intelligence** | 4 separate modules (CDS, CB, CL, UB); reverse `password:` search; Excel export. | Unified Identity Intelligence module; automated API alerts for corporate domains. | Queries third-party breach/combo transforms (HaveIBeenPwned, Social Links). | Credential Intelligence: Real-time `/indicators/stream` feed of infostealer logs. | Cross-references email and handles against historical leak and paste dumps. |
| **Incident & Extortion Monitoring** | 4 feeds: Ransomware, Leaked, Government, Defacement (`AI Verified`). | Threat Intelligence tracking ransomware blogs, extortion sites, and proof drops. | Monitored via third-party transform feeds and Maltego Monitor alerts. | Deep tracking of ransomware negotiation portals, extortion cartels, and proofs. | Horizon Monitor: Continuous keyword monitoring across social and dark feeds. |
| **Programmatic API Availability** | *Not documented in User Manual v3.3*; web portal and Excel exports only. | Connect API (REST `/v2/`, `/v3/`) via `X-RFToken`; STIX 2.1 / TAXII 2.1 server. | Extensible Python SDK (`maltego-trx`); Transform Server API. | Verity471 API (`api.intel471.cloud`, `verity471` SDK); legacy TITAN (`api.intel471.com/v1`). | Programmatic REST APIs for SocialNet and MalNet (Customer Portal gated). |
| **Authentication & SSO** | Email/Password + OTP 2FA (`Slide 2`); SAML SSO *Not documented in manual*. | Enterprise SAML 2.0 (Okta, Entra ID, Ping), SCIM 2.0 provisioning. | Desktop activation keys; SAML 2.0 SSO in Enterprise / Web editions. | Enterprise SAML 2.0 (Okta, Microsoft Entra ID), MFA enforced. | Enterprise SAML 2.0 Single Sign-On across major enterprise IdPs. |
| **Forensic Evidence Standards** | HTML/text snapshots, canvas screenshots; cryptographic hashing *Not documented*. | Intelligence Cards, evidence string snippets; cryptographic hashing *Not documented*. | **Hunchly & Maltego Evidence:** Hunchly automated SHA-256 web capture; Maltego Evidence structured social harvesting. | Sanitized raw transcripts, structured IOC packages; court-ready exports. | CJIS-aligned tamper-evident audit logs and court-ready chronological case reports. |
| **Licensing & Metering Model** | Monthly query quota; micro-metered on scrolls, clicks, and Excel exports (`Slide 50–52`). | Annual enterprise contract based on licensed modules and API seats; unmetered scroll. | Desktop license tiers (CE 10k nodes; Pro/Enterprise uncapped) + Transform credits. | Annual enterprise subscription based on intelligence modules and API streams. | Tiered annual subscription for Horizon, SocialNet, and MalNet. |

---

## 2. Synthesis of Market Capabilities

### 2.1 Common Market Capabilities (Table Stakes)
All evaluated commercial threat intelligence and investigation platforms provide:
1. **Multi-Source Indicator Resolution:** Ability to pivot from an IP address, domain name, or file hash to related threat infrastructure.
2. **Visual Relationship Mapping:** Interactive node-and-edge link graphing connecting observables and threat actors.
3. **Infostealer & Compromised Credential Awareness:** Ingestion of malware exfiltration logs (RedLine, Lumma, Vidar) to identify exposed corporate accounts.
4. **Adversary & Ransomware Cartel Surveillance:** Tracking of extortion leak blogs, ransomware announcements, and proof links.
5. **Role-Based Access Control (RBAC):** Multi-tiered user permissions isolating administrative controls from standard analyst queries.

### 2.2 Distinctive Documented Capabilities by Platform
- **StealthMole:** Granular stealer log forensics (NetBIOS computer name, stealer malware path on victim disk), license-gated webcam/screenshot downloads, and direct reverse password searching (`password:<value>`).
- **Recorded Future:** Massive automated knowledge graph (Intelligence Graph®), real-time dynamic Risk Scores (0–99), native TAXII 2.1 server, and mature SOAR integrations.
- **Maltego:** The definitive open transform ecosystem, local Python transform development (`maltego-trx`), `.mtgx` case containers, court-ready cryptographic capture in **Hunchly** (SHA-256 + timestamps), and deep social network harvesting in **Maltego Evidence** (SNH Classic).
- **Intel 471:** Elite underground human infiltration (HUMINT), access to vetted/invite-only cybercrime syndicates, real-time chunked streaming API (`/indicators/stream`), and curated YARA signature packages.
- **ShadowDragon:** Deep cross-platform identity resolution across hundreds of social networks and 140+ jurisdictional corporate registries, linking pseudonymous Telegram `@aliases` to real-world developer or gaming profiles.

---

## 3. Register of Unresolved Market Unknowns

The audit identified several technical areas that remain **UNKNOWN / NOT DOCUMENTED IN PUBLIC SOURCES** across the commercial market:
1. **Telegram Ingestion Fleet Architecture:** No vendor publicly discloses the exact technical architecture of their Telegram collection backbone (e.g., MTProto client pools, automated phone number provisioning, session rotation algorithms, or residential proxy topologies).
2. **Real-Time Voice Message Transcription:** While text NLP, OCR, and AI image captioning are documented across vendors, automated real-time speech-to-text transcription of Telegram voice notes is not documented in standard commercial product tiers.
3. **Handling of Deleted / Edited Messages:** How vendors reconcile message edits or deletions executed by threat actors in Telegram channels (whether revisions are permanently preserved in historical audit ledgers) is proprietary and undisclosed.

---

## 4. TTI Candidate Architectural Opportunities (Proposed, Not Approved)

The cross-platform analysis reveals six distinct strategic opportunities for **Telegram Threat Intelligence (TTI)** (`STATUS: PROPOSED, NOT APPROVED`):

```
+----------------------------------------------------------------------------------------------------+
|                                  TTI STRATEGIC ARCHITECTURAL NICHES                                |
+--------------------------+-----------------------+-------------------------------------------------+
| Proposed Feature         | Target Subsystem      | Market Justification & Strategic Differentiator |
+--------------------------+-----------------------+-------------------------------------------------+
| OPP-001: Thread Viewer   | connectors/telegram/  | Rejects StealthMole's scroll penalty (1/10 msgs)|
| OPP-002: AST Bool Parser | app/api/              | Breaks StealthMole's 3-OR / 5-operator ceiling  |
| OPP-003: OpenAPI + Hooks | app/api/v1/           | Exposes REST/webhooks absent in StealthMole     |
| OPP-006: Forensic Ledger | app/evidence/         | Matches Hunchly/Evidence SHA-256 legal hashing  |
| OPP-007: STIX/MISP Export| app/reports/          | Replaces Excel-only dumps with CTI JSON bundles |
| OPP-008: Dual-Tier OCR   | app/ai/               | Extracts text/credentials from image drops      |
+--------------------------+-----------------------+-------------------------------------------------+
```

1. **Continuous Chronological Thread Navigation (`OPP-001`):** While Recorded Future and Intel 471 extract structured entity snippets and StealthMole penalizes chat scrolling (1 query per 10 messages), TTI can specialize in smooth, sliding-window thread reconstruction allowing analysts to read full conversational narratives without micro-metering.
2. **Recursive AST Boolean Engine (`OPP-002`):** Provide an unconstrained, deeply nested Boolean search parser (`((A OR B) AND (C NOT D))`) overcoming StealthMole's 3-OR limit.
3. **Headless Automation & Webhook Dispatch (`OPP-003`):** Deliver first-class OpenAPI 3.1 REST endpoints and webhook event dispatchers from Phase 1, closing the automation gap observed in traditional closed portals.
4. **Cryptographic Chain of Custody (`OPP-006`):** Emulate Hunchly and Maltego Evidence by hashing every raw ingested Telegram message, media file, and exported dossier with SHA-256 and RFC 3161 timestamps, creating legally defensible evidence records.
5. **Standardized CTI Exports (`OPP-007`):** Complement CSV/Excel exports with STIX 2.1 JSON and MISP formats to enable direct ingestion into enterprise SIEMs and Threat Intelligence Platforms.
6. **Dual-Tier OCR & Multimodal Analysis (`OPP-008`):** Implement local Tesseract OCR as Tier 1 for text extraction from screenshot dumps, reserving multimodal vision LLMs for high-priority triage candidates.

---

## 5. Universal Security & Legal Imperatives (Independent of Competitors)

Regardless of competitor capabilities, TTI must adhere to strict non-negotiable security and legal boundaries:
1. **Non-Interception of Secret Chats:** Collection must strictly target public broadcast channels, open supergroups, and semi-public forums. End-to-end encrypted (E2EE) private Telegram Secret Chats must never be intercepted.
2. **Sanctions & Anti-Bribery Compliance (OFAC):** TTI must not implement automated features facilitating ransomware negotiations, cryptocurrency transfers, or purchasing stolen IP from sanctioned threat actors.
3. **Data Protection & PII Redaction (GDPR):** Ingesting stealer logs containing personal passwords requires strict tenant isolation, encrypted-at-rest storage (AES-256), and automated export redaction controls.
