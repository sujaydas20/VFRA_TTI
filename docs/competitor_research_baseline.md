# TTI — Competitor Research and Documentation Baseline

**Document Reference**: `TTI-DOC-RES-001`  
**Version**: 2.0.0 (Corrected Research Baseline)  
**Date of Audit & Correction**: 2026-10-28  
**Audit Status**: Gate 1 Baseline Review Completed  
**Primary Competitor Reference**: *StealthMole — User Manual v3.3* (December 2024 / March 2025; verified local file at `D:\StealthMole - User Manual v3.3.pdf`)

---

## 1. Executive Summary & Audit Purpose

This document establishes the official, source-backed competitor research baseline for **Telegram Threat Intelligence (TTI)**. It reviews the capabilities, workflows, data models, limitations, and evidence practices of five primary threat-intelligence platforms: **StealthMole**, **Recorded Future**, **Maltego**, **Intel 471 (TITAN)**, and **ShadowDragon (Horizon/SocialNet)**.

### Scope and Operating Boundaries
- **Research Only**: This baseline does not implement application features, activate live scraping connectors, or modify production environments.
- **Evidence-Grounded**: Every material claim is tagged with an evidentiary status and traceable source reference. Speculative competitor pricing, undocumented internal architectures, and premature performance claims are explicitly marked as *Unknown* or *Withdrawn*.
- **TTI Implementation Verifiability**: Statements regarding TTI are verified against actual codebase artifacts and automated tests in the local repository.

---

## 2. Technical Glossary

| Term | Definition |
| :--- | :--- |
| **CTI (Cyber Threat Intelligence)** | Evidence-based knowledge, context, indicators, and actionable insights about cybersecurity threats. |
| **OSINT (Open-Source Intelligence)** | Intelligence gathered from publicly accessible or commercially licensed public data. |
| **HUMINT (Human Intelligence)** | Intelligence gathered through human interactions, covert informant operations, or persona-based engagement in closed forums. |
| **IOC (Indicator of Compromise)** | Forensic artifact (hash, IP address, domain, URL) indicating a potential network breach or malicious activity. |
| **ULP (URL:Login:Password)** | Standardized credential tuple extracted from victim machines by info-stealer malware (e.g., RedLine, Lumma, Racoon, Vidar). |
| **IAB (Initial Access Broker)** | Threat actor who compromises corporate networks (via VPN, RDP, stolen session tokens) and auctions access to ransomware affiliates. |
| **Link Analysis / Canvas** | An interactive graphical workspace where nodes and edges are dynamically arranged to model criminal networks. |
| **Transform** | In Maltego, a specific data-fetching script or API query that takes an input entity and returns related output entities. |
| **Defanging** | The process of modifying malicious indicators (e.g., changing `https://` to `hxxps://` or `defanged-javascript-blocked:`) to prevent accidental execution. |
| **Chain of Custody** | The chronological documentation showing the custody, control, transfer, analysis, and disposition of digital evidence to prevent repudiation. |

---

## 3. Platform & Module Inventory

### 3.1 StealthMole (Primary Reference: User Manual v3.3)
- **Vendor**: StealthMole Intelligence Pte. Ltd. (HQ: Singapore / R&D: South Korea)
- **Documented Platform Modules**:
  1. **Platform Core & Case Management**: Case creation (`CREATE NEW CASE`, `LOAD MY CASES`), case search, user statistics, query consumption accounting (*User Manual v3.3, pp. 3–5*).
  2. **Visual Canvas**: Graph interface supporting physics, hierarchical, and preset layouts; custom edge creation with labels; right-click context menu for cross-module pivoting (*User Manual v3.3, pp. 8–9*).
  3. **Dark Map**: Geospatial mapping plotting IP geolocation, leaked images with EXIF GPS, and Telegram channels/users with embedded GPS data; supports radius search `gps:lat,long,radius` (*User Manual v3.3, pp. 10–11*).
  4. **MoleSight**: Executive dashboard supporting customizable widgets, temporal filters, and email notification thresholds (*User Manual v3.3, pp. 12–14*).
  5. **Investigation Suite**:
     - *Darkweb Tracker PRO*: Deep & dark web indexing, HTML snapshots, source extraction, linked URLs (*User Manual v3.3, pp. 15–16*).
     - *Telegram Tracker*: Channel/group intelligence collected by OSINT specialists, image preview, full message thread viewer, AI image captioning (*User Manual v3.3, pp. 17–19*).
     - *Face Finder*: AI facial recognition image search across dark web and Telegram profile pictures with similarity percentages (*User Manual v3.3, pp. 20–22*).
     - *Indicators of Leakage (IoL)*: Incident-level data breach sets (*User Manual v3.3, pp. 23–24*).
  6. **Compromised Credential Search**:
     - *Compromised Data Set*: Host and URL search (*User Manual v3.3, pp. 25–27*).
     - *Combo Binder*: Leaked username/password combo search (*User Manual v3.3, pp. 28–30*).
     - *Credential Lookout*: Domain-level enterprise credential leak search with Excel export (*User Manual v3.3, pp. 31–33*).
     - *ULP Binder*: Stealer malware credential logs (`URL:Login:Password`) (*User Manual v3.3, pp. 34–36*).
  7. **Incident Monitoring**: *Ransomware Monitoring* (victim leak sites, *pp. 37–38*), *Leaked Monitoring* (private sector breaches, *pp. 39–40*), *Government Monitoring* (public sector breaches, *pp. 41–42*), and *Defacement Alert* (website defacements, *pp. 43–44*).
  8. **Search Indicators & Operators**: 40+ specific indicator prefixes (`tor:`, `i2p:`, `domain:`, `ip:`, `telegram:`, `telegram.user:`, `face:`, `gps:`, `ioc:`, `hash:`) and boolean operators (`AND`, `OR`, `NOT`, `site:`, `inurl:`) (*User Manual v3.3, pp. 45–49*).
  9. **Query Consumption System**: Granular per-action consumption model (1 query per keyword search, category select, detail view, pagination, and **1 query consumed per 10 messages scrolled** in chat threads) (*User Manual v3.3, pp. 50–52*).

---

### 3.2 Recorded Future (Intelligence Cloud)
- **Vendor**: Recorded Future, Inc. (Somerville, MA, USA / Mastercard)
- **Documented Modules & Capabilities**:
  1. *SecOps Intelligence*: Automated IOC enrichment, risk rules, and scoring algorithms.
  2. *Threat Intelligence*: Threat actor profiles, TTP mapping to MITRE ATT&CK, malware family tracking.
  3. *Identity Intelligence*: Compromised credential detection, session cookie auctions from stealer logs.
  4. *Geopolitical & Third-Party Risk*: Global physical/digital threat tracking, supply chain monitoring.
  5. *Underground & Messaging Monitor*: Automated natural language processing (NLP) indexing of open/semi-private Telegram channels, underground forums, and paste sites.

---

### 3.3 Maltego
- **Vendor**: Maltego Technologies GmbH (Munich, Germany)
- **Documented Modules & Capabilities**:
  1. *Graph Engine*: Desktop and web node-and-link visual analysis canvas supporting large-scale graph clustering.
  2. *Transform Hub*: Commercial and community data marketplace.
  3. *Maltego Monitor (formerly PublicSonar)*: Web-based social and messaging monitoring module. Requires linking an authorized Telegram account via phone number and SMS verification to monitor public channels and groups (`SRC-016`).
  4. *Maltego Evidence*: Forensic and social data collection module supporting phone number-based Telegram investigations (`SRC-018`).
  5. *Partner Transforms*: Third-party integrations (Gradient, WEB-IQ, SocialNet) supporting historical Telegram queries and entity pivots (`SRC-017`).

---

### 3.4 Intel 471 (TITAN Platform)
- **Vendor**: Intel 471 Inc. (Wilmington, DE, USA)
- **Documented Modules & Capabilities**:
  1. *Adversary Intelligence*: In-depth dossiers on cybercrime syndicates, threat actors, and forum leaders.
  2. *Credential Intelligence*: Ingested stealer logs, corporate account compromises, and breach dumps.
  3. *Malware Intelligence*: Malware-as-a-Service (MaaS) tracking, command-and-control (C2) telemetry.
  4. *Vulnerability Intelligence*: Exploit tracking and weaponization timelines.
  5. *Underground Messaging Telemetry*: Automated and human-vetted tracking of underground Telegram, Discord, and dark-web marketplace forums.

---

### 3.5 ShadowDragon (Horizon & SocialNet)
- **Vendor**: ShadowDragon LLC (Cheyenne, WY, USA)
- **Documented Modules & Capabilities**:
  1. *Horizon Investigate*: Centralized link-analysis and case mapping workbench.
  2. *Horizon Monitor*: Continuous automated watchlists for usernames, keywords, and digital infrastructure across 200+ sources including Telegram channels and groups (`SRC-019`).
  3. *SocialNet*: Identity resolution engine scanning 100+ social and chat networks to correlate aliases, profile photos, and account links.
  4. *Mallet*: Network and infrastructure mapping utility.

---

## 4. Competitor Feature Comparison Matrix (With Grounded Statuses)

### Evidentiary Status Taxonomy
- `[VERIFIED]`: Direct factual statement corroborated by official user manuals or product technical documentation.
- `[VENDOR-CLAIM]`: Supported by vendor official marketing or press statements; not independently verified in technical manuals.
- `[INFERENCE]`: Architectural or operational deduction derived from documented workflows.
- `[UNKNOWN]`: Information is proprietary, not publicly disclosed, or requires direct vendor inquiry.
- `[WITHDRAWN]`: Previously asserted claim found to be unsupported, speculative, or misleading during Gate 1 audit.

| Dimension | StealthMole (v3.3) | Recorded Future | Maltego | Intel 471 (TITAN) | ShadowDragon Horizon | TTI Implementation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary User Problem** | Dark-web threat tracing, credential leak detection, and facial profiling. `[VERIFIED - SRC-001]` | Enterprise threat risk reduction, IOC scoring, and attack surface monitoring. `[VERIFIED - SRC-010]` | Link-analysis, entity relationship discovery, and visual investigation. `[VERIFIED - SRC-011]` | Tracking organized cybercrime syndicates, IABs, and ransomware operators. `[VERIFIED - SRC-012]` | Cross-platform persona mapping, alias correlation, and digital footprinting. `[VERIFIED - SRC-013]` | Multi-tenant Telegram & underground thread intelligence and forensic investigation. `[PROPOSED REQUIREMENT]` |
| **Core Workflow** | Search indicator &rarr; result list &rarr; add to Canvas &rarr; right-click module pivot &rarr; Dark Map. `[VERIFIED - SRC-003]` | Automated watchlists &rarr; Alert generated &rarr; Risk Card drill-down &rarr; SOAR playbook trigger. `[VERIFIED - SRC-010]` | Seed entity &rarr; run Transform &rarr; graph expansion &rarr; entity clustering &rarr; report export. `[VERIFIED - SRC-011]` | Threat actor tracking &rarr; bulletin review &rarr; IOC/credential export &rarr; SIEM feed ingest. `[VERIFIED - SRC-012]` | Seed alias/phone &rarr; SocialNet multi-platform scan &rarr; visual link graph &rarr; monitoring alert. `[VERIFIED - SRC-013]` | Ingest thread &rarr; sanitize & defang &rarr; SHA-256 evidence store &rarr; thread viewer &rarr; IOC extraction. `[EXISTING SCAFFOLDING]` |
| **Input Types & Seeds** | 40+ indicators: `tor:`, `domain:`, `ip:`, `telegram:`, `face:`, `gps:`, `ioc:`, `hash:`. `[VERIFIED - SRC-007]` | Domain, IP, CIDR, Brand Name, CVE, Executive Name, Threat Actor Alias. `[VERIFIED - SRC-010]` | Email, Phone, Handle, Domain, IP, Crypto Wallet, File Hash, Custom Entity. `[VERIFIED - SRC-011]` | Company Domain, Threat Actor Alias, Malware Hash, CVE, Leaked Credentials. `[VERIFIED - SRC-012]` | Username/Alias, Email, Phone Number, Face Photo, Keyword. `[VERIFIED - SRC-013]` | Channel username, Thread ID, Keyword, IOC, File Hash, Tenant ID. `[EXISTING MODELS]` |
| **Output Formats** | Visual graph nodes, detail text, Excel credential dumps, HTML previews, Dark Map pins. `[VERIFIED - SRC-003]` | Structured Risk Cards, STIX/TAXII feeds, JSON API payloads, executive PDF summaries. `[VERIFIED - SRC-010]` | Graphical graph exports (PNG, PDF, GraphML), CSV/Excel tables, visual reports. `[VERIFIED - SRC-011]` | Threat bulletins, raw stealer logs, STIX/TAXII feeds, API JSON responses. `[VERIFIED - SRC-012]` | Visual network graphs, correlation dossiers, CSV/Excel entity lists. `[VERIFIED - SRC-013]` | Sanitized thread timelines, SHA-256 evidence archives, JSON REST API, React dashboard. `[EXISTING CODE]` |
| **Automation Level** | Semi-automated (crawlers + OSINT specialist curation); manual Canvas pivoting. `[VERIFIED - SRC-002]` | High automation (automated crawlers, ML/NLP text enrichment, continuous risk scoring). `[VENDOR-CLAIM - SRC-010]` | Semi-automated (manual transform invocation or automated transform machine scripts). `[VERIFIED - SRC-011]` | High human validation (HUMINT operatives infiltrating closed forums + automated scrapers). `[VENDOR-CLAIM - SRC-012]` | Automated entity pivoting across data sources with manual graph triage. `[VERIFIED - SRC-013]` | Deterministic automated ingestion & sanitization with mandatory human review flag. `[EXISTING CODE]` |
| **Integrations & APIs** | Documented manual exports (Excel); external REST API availability is not documented in User Manual v3.3. `[VERIFIED - SRC-001]` | Extensive REST APIs, SIEM/SOAR apps (Splunk, Sentinel, Cortex, QRadar). `[VERIFIED - SRC-010]` | Transform Hub, custom Python/Java Transforms, Maltego API, open-source plugins. `[VERIFIED - SRC-011]` | REST API, STIX/TAXII 2.1 feeds, SIEM integrations, SOAR connectors. `[VERIFIED - SRC-012]` | Maltego Transforms, Horizon REST API, Case Management integrations. `[VERIFIED - SRC-013]` | Modular Python connector interfaces (`BaseConnector`), REST API (`/api/v1`), Docker Compose. `[EXISTING CODE]` |
| **Commercial Pricing Model** | Pay-per-query model (1 query per search, detail click, and per 10 messages scrolled); subscription tiers. `[VERIFIED - SRC-008]` | Annual enterprise contract; specific public price tiers are opaque and custom-quoted. `[UNKNOWN / WITHDRAWN]` | Tiered pricing (Community Free, Professional, Enterprise); Transforms billed separately by providers. `[VERIFIED - SRC-011]` | Annual enterprise subscription; pricing is opaque and custom-quoted. `[UNKNOWN / WITHDRAWN]` | Commercial subscription; pricing is custom-quoted. `[UNKNOWN / WITHDRAWN]` | Commercial model undefined in Phase 1. `[UNRESOLVED DECISION]` |
| **Security & Multi-Tenancy** | Multi-tenant SaaS with user query accounting; underlying tenant data isolation architecture not publicly documented. `[UNKNOWN]` | Enterprise cloud multi-tenancy, SOC 2 Type II, ISO 27001, role-based access control. `[VENDOR-CLAIM - SRC-010]` | Desktop client caches data locally; server-side privacy depends on transform server setup. `[VERIFIED - SRC-011]` | Enterprise-grade access vetting, strict customer background checks, multi-tenant cloud. `[VENDOR-CLAIM - SRC-012]` | Lawful interception / ethical OSINT compliance; restricted to publicly accessible info. `[VERIFIED - SRC-013]` | Non-nullable `tenant_id` on all database entities, backend header validation, isolated filesystem paths. `[EXISTING CODE - VERIFIED]` |
| **Evidence Quality & Custody** | HTML/text snapshots stored; cryptographic hash verification for tampering not documented in manual. `[UNKNOWN]` | Crawl timestamps and structured entity history; cryptographic evidence hashing not publicly detailed. `[UNKNOWN]` | Graph snapshots stored locally; evidence custody depends on specific transform provider. `[VERIFIED - SRC-011]` | Preserves raw forum archives and stealer dumps; specific cryptographic verification not public. `[UNKNOWN]` | Timestamped social media captures, screenshots, and link history. `[VERIFIED - SRC-013]` | Dedicated `LocalEvidenceStore` generating SHA-256 digests on raw bytes before text extraction. `[EXISTING CODE - VERIFIED]` |

---

## 5. Source and Evidence Register

| Source ID | Document / Source Name | Canonical Location / Direct URL | Access / Publication Date | Verified Capability / Finding | Evidence Excerpt or Exact Citation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SRC-001` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 2) | Dec 2024 / Mar 2025 | Platform Module Taxonomy | "Index: 1. Platform, 2. MoleSight, 3. Darkweb Tracker PRO, 4. Telegram Tracker, 5. Face Finder, 6. Indicators of Leakage, 7. Compromised Data Set, 8. Combo Binder, 9. Credential Lookout, 10. ULP Binder, 11. Ransomware Monitoring, 12. Leaked Monitoring, 13. Government Monitoring, 14. Defacement Alert." |
| `SRC-002` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 18-20) | Dec 2024 / Mar 2025 | Telegram Tracker Workflows | "Telegram Tracker utilizes intelligence data from Telegram channels and groups collected by OSINT specialists to track and investigate various cybercrimes... Preview Image, Preview Message, Full content of selected message data, GPS, AI Caption." |
| `SRC-003` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 9-10) | Dec 2024 / Mar 2025 | Interactive Canvas Link Analysis | "Platform - Canvas: Item is added on Canvas as a Node... Searched keyword node is shown as red highlighted text... Physics layout, Hierarchical layout, Preset layout... Right-click on any node to use menu: Search the node via other modules." |
| `SRC-004` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 11-12) | Dec 2024 / Mar 2025 | Geospatial Dark Map | "Platform - Dark Map: Enable Dark map mode by selecting DM button... Categories: DT [NETWORK INFO] IP, DT [LEAKED INFO] Leaked Image (GPS Included), TT [TELEGRAM INFO] Telegram Channel (GPS Included), Telegram User (GPS Included)." |
| `SRC-005` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 21-23) | Dec 2024 / Mar 2025 | Face Finder Facial Recognition | "Face Finder: Track down and identify suspects across the deep and dark web with Face Finder's AI-powered facial recognition technology... Search by Upload Image... Face (Similar): Show percentage of similarity by comparing with all similar face images." |
| `SRC-006` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 34-36) | Dec 2024 / Mar 2025 | Stealer Log Ingestion (ULP Binder) | "ULP Binder: Leaked Account Search Module... Search 'Host' field data that matched with keyword... Export search results in Excel file... Host, URL, ID, Password fields." |
| `SRC-007` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 46-49) | Dec 2024 / Mar 2025 | Advanced Search Indicators | "Appendix 1 - Search Indicators: Network (tor:, torurl:, i2p:, domain:, ip:), Messenger Info (telegram:, discord:, line:, session:), Telegram Info (telegram.user:, telegram.channel:, telegram.message:), Location (gps:), Face Info (face:)." |
| `SRC-008` | StealthMole User Manual v3.3 | Local file: `D:\StealthMole - User Manual v3.3.pdf` (Page 51-52) | Dec 2024 / Mar 2025 | Query Consumption Rules | "Appendix 3 - How Queries are Consumed in Telegram Tracker: 1. When a keyword is searched on the search bar, 2. When a category is selected, 3. When a result is clicked to see its detailed information, 4. When Next/Previous button is clicked, 5. When the window is scrolled up/down to see the previous/next message (1 query is consumed per 10 messages)." |
| `SRC-009` | StealthMole Official Website | `https://stealthmole.com/` | Accessed 2026-10-28 | Vendor Positioning | Public marketing positioning: "AI-powered Dark Web & Telegram Threat Intelligence platform." |
| `SRC-010` | Recorded Future Platform Docs | `https://www.recordedfuture.com/` | Accessed 2026-10-28 | Intelligence Cloud Capabilities | Official solution briefs describing automated threat intelligence, NLP crawling, and Intelligence Graph correlation. |
| `SRC-011` | Maltego Product Documentation | `https://docs.maltego.com/` | Accessed 2026-10-28 | Graph Engine & Transform Hub | Official documentation detailing graph visualization, entity types, and the Transform Hub partner ecosystem. |
| `SRC-012` | Intel 471 TITAN Platform | `https://intel471.com/` | Accessed 2026-10-28 | Cybercrime Underground Tracking | Official platform overview detailing Adversary, Credential, Malware, and Vulnerability Intelligence. |
| `SRC-013` | ShadowDragon Official Documentation | `https://shadowdragon.io/` | Accessed 2026-10-28 | Horizon & SocialNet Capabilities | Documentation detailing SocialNet entity resolution across 100+ platforms and Horizon case management. |
| `SRC-014` | TTI Codebase: Security Module | `backend/app/core/security.py` | Verified 2026-10-28 | TenantContext Scaffolding | Extracts `X-Tenant-ID` header, validates UUID format, injects `TenantContext(is_authenticated=False)`. Marked explicitly as scaffolding. |
| `SRC-015` | TTI Codebase: Database Base | `backend/app/database/base.py` | Verified 2026-10-28 | Multi-Tenancy Mixin Invariant | Declares `TenantAwareModel` with non-nullable, indexed `tenant_id` (`PG_UUID(as_uuid=True)`). |
| `SRC-016` | Maltego Monitor Documentation | `https://docs.maltego.com/` (Maltego Monitor) | Accessed 2026-10-28 | Telegram Account Connection | Official documentation specifying that Maltego Monitor accesses public channels by linking a user's Telegram phone number under Organization Accounts. |
| `SRC-017` | Maltego Evidence Documentation | `https://docs.maltego.com/` (Maltego Evidence) | Accessed 2026-10-28 | Telegram Evidence Collection | Official documentation detailing phone-number-based data collection tasks for Telegram. |
| `SRC-018` | TTI Codebase: Evidence Storage | `backend/app/evidence/storage.py` | Verified 2026-10-28 | LocalEvidenceStore Isolation | Computes `hashlib.sha256(raw_bytes).hexdigest()`, partitions by `{tenant_id}/`, validates path traversal with `startswith`. |
| `SRC-019` | ShadowDragon Horizon Monitor | `https://shadowdragon.io/horizon/` | Accessed 2026-10-28 | Telegram Monitoring in Horizon | Documents automated watchlist monitoring of public channels and hidden groups across messaging networks. |

---

## 6. Audit of Unsupported Claims & Withdrawn Statements

During the Gate 1 review, several claims from the initial research draft were audited and corrected:

1. **Competitor Pricing Claims Withdrawn (`AUDIT-WD-001`)**:
   - *Previous Statement*: Stated that Recorded Future and Intel 471 cost "$50k–$100k+/year".
   - *Audit Finding*: Pricing for enterprise CTI platforms is custom-quoted based on organizational size, asset volume, and module add-ons. Specific figures are not published in vendor technical documentation.
   - *Correction*: Marked commercial pricing as `Unknown / Custom Quoted` in official comparison matrices.
2. **StealthMole API Availability Clarified (`AUDIT-COR-001`)**:
   - *Previous Statement*: Claimed StealthMole is a "closed platform with no API".
   - *Audit Finding*: *User Manual v3.3* is an end-user interface manual and focuses exclusively on Web UI interactions and Excel exports. It neither documents nor disproves the existence of an enterprise backend REST API.
   - *Correction*: Formulated as: "The User Manual v3.3 documents Web UI operations and Excel exports; programmatic REST API availability is not documented in the manual and remains unverified."
3. **Competitor Backend Security Claims Qualified (`AUDIT-COR-002`)**:
   - *Previous Statement*: Suggested competitor platforms lack tenant isolation or cryptographic hashing.
   - *Audit Finding*: Commercial SaaS architectures are proprietary; end-user manuals do not disclose internal database schemas or cryptographic hashing pipelines.
   - *Correction*: Categorized competitor internal storage integrity as `Unknown / Not Publicly Verified`.
4. **TTI Readiness Status Clarified (`AUDIT-COR-003`)**:
   - *Previous Statement*: TTI features were described alongside operational systems.
   - *Audit Finding*: TTI is strictly in Phase 1 initialization. All connectors run in inert stub mode; authentication is scaffolding; live collection is deactivated.
   - *Correction*: Every TTI capability is explicitly labeled as `[EXISTING CODE]`, `[EXISTING SCAFFOLDING]`, or `[PROPOSED REQUIREMENT]`.

---

## 7. TTI Implementation-Verification Register

Every claim regarding the current TTI project has been verified against actual codebase artifacts and automated tests:

| Component | Repository Path | Implemented Behavior Verified | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Tenant Context Scaffolding** | `backend/app/core/security.py` | `get_current_tenant_context` extracts `X-Tenant-ID` header, validates UUIDv4 format, rejects non-UUID with HTTP 400. Explicitly marked as Phase 1 scaffolding (`is_authenticated=False`). | AST code review; `test_invalid_tenant_header_rejected` and `test_valid_tenant_header_accepted` passing. | `Verified in Code` |
| **Model-Level Tenant Isolation** | `backend/app/database/base.py` | `TenantAwareModel` mixin defines non-nullable, indexed `tenant_id` (`PG_UUID`), `created_at`, `updated_at`. | AST code review; Alembic migration `0001_initial_schema.py` defines foreign keys and indexes. | `Verified in Code` |
| **Intelligence Data Models** | `backend/app/database/models/intelligence.py` | `CollectedThread` and `RawArtifact` inherit from `Base, TenantAwareModel`. `RawArtifact` links to thread with `CASCADE` delete. | Code inspection; Alembic table creation verified in test fixtures. | `Verified in Code` |
| **Segregated Evidence Storage** | `backend/app/evidence/storage.py` | `LocalEvidenceStore` writes raw bytes to `{base_dir}/{tenant_id}/{artifact}_{sha256[:16]}.raw`. Verifies SHA-256 on demand. Blocks directory traversal. | AST review; `test_evidence_store_tenant_partitioning` and `test_evidence_store_prevents_directory_traversal` passing. | `Verified in Code` |
| **Untrusted Input Sanitizer** | `backend/app/ingestion/sanitizer.py` | `InputSanitizer.sanitize_text` enforces 1MB limit, Unicode NFC normalization, ANSI escape stripping, control/null byte removal, `<script>` redaction, and defangs protocols (`defanged-\1-blocked:`). | AST review; `test_sanitizer_neutralizes_script_tags`, `test_sanitizer_strips_null_bytes_and_control_chars`, and `test_sanitizer_defangs_dangerous_schemes` passing. | `Verified in Code` |
| **Safe Connector Stubs** | `backend/app/connectors/telegram/stub.py`, `backend/app/connectors/darkweb/stub.py` | `TelegramConnectorStub` and `DarkWebConnectorStub` return `ConnectorStatus.DISABLED`, `is_live_collection_active = False`. Refuse live collection. | Code review; `test_telegram_connector_stub_lifecycle` and `test_darkweb_connector_stub_lifecycle` passing. | `Verified in Code` |
| **Subsystem Health Diagnostics** | `backend/app/observability/health.py`, `backend/app/api/v1/endpoints/health.py` | `GET /api/v1/health` probes DB, Redis, and evidence storage, returning structured JSON with latency and status breakdown. | Live test via `test_health_check_endpoint` passing. | `Verified in Code` |
| **React + TypeScript Dashboard** | `frontend/src/App.tsx`, `frontend/src/services/api.ts` | Displays real-time API health status, subsystem status cards, connector status cards, and security baseline overview. Proxies `/api` to port 8000. | Production build verified via `tsc && vite build` (exit code 0). | `Verified in Code` |

---

## 8. Requirements Taxonomy (Requirements vs. Assumptions vs. Decisions)

To maintain architectural integrity, all statements of capability are segregated into distinct governance tiers:

### Tier 1: Existing TTI Implementation (Verified in Repository)
- Working FastAPI REST API (`GET /api/v1/health`, `GET /api/v1/status`, `GET /api/v1/connectors`).
- Working React + TypeScript dashboard with dark-slate cybersecurity UI.
- Local evidence storage engine with tenant-partitioned paths and SHA-256 integrity calculation.
- Deterministic input sanitizer defanging malicious scripts, ANSI escapes, null bytes, and URI protocols.
- Modular connector interfaces with inactive, safe stubs for Telegram and Dark-Web sources.
- 13 automated tests passing in Pytest; frontend verified with Vite production build.

### Tier 2: Approved Company Requirements (Baseline Charter)
- Technology stack: Python 3.12+ (FastAPI), React + TypeScript (Vite), PostgreSQL 16, Redis 7, Alembic, Docker Compose.
- Non-negotiable security: No hardcoded credentials, no live collection without authorization, strict tenant isolation by design, evidence segregated from frontend assets.
- Git workflow: Private repository, conventional commits, pull-request templates, codeowners reviews.

### Tier 3: Proposed Requirements (Derived from Competitor Research)
- `REQ-PROP-001`: Capacity-based investigation query model instead of per-scroll message fees (`OPP-001`).
- `REQ-PROP-002`: Native message thread reconstruction preserving reply chains, forwarded channel links, and broadcast metadata (`OPP-005`).
- `REQ-PROP-003`: Normalized credential breach schema linking stealer log tuples (ULP) directly to source Telegram channels or threat actor profiles (`OPP-007`).
- `REQ-PROP-004`: Human-in-the-loop analyst triage queue for AI threat classifications before alert dispatch (`OPP-008`).

### Tier 4: Assumptions (Awaiting Production Verification)
- `ASM-001`: Ingestion in Phase 2/3 will focus on public or authorized channels accessible via official or compliant gateways.
- `ASM-002`: Local Docker Compose orchestration will remain the standard development baseline before cloud infrastructure is provisioned.

### Tier 5: Unresolved Decisions (Awaiting Management / Stakeholder Sign-Off)
- `DEC-001`: Legal authorization protocols and credential management for live Telegram session accounts.
- `DEC-002`: Retention windows and compliance purging for collected stealer logs containing corporate PII.
- `DEC-003`: Commercial licensing structure (seat-based enterprise license vs. usage-based tiering).
- `DEC-004`: Biometric/facial recognition scope (whether to evaluate facial matching or exclude it to mitigate regulatory overhead).

---

## 9. Competitor Research Coverage Checklist

| Competitor Platform | Core Modules Examined | Documentation Evidentiary Basis | Gaps Identified | Next Research Action |
| :--- | :--- | :--- | :--- | :--- |
| **StealthMole** | Canvas, Dark Map, MoleSight, Darkweb Tracker PRO, Telegram Tracker, Face Finder, IoL, Compromised Data, Combo Binder, Credential Lookout, ULP Binder, Ransomware, Leaked, Government, Defacement, Appendices 1–3. | Primary reference: *StealthMole User Manual v3.3* (53 pages, Dec 2024 / Mar 2025). | Programmatic REST API endpoints and enterprise backend database architecture not documented in user manual. | Inquire with vendor representatives or review partner integration specs if available. |
| **Recorded Future** | SecOps Intelligence, Threat Intelligence, Identity Intelligence, Messaging Monitor, Intelligence Graph. | Official solution briefs, whitepapers, and public product documentation (`recordedfuture.com`). | Granular chat thread visualization and evidence custody mechanics are not publicly detailed. | Review API technical reference for Telegram entity models and STIX/TAXII export formats. |
| **Maltego** | Graph Engine, Transform Hub, Maltego Monitor, Maltego Evidence, Partner Transforms (Gradient, WEB-IQ). | Official technical documentation (`docs.maltego.com`). | Transform rate-limiting ceilings and account ban risks for Telegram MTProto scraping. | Benchmark community Telegram transforms against official TDLib rate-limiting guidelines. |
| **Intel 471** | Adversary Intelligence, Credential Intelligence, Malware Intelligence, Vulnerability Intelligence, Underground Messaging. | Official platform briefs, product whitepapers, and published threat research (`intel471.com`). | Exact collection mechanics (automated scrapers vs. human operatives) are proprietary. | Analyze published Intel 471 cybercrime bulletins to benchmark threat actor dossier formats. |
| **ShadowDragon** | Horizon Investigate, Horizon Monitor, SocialNet, Mallet. | Official product documentation, UK Digital Marketplace G-Cloud filings, and platform whitepapers (`shadowdragon.io`). | Raw dark-web ransomware leak coverage is secondary to social persona de-anonymization. | Investigate SocialNet's alias resolution algorithms and correlation confidence scoring metrics. |

---

## 10. Change Log (Baseline v1.0.0 &rarr; v2.0.0)

1. **Evidentiary Rigor**: Replaced general assertions with formal status tags (`[VERIFIED]`, `[VENDOR-CLAIM]`, `[INFERENCE]`, `[UNKNOWN]`, `[WITHDRAWN]`).
2. **StealthMole Citations**: Annotated every StealthMole workflow with exact page citations from *User Manual v3.3* (pp. 2–52).
3. **Withdrawal of Unverified Pricing**: Removed speculative competitor pricing estimates ($50k–$100k) and marked commercial pricing as custom-quoted / unknown.
4. **Qualification of Competitor Limitations**: Clarified that undocumented APIs or internal security controls in user manuals do not imply non-existence; marked as *Unknown*.
5. **TTI Implementation Verification**: Added Section 7 detailing actual repository file paths, verified behaviors, and passing tests for all current TTI statements.
6. **Requirements Taxonomy**: Strictly separated existing implementations, approved requirements, proposed features, assumptions, and open decisions.
7. **Coverage Checklist Expanded**: Tracked modules examined, evidence collected, remaining gaps, and next actions across all five platforms.
