# TTI Stakeholder Decision Register

**Document Reference:** `TTI-DOC-PRD-DEC-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Gate 3B — Stakeholder Alignment  
**Role:** Senior Product Analyst  
**Date:** 2026-10-28  
**Status:** **ACTIVE REGISTER — PENDING STAKEHOLDER RESOLUTION**  

---

## 1. Executive Overview & Governance Rules

This register catalogs the critical strategic, technical, legal, and commercial decisions that VFRA leadership and key project stakeholders must resolve before formal Product Requirements Documents (PRD), System Requirements Specifications (SRS), or final system architecture can be authored.

### Status Definitions
- `CONFIRMED`: A formal decision has been made and authorized by the confirmed decision owner.
- `PROPOSED`: A recommended option has been analyzed and proposed by the product team with evidence, awaiting formal stakeholder vote.
- `OPEN`: An active question requiring executive deliberation; options and trade-offs are documented.
- `BLOCKED`: A decision that cannot be finalized until an external prerequisite (e.g., legal counsel opinion or vendor commercial pricing) is obtained.

---

## 2. Master Stakeholder Decision Matrix

| Decision ID | Domain | Strategic Question | Recommended Option (Proposed) | Gate Impact | Status | Proposed Decision Owner |
| :---: | :--- | :--- | :--- | :---: | :---: | :--- |
| **`DEC-01`** | Scope | What is the minimum release scope for TTI Phase 1 (MVP)? | Option B: Telegram Chat Core + Basic Breach Ingestion | **Blocking (Gate 4)** | `PROPOSED` | Head of Product / CEO |
| **`DEC-02`** | Legal / Source | What is the authorized legal and technical model for data collection? | Option C: Hybrid Direct Public Scraper + Commercial Data Aggregators | **Blocking (Gate 4)** | `OPEN` | Chief Legal Counsel & CTO |
| **`DEC-03`** | Collection | What is the operational architecture for Telegram chat collection? | Option A: Centralized Cloud Collector Fleet with Virtual Account Pools | **Blocking (Gate 4)** | `PROPOSED` | Lead DevOps / Architecture |
| **`DEC-04`** | Scale | What is the target ingestion volume and storage capacity for Phase 1? | Option B: Medium Scale (500–1,500 Monitored Channels, ~1M msgs/mo) | **High (Gate 4)** | `PROPOSED` | Head of Product & Lead Architect |
| **`DEC-05`** | Tenancy | What tenant isolation architecture is required for dual-market clients? | Option B: Shared PostgreSQL with Row-Level Security (RLS) + Logical Silos | **High (Gate 4)** | `PROPOSED` | Chief Security Officer & Architect |
| **`DEC-06`** | Privacy / PII | How should compromised infostealer credentials and passwords be handled? | Option B: Masked / Salted Passwords by default with Permission-Gated Unmasking | **Blocking (Gate 4)** | `OPEN` | Legal Counsel & Product Lead |
| **`DEC-07`** | Evidence | What level of cryptographic evidence integrity is required for case exports? | Option B: Internal Immutable Ledger (SHA-256) with RFC 3161 Extensibility | **High (Gate 4)** | `PROPOSED` | Head of Product / LEA Liaison |
| **`DEC-08`** | Retention | What are the mandatory data retention and lifecycle purge policies? | Option C: Tiered Policy (90-day rolling for Corporate, Multi-year for LEA Cases) | **Medium (Gate 4)** | `PROPOSED` | Legal Counsel & Compliance Lead |
| **`DEC-09`** | Delivery | What customer deployment modalities must be supported at launch? | Option A: Multi-Tenant Cloud SaaS + Managed Intelligence Service Bureau | **Blocking (Gate 4)** | `CONFIRMED DIRECTION` | VFRA Executive Leadership |
| **`DEC-10`** | Integrations | What external programmatic integration interfaces must TTI provide? | Option B: OpenAPI 3.1 REST Endpoints + Webhooks (STIX/Maltego Phase 2) | **Medium (Gate 5)** | `PROPOSED` | Lead Architect / Product Lead |
| **`DEC-11`** | Budget / Cost | What is the initial monthly operational infrastructure budget ceiling? | Option B: Moderate Tier ($1,500 – $3,000 / month for proxies, GPU, cloud) | **High (Gate 4)** | `OPEN` | Chief Financial Officer / CEO |
| **`DEC-12`** | Packaging | How should TTI be packaged for Law Enforcement vs. Corporate SOCs? | Option A: Single Unified Platform with Role-Based Feature Modules | **High (Gate 4)** | `PROPOSED` | Head of Product & Sales Lead |
| **`DEC-13`** | Reporting | Should TTI support TXT reports with dual-scope screenshots (`REP-TXT-SCREEN-001`)? | Option B: Structured TXT + Dual Screenshots with Mandatory Pre-Delivery Review | **High (Gate 4)** | **`CONFIRMED (APPROVED BY VFRA)`** | Head of Product & LEA Liaison |
| **`DEC-14`** | IAM / RBAC | Should Release 1 implement a relational `iam.role_permissions` table or static code-level RBAC? | Option B: Static code-level RBAC for Release 1 MVP; defer relational table to Release 2 | **High (Gate 4)** | **`CONFIRMED (PO APPROVED)`** | Architecture Review Board (ARB) |
| **`DEC-15`** | Tenancy / Lifecycle | How should revoked memberships be re-invited under unique tenant-user constraints? | Option 1: In-place atomic reactivation under `UNIQUE (tenant_id, user_id)` with audit logging | **High (Gate 4)** | **`CONFIRMED (PO APPROVED)`** | Security Architect & Lead Data Architect |
| **`DEC-16`** | IAM / Immutability | How should system role immutability be enforced against runtime alteration? | Option 1: Database role grant boundaries (`SELECT` only on `iam.roles` for runtime roles) | **Medium (Gate 4)** | **`CONFIRMED (PO APPROVED)`** | Security Architect |
| **`DEC-17`** | Audit / Compliance | When should the database-backed audit event ledger be created and operationalized? | Option A: Pull forward minimal audit table to Phase 1; Option B: Defer to Phase 5 with logging | **Blocking (Gate 4)** | **`CONFIRMED (PO APPROVED: OPTION A)`** | Chief Information Security Officer & Compliance Lead |
| **`DEC-18`** | Database / Roles | How should database privileges be segregated between migration DDL and runtime admin? | Option A: Three-tier segregation (`tti_migration_role`, `tti_platform_admin_role`, `tti_app_role`)| **High (Gate 4)** | **`CONFIRMED (PO APPROVED: OPTION A)`** | Principal DevSecOps Architect & DBA |
| **`DEC-19`** | Commercial / Credits| What rules govern organization credit quota allocation, per-action costs, and overages?| Option C: Free search/thread scrolling (`FR-THR-001`); credits consumed by heavy ops | **High (Gate 4)** | **`CONFIRMED (PO APPROVED: OPTION C)`** | Chief Commercial Officer & CFO |
| **`DEC-20`** | Auth / Session | How should single active user session concurrency, expiry, and recovery be governed? | Reconciled: Default rejection on active session + explicit force-termination prompt | **High (Gate 4)** | **`CONFIRMED (PO APPROVED)`** | CISO & Lead Architect |
| **`DEC-21`** | Gov / Admin Access | What boundary governs platform administrator access to customer confidential evidence? | Option A: Strict zero-knowledge boundary; no ambient access to customer cases | **High (Gate 4)** | **`CONFIRMED (PO APPROVED: OPTION A)`** | Chief Legal Counsel & CISO |
| **`DEC-22`** | Org Lifecycle | What state transition and deprovisioning rules govern the organization lifecycle? | Option A: Gated lifecycle; new orgs default to `PENDING_APPROVAL` with schema fix | **Medium (Gate 4)** | **`CONFIRMED (PO APPROVED: OPTION A)`** | Head of Operations & Legal Counsel |

---

## 3. Detailed Decision Briefs

---

### `DEC-01`: Minimum Release Scope for TTI Phase 1 (MVP)

* **Question:** What functional scope constitutes the Minimum Viable Product (MVP) for Phase 1 release?
* **Why It Matters:** Attempting to build all 14 StealthMole modules or the full breadth of Recorded Future in Phase 1 creates massive delivery risk, delayed time-to-market, and infrastructure overspend.
* **Available Options:**
  - **Option A (Ultra-Focused Chat Core):** Public Telegram channel crawler, full-text Elasticsearch/PostgreSQL search, sliding-window thread viewer, and keyword alert notifications only. Excludes stealer credentials, dark-web Tor scrapers, and link graphing.
  - **Option B (Recommended — Focused Chat + Credential Threat Core):** Telegram continuous thread viewer, keyword alert engine, infostealer log ingestion pipeline (Host, Username, Masked Password), and basic evidence export (PDF/JSON with SHA-256). Excludes dark-web Tor crawler, face finder, and visual node-link canvas (deferred to Phase 2).
  - **Option C (Full Suite Parity):** Simultaneous launch of Telegram, dark-web Tor crawlers, 4 stealer modules, visual link canvas, and Dark Map.
* **Implications Analysis:**
  - *Option A:* Lowest cost and fastest delivery (2–3 months), but weak corporate value proposition (lacks credential breach alerting).
  - *Option B (Recommended):* Delivers high-value differentiation against StealthMole (unmetered chat reading) and immediate SOC ROI (stealer alerts) within reasonable complexity (3–5 months).
  - *Option C:* High technical risk, massive proxy/infrastructure costs, delivery timeline 9–12+ months.
* **Evidence References:** StealthMole User Manual v3.3 (`Slide 17`, `Telegram Tracker`); Recorded Future Identity Intelligence (`EVID-RF-004`).
* **Current Status:** `PROPOSED` (Awaiting VFRA Product Owner confirmation).
* **Decision Owner:** Head of Product / CEO.

---

### `DEC-02`: Source Permissions & Collection Legal Grounding

* **Question:** What is the authorized legal and operational model for collecting Telegram and dark-web threat data?
* **Why It Matters:** Scraping Telegram channels and dark-web forums touches Terms of Service (ToS), CFAA/Computer Misuse statutes, and potential platform banning of crawler phone numbers.
* **Available Options:**
  - **Option A (Direct Proprietary Scraping Only):** VFRA operates its own automated fleet of Telethon/Pyrogram MTProto client sessions and Tor SOCKS5 proxy crawlers.
  - **Option B (Commercial Data Aggregator Partnerships Only):** TTI purchases normalized data feeds from established commercial aggregators (e.g., Webhose/Enigma, Social Links, or dark-web feed brokers), avoiding direct scraping.
  - **Option C (Recommended — Hybrid Model):** Ingest public and semi-public Telegram channels directly via VFRA proprietary collectors; evaluate commercial data partnerships for deep Tor forums and stealer log feeds where infrastructure costs are prohibitive.
* **Implications Analysis:**
  - *Option A:* Maximum data control and lowest recurring data purchase cost; high operational burden in managing proxy pools, virtual SIMs, and anti-ban rotation.
  - *Option B:* Zero crawler maintenance and lower legal exposure; high recurring annual data licensing costs ($30k–$100k+/year) and dependency on vendor uptime.
  - *Option C (Recommended):* Balances core IP creation (Telegram crawler engine) with pragmatic third-party sourcing for difficult dark-web pipelines.
* **Evidence References:** Intel 471 HUMINT & automated crawler model (`EVID-I471-008`); Maltego Transform Hub partnership model (`EVID-MAL-005`).
* **Current Status:** `OPEN` (Requires formal Legal Counsel and CTO review).
* **Decision Owner:** Chief Legal Counsel & Chief Technology Officer.

---

### `DEC-03`: Operational Architecture for Telegram Collection

* **Question:** How should the Telegram data collection infrastructure be deployed and managed?
* **Why It Matters:** Telegram actively rate-limits and bans automated accounts (userbots) that violate platform flood limits. The architecture dictates whether customer queries trigger live scraping or hit pre-indexed data.
* **Available Options:**
  - **Option A (Recommended — Centralized Cloud Collector Fleet):** VFRA hosts a centralized pool of containerized MTProto ingestion workers in cloud infrastructure behind rotating residential proxies, continuously streaming data into central message buffers. Customers query only indexed storage.
  - **Option B (On-Demand Client-Initiated Scraping):** The system only scrapes a Telegram channel when an analyst manually submits a channel link or search query.
  - **Option C (Client-Side Bring-Your-Own-Session):** Each customer provides their own Telegram API credentials (`api_id`, `api_hash`, phone number), running scraping jobs within their own tenancy.
* **Implications Analysis:**
  - *Option A (Recommended):* High search performance (instant sub-second query returns); historical data persists even if a threat actor deletes their channel; protects customer anonymity completely. Requires ongoing VFRA fleet maintenance.
  - *Option B:* Fails to capture ephemeral or deleted messages; causes massive latency during analyst searches; triggers rapid account bans.
  - *Option C:* Offloads account banning liability to the customer; creates severe onboarding friction and terrible user experience for non-technical analysts.
* **Evidence References:** StealthMole central ingestion team (`Slide 17`); Maltego on-demand transform model (`EVID-MAL-002`).
* **Current Status:** `PROPOSED` (Recommended: Option A).
* **Decision Owner:** Lead DevOps / Chief Architecture.

---

### `DEC-04`: Target Ingestion Volume & Scale for Phase 1

* **Question:** What are the target ingestion throughput, channel capacity, and storage targets for Phase 1?
* **Why It Matters:** Determines database sizing, search cluster architecture (PostgreSQL Full-Text Search vs. dedicated OpenSearch/Elasticsearch), and cloud hosting tier.
* **Available Options:**
  - **Option A (Pilot Scale):** 100–300 curated high-risk channels; ~200,000 messages/month; single PostgreSQL instance with pg_trgm.
  - **Option B (Recommended — Medium Enterprise Scale):** 500–1,500 monitored channels; ~1,000,000 messages/month; PostgreSQL metadata + Redis message buffer + 500 GB media volume.
  - **Option C (Large Commercial Scale):** 5,000+ channels; 10M+ messages/month; multi-node distributed search cluster (OpenSearch) + multi-terabyte S3-compatible object storage.
* **Implications Analysis:**
  - *Option A:* Inexpensive ($200–$500/mo), but limited intelligence depth for paying enterprise clients.
  - *Option B (Recommended):* Balances comprehensive coverage of major cybercrime and leak channels with manageable infrastructure costs ($800–$1,500/mo) using the agreed Phase 1 stack (FastAPI + PostgreSQL + Redis).
  - *Option C:* Premature scaling that exceeds Phase 1 budget and necessitates architectural redesign before customer validation.
* **Evidence References:** StealthMole database coverage benchmark (`Slide 50–52`).
* **Current Status:** `PROPOSED` (Recommended: Option B).
* **Decision Owner:** Head of Product & Lead System Architect.

---

### `DEC-05`: Tenant Isolation & Multi-Tenancy Architecture

* **Question:** How must data and customer investigations be partitioned to ensure zero cross-customer leakage?
* **Why It Matters:** Law enforcement clients require absolute secrecy regarding active criminal targets; a corporate client discovering a police inquiry into an executive would trigger severe liability.
* **Available Options:**
  - **Option A (Shared Database with Row-Level Security - RLS):** All tenants share a single PostgreSQL database; every table includes a `tenant_id` column protected by PostgreSQL Row-Level Security policies.
  - **Option B (Recommended — Logical Separation with Separate Schemas/DBs for Case Work):** Ingested public threat intelligence (Telegram messages, stealer dumps) resides in a shared, read-only data repository; all customer watchlists, active cases, evidence items, and notes reside in tenant-isolated PostgreSQL schemas or databases.
  - **Option C (Physical Single-Tenant VPC / Appliance):** Each customer organization receives a completely dedicated, isolated cloud VPC or on-premises Docker appliance with no shared infrastructure.
* **Implications Analysis:**
  - *Option A:* Highest resource efficiency and easiest deployment; risk of catastrophic tenant data leakage if an application query bypasses RLS filters.
  - *Option B (Recommended):* Maximizes storage efficiency for common threat data (one copy of a 10 GB stealer dump served to all tenants) while guaranteeing absolute physical/logical isolation for sensitive customer investigations.
  - *Option C:* Maximum security for sensitive defense/police clients; dramatically increases deployment and maintenance overhead for VFRA DevOps.
* **Evidence References:** Recorded Future multi-tenant cloud security (`EVID-RF-005`); ShadowDragon CJIS compliance (`EVID-SD-009`).
* **Current Status:** `PROPOSED` (Recommended: Option B).
* **Decision Owner:** Chief Information Security Officer & System Architect.

---

### `DEC-06`: Credential & Personal Data Handling (Infostealer Logs)

* **Question:** Should TTI store and display plaintext compromised passwords exfiltrated by infostealer malware, or enforce automated hashing/masking?
* **Why It Matters:** Storing plaintext passwords AS IS (like StealthMole and Intel 471) provides critical forensic value for Account Takeover (ATO) detection, but exposes VFRA to immense GDPR/privacy liability and credential breach risks if TTI itself is compromised.
* **Available Options:**
  - **Option A (Plaintext Storage AS IS):** Store raw Host, Username, and Password in the database; display plain passwords to authenticated analysts (matching StealthMole CDS/ULP Binder and Intel 471 Credential Intel).
  - **Option B (Recommended — Masked Storage with RBAC Unmasking):** Store passwords encrypted at rest; display masked strings by default (`P@ssw****`) with an explicit "Reveal Password" action that logs an immutable audit event and requires high-privilege credentials.
  - **Option C (One-Way Hashed Only):** Store only salted cryptographic hashes (e.g., SHA-256 or bcrypt) of compromised passwords; never store or reveal plaintext strings.
* **Implications Analysis:**
  - *Option A:* Matches competitor functionality; high risk: TTI becomes a lucrative honeypot for threat actors; strict GDPR non-compliance in European jurisdictions.
  - *Option B (Recommended):* Preserves operational utility for authorized investigators while mitigating automated bulk exfiltration and complying with security audit standards.
  - *Option C:* Eliminates credential theft risk; completely destroys product value for corporate SOCs who must determine if an exfiltrated password matches active Active Directory complexity rules.
* **Evidence References:** StealthMole ULP Binder (`Slide 32–33`); Intel 471 Credential Intelligence feed (`EVID-I471-002`).
* **Current Status:** `OPEN` (Requires formal Legal Counsel and Security review).
* **Decision Owner:** Chief Legal Counsel & Head of Product.

---

### `DEC-07`: Cryptographic Evidence Integrity & Chain-of-Custody Standard

* **Question:** What cryptographic standards must be implemented for evidence capture and case reporting?
* **Why It Matters:** Law enforcement convictions require verifiable evidence that proves digital captures were not fabricated or altered post-acquisition.
* **Available Options:**
  - **Option A (Standard Application Screenshots & PDFs):** Generate standard formatted PDF summaries and PNG snapshots without cryptographic signatures (matching StealthMole's current baseline).
  - **Option B (Recommended — Internal Immutable SHA-256 Ledger):** Calculate SHA-256 hashes of all raw ingested messages, downloaded media files, and generated case exports upon creation; store hashes in an append-only, tamper-evident audit ledger with UTC timestamps.
  - **Option C (External RFC 3161 Trusted Timestamp Authority):** Submit evidence hashes to a certified external RFC 3161 Timestamp Authority (TSA) to obtain cryptographically signed `.tsr` tokens (matching Maltego Evidence standards).
* **Implications Analysis:**
  - *Option A:* Zero engineering complexity; highly vulnerable to legal challenge by defense attorneys in criminal proceedings.
  - *Option B (Recommended):* Provides robust cryptographic integrity and non-repudiation suitable for corporate audits and internal LEA cases without recurring TSA API fees.
  - *Option C:* Gold standard for courtroom evidence; introduces external network dependency, latency on export, and third-party commercial TSA subscription costs.
* **Evidence References:** Maltego Evidence & Hunchly SHA-256 / RFC 3161 standards (`EVID-MAL-003`); StealthMole lack of cryptographic hashing (`Slide 8`).
* **Current Status:** `PROPOSED` (Recommended: Option B for Phase 1, architected for Option C pluggability in Phase 2).
* **Decision Owner:** Head of Product & Law Enforcement Technical Liaison.

---

### `DEC-08`: Data Retention & Lifecycle Purge Policies

* **Question:** What data retention horizons and automated purging schedules should be enforced across the platform?
* **Why It Matters:** Law enforcement requires long-term data retention (years) to support ongoing trials, whereas corporate privacy regulations (GDPR Article 17 "Right to Erasure") penalize indefinite storage of personal data.
* **Available Options:**
  - **Option A (Indefinite Global Retention):** Store all ingested Telegram messages, stealer dumps, and case files indefinitely without automated deletion.
  - **Option B (Fixed Global Rolling TTL):** Enforce an automated 180-day or 365-day Time-To-Live (TTL); messages older than the TTL are purged automatically.
  - **Option C (Recommended — Tiered Dual-Lifecycle Policy):** Ingested public Telegram chatter and stealer telemetry follows a rolling 180-day retention schedule (unless archived); items formally tagged to an active **Case** are locked and preserved indefinitely until manually closed by an authorized case administrator.
* **Implications Analysis:**
  - *Option A:* Storage costs scale unboundedly; severe legal exposure under GDPR and data protection laws.
  - *Option B:* Unacceptable to law enforcement: critical evidence for an active trial would vanish mid-prosecution.
  - *Option C (Recommended):* Solves the dual-persona conflict: corporate compliance is satisfied for background chatter, while judicial evidence remains protected in active cases.
* **Evidence References:** Recorded Future data retention policies (`EVID-RF-005`); GDPR compliance guidelines.
* **Current Status:** `PROPOSED` (Recommended: Option C).
* **Decision Owner:** Chief Legal Counsel & Compliance Lead.

---

### `DEC-09`: Customer Access & Delivery Modality

* **Question:** What customer delivery modalities must be supported at initial commercial launch?
* **Why It Matters:** Dictates multi-tenant infrastructure design, deployment pipelines, support overhead, and software licensing models.
* **Available Options:**
  - **Option A (Confirmed Direction — Multi-Tenant Cloud SaaS + Managed Service Bureau):** VFRA hosts the platform in secure cloud infrastructure, providing web-based access to customer organizations and utilizing the platform internally to deliver managed threat intelligence services.
  - **Option B (Dedicated Customer Cloud VPCs):** VFRA provisions and manages isolated cloud infrastructure instances per customer.
  - **Option C (On-Premises Docker / Air-Gapped Appliance):** Deliver containerized software packages installed on customer-provided hardware behind police/military firewalls.
* **Implications Analysis:**
  - *Option A (Confirmed):* Fastest path to market; lowest operational overhead; single codebase deployment; immediately supports dual revenue streams (SaaS subscriptions + Managed CTI contracts).
  - *Option B & C:* Dramatically increases release complexity, version fragmentation, and on-premises support overhead; recommended only as custom enterprise add-ons for future phases.
* **Evidence References:** Confirmed Product Direction baseline; ShadowDragon Horizon cloud SaaS model (`EVID-SD-001`).
* **Current Status:** `CONFIRMED DIRECTION` (Option A confirmed; Options B/C deferred to post-MVP).
* **Decision Owner:** VFRA Executive Leadership.

---

### `DEC-10`: Programmatic API & Integration Interfaces

* **Question:** What external API protocols and integration connectors must be built in initial phases?
* **Why It Matters:** Determines whether TTI can participate in automated SOC workflows (SOAR) or function as an external data provider for graph analysis tools like Maltego.
* **Available Options:**
  - **Option A (Web Portal & File Export Only):** No programmatic API in Phase 1; access is strictly via the web UI with manual CSV/PDF exports (matching StealthMole v3.3).
  - **Option B (Recommended — OpenAPI 3.1 REST API + Outbound Webhooks):** Expose standardized REST endpoints for search and export, plus outbound Webhooks for alert dispatch into corporate SIEM/SOAR.
  - **Option C (Full Ecosystem Integrations):** REST API + Webhooks + Native TAXII 2.1 server + Official Maltego Transform Hub packages.
* **Implications Analysis:**
  - *Option A:* Fast to build; severely limits corporate enterprise value; repeating StealthMole's primary documented architectural flaw.
  - *Option B (Recommended):* Delivers enterprise automation capabilities from Day 1 using FastAPI's native OpenAPI generation with minimal development friction.
  - *Option C:* Over-engineers Phase 1; TAXII server and Maltego Transform packaging should be scheduled for Phase 2 based on customer demand.
* **Evidence References:** Recorded Future Connect API & TAXII 2.1 (`EVID-RF-001`, `002`); Maltego Transform Hub specifications (`EVID-MAL-002`).
* **Current Status:** `PROPOSED` (Recommended: Option B).
* **Decision Owner:** Lead Software Architect & Head of Product.

---

### `DEC-11`: Monthly Operational Infrastructure Budget Ceiling

* **Question:** What is the approved monthly infrastructure and services operating budget for TTI Phase 1?
* **Why It Matters:** Ingestion proxy rotation, residential proxy bandwidth, virtual SIM phone numbers, OCR/LLM GPU compute, and database storage incur recurring operational expenses that must be budgeted before architecture design.
* **Available Options:**
  - **Option A (Bootstrap Tier — <$1,000 / month):** Self-hosted PostgreSQL on standard VPS; open-source Tesseract OCR on CPU; minimal proxy pool (datacenter proxies only); capped at 300 channels.
  - **Option B (Recommended — Growth Tier — $1,500 – $3,500 / month):** Managed cloud PostgreSQL + Redis; dedicated residential proxy bandwidth pool for anti-ban resilience; modest GPU worker node for batch OCR and light multimodal triage; up to 1,500 channels.
  - **Option C (Enterprise High-Throughput Tier — $5,000 – $10,000+ / month):** Distributed search cluster; dedicated 24/7 GPU clusters for continuous OCR and vision LLM extraction; enterprise residential proxy fleet; commercial dark-web data feeds.
* **Implications Analysis:**
  - *Option A:* High risk of Telegram IP bans; slow OCR throughput creating ingestion backlogs.
  - *Option B (Recommended):* Provides adequate operational headroom to run stable, resilient collection without financial strain during discovery/MVP.
  - *Option C:* Unjustified prior to verified customer revenue and validated market traction.
* **Evidence References:** Operational findings across competitor research baselines.
* **Current Status:** `OPEN` (Requires formal CFO / Executive sign-off).
* **Decision Owner:** Chief Financial Officer & CEO.

---

### `DEC-12`: Product Packaging & SKU Differentiation

* **Question:** Should TTI be deployed as a single unified product with license-based feature flags, or as two distinct, specialized software products?
* **Why It Matters:** Developing two separate codebases doubles maintenance overhead; failing to tailor the UI alienates one of the two core target personas.
* **Available Options:**
  - **Option A (Recommended — Unified Core with Role-Based Feature Profiles):** A single unified backend and frontend codebase; the user interface dynamically adapts based on tenant profile (`profile = 'LE_FORENSIC'` vs. `profile = 'CORP_SOC'`).
  - **Option B (Two Distinct Product SKUs):** Two separate product distributions: "TTI Law Enforcement Edition" and "TTI Enterprise Threat Intelligence".
* **Implications Analysis:**
  - *Option A (Recommended):* Minimizes engineering and DevOps overhead; maximizes code reuse; allows modular feature upsells (e.g., a corporate client purchasing the forensic evidence module).
  - *Option B:* Creates divergent codebases, fragmented release cycles, and duplicated testing pipelines.
* **Evidence References:** Confirmed Product Direction baseline; ShadowDragon Horizon unified UI model (`EVID-SD-001`).
* **Current Status:** `PROPOSED` (Recommended: Option A).
* **Decision Owner:** Head of Product & Lead Architect.

---

### `DEC-13`: Reporting Deliverables & Dual-Scope Screenshot Packaging (`REP-TXT-SCREEN-001`)

* **Question:** Should TTI support a structured TXT investigation report bundled with dual-scope screenshots (individual messages and thread context), and how should package review be governed?
* **Why It Matters:** Case investigators and threat intelligence clients require a clean, parseable text summary accompanied by visual evidence that shows both the target message and the broader conversational context. Furthermore, unreviewed automated exports risk leaking sensitive third-party PII or relying on corrupted captures.
* **Available Options:**
  - **Option A (Standard PDF/Excel Exports Only):** Standard formatted PDF reports and tabular Excel sheets without structured TXT summaries or contextual screenshot packaging (matching StealthMole's export model).
  - **Option B (Recommended — Structured TXT Report + Dual-Scope Screenshots with Pre-Delivery Review):** TTI compiles a standardized TXT report containing findings, metadata, and cross-references to supporting screenshots; associates both focused individual-message screenshots and panoramic thread-context screenshots; packages all files under a single shared investigation reference; and requires a mandatory investigator pre-delivery review to verify accuracy and redact sensitive information before release.
  - **Option C (Fully Automated Unreviewed Packaging):** Automatically generates and dispatches TXT and screenshot bundles directly to clients or webhook listeners without human-in-the-loop validation.
* **Implications Analysis:**
  - *Option A:* Easiest to implement, but fails to provide lightweight, plain-text parseability and leaves analysts manually taking external desktop screenshots to prove context.
  - *Option B (Recommended):* Delivers high operational value to both Law Enforcement and Corporate CTI; ensures accountability through pre-delivery review; maintains chain-of-custody discipline without premature complex automation.
  - *Option C:* Poses severe liability: automated screenshot pipelines could capture illegal or sensitive collateral data without human filtering.
* **Evidence References:** Approved Requirement `REP-TXT-SCREEN-001`; Customer Workflows (`customer_workflows.md`, Section 1.5).
* **Current Status:** **`CONFIRMED (APPROVED BY VFRA)`** — Requirement `REP-TXT-SCREEN-001` formally approved based on stakeholder confirmation supplied by the project owner. Every applicable investigation report must support a TXT report accompanied by both relevant-message screenshots and thread-context screenshots, subject to source availability and authorized access.
* **Pending Operational Decisions:** Capture trigger modality (manual vs. automated vs. hybrid), storage retention schedules, and formal evidence/timestamping standards remain explicitly pending stakeholder decisions.
* **Decision Owner:** Head of Product & Law Enforcement Liaison.

---

### `DEC-14`: Role Permissions Architecture (Relational vs. Static Code RBAC)

* **Question:** Should Phase 1 implement a normalized database table `iam.role_permissions` for dynamic permission tokens, or defer the relational table to Release 2 and use static application code-level role-to-permission mapping (`backend/app/core/rbac.py`)?
* **Why It Matters:** Relational role-permission mappings introduce database join overhead on every request and require premature stabilization of dozens of endpoint tokens before API implementation.
* **Available Options:**
  - **Option A (Relational Table in Phase 1):** Create `iam.role_permissions` in migration `0003`, populate it with seed tuples, and query permissions dynamically.
  - **Option B (Recommended — Static Code RBAC for Release 1):** Maintain static role-to-permission mappings in Python code (`backend/app/core/rbac.py`); defer `iam.role_permissions` to Release 2 when custom tenant roles are introduced.
* **Implications Analysis:**
  - *Option A:* Provides relational purity and supports future custom role creation, but creates maintenance churn and database query overhead in Release 1 MVP.
  - *Option B (Recommended):* Provides $O(1)$ in-memory permission verification, tamper resistance against SQL manipulation of role permissions, zero migration churn, and zero database joins per request.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved Option B (Static Code RBAC for Release 1) as an engineering implementation decision. Relational `iam.role_permissions` deferred to Release 2. (Approved for implementation; does not claim separate legal/regulatory sign-off).
* **Decision Owner:** Product Owner & Lead Backend Architect.

---

### `DEC-15`: Membership Reactivation & Historical Lifecycle Strategy

* **Question:** Under the table-level constraint `UNIQUE (tenant_id, user_id)`, how should an organization re-invite or re-activate a user whose membership was previously revoked?
* **Why It Matters:** A strict unique constraint blocks inserting a new membership record for a previously revoked user, while allowing multiple rows per tenant-user risks authorization ambiguity.
* **Available Options:**
  - **Option 1 (Recommended — In-Place Atomic Reactivation):** Retain `UNIQUE (tenant_id, user_id)`. Re-invitation updates the existing row (`membership_status = 'ACTIVE'`, `assigned_role = :new_role`, `granted_at_utc = CURRENT_TIMESTAMP`, `updated_at_utc = CURRENT_TIMESTAMP`) and emits a state-transition audit event to the compliance ledger.
  - **Option 2 (Multi-Row Partial Unique Index):** Replace the constraint with `CREATE UNIQUE INDEX ... WHERE membership_status != 'REVOKED'`. Re-invitation inserts a new membership row, preserving old rows for historical tracking.
* **Implications Analysis:**
  - *Option 1 (Recommended):* Enforces strict $1:1$ user-to-tenant cardinality; foreign keys referencing `membership_id` remain deterministic; eliminates risk of multiple active/inactive rows bleeding into authorization queries. Requires audit logging to capture lifecycle history.
  - *Option 2:* Retains historical membership rows directly in the relational table, but increases table bloat and requires every query to explicitly filter `WHERE membership_status = 'ACTIVE'`, introducing severe authorization bleed risks.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved Option 1 (In-Place Atomic Reactivation under `UNIQUE (tenant_id, user_id)`) as an engineering implementation decision, accompanied by state-transition audit event emission.
* **Decision Owner:** Product Owner & Lead Data Architect.

---

### `DEC-16`: System Role Immutability Enforcement Mechanism

* **Question:** How should the platform guarantee that built-in system roles (`TENANT_ADMIN`, `INVESTIGATOR_LEAD`, `INVESTIGATOR`, `READ_ONLY_ANALYST`) cannot be altered or deleted at runtime?
* **Why It Matters:** Tampering with canonical role tokens or deleting system roles collapses platform authorization.
* **Available Options:**
  - **Option 1 (Recommended — Database Role Grant Boundary):** Enforce immutability via standard PostgreSQL permissions: grant strictly `SELECT` on `iam.roles` to `tti_app_role` and `tti_platform_admin_role`. Zero `INSERT`, `UPDATE`, or `DELETE` grants exist on runtime roles.
  - **Option 2 (Procedural PL/pgSQL Trigger):** Install a `BEFORE UPDATE OR DELETE` trigger raising an exception if `OLD.is_system_role = TRUE`.
  - **Option 3 (Defense-in-Depth):** Implement both Option 1 (privilege boundary) and a comprehensive trigger intercepting `INSERT`, `UPDATE`, `DELETE`, and `TRUNCATE`.
* **Implications Analysis:**
  - *Option 1 (Recommended for Phase 1 MVP):* Standard database permissions provide 100% protection against runtime application compromise with zero procedural code to test or maintain. Simple triggers have known blind spots (fail to block `INSERT`, allow non-system role promotion, bypassed by table owners).
  - *Option 2 & 3:* Add procedural migration complexity that is redundant for Phase 1 because no custom roles exist and runtime roles lack all mutation privileges.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved Option 1 (Database Role Grant Boundary — `SELECT` only on `iam.roles` for `tti_app_role` and `tti_platform_admin_role`) as an engineering implementation decision. Built-in system roles cannot be modified or deleted by runtime roles.
* **Decision Owner:** Product Owner & Security Architect.

---

### `DEC-17`: Audit Ledger Phasing & Provenance Architecture

* **Question:** When should the database-backed audit event ledger (`audit.audit_event_records`) be created and operationalized?
* **Why It Matters:** Gate 4B.3A migration roadmap places `audit.audit_event_records` in Phase 5, but Phase 1 IAM operations (membership creation, revocation, role reassignment) require compliance audit tracking.
* **Available Options:**
  - **Option A (Pull Forward to Phase 1):** Create a minimal, self-contained `audit.audit_event_records` table in Phase 1 with INSERT-only grants and immutability controls.
  - **Option B (Maintain Phase 5 Roadmap Boundary):** Defer the database table to Phase 5 per canonical roadmap; emit structured JSON telemetry logs (`ADR-008`) during Phases 1-4.
* **Implications Analysis:**
  - *Option A:* Delivers relational database audit trails from Day 1; eliminates dependency gap. However, it requires modifying the inter-phase dependency roadmap, and the database table is not tamper-proof against table owners or compromised applications inserting forged events.
  - *Option B:* Preserves canonical migration phasing without roadmap modifications, but application logs are ephemeral and do not satisfy courtroom-grade evidentiary standards without an external immutable log forwarder.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved Option A (Pull Forward minimal `audit.audit_event_records` table into Phase 1 with INSERT-only grants for `tti_app_role`) as an engineering implementation decision. Explicit limitation recorded: this relational table provides application-level tamper evidence, but does not claim legal or regulatory tamper-proofing without external WORM storage / RFC 3161 cryptographic sealing.
* **Decision Owner:** Product Owner & Security / Compliance Lead.

---

### `DEC-18`: Database Role Architecture & Least-Privilege Credential Separation

* **Question:** Should Phase 0's conflated `tti_admin_role` (which currently combines schema DDL creation rights and operational admin rights) be formally split into three segregated roles?
* **Why It Matters:** If an application administrative service connects as `tti_admin_role`, a vulnerability in that service exposes DDL authority (`DROP TABLE`, `ALTER TABLE`, `TRUNCATE`).
* **Available Options:**
  - **Option A (Recommended — Three-Tier Role Separation):** Segregate into `tti_migration_role` (DDL owner, used strictly in CI/CD offline migrations), `tti_platform_admin_role` (operational admin DML only, zero DDL privileges), and `tti_app_role` (customer runtime DML, subject to RLS).
  - **Option B (Two-Role Model with Operational Discipline):** Retain Phase 0's `tti_admin_role` and `tti_app_role`, relying on environment-variable credential management to avoid exposing migration credentials to runtime containers.
* **Implications Analysis:**
  - *Option A (Recommended):* True least-privilege defense-in-depth; limits blast radius of any runtime service compromise. Requires managing three database credentials in deployment manifests.
  - *Option B:* Simpler credential management, but leaves platform administration running with table-drop capabilities.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved Option A (Three-Tier Role Separation: `tti_migration_role` for DDL, `tti_platform_admin_role` for administrative DML, and `tti_app_role` for runtime DML) as an engineering implementation decision.
* **Decision Owner:** Product Owner & Principal DevSecOps Architect.

---

### `DEC-19`: Organization Credit Quota, Per-Action Costs, and Overage Policies

* **Question:** What specific quotas, action costs, reset cadences, and overage rules govern the credit accounting model mandated in `AC-REQ-005`?
* **Why It Matters:** Defines commercial billing mechanics and system resource protection against high-cost operations (e.g. OCR extraction, automated screenshots, high-volume full-text searches).
* **Available Options:**
  - **Option A (Fixed Monthly Allocation with Hard Cut-off):** Organizations receive a fixed monthly credit pool based on subscription tier; upon balance exhaustion, all metered actions return `HTTP 402 Payment Required` until next monthly reset.
  - **Option B (Prepaid Quota with Auto-Overage Invoicing):** Organizations receive a base allocation; requests exceeding quota incur automated per-action overage charges billed at month-end.
  - **Option C (Metered Action Sizing — Free Search / Paid Heavy Extraction):** Standard search queries and thread scrolling are free (preserving anti-metering differentiator `FR-THR-001`); heavy actions (formal `REP-TXT-SCREEN-001` report generation, dual screenshots, high-concurrency FTS) consume credits from quota.
* **Implications Analysis:**
  - *Option C aligns with product vision:* Charging for basic chat scrolling repeats StealthMole's documented flaw (Slide 51); charging for compute-intensive reports and screenshot generation protects infrastructure while delivering high commercial value.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved Option C (Metered Action Sizing: Free Search & Thread Scrolling per `FR-THR-001`, Paid Heavy Operations for `REP-TXT-SCREEN-001`, dual screenshots, bulk exports) as an engineering implementation decision. Credit quota models implemented in `app.tenant_credit_balances` and `app.credit_deduction_ledgers`.
* **Decision Owner:** Product Owner & Commercial / Product Lead.

---

### `DEC-20`: Single Active Session Governance, Storage, and Concurrency Override

* **Question:** How should single active authenticated sessions (`AC-REQ-006`) be enforced, tracked, and recovered across user accounts?
* **Why It Matters:** Reconciles credential sharing prevention with legitimate user workflow disruptions (lost connections, browser crashes, device switching).
* **Available Options:**
  - **Option A (Strict Server Rejection without Override):** A second login attempt while an active session exists is unconditionally rejected (`HTTP 409 Conflict`). The user must explicitly log out from the original device or wait for session timeout.
  - **Option B (Interactive Displace / Force Logout Prompt):** A second login attempt with valid credentials returns a challenge: "An active session exists on another device. Terminate previous session and continue?" Confirming immediately revokes the previous session token and creates a new session.
  - **Option C (Storage Technology Selection):** Track active session registry in Redis (using key `session:user:{user_id}` with TTL and atomic `SET NX` locks) vs. PostgreSQL `iam.user_sessions` table.
* **Implications Analysis:**
  - *Option A:* Maximum security against credential sharing, but creates severe usability friction when an investigator closes a laptop or switches workstations.
  - *Option B:* Balanced enterprise usability and security; prevents simultaneous concurrent access while allowing legitimate users to regain account access.
  - *Option C (Redis):* Sub-millisecond session validation; native TTL expiration; high-throughput concurrency checks.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved reconciled session policy (Option B: Single active session with displacement challenge `force_terminate_existing=true`; multi-tenant switching preserved within active session via context refresh without displacement rejection) as an engineering implementation decision. Session state tracked via `iam.active_user_sessions`.
* **Decision Owner:** Product Owner & Lead Software Architect.

---

### `DEC-21`: Platform Administrator Access Boundary Regarding Customer Evidence

* **Question:** What boundary governs platform administrator access to customer confidential investigation cases, notes, and evidence files?
* **Why It Matters:** Law Enforcement Agencies (LEAs) and Corporate SOCs cannot store confidential case hypotheses on a platform where hosting provider staff can freely browse private investigation files.
* **Available Options:**
  - **Option A (Strict Zero-Knowledge Administrative Boundary):** Platform administrators possess zero access to customer case workspaces, notes, search queries, or evidence packages under any circumstance. Support and debugging are performed strictly via sanitized telemetry (`ADR-008`).
  - **Option B (Audited Dual-Control Emergency Access):** Platform administrators cannot browse customer data by default, but can request temporary emergency access (e.g. for court subpoenas or critical data corruption recovery) requiring cryptographic authorization from the customer Organization Administrator and logging an immutable, high-severity audit record.
* **Implications Analysis:**
  - *Option A:* Essential for LEA prosecutorial integrity and enterprise SOC client trust; eliminates legal subpoena exposure for hosting provider.
  - *Option B:* Provides operational recovery capability, but requires complex dual-control cryptographic tooling and increases compliance audit burden.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved synthesized access policy (Option A default zero-knowledge ambient boundary for platform administrators regarding customer evidence; emergency access governed by audited dual-control procedure) as an engineering implementation decision. (Implementation-level engineering boundary; does not claim separate legal/regulatory sign-off).
* **Decision Owner:** Product Owner & Lead Security Architect.

---

### `DEC-22`: Organization Lifecycle State Transitions and Deprovisioning Rules

* **Question:** What specific criteria, grace periods, and workflows govern organization transitions between `PENDING_APPROVAL`, `ACTIVE`, `SUSPENDED`, and `DEPROVISIONED` (`AC-REQ-002`)?
* **Why It Matters:** Governs operational customer onboarding, breach containment, contract termination, and compliance with statutory retention/erasure mandates (`DEC-08`).
* **Available Options:**
  - **Option A (Manual Administrative Gating):** Onboarding transitions require manual verification of agency credentials by VFRA compliance staff. Suspension is triggered manually or by automated credit exhaustion.
  - **Option B (Automated Staged Lifecycle with Retention Grace Period):** Suspended organizations retain data in a read-only lock state for 30 days before transitioning to `DEPROVISIONED`. Permanent data purge follows authorized retention schedules.
* **Implications Analysis:** Manual verification is essential for Law Enforcement persona vetting (verifying official agency credentials) to prevent malicious actors from registering dummy investigation organizations.
* **Current Status:** **`CONFIRMED (PO APPROVED)`** — Product Owner approved synthesized lifecycle policy (`iam.tenant_organizations.account_status` includes `PENDING_APPROVAL`, default `'PENDING_APPROVAL'`, manual VFRA approval to `ACTIVE`, suspension rules, retention grace period before deprovisioning) as an engineering implementation decision.
* **Decision Owner:** Product Owner & Lead Data Architect.