# TTI Decision & Requirements Traceability Matrix

**Document Reference:** `TTI-DOC-BSL-TRC-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Product Baseline & Release 1 Scope  
**Author:** Product Research & Architecture Team  
**Date:** 2026-10-28  
**Governance Status:** `PROPOSED PRODUCT BASELINE — PENDING STAKEHOLDER REVIEW`  
**Predecessor Documents:**
- [`docs/product/gate_3b/stakeholder_decision_register.md`](file:///d:/TTI/docs/product/gate_3b/stakeholder_decision_register.md) (`TTI-DOC-PRD-DEC-001`)
- [`docs/product/gate_3b/feature_opportunity_register.md`](file:///d:/TTI/docs/product/gate_3b/feature_opportunity_register.md) (`TTI-DOC-PRD-OPP-001`)
- [`docs/product/gate_3b/assumptions_and_constraints.md`](file:///d:/TTI/docs/product/gate_3b/assumptions_and_constraints.md) (`TTI-DOC-PRD-CON-001`)
- [`docs/product/gate_3b/reporting_requirements_review.md`](file:///d:/TTI/docs/product/gate_3b/reporting_requirements_review.md) (`TTI-DOC-PRD-REV-001`)

---

## 1. Traceability Framework & Governance Rules

This matrix establishes 100% bidirectional traceability between every technical requirement in the TTI Product Baseline and its underlying research origin, stakeholder decision, or engineering recommendation.

### Governance Classification Keys
- **`CONFIRMED DECISION`**: Formally authorized by VFRA Product Ownership as a foundational project baseline.
- **`APPROVED BY VFRA`**: Formally reviewed and approved requirement (`REP-TXT-SCREEN-001`).
- **`PROPOSED PRODUCT FEATURE`**: Candidate functional capability derived from research and customer workflows, awaiting stakeholder confirmation.
- **`ENGINEERING RECOMMENDATION`**: Technical architecture, design pattern, or scoping rule proposed by engineering.
- **`UNRESOLVED CONSTRAINT`**: External dependency, platform ToS limitation, legal ambiguity, or budget ceiling requiring formal external resolution.

---

## 2. Master Requirements Traceability Matrix

```
+-----------------------------------------------------------------------------------------------------------------------------------+
|                                                 MASTER TRACEABILITY MATRIX                                                        |
+-------------------+----------------------------+-------------------------------------+--------------------+-----------------------+
| Requirement ID    | Requirement Name           | Research Origin / Benchmark         | Decision Reference | Governance Status     |
+-------------------+----------------------------+-------------------------------------+--------------------+-----------------------+
| FR-COL-001        | Telegram Channel Ingest    | StealthMole User Manual Slide 17    | Direction Baseline | CONFIRMED DECISION    |
| FR-COL-002        | MTProto Rate Throttling    | Telegram Bot API / Flood Limits     | DEC-03 (Option A)  | ENGINEERING RECOMMEND |
| FR-COL-003        | Message Revisions/Deletion | Telegram MTProto Edit Events        | Assumptions Sec 1  | PROPOSED FEATURE      |
| FR-COL-004        | Ingestion Sanitization     | Security Baseline Sec 3.1           | Security Invariant | ENGINEERING RECOMMEND |
| FR-THR-001        | Cursor Thread Viewer       | StealthMole Scroll Tax (Slide 51)   | OPP-001            | PROPOSED FEATURE      |
| FR-THR-002        | Reply & Forward Tracking   | StealthMole Chat Tracker UI         | Customer Flow 1.1  | PROPOSED FEATURE      |
| FR-SCH-001        | Multi-Observable Search    | StealthMole Slide 49; Intel 471     | DEC-01 (Option B)  | CONFIRMED DECISION    |
| FR-SCH-002        | Faceted Filter Attributes  | Standard TIP Benchmark              | Customer Flow 1.1  | PROPOSED FEATURE      |
| FR-SCH-003        | Recursive AST Boolean Parse| StealthMole 3-OR Ceiling (Slide 49) | OPP-002            | PROPOSED (Release 2)  |
| FR-EVI-001        | Isolated Case Workspaces   | ShadowDragon CJIS Compliance        | DEC-05 (Option B)  | CONFIRMED DECISION    |
| FR-EVI-002        | Cryptographic Ingest Hash  | Maltego Evidence SHA-256 (EVID-MAL) | OPP-006 / DEC-07   | PROPOSED FEATURE      |
| FR-EVI-003        | Media Asset Staging Vault  | Forensic Evidence Best Practices    | DEC-07 (Option B)  | PROPOSED FEATURE      |
| FR-REP-001        | Structured TXT Report Gen  | Gate 3B Stakeholder Decision 13     | REP-TXT-SCREEN-001 | APPROVED BY VFRA      |
| FR-REP-002        | Dual-Scope Screenshots     | Gate 3B Reporting Workflow Sec 1.5  | REP-TXT-SCREEN-001 | APPROVED BY VFRA      |
| FR-REP-003        | Unified Package & Manifest | Gate 3B Reporting Workflow Sec 1.5  | REP-TXT-SCREEN-001 | APPROVED BY VFRA      |
| FR-REP-004        | Pre-Delivery Review Gate   | Gate 3B Review Doc Sec 3.4          | REP-TXT-SCREEN-001 | APPROVED BY VFRA      |
| FR-ALT-001        | Real-Time Watchlist Alerts | Recorded Future Watchlists (RF-004) | Customer Flow 1.2  | PROPOSED FEATURE      |
| FR-ALT-002        | Outbound SOAR Webhooks     | Recorded Future Connect API (RF-001)| OPP-003 / DEC-10   | PROPOSED (Release 2)  |
| FR-TEN-001        | Multi-Tenant Isolation     | ShadowDragon Multi-Tenant (SD-009)  | DEC-05 (Option B)  | CONFIRMED DECISION    |
| FR-TEN-002        | Role-Based Access Control  | Enterprise RBAC Standards           | Assumptions Sec 2  | PROPOSED FEATURE      |
| FR-ADM-001        | Ingestion Fleet Telemetry  | StealthMole Ingestion Team (Slide 17)| Direction Baseline | CONFIRMED DECISION    |
| AC-REQ-001        | Platform Administration    | Stakeholder Guidance (Relayed)      | DEC-21             | CONFIRMED REQ (GUIDE) |
| AC-REQ-002        | Organization Approval      | Stakeholder Guidance (Relayed)      | DEC-22             | CONFIRMED REQ (GUIDE) |
| AC-REQ-003        | Org-Managed Users          | Stakeholder Guidance (Relayed)      | Assumptions Sec 2  | CONFIRMED REQ (GUIDE) |
| AC-REQ-004        | Sub-System Authorization   | Stakeholder Guidance (Relayed)      | DEC-14             | CONFIRMED REQ (GUIDE) |
| AC-REQ-005        | Org Credit Quotas & Metering| Stakeholder Guidance (Relayed)     | DEC-19             | CONFIRMED REQ (GUIDE) |
| AC-REQ-006        | Single Active User Session  | Stakeholder Guidance (Relayed)     | DEC-20             | CONFIRMED REQ (GUIDE) |
+-------------------+----------------------------+-------------------------------------+--------------------+-----------------------+
| NFR-SEC-001       | Multi-Tenant Isolation     | CJIS / Multi-Tenancy Architecture   | DEC-05 (Option B)  | ARCHITECTURAL INVARIANT
| NFR-SEC-002       | Cryptographic Hashing      | Maltego Evidence (EVID-MAL-003)     | DEC-07 (Option B)  | ARCHITECTURAL INVARIANT
| NFR-SEC-003       | Untrusted Input Sanitize   | Security Baseline Sec 3.1           | Security Invariant | ARCHITECTURAL INVARIANT
| NFR-SEC-004       | Zero Repo Secrets / Encrypt| Security Baseline Sec 2.1           | Security Invariant | ARCHITECTURAL INVARIANT
| NFR-SEC-005       | JWT & Session Timeout      | NIST SP 800-63B Guidelines          | Security Invariant | PROPOSED TARGET       |
| NFR-PERF-001      | Thread Latency <300ms      | User Interface Usability Standards  | Engineering Target | PROPOSED TARGET       |
| NFR-PERF-002      | Search Latency <1,500ms    | PostgreSQL FTS Benchmark            | Engineering Target | PROPOSED TARGET       |
| NFR-PERF-003      | Watchlist Latency <100ms   | Real-time Alerting Standard         | Engineering Target | PROPOSED TARGET       |
| NFR-PERF-004      | Report Zip Time <5,000ms   | REP-TXT-SCREEN-001 Packaging        | Engineering Target | PROPOSED TARGET       |
| NFR-PERF-005      | Screenshot Latency <2,500ms| Playwright Headless Benchmark       | Engineering Target | PROPOSED TARGET       |
| NFR-REL-001       | 99.5% API Availability     | Standard Cloud SaaS Target          | Engineering Target | PROPOSED TARGET       |
| NFR-REL-002       | Flood Wait Crash Resilience| MTProto Throttling Resilience       | Ingestion Engine   | ARCHITECTURAL INVARIANT
| NFR-REL-003       | Queue Durability           | Redis Persistence Architecture      | Infrastructure     | ENGINEERING RECOMMEND |
| NFR-SCA-001       | Channel Capacity (500-1500) | Sizing Model (Growth vs Bootstrap)  | DEC-04 / DEC-11    | PROPOSED (BUDGET DEP)  |
| NFR-SCA-002       | Storage (~1M msgs/mo)       | Storage Capacity Model              | DEC-04 / DEC-11    | PROPOSED TARGET       |
| NFR-MNT-001       | Alembic Migrations Revers. | Database Governance Standard        | Engineering Rules  | ARCHITECTURAL INVARIANT
| NFR-MNT-002       | >=80% Code Test Coverage   | Code Quality Standard               | Engineering Rules  | ENGINEERING RECOMMEND |
| NFR-MNT-003       | 100% OpenAPI 3.1 Validation| FastAPI Schema Standard             | DEC-10 (Option B)  | ARCHITECTURAL INVARIANT
| NFR-OBS-001       | Logs with Query Redaction  | Cloud Observability Standard        | Engineering Rules  | ARCHITECTURAL INVARIANT
| NFR-OBS-002       | Subsystem Health Probes    | Docker / Kubernetes Diagnostics     | Engineering Rules  | ARCHITECTURAL INVARIANT
| NFR-OBS-003       | Tamper-Evident Audit Trail | Forensic Chain of Custody Standard  | Security Baseline  | ARCHITECTURAL INVARIANT
+-------------------+----------------------------+-------------------------------------+--------------------+-----------------------+
```

---

## 3. Deep Traceability Breakdown by Subsystem

### 3.1 Collection & Ingestion Subsystem
- **`FR-COL-001` (Telegram Ingestion):** Traced directly to the **Confirmed Product Direction Baseline** (`docs/product/gate_3b/product_direction.md`, Section 2.2). Benchmarked against StealthMole User Manual Slide 17 ("Central Collection Team"). Preserves forum `message_thread_id` and linked discussion channels (`linked_chat_id`).
- **`FR-COL-002` (Rate Limiting & Throttling):** Traced to `DEC-03` (Option A) and Technical Constraints (`docs/product/gate_3b/assumptions_and_constraints.md`, Section 1.1). Prevents MTProto session bans.
- **`FR-COL-003` (Revision Tracking):** Traced to Technical Constraints (`assumptions_and_constraints.md`, Section 1.1, Item 4). Preserves original evidence when threat actors edit or delete chatter; records sequence-gap indicators without unverified assertions of deletion.
- **`FR-COL-004` (Input Sanitization & Credential Minimization):** Traced to `docs/security_baseline.md` (Section 3.1). Mitigates stored XSS, applies heuristic regex detection and field-level encryption to credentials embedded in chatter, and prevents secret emission in logs.

### 3.2 Thread Navigation & Reconstruction Subsystem
- **`FR-THR-001` (Cursor Thread Viewer):** Traced directly to Candidate Feature `OPP-001` (`docs/product/gate_3b/feature_opportunity_register.md`, Section 3). Directly overcomes StealthMole's primary usability defect: **Slide 51** penalizes users by deducting **1 search query credit for every 10 messages scrolled**. Bounded by defensive backend API rate limiting and visual sequence-gap markers.
- **`FR-THR-002` (Reply & Forward Tracking):** Traced to Customer Workflow 1.1 (`docs/product/gate_3b/customer_workflows.md`, Section 1.1). Provides narrative context on criminal networks; preserves forum topic threading.

### 3.3 Search & Discovery Subsystem
- **`FR-SCH-001` (Multi-Observable Search):** Traced to Confirmed Baseline (`product_direction.md`, Section 2.1) and `DEC-01` (Option B). Matches core observable lookup capabilities documented in StealthMole Slide 49 and Intel 471 Titan (`EVID-I471-001`).
- **`FR-SCH-002` (Faceted Filter Attributes):** Traced to customer workflows and standard TIP UI benchmarks.
- **`FR-SCH-003` (Recursive AST Boolean Parser):** Traced to `OPP-002` (`feature_opportunity_register.md`). Overcomes StealthMole's documented **3 `OR` operator / 5 total operator ceiling** (Slide 49). Scheduled for Release 2.

### 3.4 Case Management & Evidence Subsystem
- **`FR-EVI-001` (Case Workspaces):** Traced to Confirmed Baseline (`product_direction.md`, Section 2.1) and `DEC-05` (Option B). Aligns with ShadowDragon's CJIS-compliant case management (`EVID-SD-009`).
- **`FR-EVI-002` (Cryptographic SHA-256 Ingestion Hash):** Traced to `OPP-006` and `DEC-07` (Option B). Matches Hunchly and Maltego Evidence integrity standards (`EVID-MAL-003`).
- **`FR-EVI-003` (Media Asset Staging Vault):** Traced to `docs/architecture.md` (Section 4.2) and `DEC-07` (Option B). Ensures evidence binaries are isolated from public web directories; blocks raw SHA-256 existence oracle probing.

### 3.5 Investigation Reporting Subsystem (`REP-TXT-SCREEN-001`)
- **`FR-REP-001` (Structured TXT Report Generation):** Traced directly to **`APPROVED BY VFRA`** requirement `REP-TXT-SCREEN-001` (`docs/product/gate_3b/reporting_requirements_review.md`, Section 3.1).
- **`FR-REP-002` (Dual-Scope Screenshots):** Traced directly to `REP-TXT-SCREEN-001` (Customer Workflow 1.5, Section 1.5.3). Mandates both focused individual-message captures (`SCR-INDIV`) and panoramic thread-context captures (`SCR-THREAD`).
- **`FR-REP-003` (Unified Package & Manifest):** Traced to `REP-TXT-SCREEN-001` (Acceptance Criterion 1 & 4). Requires shared reference ID and `manifest.json` cryptographic verification.
- **`FR-REP-004` (Investigator Pre-Delivery Review):** Traced to `REP-TXT-SCREEN-001` (Acceptance Criterion 5). Mandates human verification and PII redaction before delivery.

### 3.6 Watchlists & Alerting Subsystem
- **`FR-ALT-001` (Real-Time Watchlist Alerts):** Traced to Customer Workflow 1.2 (`customer_workflows.md`, Section 1.2) and Recorded Future alert triggers (`EVID-RF-004`).
- **`FR-ALT-002` (Outbound SOAR Webhooks):** Traced to `OPP-003` and `DEC-10` (Option B). Matches Recorded Future Connect API automation patterns. Scheduled for Release 2.

### 3.7 Multi-Tenancy & Access Control Subsystem
- **`FR-TEN-001` (Multi-Tenant Data Isolation):** Traced to `DEC-05` (Option B) and `docs/architecture.md` (Section 4). Guarantees zero cross-customer data leakage; enforces tenant-prefixed Redis caching and fails closed when tenant context is missing.
- **`FR-TEN-002` (Role-Based Access Control):** Traced to Customer Workflow 1.4 (`customer_workflows.md`, Section 1.4) and Legal Guardrails (`assumptions_and_constraints.md`, Section 2).

### 3.8 Platform Administration Subsystem
- **`FR-ADM-001` (Collector Fleet Telemetry):** Traced to Confirmed Baseline (`product_direction.md`, Section 2.3) and Customer Workflow 1.3 (`customer_workflows.md`, Section 1.3). Enables VFRA operations to maintain crawler uptime and proxy health.

### 3.9 Access Control, Organization Approval, Credits, and Session Policy Subsystem
- **`AC-REQ-001` (Platform Administration Scope):** Traced to stakeholder guidance relayed by developer from company discussions. Grants platform administrators platform-level configuration and organization approval authority, while explicitly restricting unsupervised access to client investigative case files and original evidence binaries (`DEC-21`).
- **`AC-REQ-002` (Organization Approval Lifecycle):** Traced to stakeholder guidance relayed by developer. Mandates platform administrator approval before an organization receives active access; defines lifecycle states (`PENDING_APPROVAL`, `ACTIVE`, `SUSPENDED`, `DEPROVISIONED`) (`DEC-22`).
- **`AC-REQ-003` (Organization-Managed Users):** Traced to stakeholder guidance relayed by developer and enterprise administrative delegation models. Confines organization administrator control strictly to their own tenant (`tenant_id`); bars cross-tenant user approval or platform-admin role assignment.
- **`AC-REQ-004` (Least-Privilege Sub-System Authorization):** Traced to stakeholder guidance relayed by developer and Product Baseline module boundaries (`FR-SCH-001`, `FR-THR-001`, `FR-EVI-001`, `FR-EVI-003`, `FR-REP-001`, `FR-ALT-001`, `NFR-OBS-003`). Enforces least-privilege RBAC tokens per endpoint.
- **`AC-REQ-005` (Organization Credit Quota & Per-Action Metering):** Traced to stakeholder guidance relayed by developer. Establishes two-level credit accounting (organization quota + per-action deduction), atomic balance deduction, retry idempotency, explicit insufficient-credit outcomes, and segregated accounting (`DEC-19`).
- **`AC-REQ-006` (Single Active User Session):** Traced to stakeholder guidance relayed by developer and account sharing prevention standards. Enforces server-side rejection of concurrent logins for the same user account across all devices and organizations (`DEC-20`).

---

## 4. Traceability of Unresolved Constraints & Governance Decisions

```
+----------------------------------------------------------------------------------------------------+
|                               UNRESOLVED DECISIONS & RISK DEPENDENCIES                             |
+-------------------+----------------------------+-----------------------------------+---------------+
| Decision Ref      | Strategic Domain           | Unresolved Dimension              | Risk Impact   |
+-------------------+----------------------------+-----------------------------------+---------------+
| DEC-01 (Scope)    | Release 1 MVP Scope        | Confirmation of LEA-weighted core | High          |
|                   |                            | vs full stealer log ingestion     |               |
| DEC-02 (Legal)    | Collection Legal Grounding | In-house scraping vs Commercial   | High          |
|                   |                            | dark-web data feed licensing      |               |
| DEC-04 (Scale)    | Release 1 Storage & Scale  | Confirmation of 500-1,500 vs      | Medium        |
|                   |                            | 100-300 channels (load test dep)  |               |
| DEC-06 (PII/Pass) | Compromised Credentials    | Option A (Plaintext) REJECTED;    | High          |
|                   |                            | Option B (Masked/Encrypted) pend. |               |
| DEC-08 (Retention)| Data Purge & Lifecycles    | 180-day TTL vs Case Lock; GDPR    | High          |
|                   |                            | Art. 17 Erasure vs Immutability   |               |
| DEC-11 (Budget)   | Monthly Operating Spend    | Confirmation of $1,500-$3,500/mo  | High          |
|                   |                            | Growth Tier (conditions NFR-SCA)  |               |
| DEC-13 (Reporting)| REP-TXT-SCREEN-001 Ops     | Capture trigger modality &        | Medium        |
|                   |                            | screenshot retention quotas       |               |
| DEC-14 (IAM/RBAC) | Role Permissions Model     | Static code RBAC vs relational    | High (Phase 1)|
|                   |                            | iam.role_permissions table        |               |
| DEC-15 (Lifecycle)| Membership Reactivation    | In-place update with UNIQUE vs    | High (Phase 1)|
|                   |                            | multi-row partial unique index    |               |
| DEC-16 (Immutab.) | Role Immutability Control  | PostgreSQL table grant boundary   | Medium(Phase 1)|
|                   |                            | vs procedural PL/pgSQL trigger    |               |
| DEC-17 (Audit)    | Audit Phasing Strategy     | Minimal audit table in Phase 1    | Critical(Ph 1)|
|                   |                            | vs deferral to Phase 5            |               |
| DEC-18 (Database) | Database Role Architecture | 3-tier role separation (migration/| High (Phase 1)|
|                   |                            | admin/app) vs Phase 0 conflation  |               |
| DEC-19 (Credits)  | Quota & Consumption Policy | Credit quotas, action costs,      | High (Commerc)|
|                   |                            | resets, overages, and refunds     |               |
| DEC-20 (Sessions) | Single Session Governance  | Invalidation tech, TTL, idle      | High (Security|
|                   |                            | timeout, and override handling    |               |
| DEC-21 (Gov/Admin)| Platform Admin Boundaries  | Dual-control policy & restrictions| High (Security|
|                   |                            | on inspecting customer evidence   |               |
| DEC-22 (Lifecycle)| Organization Lifecycle     | Onboarding, approval, suspension, | Medium(Ops)   |
|                   |                            | and deprovisioning workflows      |               |
+-------------------+----------------------------+-----------------------------------+---------------+
```
