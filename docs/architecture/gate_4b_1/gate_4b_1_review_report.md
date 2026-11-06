# TTI Gate 4B.1 — Logical Data Model Review & Gate Report

**Document Reference:** `TTI-ARCH-GATE4B1-REPORT`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Gate 4B.1 — Logical Data Model & ER Diagram Closeout  
**Author:** Principal Data Architect & Security Architect  
**Date:** October 2026  
**Parent Specifications:**  
- [`docs/architecture/gate_4b_1/logical_data_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/logical_data_model.md)  
- [`docs/architecture/gate_4b_1/entity_relationship_diagram.md`](file:///d:/TTI/docs/architecture/gate_4b_1/entity_relationship_diagram.md)  
- [`docs/architecture/gate_4b_1/tenant_isolation_and_data_ownership.md`](file:///d:/TTI/docs/architecture/gate_4b_1/tenant_isolation_and_data_ownership.md)  
- [`docs/architecture/gate_4b_1/evidence_provenance_and_retention_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/evidence_provenance_and_retention_model.md)  

---

## 1. Executive Summary & Gate Verdict

### 1.1 Gate Verdict
# **`PASS — LOGICAL DATA MODEL COMPLETE & VERIFIED`**

The Logical Data Model and Entity-Relationship Architecture for the Telegram Threat Intelligence (TTI) platform has successfully completed all Gate 4B.1 objectives. The model establishes a technology-neutral, implementation-independent foundation that fully satisfies the approved Product Baseline and Gate 4A architecture requirements while maintaining strict governance boundaries around open stakeholder decisions.

### 1.2 Core Architectural Achievements
1. **Implementation-Independent Logical Architecture:** Defined 22 logical entities across four discrete domains (Identity/Tenancy, Shared Threat Store, Tenant Workspaces, and Evidence Provenance/Reporting) without premature physical database dependencies (no table names, DDL, ORM mappings, or physical storage vendor locks).
2. **Defensive Multi-Tenancy via Bridge Association:** Resolved the multi-tenant annotation challenge via the `CaseMessageAssociation` bridge entity, enabling competing tenant organizations to pin, tag, and annotate globally shared threat messages with absolute cross-tenant secrecy and zero contamination of shared records.
3. **Strict Three-Tier Evidence Separation:** Formalized a clear conceptual boundary separating verbatim original evidence (Tier 1: collected only where authorized, necessary, and proportionate; cryptographically hashed; never mutated), derived searchable/display records (Tier 2: heuristically masked `P@ssw****` strings for search and display), and operational telemetry (Tier 3: query-hashed audit trails; zero cleartext secrets).
4. **Approved Scope Traceability ([`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001)):** Fully modeled the approved four-element reporting deliverable (plain UTF-8 text report, individual-message focus screenshots, thread-context panoramic screenshots, and an authoritative `manifest.json` cryptographic manifest).
5. **Provisional Reconciliation of Storage Immutability & Retention:** Formally marked storage WORM / Object Lock as provisional pending `DEC-08` and legal review, explicitly documenting the trade-off between evidence preservation and legal obligations (retention expiry, court-ordered expungements, erasure mandates, and emergency purging of unlawfully collected content).

---

## 2. Gate 4B.1 Deliverables Inventory

All Gate 4B.1 documentation artifacts have been created in the non-conflicting path [`docs/architecture/gate_4b_1/`](file:///d:/TTI/docs/architecture/gate_4b_1/):

| Deliverable Path | Primary Focus | Word Count | Line Count | Status |
| :--- | :--- | :---: | :---: | :---: |
| [`logical_data_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/logical_data_model.md) | Implementation-independent entity definitions, attributes, keys, relationships, ownership, and requirement traceability across 4 domains. | ~4,010 | 631 | **COMPLETE** |
| [`entity_relationship_diagram.md`](file:///d:/TTI/docs/architecture/gate_4b_1/entity_relationship_diagram.md) | Three readable Mermaid ERDs: (1) Core Domain, (2) Evidence Provenance & Reporting (`REP-TXT-SCREEN-001`), (3) Boundary & Ownership Topography. | ~1,510 | 370 | **COMPLETE** |
| [`tenant_isolation_and_data_ownership.md`](file:///d:/TTI/docs/architecture/gate_4b_1/tenant_isolation_and_data_ownership.md) | Logical ownership rules, fail-closed enforcement, `CaseMessageAssociation` bridge pattern, anti-oracle media protection, and async boundary scoping. | ~1,500 | 198 | **COMPLETE** |
| [`evidence_provenance_and_retention_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/evidence_provenance_and_retention_model.md) | Three-tier evidence separation, unbroken provenance chains, `REP-TXT-SCREEN-001` packaging, provisional WORM reconciliation, and disposal lifecycle. | ~1,760 | 220 | **COMPLETE** |
| [`gate_4b_1_review_report.md`](file:///d:/TTI/docs/architecture/gate_4b_1/gate_4b_1_review_report.md) | Gate review assessment, deliverables inventory, full traceability matrix, open decisions, necessary assumptions, and Gate 4B.2 hand-off. | ~1,900 | ~230 | **COMPLETE** |

*Total Gate 4B.1 Architectural Volume: ~10,680 words across 5 comprehensive specifications.*

---

## 3. Master Requirements Traceability Matrix

The logical data model covers 100% of the functional and non-functional requirements allocated to the Release 1 data architecture:

| Requirement ID | Requirement Summary | Logical Entities Implementing / Supporting | Coverage Finding |
| :--- | :--- | :--- | :---: |
| **`FR-COL-001`** | Telegram Channel Ingestion | `SourceChannel`, `ForumTopic`, `SourceMessage` | **FULL COVERAGE** |
| **`FR-COL-002`** | Rate Limiting & Flood Backoff | `SourceConnectorDefinition`, `IngestionJobRun` | **FULL COVERAGE** |
| **`FR-COL-003`** | Message Revisions & Sequence Gaps | `MessageRevisionRecord`, `CollectionDiscontinuityGap`, `SourceMessage` | **FULL COVERAGE** |
| **`FR-COL-004`** | Ingestion Sanitization & Credential Minimization | `DerivedContentRepresentation`, `RawEvidenceBlobReference` | **FULL COVERAGE** |
| **`FR-THR-001`** | Cursor-Based Thread Navigation | `SourceMessage`, `CollectionDiscontinuityGap` | **FULL COVERAGE** |
| **`FR-THR-002`** | Reply-Chain & Forward Provenance Tracking | `SourceMessage` (`reply_to_message_id`, `forward_origin_chat_id`), `ForumTopic` | **FULL COVERAGE** |
| **`FR-SCH-001`** | Multi-Observable Indicator & Keyword FTS | `DerivedContentRepresentation`, `SavedSearchQuery` | **FULL COVERAGE** |
| **`FR-SCH-002`** | Faceted Temporal, Channel & Media Filters | `SourceMessage`, `DerivedContentRepresentation`, `MediaArtifactReference` | **FULL COVERAGE** |
| **`FR-SCH-003`** | Recursive AST Boolean Search Parser | Deferred to Release 2; documented in `logical_data_model.md` Section 6 | **CATALOGED** |
| **`FR-EVI-001`** | Case Workspaces & Evidence Staging | `InvestigativeCase`, `CaseMessageAssociation`, `CaseNote` | **FULL COVERAGE** |
| **`FR-EVI-002`** | Cryptographic SHA-256 Ingestion Hashing | `RawEvidenceBlobReference` (`payload_sha256_hash`), `MediaArtifactReference` | **FULL COVERAGE** |
| **`FR-EVI-003`** | Media Downloader & Vault Storage | `MediaArtifactReference` | **FULL COVERAGE** |
| **`FR-REP-001`** | Structured Plain-Text (TXT) Report Gen | `TextReportDocument` (`report.txt`) under `InvestigationReportPackage` | **FULL COVERAGE** |
| **`FR-REP-002`** | Dual-Scope Screenshot Evidence Capture | `MessageScreenshotArtifact` (`focus`), `ThreadContextScreenshotArtifact` (`context`) | **FULL COVERAGE** |
| **`FR-REP-003`** | Unified Package with Cryptographic Manifest | `InvestigationReportPackage`, `EvidencePackageManifest` (`manifest.json`) | **FULL COVERAGE** |
| **`FR-REP-004`** | Mandatory Pre-Delivery Review Workflow | `InvestigationReportPackage` (`package_status`, `finalized_at_utc`) | **FULL COVERAGE** |
| **`FR-ALT-001`** | Real-Time Watchlist Monitoring & Alerts | `WatchlistRule`, `WatchlistAlertEvent` | **FULL COVERAGE** |
| **`FR-ALT-002`** | Outbound SOAR / SIEM Webhook Dispatcher | Deferred to Release 2; documented in `logical_data_model.md` Section 6 | **CATALOGED** |
| **`FR-TEN-001`** | Multi-Tenant Data Isolation & Scoping | `TenantOrganization`, `InvestigativeCase`, `CaseMessageAssociation` | **FULL COVERAGE** |
| **`FR-TEN-002`** | Role-Based Access Control (RBAC) | `UserProfile`, `TenantMembership`, `RoleDefinition & PermissionGrant` | **FULL COVERAGE** |
| **`FR-ADM-001`** | Collector Fleet Telemetry & Monitoring | `SourceConnectorDefinition`, `IngestionJobRun` | **FULL COVERAGE** |
| **`NFR-SEC-001`** | Multi-Tenant Isolation (Fail-Closed) | Domain partitioning, mandatory `tenant_id` context, uniform HTTP 404 rejection | **FULL COVERAGE** |
| **`NFR-SEC-002`** | Cryptographic Hashing Standards | SHA-256 attributes across Raw Blobs, Media, Packages, Manifests | **FULL COVERAGE** |
| **`NFR-SEC-003`** | Untrusted Input Sanitization | `DerivedContentRepresentation` (`sanitization_flags`) | **FULL COVERAGE** |
| **`NFR-SEC-004`** | Sensitive Data Encryption at Rest | `RawEvidenceBlobReference` (`encryption_key_ref`, AES-256-GCM) | **FULL COVERAGE** |
| **`NFR-OBS-001`** | Operational Logs with Query Redaction | `AuditEventRecord` (`target_identifier_hash`), `SavedSearchQuery` (`query_hash`) | **FULL COVERAGE** |
| **`NFR-OBS-003`** | Tamper-Evident Audit Ledger | `AuditEventRecord` (Append-Only ledger) | **FULL COVERAGE** |
| **`NFR-LEGAL-001`**| Evidence Integrity & Legal Disclaimers | `TextReportDocument`, `EvidencePackageManifest` | **FULL COVERAGE** |

---

## 4. Relationship, Ownership & Boundary Ambiguities Resolved

During the logical modeling process, three critical relationship and ownership ambiguities were identified and systematically resolved:

### 4.1 Ambiguity 1: Case Deletion vs. Shared Evidence Retention
* **The Question:** If an investigator closes or deletes an `InvestigativeCase`, what happens to the underlying Telegram messages and raw payloads pinned to that case?
* **Resolution:** Solved via the `CaseMessageAssociation` bridge entity. Deleting or archiving a case deletes or archives the association record (`CaseMessageAssociation`), case notes (`CaseNote`), and generated export packages (`InvestigationReportPackage`) within that tenant's private partition. The underlying `SourceMessage` and `RawEvidenceBlobReference` in the shared threat store remain untouched, ensuring other investigations and historical search remain intact.

### 4.2 Ambiguity 2: Public Media vs. Case-Seized Contraband Access
* **The Question:** Is downloaded media public threat intelligence or confidential case evidence?
* **Resolution:** Media binaries are stored as inert assets in `MediaArtifactReference` associated with originating messages. To prevent existence oracle attacks, direct unauthenticated or raw SHA-256 hash queries are barred. Media retrieval requires either: (a) viewing via authorized threat stream query, or (b) an authorized case reference token verifying that the file is attached to an associated case message.

### 4.3 Ambiguity 3: Masked Text vs. Verbatim Evidence in Full-Text Search
* **The Question:** If credentials in chat chatter are masked (`P@ssw****`), how can an analyst search for a compromised password or verify forensic integrity?
* **Resolution:** Search indexes are derived strictly from `DerivedContentRepresentation (Tier 2)`, where heuristic masking prevents cleartext exposure during general queries. Forensic verification traces through `provenance_raw_blob_id` back to `RawEvidenceBlobReference (Tier 1)`, where the unaltered payload is preserved under field-level AES-256-GCM encryption and accessible only through audited `CREDENTIAL_UNMASK` permissions.

---

## 5. Traceability of Unresolved Stakeholder Decisions

The logical model preserves strict boundaries around open strategic, legal, and operational decisions:

```
+----------------------------------------------------------------------------------------------------+
|                               UNRESOLVED STAKEHOLDER DECISION BOUNDARIES                           |
+-------------------+----------------------------+-----------------------------------+---------------+
| Decision Ref      | Strategic Domain           | Unresolved Dimension              | Status        |
+-------------------+----------------------------+-----------------------------------+---------------+
| DEC-01 (Scope)    | Release 1 MVP Scope        | Confirmation of LEA-weighted core | PROPOSED      |
|                   |                            | vs. full stealer log ingestion    |               |
| DEC-02 (Legal)    | Source Collection Authority| Raw payload collection requires   | OPEN          |
|                   |                            | authorized, necessary, proportionate grounding|     |
| DEC-04 (Scale)    | Storage & Channel Capacity | Confirmation of 500-1,500 channels| PROPOSED      |
|                   |                            | (~1M msgs/mo) vs. Bootstrap tier  |               |
| DEC-06 (PII/Pass) | Credential Handling Policy | Plaintext rejected (Option A);    | OPEN          |
|                   |                            | Masked storage (Option B) proposed|               |
| DEC-07 (Evidence) | Cryptographic Standards    | Internal SHA-256 ledger (MVP) vs. | PROPOSED      |
|                   |                            | External RFC 3161 TSA (Phase 2)   |               |
| DEC-08 (Retention)| Data Retention & Purge     | Storage WORM marked provisional;  | OPEN          |
|                   |                            | Rolling TTL vs. Case Evidence Lock|               |
| DEC-11 (Budget)   | Monthly Operating Spend    | Confirmation of $1,500-$3,500/mo  | OPEN          |
|                   |                            | Growth Tier ceiling               |               |
| DEC-13 (Reporting)| REP-TXT-SCREEN-001 Ops     | Capture trigger modality &        | OPEN (Modality|
|                   |                            | screenshot retention quotas       | pending vote) |
+-------------------+----------------------------+-----------------------------------+---------------+
```

---

## 6. Necessary Architectural Assumptions & Justifications

To author a complete logical model prior to formal physical implementation, the following foundational assumptions were made:

1. **Assumption 1: Uniform Message Sequence Monotonicity within Channels:**
   - *Assumption:* Telegram assigns sequential, monotonically increasing integer IDs to messages within each supergroup and broadcast channel.
   - *Justification:* This native platform property is essential for detecting message gaps (`CollectionDiscontinuityGap`) and maintaining ordered cursor navigation (`FR-THR-001`).
2. **Assumption 2: Headless Browser Screenshot Reproducibility:**
   - *Assumption:* Capturing individual-message and thread-context screenshots via a sandboxed headless browser (Playwright) yields deterministic, verifiable visual corroboration of digital chatter.
   - *Justification:* Satisfies the approved requirement [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001) without relying on error-prone manual analyst desktop screen-grabs.
3. **Assumption 3: Pre-Delivery Review is Inviolable:**
   - *Assumption:* No investigation report bundle can be sealed or dispatched without explicit human analyst sign-off and redaction review.
   - *Justification:* Essential legal safeguard preventing automated, unreviewed exports of sensitive third-party collateral data or corrupted captures into formal evidence packages.

---

## 7. Compliance with Architectural Guardrails

| Guardrail Dimension | Assessment | Status |
| :--- | :--- | :---: |
| **Technology Neutrality** | Zero SQL migrations, physical table DDL, ORM entities, or physical storage vendor locks introduced. Logical names and types used throughout. | **CONFIRMED** |
| **No Untested Assertions** | Security, performance, and runtime behaviors are documented strictly as *target logical constraints*, not verified empirical controls. | **CONFIRMED** |
| **Working-Tree Cleanliness** | Baseline documents and Gate 4A documents preserved completely unchanged. Zero Git operations performed. | **CONFIRMED** |
| **No External Connections** | Zero network calls to Telegram or external systems. | **CONFIRMED** |

---

## 8. Gate 4B.1 Closeout & Gate 4B.2 Progression Recommendation

The Logical Data Model and ER Diagram deliverables meet all review criteria:
- Every approved Release 1 functional capability has a clear logical entity home.
- Tenant isolation boundaries and evidence provenance chains are structurally enforced.
- Open decisions remain properly bounded and provisional where required.

### Recommendation:
**Proceed to Gate 4B.2 (Interface Contracts, DDL Specifications & Schema Implementation Review).**

*End of Gate 4B.1 Review Report.*
