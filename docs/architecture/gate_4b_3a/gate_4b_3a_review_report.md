# TTI Gate 4B.3A — Physical Database Design Review Report

## 1. Document Control & Executive Verdict

| Document Property | Specification |
| :--- | :--- |
| **Document UID** | `TTI-ARCH-G4B3A-RPT-001` |
| **Review Stage** | Gate 4B.3A — Physical Database Design Review |
| **Review Date** | 2026-10-29 |
| **Lead Roles** | Principal Data Architect & Security Architect |
| **Repository Path** | `docs/architecture/gate_4b_3a/gate_4b_3a_review_report.md` |
| **Canonical Sources** | [`decision_and_traceability_matrix.md`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md)<br>[`security_and_evidence_requirements.md`](file:///d:/TTI/docs/product/product_baseline/security_and_evidence_requirements.md)<br>[`architecture_decision_register.md`](file:///d:/TTI/docs/architecture/gate_4a/architecture_decision_register.md)<br>[`logical_data_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/logical_data_model.md)<br>[`tenant_isolation_and_data_ownership.md`](file:///d:/TTI/docs/architecture/gate_4b_1/tenant_isolation_and_data_ownership.md)<br>[`evidence_provenance_and_retention_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/evidence_provenance_and_retention_model.md)<br>[`api_contracts.md`](file:///d:/TTI/docs/architecture/gate_4b_2/api_contracts.md)<br>[`subsystem_interface_contracts.md`](file:///d:/TTI/docs/architecture/gate_4b_2/subsystem_interface_contracts.md) |
| **Gate Verdict** | **PASS — PHYSICAL DATABASE DESIGN REVIEW COMPLETE** |

> [!IMPORTANT]
> **Stage Restriction & Implementation Boundary:**
> This review represents a formal engineering design and review checkpoint. In accordance with the Gate 4B.3A mandate, **no executable SQL DDL, database migration files, ORM entities, application repositories, or automated tests have been generated or modified.** Implementation of physical database artifacts remains strictly barred until authorized under Gate 4B.3B or Gate 5.

---

## 2. Gate 4B.3A Deliverables Inventory

The physical database design review has produced five comprehensive design documents located under `docs/architecture/gate_4b_3a/`. All documents have been reviewed and validated against baseline functional, security, and architectural invariants.

| # | Deliverable File | Target Path | Scope & Subject Matter | Review Status |
| :-: | :--- | :--- | :--- | :--- |
| 1 | **Physical Schema Design** | [`physical_schema_design.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md) | Complete translation of all 22 Gate 4B.1 logical entities into 5 relational schemas (`iam`, `threat`, `evidence`, `app`, `audit`). Comprehensive specification of columns, data types, nullability, defaults, primary keys, foreign keys, check constraints, and referential integrity deletion semantics. | **PASS / APPROVED** |
| 2 | **Tenant Security & Constraints** | [`tenant_security_and_constraints.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md) | Multi-tenant defense-in-depth model. Fail-closed Restrictive Row-Level Security (RLS) policies across all 12 `app.*` tables. Connection pool dirty context bleed mitigations (`SET LOCAL`, `DISCARD ALL`). Anti-oracle protection for media lookups. Cryptographic immutability and `DEC-08` legal retention reconciliation. | **PASS / APPROVED** |
| 3 | **Indexing & Query Design** | [`indexing_and_query_design.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md) | Indexing architecture aligned with Release 1 query access patterns. Composite B-Tree indexes, partial indexes for forum topics, and GIN trigram indexes (`pg_trgm`) on derived chat content. Write-amplification budget and evaluation of the 10M-message OpenSearch transition trigger. | **PASS / APPROVED** |
| 4 | **Migration & Rollback Strategy** | [`migration_and_rollback_strategy.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/migration_and_rollback_strategy.md) | Seven-phase ordered migration deployment DAG. Linear Alembic versioning standards. Zero-downtime Expand/Contract migration lifecycle. Disaster recovery prerequisites (PITR, basebackups). Forensic rollback limits prohibiting destruction of Tier 1 evidence blobs or audit logs. Pre-release Tenant Isolation Verification Test (IVT) suite. | **PASS / APPROVED** |
| 5 | **Review Report** | [`gate_4b_3a_review_report.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/gate_4b_3a_review_report.md) | Executive gate evaluation, deliverables inventory, canonical decisions traceability matrix, analysis of unresolved decisions, multi-tenant risk audit, and provisional technology framing. | **PASS / APPROVED** |

---

## 3. Master Requirements and Canonical Decisions Traceability Matrix

The physical database design maintains 100% traceability to canonical Product Baseline requirements, architectural decisions, and interface contracts.

### 3.1 Stakeholder Decisions Traceability

| Decision UID | Canonical Decision Title & Baseline Scope | Physical Schema Design Implementation | Verification Mechanism | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`DEC-01`** | **Scope:** Minimum Release Scope for TTI Phase 1 (MVP). | Physical schema models focused Telegram chat core + basic breach metadata; strictly excludes dark-web Tor scrapers, facial recognition, and visual canvas graphs. | Schema table inventory audit (0 deferred tables). | **PROPOSED RECOMMENDATION** |
| **`DEC-02`** | **Legal / Source:** Source Permissions & Collection Legal Grounding. | Physical schema enforces collection prerequisite on raw payloads (`evidence.raw_evidence_blobs`), collected only where authorized, necessary, and proportionate. | Schema DDL specifications ([`physical_schema_design.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#5-evidence-vault-schema-evidence)) | **OPEN QUESTION** |
| **`DEC-03`** | **Collection:** Operational Architecture for Telegram Collection. | Centralized cloud collector fleet mapped to `threat.source_connectors` and `threat.ingestion_job_runs`, streaming continuous sequence histories and recording gap markers (`threat.collection_discontinuity_gaps`). | Schema DDL specifications ([`physical_schema_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#4-threat-store--ingestion-schema-threat)) | **PROPOSED RECOMMENDATION** |
| **`DEC-04`** | **Scale:** Target Ingestion Volume & Scale for Phase 1. | Sizing model configured for 500–1,500 channels (~1M msgs/month). In-engine PostgreSQL trigram search sized for Phase 1, with 10M-message OpenSearch transition trigger. | Indexing Catalogue ([`indexing_and_query_design.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#5-scaling-thresholds--opensearch-transition-trigger)) | **PROPOSED TARGET** |
| **`DEC-05`** | **Tenancy:** Tenant Isolation & Multi-Tenancy Architecture. | Implemented via 5 schemas: shared threat store (`threat.*`, `evidence.*`) + tenant-isolated case workspace (`app.*`) guarded by Restrictive RLS policies and `tenant_id` foreign keys. | RLS Fail-Closed Policy Matrix ([`tenant_security_and_constraints.md#section-2`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md#2-tenant-isolation-invariants--rls-policy-matrix)) | **PROPOSED RECOMMENDATION** |
| **`DEC-06`** | **Privacy / PII:** Credential & Personal Data Handling. | Plaintext rejected. Derived searchable text tier (`threat.derived_content_representations`) enforces heuristic masking (`P@ssw****`) and field-level encryption. | Schema DDL specifications ([`physical_schema_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#4-threat-store--ingestion-schema-threat)) | **OPEN QUESTION** |
| **`DEC-07`** | **Evidence:** Cryptographic Evidence Integrity Standards. | Verbatim original evidence in `evidence.raw_evidence_blobs` and media in `evidence.media_artifacts` protected by cryptographic SHA-256 digests and immutability triggers. | Evidence Vault Specifications ([`physical_schema_design.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#5-evidence-vault-schema-evidence)) | **PROPOSED RECOMMENDATION** |
| **`DEC-08`** | **Retention:** Data Retention & Lifecycle Purge Policies. | WORM Object Lock marked provisional; zero automated purges in schema; `retention_policy_assignments` models legal holds; controlled exception process proposed for lawful purges. | Legal Hold Model ([`tenant_security_and_constraints.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md#5-three-tier-evidence-lifecycle--dec-08-legal-retention-reconciliation)) | **UNRESOLVED PENDING LEGAL REVIEW** |
| **`DEC-11`** | **Budget / Cost:** Monthly Operational Infrastructure Budget Ceiling. | Database compute and replication topologies planned within $1,500–$3,500/month operational budget ceiling. | Budget sizing analysis ([`indexing_and_query_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#4-write-amplification--maintenance-overhead)) | **OPEN QUESTION** |
| **`DEC-12`** | **Packaging:** Product Packaging & SKU Differentiation. | Unified core platform with role-based feature modules mapped in `iam.roles` and `iam.tenant_memberships`. | IAM Schema Specifications ([`physical_schema_design.md#section-3`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#3-iam-schema-iam)) | **PROPOSED RECOMMENDATION** |
| **`DEC-13`** | **Reporting:** Reporting Deliverables & Dual Screenshots. | Dedicated tables `app.text_report_documents`, `app.message_screenshots`, and `app.thread_context_screenshots` implementing approved `REP-TXT-SCREEN-001`. Screenshot sidecar is provisional. | Reporting Schema ([`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app)) | **`CONFIRMED (APPROVED BY VFRA)`** |

*(Note: Candidate features for Threat Actor Profiling [`OPP-004`] and Multi-Source Correlation [`OPP-005`] remain deferred to Release 2 and are strictly excluded from the physical schema.)*

---

### 3.2 Requirements Coverage Matrix

| Requirement UID | Description | Physical Database Design Control | Design Artifact Reference |
| :--- | :--- | :--- | :--- |
| **`FR-ING-001`** | Ingest Telegram channels & messages | `threat.source_channels`, `threat.source_messages` tables. | [`physical_schema_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#4-threat-store--ingestion-schema-threat) |
| **`FR-ING-002`** | Forum topic & thread reconstruction | `threat.forum_topics`, `threat.source_messages.message_thread_id`. | [`physical_schema_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#4-threat-store--ingestion-schema-threat) |
| **`FR-ING-003`** | Sequence gap detection | `threat.collection_discontinuity_gaps` table. | [`physical_schema_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#4-threat-store--ingestion-schema-threat) |
| **`FR-ING-004`** | Edited / deleted message revision history | `threat.message_revision_records` table. | [`physical_schema_design.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#4-threat-store--ingestion-schema-threat) |
| **`FR-ING-005`** | Media attachment metadata & hash capture | `evidence.media_artifacts` with SHA-256 digests. | [`physical_schema_design.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#5-evidence-vault-schema-evidence) |
| **`FR-SRCH-001`** | Full-text and keyword search | GIN Trigram index (`gin_trgm_ops`) on `threat.derived_content_representations.search_vector_trgm`. | [`indexing_and_query_design.md#section-3`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#3-full-text-and-trigram-search-indexing) |
| **`FR-SRCH-002`** | Channel, author, and date-range filtering | Composite B-Tree indexes: `(channel_id, telegram_message_id)`, `(channel_id, timestamp_utc)`. | [`indexing_and_query_design.md#section-2`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#2-b-tree-composite-indexing-catalogue) |
| **`FR-SRCH-003`** | Saved search queries | `app.saved_search_queries` table with tenant isolation. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-CASE-001`** | Case workspace creation & lifecycle | `app.investigative_cases` table with tenant ownership. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-CASE-002`** | Pinning messages to investigative cases | `app.case_message_associations` table (`RESTRICT` on delete). | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-CASE-003`** | Case notes and analyst annotations | `app.case_notes` table with versioning. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-REP-001`** | Export investigative cases | `app.investigation_report_packages`, `app.evidence_package_manifests`. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-REP-002`** | Generate text report with screenshots (`REP-TXT-SCREEN-001`) | `app.text_report_documents`, `app.message_screenshots`, `app.thread_context_screenshots`. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-REP-003`** | Evidence package verification manifests | `app.evidence_package_manifests` with SHA-256 package hash. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-WL-001`** | Watchlist keyword & entity rules | `app.watchlist_rules` table with tenant isolation. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-WL-002`** | Automated alert event generation | `app.watchlist_alert_events` table with triage workflow. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`FR-WL-003`** | Alert triage & promotion to case | Composite index on `(tenant_id, triage_status, triggered_at)`. | [`indexing_and_query_design.md#section-2`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#2-b-tree-composite-indexing-catalogue) |
| **`FR-ADM-001`** | Multi-tenant organization administration | `iam.tenant_organizations` table with operational quotas. | [`physical_schema_design.md#section-3`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#3-iam-schema-iam) |
| **`FR-ADM-002`** | Role-Based Access Control (RBAC) | `iam.roles`, `iam.role_permissions`, `iam.tenant_memberships`. | [`physical_schema_design.md#section-3`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#3-iam-schema-iam) |
| **`FR-ADM-003`** | Audit logging of analyst and admin actions | `audit.audit_event_records` table (Append-only). | [`physical_schema_design.md#section-7`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#7-audit-ledger-schema-audit) |
| **`NFR-SEC-001`** | Multi-tenant isolation | Restrictive RLS policies, `SET LOCAL app.current_tenant_id`, pool reset hooks (`DISCARD ALL`). | [`tenant_security_and_constraints.md#section-2`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md#2-tenant-isolation-invariants--rls-policy-matrix) |
| **`NFR-SEC-002`** | Anti-oracle protection for media assets | Tenant-scoped media verification queries preventing cross-tenant existence probes. | [`tenant_security_and_constraints.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md#4-database-query-anti-oracle-protection) |
| **`NFR-SEC-003`** | Tamper-evident evidence storage | Cryptographic SHA-256 digest validation, write-once immutability triggers on `evidence.*`. | [`tenant_security_and_constraints.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md#5-three-tier-evidence-lifecycle--dec-08-legal-retention-reconciliation) |
| **`NFR-REL-001`** | High availability & zero-downtime evolution | Three-stage Expand/Contract migration pattern, non-blocking concurrent index creation. | [`migration_and_rollback_strategy.md#section-4`](file:///d:/TTI/docs/architecture/gate_4b_3a/migration_and_rollback_strategy.md#4-zero-downtime-expandcontract-migration-pattern) |
| **`NFR-REL-002`** | Backup and disaster recovery | PITR with continuous WAL archiving, pre-migration snapshot gates, $\le 5$ min RPO. | [`migration_and_rollback_strategy.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/migration_and_rollback_strategy.md#5-backup-restore-and-disaster-recovery-prerequisites) |
| **`NFR-PERF-001`** | Query latency within bounds | Dedicated composite B-tree indexes, topic partial indexes, write-amplification budget. | [`indexing_and_query_design.md#section-2`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#2-b-tree-composite-indexing-catalogue) |
| **`NFR-PERF-002`** | Search indexing scalability | GIN trigram indexing with explicit 10M-message OpenSearch evaluation trigger. | [`indexing_and_query_design.md#section-5`](file:///d:/TTI/docs/architecture/gate_4b_3a/indexing_and_query_design.md#5-scaling-thresholds--opensearch-transition-trigger) |
| **`NFR-AUD-001`** | Forensic audit trail integrity | Append-only audit ledger excluding UPDATE/DELETE via database triggers, forensic rollback limits. | [`migration_and_rollback_strategy.md#section-7`](file:///d:/TTI/docs/architecture/gate_4b_3a/migration_and_rollback_strategy.md#7-forensic-rollback-limits--evidence-integrity-preservation) |
| **`NFR-AUD-002`** | Non-repudiation of evidence exports | Cryptographic manifest linkage in `app.evidence_package_manifests`. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |
| **`REP-TXT-SCREEN-001`** | Text report with embedded screenshot | Physical tables `app.text_report_documents`, `app.message_screenshots`, `app.thread_context_screenshots`. | [`physical_schema_design.md#section-6`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md#6-tenant-application--case-workspace-schema-app) |

---

## 4. Analysis of Unresolved Decisions & Architectural Constraints

The physical design strictly adheres to baseline boundaries by identifying unresolved decisions and implementing safe, non-preemptive database structures:

1. **`DEC-01` (Minimum Release Scope for Phase 1 MVP):**
   - *Status:* `PROPOSED RECOMMENDATION` (Awaiting formal VFRA executive vote).
   - *Design Impact:* Focuses physical schema strictly on core Telegram chat ingestion, thread reconstruction, and case evidence management. Entities for dark-web Tor scrapers, facial recognition, and visual node-link canvas are strictly excluded.
2. **`DEC-02` (Source Permissions & Collection Legal Grounding):**
   - *Status:* `OPEN QUESTION` (Requires formal Legal Counsel and CTO review).
   - *Design Impact:* Raw payload collection is treated as an evidentiary privilege requiring authorized, necessary, and proportionate grounding. Schema incorporates explicit collection prerequisite constraints on `evidence.raw_evidence_blobs`.
3. **`DEC-03` (Operational Architecture for Telegram Collection):**
   - *Status:* `PROPOSED RECOMMENDATION` (Option A: Centralized Cloud Collector Fleet).
   - *Design Impact:* Physical schema models centralized ingestion via `threat.source_connectors` and `threat.ingestion_job_runs`. Explicitly models forum topics (`message_thread_id`), sequence continuity, and discontinuity gaps (`threat.collection_discontinuity_gaps`), recording gaps as capture events rather than unverified deletion claims.
4. **`DEC-04` (Target Ingestion Volume & Scale for Phase 1):**
   - *Status:* `PROPOSED TARGET` (Option B: 500–1,500 Monitored Channels, ~1M msgs/month).
   - *Design Impact:* Database indexing and write-amplification budgets are optimized for 1M msgs/month on PostgreSQL 16. Full-text and substring search is accommodated via `pg_trgm` GIN indexes, with a documented threshold to evaluate a dedicated OpenSearch cluster at $\ge 10\text{M}$ messages.
5. **`DEC-05` (Tenant Isolation & Multi-Tenancy Architecture):**
   - *Status:* `PROPOSED RECOMMENDATION` (Option B: Shared Threat Store + Isolated Case Workspace with RLS).
   - *Design Impact:* Implemented as a pooled, shared-database model: shared threat intelligence resides in `threat.*` and `evidence.*`, while sensitive customer cases reside in `app.*` protected by PostgreSQL Restrictive Row-Level Security (`AS RESTRICTIVE`) and transaction-scoped context management (`SET LOCAL`).
6. **`DEC-06` (Credential & Personal Data Handling):**
   - *Status:* `OPEN QUESTION` (Option B: Masked Storage with RBAC Unmasking proposed; Option A Plaintext REJECTED).
   - *Design Impact:* Plaintext credential storage is barred. Derived searchable text representations (`threat.derived_content_representations`) enforce heuristic regex masking (`P@ssw****`) and field-level encryption. (Threat actor profiling dossiers remain deferred to Release 2).
7. **`DEC-07` (Cryptographic Evidence Integrity Standards):**
   - *Status:* `PROPOSED RECOMMENDATION` (Option B: Internal Immutable Ledger with SHA-256).
   - *Design Impact:* Absolute physical separation between verbatim raw evidence (`evidence.raw_evidence_blobs`) and derived presentations. Ingestion SHA-256 digests and package manifests ensure non-repudiation. (Multi-source cross-platform correlation is deferred to Release 2).
8. **`DEC-08` (Retention Schedule & Legal Review):**
   - *Status:* **`UNRESOLVED PENDING FORMAL LEGAL COUNSEL REVIEW`**.
   - *Design Impact:* Hardware WORM / Object Lock Compliance Mode is provisional and barred from Release 1. Zero automated purge scripts, TTL drops, or cascading deletions exist in the physical schema. The `retention_policy_assignments` entity models legal holds. A proposed controlled exception process allows lawful court-ordered suppression under verified judicial orders, separation of duties, least privilege, and auditable logging.
9. **`DEC-11` (Monthly Operational Infrastructure Budget Ceiling):**
   - *Status:* `OPEN QUESTION` (Option B: $1,500–$3,500/month growth tier).
   - *Design Impact:* Ingestion worker scaling, database compute sizing, and single-region replication topology are bounded to fit within this ceiling.
10. **`DEC-12` (Product Packaging & SKU Differentiation):**
    - *Status:* `PROPOSED RECOMMENDATION` (Option A: Single Unified Platform with Role-Based Feature Modules).
    - *Design Impact:* Unified database schema supporting both Law Enforcement and Corporate SOC profiles via granular permissions in `iam.roles` and `iam.tenant_memberships`.
11. **`DEC-13` (Reporting Deliverables & Dual Screenshots):**
    - *Status:* **`CONFIRMED (APPROVED BY VFRA)`** (`REP-TXT-SCREEN-001`).
    - *Design Impact:* Physical tables `app.text_report_documents`, `app.message_screenshots`, and `app.thread_context_screenshots` implement the approved text report with embedded individual and thread screenshots. Screenshot capture modality (headless Chromium sidecar) is a provisional engineering recommendation.

---

## 5. Multi-Tenant Security & Isolation Defense-in-Depth Summary

The review evaluated the physical schema against cross-tenant attack vectors:

```
+---------------------------------------------------------------------------------------------------+
| MULTI-TENANT DEFENSE-IN-DEPTH ARCHITECTURE                                                        |
+---------------------------------------------------------------------------------------------------+
  |
  +--> [Layer 1: Restrictive Row-Level Security (RLS)]
  |    All 12 app.* tables enforce AS RESTRICTIVE policies.
  |    Evaluates NULLIF(current_setting('app.current_tenant_id', true), '')::UUID = tenant_id.
  |    Missing or unauthenticated context fails closed (0 rows visible).
  |
  +--> [Layer 2: Transaction-Scoped Context Management]
  |    All application transactions issue SET LOCAL app.current_tenant_id.
  |    Scope automatically terminates on COMMIT / ROLLBACK.
  |
  +--> [Layer 3: Connection Pooler Context Hygiene]
  |    Checkout/checkin hooks execute DISCARD ALL / RESET ALL.
  |    Eliminates session state leakage across connection reuse.
  |
  +--> [Layer 4: Anti-Oracle Query Protection]
  |    Raw SHA-256 media existence queries are strictly barred.
  |    Media lookups require JOIN through tenant-scoped case associations.
  |
  +--> [Layer 5: Pre-Release Tenant Isolation Verification Test (IVT) Suite]
       Mandatory automated smoke suite in deployment pipeline verifying
       zero cross-tenant leakage before production migration activation.
```

---

## 6. Provisional Technology Framing Statement

In accordance with architectural review standards, all underlying technology selections specified in Gate 4B.3A are explicitly recognized as **provisional engineering recommendations** under [`ADR-002`](file:///d:/TTI/docs/architecture/gate_4a/architecture_decision_register.md), pending final architectural confirmation:
- **PostgreSQL 16:** Provisional relational database engine target.
- **pg_trgm:** Provisional in-engine trigram search extension for Release 1 text search.
- **Alembic:** Provisional database migration management framework.
- **Redis 7.2 & Celery:** Provisional asynchronous task execution and rate-limiting infrastructure.
- **MinIO / AWS S3:** Provisional object storage tier for raw evidence and media artifacts.

**No technology approval has been invented or assumed.** The physical schema design is structured such that ANSI-standard relational semantics are preserved, ensuring adaptability should alternative database engines be mandated by stakeholders.

---

## 7. Stage Restrictions & Next Steps Transition

### 7.1 Stage Restriction Reaffirmation
- The Gate 4B.3A deliverables are **documentation only**.
- Zero executable SQL files, migration scripts, ORM models, or test suites have been committed or added to application source trees.
- Git working tree remains clean of unapproved changes.

### 7.2 Gate Transition Recommendations
Upon stakeholder and architectural approval of this Gate 4B.3A review report, the project is authorized to proceed to:
1. **Gate 4B.3B (Database Implementation & DDL Generation):**
   - Generation of executable PostgreSQL 16 DDL scripts based strictly on `physical_schema_design.md`.
   - Creation of baseline Alembic migration scripts adhering to the linear DAG and zero-downtime guidelines in `migration_and_rollback_strategy.md`.
   - Authoring of SQLAlchemy 2.0 ORM entity definitions mirroring the physical schema specifications.
2. **Gate 5 (Application Integration Sprint):**
   - Integration of connection pooling hooks, RLS context interceptors, and Celery ingestion workers.
