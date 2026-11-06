# TTI Gate 4B.3A — Database Migration, Evolution, and Rollback Strategy

## 1. Document Control & Objective

| Document Property | Specification |
| :--- | :--- |
| **Document UID** | `TTI-ARCH-G4B3A-MIGRATE-001` |
| **Stage & Classification** | Gate 4B.3A — Physical Database Design Review / Engineering Design Only |
| **Target Repository Path** | `docs/architecture/gate_4b_3a/migration_and_rollback_strategy.md` |
| **Canonical Dependencies** | [`decision_and_traceability_matrix.md`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md)<br>[`architecture_decision_register.md`](file:///d:/TTI/docs/architecture/gate_4a/architecture_decision_register.md)<br>[`logical_data_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/logical_data_model.md)<br>[`physical_schema_design.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/physical_schema_design.md)<br>[`tenant_security_and_constraints.md`](file:///d:/TTI/docs/architecture/gate_4b_3a/tenant_security_and_constraints.md) |
| **Design Status** | **Provisional Architecture Recommendation** (Pending confirmed architecture decision for PostgreSQL 16 per [`ADR-002`](file:///d:/TTI/docs/architecture/gate_4a/architecture_decision_register.md)) |

> [!IMPORTANT]
> **Stage Restriction & Implementation Boundary:**
> This document is an implementation-independent migration, evolution, and rollback strategy. It establishes the technical procedures, validation gates, zero-downtime evolution patterns, and forensic rollback limits for the Telegram Threat Intelligence (TTI) relational database. In compliance with the Gate 4B.3A design mandate, **no executable SQL DDL, Python migration scripts (e.g., Alembic files), ORM models, or test scripts are created during this stage.**

---

## 2. Ordered Migration Phases & Dependency Topography

To ensure strict referential integrity, eliminate circular dependencies, and prevent security misconfigurations, physical schema deployment must execute in seven strictly ordered phases. Each phase represents an atomic deployment boundary guarded by automated validation gates.

```
+-----------------------------------------------------------------------------------------+
| Phase 0: System Extensions, Schemas, & Security Roles                                   |
| - Extensions: pgcrypto, uuid-ossp, pg_trgm                                              |
| - Schemas: iam, threat, app, evidence, audit                                            |
| - Roles: tti_app_role, tti_ingest_role, tti_admin_role                                  |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 1: Identity & Access Management (IAM)                                             |
| - iam.tenant_organizations, iam.user_profiles                                           |
| - iam.roles, iam.role_permissions, iam.tenant_memberships                               |
+-----------------------------------------------------------------------------------------+
                    |                                                     |
                    v                                                     v
+---------------------------------------+   +---------------------------------------------+
| Phase 2: Ingestion & Threat Store     |   | Phase 3: Cryptographic Evidence Vault       |
| - threat.source_connectors            |   | - evidence.raw_evidence_blobs (Tier 1)      |
| - threat.ingestion_job_runs           |   | - evidence.media_artifacts (Tier 1)         |
| - threat.source_channels              |   +---------------------------------------------+
| - threat.forum_topics                 |                          |
| - threat.source_messages              |                          |
| - threat.collection_discontinuity_gaps|                          |
| - threat.message_revision_records     |                          |
| - threat.derived_content_reps (Tier 2)|                          |
+---------------------------------------+                          |
                    |                                              |
                    +----------------------+-----------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 4: Tenant Application & Case Workspace                                            |
| - app.investigative_cases, app.case_message_associations, app.case_notes                |
| - app.saved_search_queries, app.watchlist_rules, app.watchlist_alert_events             |
| - app.investigation_report_packages, app.text_report_documents (REP-TXT-SCREEN-001)      |
| - app.message_screenshots, app.thread_context_screenshots (DEC-13)                      |
| - app.evidence_package_manifests, app.retention_policy_assignments                      |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 5: Row-Level Security (RLS) & Immutability Triggers                               |
| - audit.audit_event_records (Append-Only)                                               |
| - Restrictive RLS Policies applied to all app.* tables                                  |
| - Immutability trigger functions (FOR EACH ROW preventing UPDATE/DELETE on Tier 1/3)    |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 6: Performance Indexes & Trigram Text Accelerators                                |
| - B-Tree Composite Indexes (Tenant + CreatedAt, Channel + SequenceGap)                  |
| - Partial Indexes (Forum Topics, Non-Deleted Cases)                                     |
| - GIN Trigram Search Indexes (pg_trgm on threat.derived_content_representations)        |
+-----------------------------------------------------------------------------------------+
```

### Detailed Phase Execution Breakdown

| Phase | Target Scope | Objects Created / Modified | Inter-Phase Dependencies |
| :--- | :--- | :--- | :--- |
| **Phase 0** | Infrastructure & Security Primitives | PostgreSQL extensions (`pgcrypto`, `uuid-ossp`, `pg_trgm`); Database schemas (`iam`, `threat`, `evidence`, `app`, `audit`); Least-privilege application roles (`tti_app_role`, `tti_ingest_role`, `tti_admin_role`). | Base PostgreSQL instance must be online and initialized. Requires superuser or DB owner privileges. |
| **Phase 1** | Identity & Access Management | Tables: `iam.tenant_organizations`, `iam.user_profiles`, `iam.roles`, `iam.tenant_memberships`, `iam.active_user_sessions`, and minimal `audit.audit_event_records` (pulled forward per `DEC-17`). Dynamic `iam.role_permissions` deferred to Release 2 per `DEC-14`. Role privilege grants applied per `DEC-16` and `DEC-18`. Baseline system roles seeded. | Depends on Phase 0. Must complete before any multi-tenant entities can reference `tenant_id` or `user_id`. |
| **Phase 2** | Threat Store & Ingestion Pipeline | Tables: `threat.source_connectors`, `threat.ingestion_job_runs`, `threat.source_channels`, `threat.forum_topics`, `threat.source_messages`, `threat.collection_discontinuity_gaps`, `threat.message_revision_records`, `threat.derived_content_representations`. | Depends on Phase 0 and Phase 1 (`user_profiles` for connector ownership audit). |
| **Phase 3** | Evidence Vault | Tables: `evidence.raw_evidence_blobs`, `evidence.media_artifacts`. Cryptographic hash unique indexes (`sha256_hex`). | Depends on Phase 0 and Phase 2 (`source_messages` for foreign key linkage). |
| **Phase 4** | Case Workspace & Reporting | Tables: `app.investigative_cases`, `app.case_message_associations`, `app.case_notes`, `app.saved_search_queries`, `app.watchlist_rules`, `app.watchlist_alert_events`, `app.investigation_report_packages`, `app.text_report_documents`, `app.message_screenshots`, `app.thread_context_screenshots`, `app.evidence_package_manifests`, `app.retention_policy_assignments`. | Depends on Phase 1 (`tenant_organizations`, `user_profiles`), Phase 2 (`source_messages`), and Phase 3 (`media_artifacts`). |
| **Phase 5** | Security Policies & Audit Ledger | Table: `audit.audit_event_records`. Row-Level Security activation (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY; ALTER TABLE ... FORCE ROW LEVEL SECURITY;`) on all 12 `app.*` tables. Restrictive RLS security policies. Immutability trigger functions attached to `evidence.*` and `audit.*`. | Depends on Phases 1 through 4. RLS cannot be enforced until tenant foreign key tables and application tables exist. |
| **Phase 6** | Indexes & Query Optimization | Composite B-Tree indexes, partial indexes, and GIN trigram indexes (`gin_trgm_ops`). Executed using concurrent index creation patterns to prevent blocking DML operations. | Depends on Phases 1 through 5. Applying indexes after initial table definitions enables non-blocking deployment during zero-downtime upgrades. |

---

## 3. Migration Versioning & Tooling Protocol (Alembic Framework Architecture)

The TTI platform adopts **Alembic** (in conjunction with SQLAlchemy metadata definitions) as the provisional database migration tool. To ensure complete auditability, determinism, and compatibility with continuous deployment pipelines, migrations must adhere to strict structural constraints.

### 3.1 Linear Migration Dependency DAG
- **No Split Branches:** Branching in migration histories (`alembic merge`) is strictly prohibited in the release pipeline. The migration tree must form a strictly linear, monotonically increasing Directed Acyclic Graph (DAG).
- **Sequential Revision Identifiers:** Each migration script must be prefixed with an ISO-8601 UTC timestamp and a deterministic semantic slug:
  ```text
  migrations/versions/
  ├── 20261101_000001_phase0_extensions_and_schemas.py
  ├── 20261101_000002_phase1_iam_core.py
  ├── 20261101_000003_phase2_threat_store.py
  ├── 20261101_000004_phase3_evidence_vault.py
  ├── 20261101_000005_phase4_app_workspace.py
  ├── 20261101_000006_phase5_audit_and_rls.py
  └── 20261101_000007_phase6_indexes_and_trigram.py
  ```
- **Explicit Head Resolution:** CI/CD validation gates must execute `alembic heads` to ensure that exactly one head revision exists prior to allowing pull request merges.

### 3.2 Transactional DDL Boundaries and Non-Transactional Exceptions
- **Transactional DDL Default:** PostgreSQL natively supports transactional DDL (`CREATE TABLE`, `ALTER TABLE ADD COLUMN`, `DROP VIEW`, etc.). All standard schema migrations must execute inside an explicit database transaction (`transaction_per_migration = True` in Alembic configuration). If any step within a migration fails, the entire transaction rolls back cleanly, leaving the database in its previous valid state.
- **Non-Transactional DDL Exception (`CREATE INDEX CONCURRENTLY`):**
  - PostgreSQL does **not** allow `CREATE INDEX CONCURRENTLY` or `DROP INDEX CONCURRENTLY` inside an active transaction block.
  - Migrations introducing large indexes (especially Phase 6 GIN trigram indexes on `threat.derived_content_representations`) must set Alembic execution mode to autocommit (`connection.execution_options(isolation_level="AUTOCOMMIT")`).
  - Index migrations must be isolated into dedicated revision files containing zero structural DDL operations.

### 3.3 Strict Separation of DDL and DML
- **DDL Only in Migration Scripts:** Alembic migration scripts are strictly reserved for structural DDL (table definitions, constraint modifications, RLS policy declarations, index operations).
- **No High-Volume DML in Migrations:** Large-scale data transformations, historical backfills, or cross-table data copying must **never** be placed inside Alembic migration scripts. Such operations hold lock queues, extend transaction durations, trigger replication lag, and risk catastrophic timeouts during production deployment.
- **Independent Backfill Worker Jobs:** Data backfills must be authored as standalone, idempotently resumable background worker tasks executed via Celery background workers after DDL deployment has succeeded.

---

## 4. Zero-Downtime Expand/Contract Migration Pattern

To maintain compliance with high-availability operational requirements ([`NFR-REL-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md)) and prevent service interruption for continuous threat monitoring, schema changes must execute using the three-stage **Expand / Migrate / Contract** pattern.

```
+---------------------------------------------------------------------------------------------------+
| Stage 1: EXPAND                                                                                   |
| - Add new nullable column or new table alongside existing structures.                             |
| - Deploy application version N supporting both old and new schema structures.                     |
| - Both v(N-1) and v(N) run concurrently without failure.                                          |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| Stage 2: MIGRATE (Backfill & Dual-Write)                                                          |
| - Application v(N) dual-writes to both old and new columns.                                       |
| - Background worker task incrementally backfills historical data in throttled batches.             |
| - Continuous validation monitors data parity and replication lag.                                 |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| Stage 3: CONTRACT                                                                                 |
| - Deploy application version N+1 reading exclusively from new column.                             |
| - Apply NOT NULL constraint (using NOT VALID -> VALIDATE CONSTRAINT).                             |
| - Drop legacy column or table in a subsequent scheduled maintenance release.                      |
+---------------------------------------------------------------------------------------------------+
```

### 4.1 Forward and Backward Compatibility Rules
Every schema change must be forward and backward compatible with running application code:
1. **Rule 1 (Additive Only in Expand):** Never drop a column, rename a column, or alter a column data type in an Expand migration. New columns must be created as `NULL` or have a safe default value that does not require a full-table rewrite.
2. **Rule 2 (No SELECT * in Application Queries):** Application ORM models and raw queries must explicitly list projected column names. Wildcard projections (`SELECT *`) break application instances when new columns are expanded.
3. **Rule 3 (Safe Constraint Application):** Foreign keys and check constraints on high-volume tables (`source_messages`, `derived_content_representations`) must be added in two phases:
   - *Phase A:* `ALTER TABLE ... ADD CONSTRAINT ... NOT VALID;` (Acquires a brief `ShareUpdateExclusiveLock` without table scan).
   - *Phase B:* `ALTER TABLE ... VALIDATE CONSTRAINT ...;` (Validates existing data concurrently without blocking concurrent read/write queries).

### 4.2 Safe Index Creation Ergonomics
- To prevent locking threat ingestion or analyst case operations:
  ```text
  -- Phase 6 Index Creation Pattern:
  CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_app_cma_case_pinned
      ON app.case_message_associations (case_id, pinned_at DESC);
  ```
- If a concurrent index creation fails due to a network blip or deadlock, PostgreSQL marks the index as `INVALID`. The rollback/retry procedure must explicitly execute `DROP INDEX CONCURRENTLY IF EXISTS <index_name>` before reattempting creation.

---

## 5. Backup, Restore, and Disaster Recovery Prerequisites

Before executing any schema migration in staging or production environments, rigorous disaster recovery prerequisites must be satisfied to guarantee zero data loss and verifiable restore capability.

### 5.1 Point-in-Time Recovery (PITR) & Continuous WAL Archiving
- **Continuous Archiving:** PostgreSQL Write-Ahead Logs (WAL) must be continuously archived to dedicated, immutable secondary storage (e.g., S3/MinIO bucket with separate administrative credentials).
- **Basebackups:** Automated full physical basebackups (`pg_basebackup`) must execute on a 24-hour cycle, retained for a minimum of 30 days.
- **Recovery Point Objective (RPO):** Maximum allowable data loss is $\le 5$ minutes of threat intelligence data, guaranteed by continuous WAL streaming.
- **Recovery Time Objective (RTO):** Database restore and service recovery to fully operational state within $\le 60$ minutes.

### 5.2 Pre-Migration Snapshot Gates
Every deployment pipeline executing database migrations must automate the following pre-flight gates:
1. **Pre-Migration Physical Snapshot:** A cloud storage snapshot (EBS/Ceph volume snapshot) or dedicated database replica snapshot must be confirmed completed within 15 minutes prior to migration execution.
2. **Schema-Only Dump Validation:** A full schema-only export (`pg_dump --schema-only --format=custom`) must be generated and stored alongside the deployment manifest for rapid schema diff analysis.
3. **Staging Rehearsal Verification:** No migration script may execute in production without having executed successfully against an anonymized staging database of equivalent volume within the preceding 48 hours.

---

## 6. Reversible vs. Irreversible Schema Alterations

Database schema changes fall into two distinct operational classes: structurally reversible changes and inherently irreversible changes. The migration strategy defines strict operational protocols for each class.

```
+---------------------------------------------------------------------------------------------------+
| REVERSIBLE ALTERATIONS                                                                            |
| - Adding a new nullable column                                                                    |
| - Creating a new standalone table                                                                 |
| - Adding a new non-blocking index (CONCURRENTLY)                                                  |
| - Adding an additive CHECK constraint (NOT VALID -> VALIDATE)                                     |
| - Creating a new view or read-only function                                                       |
| -> Action on failure: Execute standard Alembic downgrade() script.                               |
+---------------------------------------------------------------------------------------------------+

+---------------------------------------------------------------------------------------------------+
| IRREVERSIBLE ALTERATIONS                                                                          |
| - Dropping an existing column with historical data                                                |
| - Dropping a table or schema                                                                      |
| - Truncating or narrowing column data types (e.g., VARCHAR(255) -> VARCHAR(64), INT8 -> INT4)     |
| - In-place cryptographic re-hashing or destructive redaction                                      |
| - Purging evidence blobs or audit logs                                                            |
| -> Action on failure: Automated downgrade impossible. Requires full PITR restore from backup.     |
+---------------------------------------------------------------------------------------------------+
```

### De-risking Irreversible Changes: The Shadow Column & Deferred Drop Policy
1. **Shadow Columns:** When altering a data type or transforming data, the existing column is never modified in place. A shadow column (e.g., `body_v2`) is introduced. Data is dual-written and backfilled. The old column is kept intact.
2. **Deferred Drop Policy:** Legacy columns are **never dropped in the same release cycle** as their replacement. A column must remain deprecated for a minimum of **two full release cycles ($N+2$)** before a drop migration is scheduled.
3. **Tombstone Marking:** Tables scheduled for retirement are first renamed to an archival schema (`legacy.<table>`) and set to read-only for 30 days before irreversible drop commands are authorized.

---

## 7. Forensic Rollback Limits & Evidence Integrity Preservation

The TTI platform is an evidentiary system serving law-enforcement and corporate investigations. Standard software engineering rollback assumptions ("simply revert to yesterday's database snapshot") are **forensically invalid and legally catastrophic** if applied blindly to evidence stores.

### 7.1 The Immutability Invariant & Forensic Non-Repudiation
- **Verbatim Evidence Invariance:** Raw Telegram messages, attachments, media hashes, and ingestion job manifests stored in `threat.source_messages`, `evidence.raw_evidence_blobs`, and `evidence.media_artifacts` represent seized digital evidence.
- **No Evidentiary Rollback:** If an application rollback occurs due to a defect in case workspace features or UI presentation logic:
  - Application code and `app.*` schema definitions may be downgraded.
  - **Tier 1 evidence blobs, cryptographic SHA-256 hashes, and ingestion records must NEVER be rolled back, overwritten, or deleted.**
  - Reverting the threat store to an earlier snapshot would forge an evidentiary gap, invalidate downstream export package hashes, and destroy chain-of-custody continuity.

### 7.2 Forensic Rollback Decision Matrix

| Layer | Component | Permissible Rollback Action | Prohibited Rollback Action | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1 (Evidence Vault)** | `evidence.raw_evidence_blobs`, `evidence.media_artifacts` | **None.** Append-only. Schema additions only. | Restoring snapshot from prior point in time; deleting blobs; modifying hashes. | Rolling back destroys legally collected evidence and invalidates verified SHA-256 manifests. |
| **Tier 1 (Threat Store)** | `threat.source_messages`, `threat.forum_topics`, `threat.collection_discontinuity_gaps` | **None.** Forward-only migration. | Reverting table to drop newly ingested messages. | Ingestion gaps and sequence histories must preserve continuous capture timelines. |
| **Tier 2 (Derived Layer)** | `threat.derived_content_representations` | Re-running redaction/masking algorithms; backfilling updated transformations. | Dropping without regeneration capability. | Derived data can be recomputed from Tier 1 verbatim evidence blobs at any time. |
| **Tier 3 (Application Cases)** | `app.investigative_cases`, `app.case_message_associations`, `app.case_notes` | Soft-state rollback; schema downgrade of case metadata tables via Alembic `downgrade()`. | Hard deletion of case audit trails or report packages. | Analyst workflows can be restored, but associated audit records must be preserved. |
| **Tier 3 (Audit Ledger)** | `audit.audit_event_records` | **None.** Strictly append-only. | Deleting, modifying, or truncating audit logs during rollback. | Audit log must record the rollback event itself as a high-severity security event. |

### 7.3 Reconciliation with Legal Review (`DEC-08`)
- In compliance with [`DEC-08`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md), long-term retention policies, statutory erasure workflows, and GDPR/privacy purge mechanisms remain **unresolved pending formal legal counsel review**.
- **Provisional Immutability & Exception Protocol:** Hardware-enforced WORM / Object Lock Compliance Mode remains strictly **provisional**. Software-level immutability triggers (`trg_prevent_raw_evidence_mutation` and `trg_prevent_audit_tampering`) block ordinary application mutation and deletion. If an authorized judicial suppression or statutory compliance order requires expungement:
  - Technical bypass is governed by a **proposed controlled exception process** requiring verified judicial authorization, separation of duties (dual compliance and security authorization), least privilege (isolated administrative session), mandatory docket reference, and auditable logging.
  - This exception mechanism is an **engineering design proposal requiring independent security review and empirical validation**; no formal legal approval is claimed.
- **No Automated Purge Migrations:** No migration script may implement automated time-to-live (TTL) expiration drops, cascading evidentiary purges, or automatic table partitioning drops until legal review is concluded and approved by stakeholders.
- **Rollback Audit Logging:** Any emergency database restoration or rollback procedure must trigger an external forensic audit log entry documenting:
  - Exact timestamp and operator identity.
  - Reason for rollback and authorized change management ticket UID.
  - Verification of pre-rollback and post-rollback SHA-256 hash tree parity for all Tier 1 evidence objects.

---

## 8. Data Backfill Strategy & Pre-Release Tenant Isolation Verification

### 8.1 Batched, Throttled Data Backfill Architecture
When a new derived column or indexed expression requires backfilling across millions of historical threat messages, the backfill must execute via background worker queues using batched chunking:
1. **Keyset Chunking:** Queries paginate using monotonically increasing primary keys (`WHERE id > :last_seen_id ORDER BY id ASC LIMIT 1000`). Never use high-offset pagination (`OFFSET 500000`).
2. **Lock Minimization:** Each 1,000-row batch executes in its own isolated transaction, preventing long-held row locks and allowing concurrent ingestion and case queries to proceed uninhibited.
3. **Replication Throttling:** Background workers monitor replication lag on database read replicas. If replica lag exceeds 5 seconds, backfill workers sleep for 500ms before processing the next batch.

### 8.2 Pre-Release Tenant Isolation Verification Test (IVT) Suite
Prior to promoting any schema migration to production, the deployment pipeline must execute the automated **Tenant Isolation Verification Test (IVT)** suite. This suite simulates adversarial cross-tenant access across all updated schema layers.

```
+---------------------------------------------------------------------------------------------------+
| PRE-RELEASE TENANT ISOLATION VERIFICATION TEST (IVT) SUITE                                        |
+---------------------------------------------------------------------------------------------------+
  |
  +--> [Test 1: NULL Session Context Rejection]
  |    Execute SELECT * across all 12 app.* tables with app.current_tenant_id unset.
  |    Pass Criteria: MUST return 0 rows for every table (Fail-Closed Invariant).
  |
  +--> [Test 2: Cross-Tenant Boundary Injection]
  |    Set context to Tenant Alpha. Attempt direct SELECT/UPDATE/DELETE on Tenant Beta case UUID.
  |    Pass Criteria: SQL engine MUST return 0 rows affected. Zero cross-tenant leakage.
  |
  +--> [Test 3: Anti-Oracle Media Exists Probe]
  |    Tenant Alpha queries media hash possessed by Tenant Beta using tenant-blind WHERE clause.
  |    Pass Criteria: Query fails or returns no rows; existence of asset is completely obscured.
  |
  +--> [Test 4: Connection Pooler Context Reset Verification]
  |    Execute transaction as Tenant Alpha. Release connection back to pool without DISCARD ALL.
  |    Check out connection as Tenant Beta. Verify previous context does NOT bleed.
  |    Pass Criteria: app.current_tenant_id is NULL or immediately set to Tenant Beta.
  |
  +--> [Test 5: Audit Event Attribution Integrity]
  |    Execute multi-tenant mutation. Verify audit.audit_event_records accurately logs
  |    actor_tenant_id, target_tenant_id, and actor_user_id.
  |    Pass Criteria: Exact attribution with valid SHA-256 payload digest.
+---------------------------------------------------------------------------------------------------+
```

### 8.3 Emergency Abort and Circuit Breaker Criteria
The migration execution runner must immediately abort, rollback the active transaction (where transactional DDL applies), and page on-call engineering if any of the following circuit breakers trip:
- **Lock Wait Timeout:** A DDL statement waits for an exclusive lock for $> 5.0\text{ seconds}$ (`SET lock_timeout = '5s'`).
- **Statement Timeout:** Any migration transaction runs for longer than $60.0\text{ seconds}$ (`SET statement_timeout = '60s'`).
- **Replication Lag Breach:** Streaming replication lag on any standby replica exceeds $10.0\text{ seconds}$ during migration execution.
- **Active Connection Saturation:** Active database connection pool utilization exceeds $85\%$ during migration window.
- **IVT Suite Failure:** Any single assertion in the Pre-Release Tenant Isolation Verification Test suite fails.

---

## 9. Traceability Matrix

| Requirement / Decision UID | Schema & Migration Strategy Control | Verification Mechanism |
| :--- | :--- | :--- |
| **`DEC-05`** | Tenant isolation model: Shared threat store, isolated case data (`DEC-05 Option B`). Enforced in Phase 4 and Phase 5 migrations via RLS and composite tenant foreign keys. | Pre-Release IVT Test Suite (Tests 1, 2, and 4). |
| **`DEC-03`** | Telegram collection pipeline: Continuous sequence ingestion, gap tracking, and rate-limiting structures migrated in Phase 2 (`source_messages`, `collection_discontinuity_gaps`). | Phase 2 migration validation test. |
| **`DEC-07`** | Evidence integrity: Verbatim raw evidence preserved in Phase 3 (`raw_evidence_blobs`) with SHA-256 digests. Tier 1 immutability triggers in Phase 5 with controlled exception process. | Forensic Rollback Limit Matrix (Section 7.2). |
| **`DEC-08`** | Retention and legal review: No automated TTL purges or destructive deletion scripts included in migration catalogue pending legal review. | Policy audit; absence of drop/purge triggers in Phase 5. |
| **`DEC-13`** | Reporting approval & screenshots: Physical tables for text report document (`app.text_report_documents`) and dual-scope screenshots (`app.message_screenshots`, `app.thread_context_screenshots`) implementing `REP-TXT-SCREEN-001` migrated in Phase 4. | Schema validation for `REP-TXT-SCREEN-001` columns. |
| **`NFR-REL-001`** | High availability and zero-downtime evolution: Expand/Contract migration pattern with concurrent index creation. | Expand/Contract operational lifecycle (Section 4). |
| **`NFR-AUD-001`** | Tamper-evident audit logging: Audit schema migrated in Phase 5 with append-only triggers and forensic rollback exclusion. | Immutability triggers and IVT Test 5. |
