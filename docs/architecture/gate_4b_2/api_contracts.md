# TTI Gate 4B.2 — REST API Contract Catalogue

**Document Reference:** `TTI-ARCH-API-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Gate 4B.2 — Interface Contracts  
**Author:** Principal Data Architect & Security Architect  
**Date:** October 2026  
**Governance Status:** `PROPOSED INTERFACE CONTRACTS — PENDING TECHNICAL REVIEW`  
**Parent Specifications:**  
- [`docs/architecture/gate_4b_1/logical_data_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/logical_data_model.md)  
- [`docs/architecture/gate_4b_1/tenant_isolation_and_data_ownership.md`](file:///d:/TTI/docs/architecture/gate_4b_1/tenant_isolation_and_data_ownership.md)  
- [`docs/architecture/gate_4b_1/evidence_provenance_and_retention_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/evidence_provenance_and_retention_model.md)  
- [`docs/product/product_baseline/functional_requirements.md`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md)  
- [`docs/product/product_baseline/non_functional_requirements.md`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md)  

---

## 1. Architectural Principles & API Governance

### 1.1 Scope & Purpose
This document defines the proposed logical REST API contract catalogue for Release 1 MVP of the Telegram Threat Intelligence (TTI) platform. 

All contracts in this catalogue are:
1. **Implementation-Independent:** Expressed in structured logical request/response shapes without assuming specific Python/FastAPI decorators, ORM models, or framework serialization quirks.
2. **Strictly Tenant-Scoped & Fail-Closed:** Every tenant-facing operation mandates cryptographically validated session tokens and tenant identifiers. Missing, malformed, or cross-tenant contexts fail closed immediately.
3. **Anti-Enumeration Guarded:** Probes attempting to inspect, query, or enumerate entities belonging to rival tenants return uniform `HTTP 404 Not Found` responses.
4. **Traceable:** Mapped directly to approved Product Baseline functional requirements (`FR-*`), non-functional targets (`NFR-*`), and approved requirement [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001).

> [!NOTE] Contract Governance Status
> All endpoints in this document are **PROPOSED / CANDIDATE INTERFACE CONTRACTS**. They represent target interface definitions subject to architectural review and test-fixture validation. They do not claim that the API is implemented or verified.

### 1.2 Common Request Headers
All API interactions (except unauthenticated login) require the following HTTP headers:

| Header Name | Type | Description | Mandatory |
| :--- | :--- | :--- | :---: |
| `Authorization` | String | Bearer JWT containing validated user, tenant, and role claims. | Yes |
| `X-Correlation-ID` | String (UUID) | Unique client- or edge-assigned transaction tracing identifier. | Yes |
| `X-Tenant-ID` | String | Contextual tenant ID matching the JWT `tenant_id` claim. | Yes (Multi-tenant) |
| `Accept` | String | Expected MIME type (`application/json`, `application/zip`). | Yes |

---

## 2. API Catalogue Index

| Endpoint Category | Method & Path | Summary Purpose | Traceability ID |
| :--- | :--- | :--- | :--- |
| **Authentication** | `POST /api/v1/auth/login` | Authenticate user and issue scoped JWT | `FR-TEN-002`, `NFR-SEC-005` |
| **Authentication** | `POST /api/v1/auth/refresh` | Refresh expired access token | `NFR-SEC-005` |
| **Authentication** | `GET /api/v1/auth/me` | Retrieve active user profile & memberships | `FR-TEN-002` |
| **Authentication** | `POST /api/v1/auth/logout` | Revoke active session tokens | `NFR-SEC-005` |
| **Tenant Admin** | `GET /api/v1/admin/tenants/{tenant_id}` | Retrieve organization profile & limits | `FR-TEN-001` |
| **Tenant Admin** | `POST /api/v1/admin/tenants/{tenant_id}/memberships` | Provision new investigator user | `FR-TEN-002` |
| **Tenant Admin** | `PATCH /api/v1/admin/tenants/{tenant_id}/memberships/{user_id}` | Update investigator role or status | `FR-TEN-002` |
| **Sources & Jobs** | `GET /api/v1/sources/connectors` | List ingestion collector health & telemetry | `FR-ADM-001`, `DEC-03` |
| **Sources & Jobs** | `GET /api/v1/sources/channels` | List monitored channels & topic metadata | `FR-COL-001` |
| **Sources & Jobs** | `POST /api/v1/sources/channels` | Register new Telegram channel for monitoring | `FR-COL-001`, `DEC-01` |
| **Search & Discovery** | `POST /api/v1/search/query` | Structured observable & keyword FTS | `FR-SCH-001`, `FR-SCH-002` |
| **Thread Navigation** | `GET /api/v1/threads/{channel_id}/messages` | Continuous cursor-based thread viewer | `FR-THR-001`, `FR-COL-003` |
| **Thread Navigation** | `GET /api/v1/threads/{channel_id}/context/{message_id}` | Panoramic conversational context window | `FR-THR-001`, `FR-THR-002` |
| **Case Workspaces** | `POST /api/v1/cases` | Create compartmentalized case workspace | `FR-EVI-001`, `DEC-05` |
| **Case Workspaces** | `GET /api/v1/cases` | List tenant cases with filter metadata | `FR-EVI-001` |
| **Case Workspaces** | `GET /api/v1/cases/{case_id}` | Retrieve case details & evidence inventory | `FR-EVI-001` |
| **Case Workspaces** | `POST /api/v1/cases/{case_id}/messages` | Pin shared message with tenant annotations | `FR-EVI-001`, `NFR-SEC-001` |
| **Case Workspaces** | `DELETE /api/v1/cases/{case_id}/messages/{message_id}` | Unpin message from case workspace | `FR-EVI-001` |
| **Case Notes** | `POST /api/v1/cases/{case_id}/notes` | Attach confidential investigative hypothesis | `FR-EVI-001`, `NFR-OBS-001` |
| **Case Notes** | `GET /api/v1/cases/{case_id}/notes` | Retrieve notes associated with case | `FR-EVI-001` |
| **Evidence Retrieval** | `GET /api/v1/cases/{case_id}/evidence/{artifact_id}/download` | Authorized anti-oracle media retrieval | `FR-EVI-003`, `NFR-SEC-002` |
| **Reporting** | `POST /api/v1/cases/{case_id}/reports/generate` | Enqueue `REP-TXT-SCREEN-001` package generation | `REP-TXT-SCREEN-001`, `FR-REP-001` |
| **Reporting** | `GET /api/v1/cases/{case_id}/reports/{report_id}/preview` | Pre-delivery inspection & redaction gate | `FR-REP-004` |
| **Reporting** | `POST /api/v1/cases/{case_id}/reports/{report_id}/finalize` | Seal report bundle with SHA-256 manifest | `FR-REP-003`, `FR-REP-004` |
| **Reporting** | `GET /api/v1/cases/{case_id}/reports/{report_id}/download` | Download sealed ZIP evidence deliverable | `REP-TXT-SCREEN-001` |
| **Audit & Ops** | `GET /api/v1/audit/events` | Query tenant-scoped audit ledger | `NFR-OBS-001`, `NFR-OBS-003` |
| **Audit & Ops** | `GET /api/v1/health` | Subsystem diagnostic probes (DB, Cache, Disk) | `NFR-OBS-002` |

---

## 3. Detailed Endpoint Contracts

### 3.1 Authentication & Session Management

#### 3.1.1 `POST /api/v1/auth/login`
* **Purpose:** Authenticate an analyst using credentials and optional MFA token; issues access and refresh JWTs.
* **Authorization:** Public / Unauthenticated. Rate limited to 5 attempts/minute per IP.
* **Tenant Scope:** Discovers tenant memberships associated with user.
* **Request Shape:**
  ```json
  {
    "email_address": "analyst@agency.gov",
    "password": "CleartextPasswordSubmittedViaTLS",
    "mfa_token": "849201"
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in_seconds": 900,
    "user_profile": {
      "user_id": "USR-1042",
      "full_name": "Detective Miller",
      "email_address": "analyst@agency.gov"
    },
    "available_tenants": [
      {
        "tenant_id": "TNT-7049-LEA",
        "organization_name": "State Cyber Division",
        "assigned_role": "INVESTIGATOR_LEAD"
      }
    ],
    "active_tenant_id": "TNT-7049-LEA"
  }
  ```
* **Error Responses:**
  - `401 Unauthorized` (`AUTH_CREDENTIALS_INVALID`): Invalid email or password.
  - `403 Forbidden` (`AUTH_MFA_REQUIRED` / `ACCOUNT_LOCKED`): Missing or invalid MFA token.
  - `429 Too Many Requests` (`AUTH_RATE_LIMIT_EXCEEDED`): IP backoff triggered.
* **Traceability:** [`FR-TEN-002`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-ten-002), [`NFR-SEC-005`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-sec-005).

---

### 3.2 Search & Discovery Subsystem

#### 3.2.1 `POST /api/v1/search/query`
* **Purpose:** Execute structured multi-observable indicator lookup and keyword full-text search across historical Telegram chatter.
* **Authorization:** Role `INVESTIGATOR`, `INVESTIGATOR_LEAD`, or `TENANT_ADMIN`. Permission `search:execute`.
* **Tenant Scope:** Searches global threat chatter; search cache and telemetry are strictly scoped to `X-Tenant-ID`.
* **Request Shape:**
  ```json
  {
    "query_text": "breach database @leak_broker",
    "filters": {
      "channel_ids": [100184920394],
      "date_from_utc": "2026-09-01T00:00:00Z",
      "date_to_utc": "2026-10-28T23:59:59Z",
      "has_media": true,
      "sender_username": "leak_broker"
    },
    "pagination": {
      "limit": 50,
      "cursor": "eyJtc2dfaWQiOjEwNDAsInRzIjoxNjk4NTM3NjAwfQ=="
    }
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "items": [
      {
        "message_id": "CHN-100184920394:1040",
        "channel_id": 100184920394,
        "source_sequence_id": 1040,
        "message_thread_id": 45,
        "broadcast_timestamp_utc": "2026-10-28T14:22:10Z",
        "sender_username": "leak_broker",
        "masked_text": "New corporate breach data available. Credentials: admin:P@ssw**** Contact via PM.",
        "has_media": true,
        "media_artifacts": [
          {
            "artifact_id": "ART-84920a",
            "mime_type": "image/png",
            "byte_size": 204850
          }
        ],
        "reply_to_message_id": null,
        "has_revisions": false
      }
    ],
    "pagination": {
      "next_cursor": "eyJtc2dfaWQiOjEwMzksInRzIjoxNjk4NTM3NTgwfQ==",
      "has_more": true
    },
    "execution_metrics": {
      "execution_time_ms": 42,
      "query_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
  ```
* **Security & Log Invariant:** Application logs record only `query_hash` and `execution_time_ms`. Raw `query_text` is stripped prior to log emission (`ADR-008`).
* **Traceability:** [`FR-SCH-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-sch-001), [`FR-SCH-002`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-sch-002), [`NFR-OBS-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-obs-001).

---

### 3.3 Thread Navigation & Reconstruction

#### 3.3.1 `GET /api/v1/threads/{channel_id}/messages`
* **Purpose:** Continuous cursor-based conversational thread viewer allowing investigators to navigate forwards and backwards through channel chatter free of commercial query fees, while rendering honest sequence-gap markers.
* **Authorization:** Permission `threads:read`.
* **Tenant Scope:** Read-only access to global threat store; throttled per tenant session.
* **Query Parameters:**
  - `cursor`: Opaque base64 cursor encoding (`source_sequence_id`, `timestamp`).
  - `direction`: `BEFORE` or `AFTER` (relative to cursor).
  - `limit`: Integer (default 50, maximum 100).
  - `topic_id`: Optional forum topic identifier (`message_thread_id`).
* **Response (200 OK):**
  ```json
  {
    "channel_metadata": {
      "channel_id": 100184920394,
      "channel_title": "Underground Breach Channel",
      "channel_type": "SUPERGROUP_FORUM"
    },
    "messages": [
      {
        "type": "MESSAGE",
        "message_id": "CHN-100184920394:1040",
        "sequence_id": 1040,
        "message_thread_id": 45,
        "sender_username": "leak_broker",
        "broadcast_timestamp_utc": "2026-10-28T14:22:10Z",
        "masked_text": "Sample data dump link posted below.",
        "reply_to_message_id": null
      },
      {
        "type": "DISCONTINUITY_GAP",
        "gap_id": "GAP-1041-1044",
        "gap_start_id": 1041,
        "gap_end_id": 1044,
        "status": "UNRECORDED_DISCONTINUITY",
        "display_notice": "[Sequence Discontinuity: Messages 1041 to 1044 unrecorded]"
      },
      {
        "type": "MESSAGE",
        "message_id": "CHN-100184920394:1045",
        "sequence_id": 1045,
        "message_thread_id": 45,
        "sender_username": "buyer_analyst",
        "broadcast_timestamp_utc": "2026-10-28T14:35:00Z",
        "masked_text": "Are these credentials verified?",
        "reply_to_message_id": 1040
      }
    ],
    "pagination": {
      "next_cursor": "eyJtc2dfaWQiOjEwNDUsInRzIjoxNjk4NTM3OTAwfQ==",
      "has_more": true
    }
  }
  ```
* **Honest Gap Invariant:** The response explicitly distinguishes real message records from `DISCONTINUITY_GAP` records without asserting deletion (`FR-COL-003`, `FR-THR-001`).
* **Traceability:** [`FR-THR-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-thr-001), [`FR-COL-003`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-col-003).

---

### 3.4 Case Management & Workspace Subsystem

#### 3.4.1 `POST /api/v1/cases`
* **Purpose:** Create an isolated case investigation workspace.
* **Authorization:** Role `INVESTIGATOR`, `INVESTIGATOR_LEAD`, `TENANT_ADMIN`. Permission `cases:create`.
* **Tenant Scope:** Entity is bound exclusively to `X-Tenant-ID`.
* **Request Shape:**
  ```json
  {
    "case_title": "Operation Nightfall",
    "internal_agency_ref": "WARRANT-2026-CR-8921",
    "lead_investigator_id": "USR-1042",
    "initial_notes": "Investigation into Telegram credential broker syndicate."
  }
  ```
* **Response (201 Created):**
  ```json
  {
    "case_id": "CASE-2026-088",
    "tenant_id": "TNT-7049-LEA",
    "case_title": "Operation Nightfall",
    "internal_agency_ref": "WARRANT-2026-CR-8921",
    "case_status": "ACTIVE",
    "created_at_utc": "2026-10-28T16:00:00Z",
    "pinned_message_count": 0
  }
  ```
* **Traceability:** [`FR-EVI-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-evi-001), [`DEC-05`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md#dec-05).

---

#### 3.4.2 `POST /api/v1/cases/{case_id}/messages` (Bridge Association)
* **Purpose:** Associate a globally shared threat message with an isolated case workspace, applying tenant-specific tags and notes without mutating the shared record.
* **Authorization:** Permission `cases:write`.
* **Tenant Scope:** Requires `case_id` to match `X-Tenant-ID`.
* **Request Shape:**
  ```json
  {
    "message_id": "CHN-100184920394:1040",
    "investigator_tags": ["suspect_broker", "credential_sale"],
    "analyst_annotation": "Primary broker offering sample dumps. Matches suspect handle."
  }
  ```
* **Response (201 Created):**
  ```json
  {
    "association_id": "ASC-88-1040",
    "case_id": "CASE-2026-088",
    "message_id": "CHN-100184920394:1040",
    "investigator_tags": ["suspect_broker", "credential_sale"],
    "pinned_at_utc": "2026-10-28T16:15:00Z",
    "pinned_by_user_id": "USR-1042"
  }
  ```
* **Error Responses:**
  - `404 Not Found` (`CASE_NOT_FOUND`): Returned if `case_id` does not exist OR belongs to another tenant (anti-enumeration).
  - `404 Not Found` (`MESSAGE_NOT_FOUND`): Message does not exist in shared store.
  - `409 Conflict` (`MESSAGE_ALREADY_ASSOCIATED`): Message already pinned to this case.
* **Traceability:** [`FR-EVI-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-evi-001), [`NFR-SEC-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-sec-001).

---

### 3.5 Authorized Evidence Retrieval (Anti-Oracle Protection)

#### 3.5.1 `GET /api/v1/cases/{case_id}/evidence/{artifact_id}/download`
* **Purpose:** Download a media binary (PDF, screenshot, image) attached to a message pinned to an authorized case.
* **Authorization:** Permission `evidence:download`.
* **Tenant Scope:** Strictly validates that `case_id` belongs to `X-Tenant-ID` and that `artifact_id` is linked to that case.
* **Anti-Oracle Security Behavior:**
  - Probing files by raw SHA-256 hash without case context is completely barred.
  - If `case_id` belongs to another tenant, or if `artifact_id` is not pinned to `case_id`, the system immediately returns `HTTP 404 Not Found`.
* **Response (200 OK):** Binary stream with headers:
  - `Content-Type`: `image/png` (or appropriate MIME).
  - `Content-Disposition`: `attachment; filename="evidence_artifact_84920a.png"`.
  - `X-Evidence-SHA256`: `8f4c2b9a10d948...` (Canonical digest for integrity verification).
* **Traceability:** [`FR-EVI-003`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-evi-003), [`NFR-SEC-002`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-sec-002).

---

### 3.6 Investigation Reporting & Packaging (`REP-TXT-SCREEN-001`)

#### 3.6.1 `POST /api/v1/cases/{case_id}/reports/generate`
* **Purpose:** Enqueue background rendering of court-ready evidence package conforming to approved requirement [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001).
* **Authorization:** Role `INVESTIGATOR_LEAD` or `TENANT_ADMIN`. Permission `reports:create`.
* **Tenant Scope:** Scoped to `X-Tenant-ID`.
* **Request Shape:**
  ```json
  {
    "target_message_ids": ["CHN-100184920394:1040"],
    "include_thread_context": true,
    "context_window_size": 3,
    "report_title": "Preliminary Intelligence Summary - Operation Nightfall",
    "target_observable": "@leak_broker"
  }
  ```
* **Response (202 Accepted):**
  ```json
  {
    "report_id": "REP-2026-CASE88-001",
    "case_id": "CASE-2026-088",
    "status": "PROCESSING",
    "message": "Report compilation and Playwright screenshot rendering enqueued.",
    "estimated_completion_seconds": 12,
    "status_check_url": "/api/v1/cases/CASE-2026-088/reports/REP-2026-CASE88-001/preview"
  }
  ```
* **Traceability:** [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001), [`FR-REP-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-rep-001), [`FR-REP-002`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-rep-002).

---

#### 3.6.2 `GET /api/v1/cases/{case_id}/reports/{report_id}/preview`
* **Purpose:** Render pre-delivery review workspace, displaying draft plain-text report and captured screenshots for human investigator verification and redaction before final sealing.
* **Authorization:** Permission `reports:review`.
* **Response (200 OK):**
  ```json
  {
    "report_id": "REP-2026-CASE88-001",
    "status": "READY_FOR_PREVIEW",
    "draft_report_text": "TELEGRAM THREAT INTELLIGENCE REPORT\nRef: REP-2026-CASE88-001\nCase: CASE-2026-088\n...",
    "screenshots": [
      {
        "type": "FOCUS_MESSAGE",
        "file_name": "assets/msg_1040_focus.png",
        "preview_url": "/api/v1/cases/CASE-2026-088/reports/REP-2026-CASE88-001/assets/msg_1040_focus.png",
        "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
      },
      {
        "type": "THREAD_CONTEXT",
        "file_name": "assets/msg_1040_thread_context.png",
        "preview_url": "/api/v1/cases/CASE-2026-088/reports/REP-2026-CASE88-001/assets/msg_1040_thread_context.png",
        "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"
      }
    ],
    "review_checklist_pending": [
      "CONFIRM_EVIDENTIARY_ACCURACY",
      "CONFIRM_COLLATERAL_PII_REDACTION"
    ]
  }
  ```
* **Traceability:** [`FR-REP-004`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-rep-004).

---

#### 3.6.3 `POST /api/v1/cases/{case_id}/reports/{report_id}/finalize`
* **Purpose:** Execute formal human investigator sign-off, assemble `manifest.json`, compute final package SHA-256 hash, and seal the bundle for delivery.
* **Authorization:** Role `INVESTIGATOR_LEAD` or `TENANT_ADMIN`. Permission `reports:sign`.
* **Request Shape:**
  ```json
  {
    "investigator_confirmation": true,
    "redaction_reviewed": true,
    "analyst_signature_note": "Reviewed by Det. Miller. Evidence verified against warrant."
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "report_id": "REP-2026-CASE88-001",
    "status": "FINALIZED_SEALED",
    "package_sha256_hash": "c8b417e990c8a66a1a9e5efd8d77d13cf4ff2a7e72a4ff76b2f6ef3cf76326e6",
    "manifest_summary": {
      "item_count": 3,
      "manifest_sha256": "a35d72f1295b9c24098ec92b3a98f4803d12d4957e84a28b03126ecba50d1829"
    },
    "download_url": "/api/v1/cases/CASE-2026-088/reports/REP-2026-CASE88-001/download",
    "legal_notice": "Cryptographic SHA-256 hashes detect subsequent alteration of exported files across transit. They do not independently establish upstream message authenticity or legal admissibility."
  }
  ```
* **Traceability:** [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001), [`FR-REP-003`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-rep-003), [`NFR-LEGAL-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-legal-001).

---

### 3.7 Operational Health & Diagnostics

#### 3.7.1 `GET /api/v1/health`
* **Purpose:** Operational readiness and liveness diagnostic probe evaluating core platform dependencies.
* **Authorization:** Open to infrastructure orchestrators (Docker, Kubernetes) and administrators.
* **Response (200 OK / 503 Service Unavailable):**
  ```json
  {
    "status": "HEALTHY",
    "timestamp_utc": "2026-10-28T16:30:00Z",
    "version": "0.1.0-mvp",
    "components": {
      "database_connection": {"status": "UP", "latency_ms": 3},
      "redis_broker": {"status": "UP", "latency_ms": 1},
      "evidence_vault_storage": {"status": "UP", "writeable": true},
      "ingestion_workers": {"active_workers": 4, "throttled_connectors": 0}
    }
  }
  ```
* **Traceability:** [`NFR-OBS-002`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-obs-002).

---

*Next Interface Specification:* [`subsystem_interface_contracts.md`](file:///d:/TTI/docs/architecture/gate_4b_2/subsystem_interface_contracts.md)
