# TTI Functional Requirements Specification

**Document Reference:** `TTI-DOC-BSL-REQ-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Product Baseline & Release 1 Scope  
**Author:** Product Research & Architecture Team  
**Date:** 2026-10-28  
**Governance Status:** `PROPOSED PRODUCT BASELINE — PENDING STAKEHOLDER REVIEW`  
**Predecessor Documents:**
- [`docs/product/gate_3b/customer_workflows.md`](file:///d:/TTI/docs/product/gate_3b/customer_workflows.md) (`TTI-DOC-PRD-WF-001`)
- [`docs/product/gate_3b/feature_opportunity_register.md`](file:///d:/TTI/docs/product/gate_3b/feature_opportunity_register.md) (`TTI-DOC-PRD-OPP-001`)
- [`docs/product/gate_3b/reporting_requirements_review.md`](file:///d:/TTI/docs/product/gate_3b/reporting_requirements_review.md) (`TTI-DOC-PRD-REV-001`)

---

## 1. Requirements Governance & Priority Hierarchy

Every functional requirement in this specification is assigned an explicit **Priority** and a **Governance Classification**:

### Priority Definitions
- **`P0 (Must Have - Release 1 Core)`**: Essential for the functional viability, defensibility, or compliance of Release 1. Without this requirement, Release 1 cannot ship.
- **`P1 (Should Have - Release 1 Secondary / Early Release 2)`**: High-value operational requirement; planned for Release 1 if velocity permits, otherwise priority candidate for Release 2.
- **`P2 (Nice to Have - Release 2+)`**: Advanced feature planned for Release 2 or 3; non-blocking for initial commercial and pilot operations.

### Governance Classifications
- `CONFIRMED DECISION`: Authorized by VFRA Product Ownership.
- `APPROVED BY VFRA`: Formally reviewed and approved requirement (`REP-TXT-SCREEN-001`).
- `PROPOSED PRODUCT FEATURE`: Candidate functional capability derived from research and customer workflows.
- `ENGINEERING RECOMMENDATION`: Technical implementation pattern recommended by architecture.

---

## 2. Requirements Master Summary Table

| Requirement ID | Functional Area | Requirement Summary | Priority | Governance Status | Target Release |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **`FR-COL-001`** | Collection | Ingestion of Public & Semi-Public Telegram Channels | `P0` | Confirmed Decision | Release 1 |
| **`FR-COL-002`** | Collection | MTProto Rate Limiting, Flood Backoff & Circuit Breaking | `P0` | Engineering Recommendation | Release 1 |
| **`FR-COL-003`** | Collection | Message Revision (Edit) & Deletion Tombstone Tracking | `P0` | Proposed Product Feature | Release 1 |
| **`FR-COL-004`** | Collection | Ingestion Input Sanitization & Threat Neutralization | `P0` | Engineering Recommendation | Release 1 |
| **`FR-THR-001`** | Thread Navigation | Continuous Cursor-Based Sliding-Window Thread Viewer | `P0` | Proposed (`OPP-001`) | Release 1 |
| **`FR-THR-002`** | Thread Navigation | Conversational Reply-Chain & Forward Provenance Tracking | `P0` | Proposed Product Feature | Release 1 |
| **`FR-SCH-001`** | Search & Discovery | Multi-Observable Indicator & Keyword Full-Text Search | `P0` | Confirmed Decision | Release 1 |
| **`FR-SCH-002`** | Search & Discovery | Faceted Temporal, Channel, and Media Filter Attributes | `P0` | Proposed Product Feature | Release 1 |
| **`FR-SCH-003`** | Search & Discovery | Recursive AST Boolean Search Parser | `P1` | Proposed (`OPP-002`) | Release 2 |
| **`FR-EVI-001`** | Case Management | Compartmentalized Case Workspace & Evidence Staging | `P0` | Confirmed Decision | Release 1 |
| **`FR-EVI-002`** | Case Management | Cryptographic SHA-256 Ingestion Fingerprinting | `P0` | Proposed (`OPP-006`) | Release 1 |
| **`FR-EVI-003`** | Case Management | Media Asset Downloader & Local Vault Storage | `P0` | Proposed Product Feature | Release 1 |
| **`FR-REP-001`** | Reporting | Structured Plain-Text (TXT) Investigation Report Generation | `P0` | **Approved by VFRA** (`REP-TXT-SCREEN-001`) | Release 1 |
| **`FR-REP-002`** | Reporting | Dual-Scope Screenshot Evidence Association | `P0` | **Approved by VFRA** (`REP-TXT-SCREEN-001`) | Release 1 |
| **`FR-REP-003`** | Reporting | Unified Deliverable Packaging with Cryptographic Manifest | `P0` | **Approved by VFRA** (`REP-TXT-SCREEN-001`) | Release 1 |
| **`FR-REP-004`** | Reporting | Mandatory Investigator Pre-Delivery Review Workflow | `P0` | **Approved by VFRA** (`REP-TXT-SCREEN-001`) | Release 1 |
| **`FR-ALT-001`** | Alerting | Real-Time Watchlist Monitoring & In-App Alert Triage | `P0` | Proposed Product Feature | Release 1 |
| **`FR-ALT-002`** | Alerting | Outbound SOAR / SIEM Webhook Event Dispatcher | `P1` | Proposed (`OPP-003`) | Release 2 |
| **`FR-TEN-001`** | Multi-Tenancy | Tenant Data Isolation & Request Scope Verification | `P0` | Confirmed Decision | Release 1 |
| **`FR-TEN-002`** | Multi-Tenancy | Granular Role-Based Access Control (RBAC) System | `P0` | Proposed Product Feature | Release 1 |
| **`FR-ADM-001`** | Administration | Platform Collector Fleet Telemetry & Health Monitoring | `P0` | Confirmed Decision | Release 1 |
| **`AC-REQ-001`** | Access Control | Platform Administration & Access Policy Scope | `P0` | Confirmed Requirement (Stakeholder Guidance) | Release 1 |
| **`AC-REQ-002`** | Access Control | Organization Approval & Lifecycle Gating | `P0` | Confirmed Requirement (Stakeholder Guidance) | Release 1 |
| **`AC-REQ-003`** | Access Control | Organization-Managed User Provisioning & Scoping | `P0` | Confirmed Requirement (Stakeholder Guidance) | Release 1 |
| **`AC-REQ-004`** | Access Control | Least-Privilege Sub-System Authorization | `P0` | Confirmed Requirement (Stakeholder Guidance) | Release 1 |
| **`AC-REQ-005`** | Quotas & Billing | Organization Credit Quota & Per-Action Consumption | `P0` | Confirmed Requirement (Stakeholder Guidance) | Release 1 |
| **`AC-REQ-006`** | Session Security | Single Active Authenticated Session Per User Account | `P0` | Confirmed Requirement (Stakeholder Guidance) | Release 1 |

---

## 3. Detailed Functional Requirements

---

### 3.1 Collection & Ingestion Subsystem

#### `FR-COL-001`: Ingestion of Public and Semi-Public Telegram Channels
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED DECISION`
- **Description:** The system must passively ingest messages, metadata, forward provenance, and media metadata from configured public broadcast channels, open discussion groups, and authorized semi-public supergroups.
- **Verifiable Acceptance Criteria:**
  1. The connector must successfully ingest messages from designated public Telegram channels using MTProto client sessions.
  2. For every ingested message, the system must extract and store: channel ID, message ID, UTC timestamp, message text body, sender ID/handle (when exposed), forward origin (when available), and media attachment metadata.
  3. The system must support ingesting channels configured with standard username handles (`@channel`) and valid HTTP invite links.
  4. The system must strictly reject any configuration attempting to join or intercept Telegram end-to-end encrypted (E2EE) Secret Chats.
  5. For Telegram forum supergroups, the connector must extract and preserve `message_thread_id`; where a broadcast channel links to a separate discussion group (`linked_chat_id`), the ingestion pipeline must record the linked chat association to enable cross-chat thread reconstruction.

#### `FR-COL-002`: MTProto Rate Limiting, Flood Backoff & Circuit Breaking
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `ENGINEERING RECOMMENDATION`
- **Description:** The ingestion engine must implement intelligent client-side throttling to respect Telegram platform rate limits and prevent account bans.
- **Verifiable Acceptance Criteria:**
  1. When Telegram servers return a `FLOOD_WAIT_X` exception, the collector worker must automatically suspend requests for the specified `X` seconds plus a randomized jitter of 1–5 seconds.
  2. The system must record a structured log event whenever a `FLOOD_WAIT` is triggered, capturing session identifier, channel target, and backoff duration.
  3. If three consecutive `FLOOD_WAIT` exceptions exceeding 300 seconds occur on a single session, the system must activate an automated circuit breaker, taking the session offline and alerting platform administrators.

#### `FR-COL-003`: Message Revision (Edit) & Deletion Tombstone Tracking
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE`
- **Description:** Threat actors frequently edit or delete incriminating chatter. The platform must preserve the evidentiary state of original messages while recording subsequent edits or deletions without making unverified assertions about source causality.
- **Verifiable Acceptance Criteria:**
  1. When a message edit event is detected, the original message record must remain immutable; an edit revision record must be appended with the new content and edit UTC timestamp.
  2. When a message deletion event is detected, the stored message record must NOT be deleted from the database; its status must be updated to `DELETED_AT_SOURCE` with the detection timestamp.
  3. The user interface must display an "Edited" badge or "Deleted at Source" indicator on revised messages, allowing investigators to inspect the revision history.
  4. When numerical message sequence gaps occur between ingested records, the system must display an explicit sequence-gap indicator (`[Sequence Discontinuity: Messages X to Y unrecorded — unobserved, dropped during throttling, or deleted at source]`) rather than asserting that unobserved messages were definitely deleted.

#### `FR-COL-004`: Ingestion Input Sanitization & Threat Neutralization
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `ENGINEERING RECOMMENDATION`
- **Description:** All incoming text payloads from external threat channels must be sanitized prior to database indexing to prevent stored XSS, terminal injection, database corruption, or unintended plaintext credential exposure.
- **Verifiable Acceptance Criteria:**
  1. All text fields must undergo Unicode NFC normalization.
  2. All ASCII control characters (`\x00` through `\x1F`, excluding standard line breaks `\n`, `\r`, `\t`) must be stripped.
  3. HTML script tags (`<script>`, `<iframe>`, `<object>`) must be stripped or neutralized.
  4. Hyperlink URI protocols must be defanged: `javascript:`, `data:`, and `file:` protocols must be replaced with safe indicators (`[defanged-uri]`).
  5. The ingestion processor must apply defensive heuristic regex patterns to detect suspected structured credential dumps (`email:password`, `username:password`) embedded in chat message bodies. Suspected credential strings must be masked by default in search and thread displays, and encrypted at rest using field-level AES-256 encryption. Raw secrets must never be emitted into application logs or stack traces.

---

### 3.2 Thread Navigation & Reconstruction Subsystem

#### `FR-THR-001`: Continuous Cursor-Based Sliding-Window Thread Viewer
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE` (`OPP-001`)
- **Description:** The UI must provide a smooth conversational chat view allowing investigators to scroll backwards and forwards through chat history free of per-scroll commercial credit penalties, protected by defensive backend API rate limiting.
- **Verifiable Acceptance Criteria:**
  1. The thread viewer must implement cursor-based pagination (using message ID or timestamp offsets), fetching sliding windows of 25–50 messages per scroll event.
  2. Scrolling through conversation history must NOT decrement customer search query quotas or trigger commercial credit consumption.
  3. When an investigator opens a specific search result, the thread viewer must automatically center the target message and fetch up to 20 preceding and 20 succeeding messages in chronological order.
  4. Response time for loading an adjacent 50-message thread window must be under 300 milliseconds on a reference test fixture (simulated network RTT < 50ms, 50 concurrent virtual user sessions on standard cloud reference hardware: 4 vCPU, 16 GB RAM).
  5. The backend API must enforce defensive sliding-window request throttling (maximum 60 window requests per minute per user session), returning HTTP 429 Too Many Requests with a `Retry-After` header when exceeded.
  6. When numerical message sequence gaps occur in the thread, the viewer must render an explicit visual gap marker (`[Discontinuity: Sequence gap from message X to Y]`), preserving narrative honesty regarding missing context.

#### `FR-THR-002`: Conversational Reply-Chain & Forward Provenance Tracking
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE`
- **Description:** The system must visualize conversational parent-child relationships and message forward origins.
- **Verifiable Acceptance Criteria:**
  1. If a message contains a `reply_to_msg_id`, the UI must render an interactive quote preview of the parent message.
  2. Clicking a parent reply quote must update viewport focus and scroll offset directly to the parent message within the active thread view.
  3. If a message is forwarded from another channel or user, the UI must display the originating source channel name, original message ID, and forward timestamp (where exposed by Telegram).
  4. For messages in forum supergroups, reply tracking must preserve `message_thread_id` context to prevent cross-topic reply confusion.

---

### 3.3 Search & Discovery Subsystem

#### `FR-SCH-001`: Multi-Observable Indicator & Keyword Full-Text Search
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED DECISION`
- **Description:** Investigators must be able to search the centralized indexed repository across multiple technical indicators and text terms.
- **Verifiable Acceptance Criteria:**
  1. The search engine must support exact and substring matching on Telegram handles (`@username`), numeric user IDs, channel IDs, phone numbers, and cryptocurrency wallet addresses (Bitcoin, Ethereum, Monero, TRON).
  2. The search engine must support full-text search across message text bodies using PostgreSQL Full-Text Search (`tsvector`/`tsquery`) with language stemming.
  3. Search query execution time must not exceed 1.5 seconds (p95) on a reference test fixture indexing up to 2,000,000 synthetic threat messages under a simulated 20 concurrent query load.

#### `FR-SCH-002`: Faceted Temporal, Channel, and Media Filter Attributes
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE`
- **Description:** Analysts must be able to filter search results by date range, channel categories, and media presence.
- **Verifiable Acceptance Criteria:**
  1. The search interface must provide date-range pickers filtering by message broadcast timestamp (UTC).
  2. The interface must provide multi-select channel dropdowns enabling scoping to specific monitored channels.
  3. The interface must allow filtering by media attachment type (e.g., has image, has document/archive, text only).

#### `FR-SCH-003`: Recursive AST Boolean Search Parser
- **Priority:** `P1 (Should Have - Release 2)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE` (`OPP-002`)
- **Description:** Support for complex nested Boolean expressions `((A OR B) AND (C NOT D))` without arbitrary operator limits.
- **Verifiable Acceptance Criteria:**
  1. The search parser must compile nested parenthetical Boolean queries into a valid Abstract Syntax Tree.
  2. The parser must support arbitrary combinations of `AND`, `OR`, `NOT`, and phrase quotes (`"..."`).
  3. The system must reject malformed unbalanced parenthetical queries with clear syntax error indicators pointing to the error offset.

---

### 3.4 Case Management & Evidence Staging Subsystem

#### `FR-EVI-001`: Compartmentalized Case Workspace & Evidence Staging
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED DECISION`
- **Description:** Investigators must be able to create isolated Case containers to organize findings, tag evidentiary messages, and record investigative hypotheses.
- **Verifiable Acceptance Criteria:**
  1. Authorized users must be able to create a Case record containing: Case Title, Case Reference ID (e.g., `CASE-2026-CR-012`), Judicial Warrant/Incident Ticket Reference, and Narrative Description.
  2. Investigators must be able to tag any ingested message or media item into an active Case with one click.
  3. Tagged evidence items must remain locked to the Case workspace; deleting or editing user notes must not alter underlying ingested threat data.
  4. Access to a Case container must be strictly restricted to assigned users within the authenticated tenant.

#### `FR-EVI-002`: Cryptographic SHA-256 Ingestion Fingerprinting
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE` (`OPP-006`)
- **Description:** The system must generate immutable cryptographic digests upon initial data receipt to establish tamper-evident provenance.
- **Verifiable Acceptance Criteria:**
  1. Upon receiving a raw message payload from the Telegram ingestion worker, the backend must calculate a SHA-256 cryptographic hash of the normalized JSON string.
  2. The calculated SHA-256 hash must be stored in a non-nullable database column alongside the record creation timestamp.
  3. Re-calculating the hash over the stored payload must return an exact match, verifying zero database mutation.

#### `FR-EVI-003`: Media Asset Downloader & Local Vault Storage
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE`
- **Description:** Ingested media previews and high-priority file attachments must be staged into a secured evidence vault.
- **Verifiable Acceptance Criteria:**
  1. Media files (images, documents) associated with tagged case messages must be downloaded and stored in the tenant-isolated evidence directory: `/evidence_store/{tenant_id}/{case_id}/`.
  2. The system must calculate and store the SHA-256 hash of each downloaded media binary file upon write completion.
  3. Direct public web access to the evidence storage path must be blocked; files must only be retrieved via authenticated, tenant-scoped API routes.
  4. Direct API lookup or probing of media assets using raw SHA-256 digests without an authorized tenant Case reference token is strictly prohibited, preventing cross-tenant existence oracle attacks. Cross-tenant or unassociated media queries must return HTTP 404 Not Found.

---

### 3.5 Investigation Reporting & Packaging Subsystem (`REP-TXT-SCREEN-001`)

#### `FR-REP-001`: Structured Plain-Text (TXT) Investigation Report Generation
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** **`APPROVED BY VFRA`** (`REP-TXT-SCREEN-001`)
- **Description:** The reporting engine must compile a structured, parseable UTF-8 plain-text (`.txt`) report documenting investigative findings, source metadata, and cross-references.
- **Verifiable Acceptance Criteria:**
  1. The report must be generated in valid UTF-8 encoding with human-readable headers and ASCII delimiter sections.
  2. The header must contain: Report Reference ID, Case Reference ID, Export Date/Time (UTC), Generating Analyst ID, and Total Findings Count.
  3. For every included message, the report must output: Message Reference ID, Channel Name, Channel Handle, Channel ID, Message ID, Broadcast Timestamp (UTC), Sender Handle/ID (or explicit `NOT_AVAILABLE_FROM_SOURCE`), Message Content, and explicit file pointers to supporting screenshots.
  4. If source metadata attributes are missing or anonymized, the system must explicitly output `NOT_AVAILABLE_FROM_SOURCE` rather than omitting the field.

#### `FR-REP-002`: Dual-Scope Screenshot Evidence Association
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** **`APPROVED BY VFRA`** (`REP-TXT-SCREEN-001`)
- **Description:** The system must capture and associate both individual-message screenshots and thread-context screenshots to accompany the TXT report.
- **Verifiable Acceptance Criteria:**
  1. For each tagged message in the report, the system must generate or associate an **Individual-Message Screenshot** named `SCR-INDIV-<msg_id>.png` cropped tightly to the message body, sender handle, and timestamp.
  2. Where available and authorized, the system must generate or associate a **Thread-Context Screenshot** named `SCR-THREAD-<msg_id>.png` showing the surrounding chronological conversation thread (minimum 5 preceding and 5 succeeding messages).
  3. If surrounding thread context is unavailable (e.g., isolated broadcast post, deleted surrounding thread), the system must log a `CAPTURE_LIMITATION_LOG` entry in the TXT report explaining the absence.

#### `FR-REP-003`: Unified Deliverable Packaging with Cryptographic Manifest
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** **`APPROVED BY VFRA`** (`REP-TXT-SCREEN-001`)
- **Description:** The TXT report and all supporting screenshot images must be packaged into a single standardized bundle with an integrity manifest.
- **Verifiable Acceptance Criteria:**
  1. The system must package the deliverable as a `.zip` archive named `{Report_Ref_ID}_bundle.zip`.
  2. The root of the archive must contain: `report.txt`, `manifest.json`, and an `assets/` directory containing all referenced `.png` screenshots.
  3. `manifest.json` must record the file name, byte size, and SHA-256 cryptographic digest of `report.txt` and every file in `assets/`.
  4. Every screenshot file name referenced in `report.txt` must match an actual file existing in the `assets/` directory.

#### `FR-REP-004`: Mandatory Investigator Pre-Delivery Review Workflow
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** **`APPROVED BY VFRA`** (`REP-TXT-SCREEN-001`)
- **Description:** Before an evidence package can be exported or marked as final, the platform must require an authorized investigator to complete a pre-delivery review.
- **Verifiable Acceptance Criteria:**
  1. The UI must present a draft review screen displaying the compiled TXT report side-by-side with preview renders of the associated individual and thread-context screenshots.
  2. The interface must provide redact/mask controls allowing the investigator to redact sensitive third-party PII (e.g., innocent victim phone numbers or personal photos) before final package assembly.
  3. The system must block package download or external transmission until an authorized user clicks "Approve & Authorize Delivery", recording an immutable audit event with the reviewer's user ID, timestamp, and review notes.

---

### 3.6 Watchlists & Alerting Subsystem

#### `FR-ALT-001`: Real-Time Watchlist Monitoring & In-App Alert Triage
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE`
- **Description:** Analysts must be able to configure keyword and indicator watchlists that trigger immediate alerts upon incoming message matches.
- **Verifiable Acceptance Criteria:**
  1. Users must be able to create watchlists containing exact keywords, wildcards (e.g., `*bank.com`), or specific threat actor handles.
  2. Incoming messages processed by the ingestion pipeline must be evaluated against active watchlists in under 100 milliseconds per message.
  3. Upon a match, the system must generate an in-app Alert Record containing: Alert ID, Watchlist ID, Matched Term, Message ID, Channel Name, and Detection Timestamp.
  4. Analysts must be able to update alert states: `New`, `Acknowledged`, `Escalated to Case`, or `False Positive`.

#### `FR-ALT-002`: Outbound SOAR / SIEM Webhook Event Dispatcher
- **Priority:** `P1 (Should Have - Release 2)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE` (`OPP-003`)
- **Description:** Outbound dispatch of alert payloads to corporate SIEM/SOAR platforms via HTTPS webhooks.
- **Verifiable Acceptance Criteria:**
  1. Organization admins must be able to configure outbound webhook target URLs with custom HMAC secret headers.
  2. High-severity alerts must dispatch a JSON webhook payload within 2 seconds of ingestion.
  3. The dispatcher must support exponential retry on target endpoint HTTP 5xx responses (3 retries).

---

### 3.7 Multi-Tenancy & Access Control Subsystem

#### `FR-TEN-001`: Tenant Data Isolation & Request Scope Verification
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED DECISION`
- **Description:** Ingested public threat chatter resides in a shared read-only repository; all customer cases, watchlists, notes, and search logs must be strictly isolated by tenant.
- **Verifiable Acceptance Criteria:**
  1. Every database query accessing customer cases, evidence notes, watchlists, or search audit logs must enforce a non-nullable `tenant_id` filter.
  2. API endpoints must resolve and validate the `tenant_id` from the authenticated user session; any attempt to query data belonging to a different `tenant_id` must return HTTP 403 Forbidden.
  3. Evidence files must be stored in tenant-partitioned filesystem paths; automated integration tests must verify zero cross-tenant directory traversal.

#### `FR-TEN-002`: Granular Role-Based Access Control (RBAC) System
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `PROPOSED PRODUCT FEATURE`
- **Description:** The system must enforce least-privilege role boundaries within customer organizations.
- **Verifiable Acceptance Criteria:**
  1. The platform must support at minimum four standard organizational roles:
     - *Tenant Admin:* Manage organization users, watchlists, and SSO settings.
     - *Senior Investigator:* Full search, thread viewing, case creation, and evidence package export.
     - *Junior Analyst (Triage):* Search, thread viewing, and alert acknowledgement; report export restricted.
     - *Auditor:* Read-only access to organizational search audit logs; zero operational case editing access.
  2. Unauthorized API calls attempting actions outside assigned role permissions must be rejected with HTTP 403 Forbidden.

---

### 3.8 Platform Administration Subsystem

#### `FR-ADM-001`: Platform Collector Fleet Telemetry & Health Monitoring
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED DECISION`
- **Description:** VFRA platform operations engineers must have an administrative console to monitor collector fleet health, proxy latencies, and ingestion queues.
- **Verifiable Acceptance Criteria:**
  1. The Platform-Admin Panel must display real-time status of all configured MTProto ingestion sessions (Active, Rate-Limited, Disconnected, Error).
  2. The panel must display real-time ingestion throughput metrics (messages ingested per minute, queued messages, error count).
  3. The administrator must be able to manually pause, resume, or restart individual channel collection tasks without restarting the application server.

---

### 3.9 Access Control, Organization Approval, Credits, and Session Policy

> [!NOTE] Provenance and Governance Classification
> Requirements in this section (`AC-REQ-001` through `AC-REQ-006`) record confirmed product requirements as relayed by the developer from company discussions. They represent authoritative product direction and stakeholder guidance for system design. Unresolved business rules, specific pricing/credit amounts, session timeouts, and technical enforcement mechanisms are maintained separately under Subsection B as **Pending Stakeholder Decisions** pending formal architectural and commercial approval.

#### A. Confirmed Product Requirements

##### `AC-REQ-001`: Platform Administration & Access Policy Scope
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED REQUIREMENT (Stakeholder Guidance Relayed by Developer)`
- **Description:** The platform administrator possesses platform-level administrative access, including organization onboarding/approval and management of global platform access policies.
- **Security Invariant & Scoping Boundary:** "Full access" is strictly scoped to platform infrastructure, collector fleet telemetry, organization approvals, and platform-wide policy management. Platform administrators do NOT possess automatic or unrestricted access to inspect, browse, or query customer confidential case files, analytical notes, suspect tags, or original evidentiary binaries without an explicit, audit-logged authorization policy (`DEC-21`).
- **Verifiable Acceptance Criteria:**
  1. Platform administrators can view and manage organization registrations, operational states, and access policy configurations across the platform.
  2. Platform administrators cannot browse, search, or export tenant-private investigative case workspaces or evidence stores unless an explicit dual-control authorization policy is active and logged.
  3. All platform administrative actions must emit high-severity security events to the immutable audit trail.

##### `AC-REQ-002`: Organization Approval & Lifecycle Gating
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED REQUIREMENT (Stakeholder Guidance Relayed by Developer)`
- **Description:** An organization must be formally approved by the platform administrator before receiving active platform access or executing threat intelligence operations.
- **Organization Lifecycle States:** The organization lifecycle must distinguish at least the following states:
  - `PENDING_APPROVAL`: Organization registered/requested; zero operational access; all investigator logins blocked.
  - `ACTIVE`: Formally approved by platform administrator; tenant workspaces, search, and user provisioning enabled.
  - `SUSPENDED`: Temporarily deactivated by platform administrator (e.g., non-payment, security breach, quota exhaustion); all active sessions terminated; new logins blocked.
  - `DEPROVISIONED`: Permanently closed; data subject to authorized retention/purge lifecycle (`DEC-08`).
- **Verifiable Acceptance Criteria:**
  1. Newly provisioned organizations default to `PENDING_APPROVAL` (or equivalent onboarding status) and cannot access threat data or case workspaces.
  2. An approval action by a platform administrator transitions the organization to `ACTIVE` and enables operational access.
  3. Transitioning an organization to `SUSPENDED` immediately blocks all user authentication attempts for that tenant and invalidates active sessions.

##### `AC-REQ-003`: Organization-Managed User Provisioning & Scoping
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED REQUIREMENT (Stakeholder Guidance Relayed by Developer)`
- **Description:** Each approved organization has designated Organization Administrators (Tenant Admins) who approve their own organization's users, assign permitted roles, and manage module access.
- **Scoping & Anti-Escalation Boundary:** Organization administrators can only manage users within their own organization. They must NOT approve users for another organization, view users of rival organizations, or grant platform-administrator privileges to any account.
- **Verifiable Acceptance Criteria:**
  1. Organization administrators can invite, approve, assign roles to, and revoke users strictly within their own `tenant_id`.
  2. API endpoints for user administration enforce strict tenant boundary checks; any attempt to manage a user belonging to another organization returns HTTP 403 Forbidden or HTTP 404 Not Found.
  3. Role assignment is restricted to authorized tenant-level operational roles (`TENANT_ADMIN`, `INVESTIGATOR_LEAD`, `INVESTIGATOR`, `READ_ONLY_ANALYST`). Platform administrator roles cannot be assigned by an organization administrator.

##### `AC-REQ-004`: Least-Privilege Sub-System Authorization
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED REQUIREMENT (Stakeholder Guidance Relayed by Developer)`
- **Description:** Access to TTI sub-systems and capabilities (Collection Telemetry, Threat Search, Thread Reconstruction, Case Workspaces, Evidence Vault, Investigation Reporting, Watchlist Alerts) is granted strictly according to the user's assigned permissions within their organization.
- **Approved Modules Inventory:** Sub-systems and capabilities are constrained strictly to approved product requirements:
  - *Threat Search & Navigation:* Observable FTS (`FR-SCH-001`), Sliding-Window Thread Viewer (`FR-THR-001`).
  - *Case Management:* Isolated Case Containers (`FR-EVI-001`), Evidence Pinning, Case Notes.
  - *Evidence & Reporting:* Media Vault Staging (`FR-EVI-003`), `REP-TXT-SCREEN-001` Report & Screenshot Generation (`FR-REP-001` to `FR-REP-004`).
  - *Alerts & Watchlists:* Real-Time Watchlist Rules & In-App Alerts (`FR-ALT-001`).
  - *Compliance Audit:* Organizational Activity Audit Inspection (`NFR-OBS-003`).
- **Verifiable Acceptance Criteria:**
  1. Every incoming API request validates that the authenticated user possesses the required permission token for the target endpoint.
  2. Users assigned read-only roles (e.g. `READ_ONLY_ANALYST`) are blocked from creating cases, editing notes, or modifying watchlists (HTTP 403 Forbidden).
  3. Junior triage analysts cannot export or finalize formal investigation packages (`FR-REP-001`).
  4. Access enforcement preserves strict multi-tenant isolation; cross-tenant access attempts fail closed.

##### `AC-REQ-005`: Organization Credit Quota & Per-Action Consumption
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED REQUIREMENT (Stakeholder Guidance Relayed by Developer)`
- **Description:** Platform utilization is governed by a two-level credit accounting model:
  1. An organization is allocated a credit quota.
  2. Eligible metered actions consume credits from the organization's balance according to approved consumption rules.
- **Accounting & Concurrency Invariants:**
  - *Organization Balance:* Credits are tracked at the organization level, shared across authorized users of that organization.
  - *Atomic Check & Deduction:* Balance verification and deduction must occur atomically (e.g., via database row-level locking or atomic Redis Lua script) to prevent concurrent requests from overspending or causing negative balances.
  - *Auditable Ledger:* Every credit deduction must record an auditable transaction capturing: Transaction ID, Organization ID, User ID, Action Type, Credits Deducted, Remaining Balance, and Timestamp.
  - *Idempotency & Retry Protection:* Deductions must be guarded by client- or server-assigned idempotency keys to prevent duplicate deductions during network retries or transient failures.
  - *Insufficient-Credit Outcome:* If an action requires more credits than the organization's available balance, the request must fail with an explicit `HTTP 402 Payment Required` (or `HTTP 403 / INSUFFICIENT_CREDITS`) error, returning current balance and required credits without executing the metered action.
  - *Multi-Tenant Isolation:* Credit balances, quota pools, and transaction ledgers are strictly segregated between organizations. Under no circumstances may an action in Organization A deduct credits from Organization B.
- **Unresolved Business Rules (Pending Stakeholder Decision):** Credit allocation amounts, pricing tiers, eligible action costs, reset intervals (monthly vs rolling), overage handling, and refund policies for failed background jobs are unconfirmed and recorded under `DEC-19`.

##### `AC-REQ-006`: Single Active Authenticated Session Per User Account
- **Priority:** `P0 (Must Have - Release 1)`
- **Governance Status:** `CONFIRMED REQUIREMENT (Stakeholder Guidance Relayed by Developer)`
- **Description:** A second login must be rejected while the same user account has an active authenticated session.
- **Session Governance Invariants:**
  - *Server-Side Enforcement:* The single active session rule must be enforced authoritatively on the server; client-side checks alone are explicitly rejected as insufficient.
  - *Account-Level Scoping:* The confirmed interpretation is **one active session per user account** across all devices and organizations. (If an investigator belongs to multiple organizations, they maintain one active authenticated session globally).
  - *Atomic Race Handling:* Simultaneous login attempts with the same valid credentials must be handled atomically so that two concurrent requests cannot both succeed.
  - *Session Lifecycle:* An active session is defined by a valid, unexpired server-tracked session token/key. A session terminates upon explicit user logout, session expiration (idle timeout / max lifetime), administrative revocation, or account lockout.
  - *Second Login Rejection & Displacement Override (Reconciled DEC-20 Policy):* When an authenticated session is active, an incoming login attempt with valid credentials without displacement confirmation must be rejected with an explicit error (`HTTP 409 Conflict: ACTIVE_SESSION_EXISTS`) informing the user that an active session is currently open. If the user explicitly confirms session displacement (e.g. passing `force_terminate_existing=true`), the previous active session is immediately revoked and displaced, allowing legitimate users to recover access after an abrupt disconnection or workstation switch while still preventing silent simultaneous concurrent sharing.
  - *Multi-Tenant Context Switching:* For users belonging to multiple organizations, switching active organization context is handled within the existing authenticated session via context refresh without triggering concurrent-session rejection.
  - *Session Audit Events:* Every session creation, rejected concurrent login attempt, intentional session displacement, logout, expiration, and administrative session termination must emit an immutable security audit event with client IP, user-agent, user ID, and timestamp.
  - *Administrative & Lost-Device Revocation:* An administrator or user recovery workflow must allow terminating existing sessions to release the lock in the event of a lost device or crashed browser.
- **Approved Engineering Implementation Decision (`DEC-20`):** Tracked via PostgreSQL `iam.active_user_sessions` enforcing `UNIQUE (user_id)` at the database constraint level. Interactive session displacement challenge (`force_terminate_existing=true`) approved by Product Owner for Release 1 implementation.

---

#### B. Stakeholder Decisions Associated with Access Control & Governance (PO Approved Engineering Baseline)

The following engineering decisions have been approved by the Product Owner for implementation (without claiming separate legal, CISO, or regulatory sign-off):

1. **`DEC-19`: Credit Quota Sizing, Per-Action Costs, and Overage Policies**
   - *Approved Engineering Baseline:* Standard thread search and scrolling remain unmetered per `FR-THR-001`. Designated heavy operations (formal `REP-TXT-SCREEN-001` report generation, dual screenshot captures, high-concurrency FTS bulk export) deduct credits from `app.tenant_credit_balances` and record immutable transaction entries in `app.credit_deduction_ledgers`. Hard cut-off blocks overdrafts (`HTTP 402 Payment Required`). Specific commercial pricing figures remain configurable.
2. **`DEC-20`: Single Active Session Expiry, Storage Technology, and Concurrency Override**
   - *Approved Engineering Baseline:* Enforced via `iam.active_user_sessions` with `UNIQUE (user_id)`. Default rejection (`HTTP 409 Conflict`) on concurrent login; interactive user displacement (`force_terminate_existing=true`) revokes previous session. Multi-tenant switching supported within active session.
3. **`DEC-21`: Platform Administrator Access Boundary Regarding Customer Evidence**
   - *Approved Engineering Baseline:* Zero ambient platform-administrator access to customer investigative workspaces, case notes, or evidence binaries. Emergency administrative access strictly gated by audited dual-control procedure.
4. **`DEC-22`: Organization Lifecycle State Transitions and Deprovisioning Rules**
   - *Approved Engineering Baseline:* Newly registered organizations enter `PENDING_APPROVAL` by default; platform-administrator verification required to transition to `ACTIVE`. Suspended and deprovisioned states block protected API access. Data purge remains subject to statutory retention schedules (`DEC-08`).
