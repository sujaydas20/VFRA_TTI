# TTI Gate 4B.2 — Subsystem Interface Contracts

**Document Reference:** `TTI-ARCH-INT-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Gate 4B.2 — Interface Contracts  
**Author:** Principal Data Architect & Security Architect  
**Date:** October 2026  
**Governance Status:** `PROPOSED SUBSYSTEM CONTRACTS — PENDING TECHNICAL REVIEW`  
**Parent Specifications:**  
- [`docs/architecture/gate_4a/subsystem_decomposition.md`](file:///d:/TTI/docs/architecture/gate_4a/subsystem_decomposition.md)  
- [`docs/architecture/gate_4a/trust_boundaries_and_data_flows.md`](file:///d:/TTI/docs/architecture/gate_4a/trust_boundaries_and_data_flows.md)  
- [`docs/architecture/gate_4b_1/logical_data_model.md`](file:///d:/TTI/docs/architecture/gate_4b_1/logical_data_model.md)  

---

## 1. Architectural Scope & Modularity Invariants

This specification defines the logical interface contracts governing communication between internal subsystems of the TTI platform. 

In accordance with the **Modular Monolith** architecture recommended in Gate 4A ([`ADR-001`](file:///d:/TTI/docs/architecture/gate_4a/architecture_decision_register.md#adr-001)):
1. **In-Process Interface Decoupling:** Subsystem boundaries are enforced via abstract interface definitions and strongly typed Data Transfer Objects (DTOs), rather than direct database table sharing or unconstrained module imports.
2. **Asynchronous Task Boundaries:** Long-running or resource-intensive tasks (network polling, Playwright screenshot capture, export zipping) transition through explicit, serialized task envelope contracts.
3. **Zero Cross-Domain Contamination:** Global threat ingestion interfaces have zero knowledge of tenant cases; case management interfaces receive immutable references to threat telemetry without mutating shared intelligence.
4. **Technology Neutrality:** Method signatures and DTOs are specified in language-neutral logical syntax, avoiding framework-specific bindings.

---

## 2. Ingestion Subsystem (`IIngestionOrchestrator`)

### 2.1 Interface Definition
The Ingestion Subsystem coordinates external Telegram polling across connectors, manages circuit breaker states, and enqueues raw ingestion payloads into the normalization pipeline.

```
interface IIngestionOrchestrator {
    schedule_channel_poll(channel_id: ChannelID, priority: PriorityLevel) -> JobRunID
    record_flood_penalty(connector_id: ConnectorID, penalty_seconds: Integer) -> Void
    get_connector_health(connector_id: ConnectorID) -> ConnectorHealthDTO
}
```

### 2.2 Method Contract: `schedule_channel_poll`
* **Inputs:**
  - `channel_id`: Canonical numerical identifier of target Telegram channel.
  - `priority`: Scheduling tier (`REALTIME_ALERT`, `STANDARD_POLL`, `HISTORICAL_BACKFILL`).
* **Outputs:** `JobRunID` (UUID tracking the initiated polling task).
* **Failure Behavior:** If the assigned connector is currently in circuit breaker state (`PAUSED_BACKOFF`), the method returns `CIRCUIT_OPEN_ERROR` and defers execution until the backoff penalty expires.
* **Idempotency:** Idempotent. Subsequent calls within an active polling interval return the existing active `JobRunID`.
* **Trust Boundary Crossing:** Operates within TB-1 (Ingestion DMZ). Communicates outbound to Telegram MTProto/Bot API via egress proxies; initiates zero inbound ports.
* **Traceability:** [`FR-COL-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-col-001), [`FR-COL-002`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-col-002).

---

## 3. Normalization & Sanitization Subsystem (`INormalizationService`)

### 3.1 Interface Definition
Processes raw inbound Telegram events, identifies conversational sequence gaps, applies heuristic credential masking, and produces canonical normalized records.

```
interface INormalizationService {
    normalize_message(raw_event: RawIngestPayloadDTO) -> NormalizationResultDTO
    reconcile_sequence_gaps(channel_id: ChannelID, observed_seq_id: Integer) -> SequenceCheckDTO
}
```

### 3.2 Method Contract: `normalize_message`
* **Inputs:**
  - `raw_event`: Verbatim JSON/Protobuf payload received from source connector, including platform metadata (`broadcast_utc`, `sender_id`, `reply_to_id`, `message_thread_id`, `linked_chat_id`).
* **Outputs:**
  - `NormalizationResultDTO`:
    - `tier1_raw_reference`: Reference locator and SHA-256 digest of original unmodified bytes.
    - `tier2_derived_record`: Normalized message object with heuristically masked text (`P@ssw****`) and extracted metadata.
    - `discontinuity_flag`: Boolean indicating whether an unrecorded sequence gap precedes this message.
* **Idempotency:** Strictly idempotent. Submitting the exact same raw payload twice yields the identical SHA-256 hash and updates zero downstream entities.
* **Security & Forensic Invariant:** **Separation of Original Evidence from Derived Data.** Normalization routines **never** overwrite or mutate Tier 1 raw evidence. The masked string (`P@ssw****`) is written exclusively to the Tier 2 derived model and search index.
* **Traceability:** [`FR-COL-003`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-col-003), [`FR-COL-004`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-col-004), [`DEC-06`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md#dec-06).

---

## 4. Thread Reconstruction Subsystem (`IThreadReconstructionEngine`)

### 4.1 Interface Definition
Reconstructs chronological conversational thread hierarchies, handles Telegram forum topic partitioning, and injects visual sequence-gap indicators.

```
interface IThreadReconstructionEngine {
    fetch_thread_window(query: ThreadWindowQueryDTO) -> ThreadWindowResponseDTO
    fetch_message_context(channel_id: ChannelID, message_id: MessageID, window_size: Integer) -> MessageContextDTO
}
```

### 4.2 Method Contract: `fetch_thread_window`
* **Inputs:**
  - `query`:
    - `channel_id`: Target channel.
    - `cursor`: Opaque base64 sequence pointer.
    - `direction`: `BEFORE` or `AFTER`.
    - `limit`: Integer (capped at 100).
    - `topic_id`: Optional forum `message_thread_id`.
* **Outputs:**
  - `ThreadWindowResponseDTO`: Chronologically ordered array of interleaved `SourceMessageDTO` and `SequenceGapDTO` items, plus `next_cursor` and `has_more`.
* **Gap Honesty Invariant:** When sequence gaps exist between consecutive messages, the engine injects explicit `SequenceGapDTO` elements (`[Sequence Discontinuity: Messages X to Y unrecorded]`) rather than assuming deletion without platform deletion events.
* **Traceability:** [`FR-THR-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-thr-001), [`FR-THR-002`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-thr-002).

---

## 5. Search Subsystem (`ISearchRepository`)

### 5.1 Interface Definition
Executes fast multi-observable lookups and full-text searches across historical chatter while strictly isolating tenant search caches and sanitizing operational telemetry.

```
interface ISearchRepository {
    execute_search(tenant_context: TenantSecurityContextDTO, query: SearchQueryDTO) -> SearchResultSetDTO
}
```

### 5.2 Method Contract: `execute_search`
* **Inputs:**
  - `tenant_context`: Validated caller identity (`tenant_id`, `user_id`, permissions).
  - `query`: Search string, indicator terms, channel filters, date boundaries, and pagination cursor.
* **Outputs:**
  - `SearchResultSetDTO`: Array of matching derived message records (with masked text snippets), pagination metadata, and execution performance metrics.
* **Security & Log Invariants:**
  1. *Cache Isolation:* Cached search results are partitioned using `tenant:{tenant_id}:search:{query_hash}`. Cross-tenant cache hits are structurally barred.
  2. *Log Sanitization:* Application telemetry records strictly `query_hash = sha256(query_text)` and execution latency. Raw query terms are excluded from logs (`ADR-008`).
* **Traceability:** [`FR-SCH-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-sch-001), [`FR-SCH-002`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-sch-002), [`NFR-OBS-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-obs-001).

---

## 6. Case Workspace & Bridge Subsystem (`ICaseWorkspaceService`)

### 6.1 Interface Definition
Manages tenant-isolated investigation workspaces, private analyst notes, and the pinning of shared threat messages via bridge associations.

```
interface ICaseWorkspaceService {
    create_case(tenant_context: TenantSecurityContextDTO, case_data: CreateCaseDTO) -> CaseRecordDTO
    pin_message_to_case(tenant_context: TenantSecurityContextDTO, pin_request: PinMessageDTO) -> CaseAssociationDTO
    unpin_message_from_case(tenant_context: TenantSecurityContextDTO, case_id: CaseID, message_id: MessageID) -> Void
    attach_case_note(tenant_context: TenantSecurityContextDTO, note_data: CreateNoteDTO) -> CaseNoteDTO
}
```

### 6.2 Method Contract: `pin_message_to_case` (Bridge Association)
* **Inputs:**
  - `tenant_context`: Mandates valid `tenant_id`.
  - `pin_request`: `case_id`, `message_id`, `investigator_tags`, `analyst_annotation`.
* **Outputs:** `CaseAssociationDTO` confirming linkage.
* **Failure Behavior:** If `case_id` does not exist or belongs to another tenant, the service returns `CASE_NOT_FOUND` (HTTP 404).
* **Multi-Tenant Invariant:** Creates an isolated `CaseMessageAssociation` row in the tenant workspace. The underlying `SourceMessage` in the shared threat layer is completely untouched. Zero information is exposed to other tenants.
* **Traceability:** [`FR-EVI-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-evi-001), [`NFR-SEC-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-sec-001), [`DEC-05`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md#dec-05).

---

## 7. Evidence Vault & Media Retrieval Subsystem (`IEvidenceStorageVault`)

### 7.1 Interface Definition
Stages downloaded media binaries into an encrypted filesystem or object vault, computes immutable SHA-256 hashes on write, and enforces controlled anti-oracle retrieval.

```
interface IEvidenceStorageVault {
    store_media_binary(raw_stream: ByteStream, mime_type: String) -> MediaStorageReceiptDTO
    retrieve_case_evidence(tenant_context: TenantSecurityContextDTO, case_id: CaseID, artifact_id: ArtifactID) -> EvidenceStreamDTO
}
```

### 7.2 Method Contract: `retrieve_case_evidence` (Anti-Oracle Protection)
* **Inputs:**
  - `tenant_context`: Authenticated session.
  - `case_id`: Owning case identifier.
  - `artifact_id`: Target media binary identifier.
* **Outputs:** `EvidenceStreamDTO` (Readable binary stream, MIME type, verified SHA-256 hash).
* **Anti-Oracle Security Logic:**
  - The vault refuses any lookup by raw SHA-256 digest without an authorized case context.
  - If `case_id` is foreign to `tenant_context.tenant_id`, or if `artifact_id` is not pinned to that case, the service immediately throws `EvidenceNotFoundException` (yielding HTTP 404).
* **Storage Immutability Status:** Media storage semantics are **`PROVISIONAL PENDING RESOLUTION OF DEC-08 AND RELEVANT LEGAL REVIEW`**. The vault balances tamper-proof retention against court-ordered expungements, erasure mandates, and unlawful content purging.
* **Traceability:** [`FR-EVI-003`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-evi-003), [`NFR-SEC-002`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-sec-002), [`DEC-08`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md#dec-08).

---

## 8. Investigation Reporting Subsystem (`IReportPackagingOrchestrator`)

### 8.1 Interface Definition
Implements the approved [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001) pipeline: compiles UTF-8 plain-text summaries, orchestrates Playwright headless screenshot capture, manages human pre-delivery review, and seals deliverables with cryptographic manifests.

```
interface IReportPackagingOrchestrator {
    initiate_report_job(tenant_context: TenantSecurityContextDTO, spec: ReportGenerationSpecDTO) -> ReportJobReceiptDTO
    render_report_preview(tenant_context: TenantSecurityContextDTO, report_id: ReportID) -> ReportPreviewDTO
    finalize_and_seal_package(tenant_context: TenantSecurityContextDTO, sign_off: ReportSignOffDTO) -> SealedPackageDTO
}

interface IScreenshotRenderer {
    capture_message_screenshot(target_msg_id: MessageID) -> ScreenshotResultDTO
    capture_thread_context_screenshot(target_msg_id: MessageID, window_size: Integer) -> ScreenshotResultDTO
}
```

### 8.2 Method Contract: `finalize_and_seal_package`
* **Inputs:**
  - `tenant_context`: Mandates role `INVESTIGATOR_LEAD` or `TENANT_ADMIN`.
  - `sign_off`: `report_id`, investigator confirmation flag, redaction completion flag, analyst notes.
* **Outputs:**
  - `SealedPackageDTO`:
    - `report_package_id`: Canonical shared investigation reference.
    - `package_sha256_hash`: Hash of finalized `.zip` archive.
    - `manifest_sha256`: Hash of `manifest.json`.
    - `download_locator`: Temporary presigned token for sealed archive download.
* **Inviolable Pre-Delivery Gate:** If `redaction_reviewed` is false or sign-off is missing, the service throws `PreDeliveryReviewIncompleteException`. Deliverables cannot be downloaded without human sign-off (`FR-REP-004`).
* **Open Decisions Preserved:** Capture trigger modality (manual vs automated vs hybrid under `DEC-13`), storage retention schedule (`DEC-08`), and courtroom admissibility standards remain open stakeholder decisions.
* **Traceability:** [`REP-TXT-SCREEN-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#rep-txt-screen-001), [`FR-REP-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-rep-001) to [`FR-REP-004`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-rep-004), [`DEC-13`](file:///d:/TTI/docs/product/product_baseline/decision_and_traceability_matrix.md#dec-13).

---

## 9. Audit Logging & Telemetry Subsystem (`IAuditLogger`)

### 9.1 Interface Definition
Maintains an immutable append-only ledger of security-sensitive events and provides sanitized logging utilities.

```
interface IAuditLogger {
    log_security_event(event: SecurityAuditEventDTO) -> Void
    sanitize_telemetry(raw_query: String) -> TelemetryDigestDTO
}
```

### 9.2 Invariants:
1. **Append-Only Immutability:** The audit store exposes zero update or deletion interfaces.
2. **Query Target Hashing:** `sanitize_telemetry` transforms raw query strings into HMAC/SHA-256 hashes (`target_identifier_hash`), ensuring zero cleartext search terms in logs.
3. **Traceability:** [`NFR-OBS-001`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-obs-001), [`NFR-OBS-003`](file:///d:/TTI/docs/product/product_baseline/non_functional_requirements.md#nfr-obs-003).

---

## 10. Optional AI Advisory Subsystem (`IAIAdvisoryService`)

### 10.1 Interface Definition
Provides optional, asynchronous post-processing assistance (translation, summarization, entity tagging).

```
interface IAIAdvisoryService {
    request_message_summary(tenant_context: TenantSecurityContextDTO, message_ids: Array<MessageID>) -> AISummaryDTO
    request_translation(tenant_context: TenantSecurityContextDTO, message_id: MessageID, target_lang: String) -> AITranslationDTO
}
```

### 10.2 Architectural Boundaries & Invariants:
1. **Zero Core Pipeline Dependency:** The core ingestion, normalization, thread viewer, and reporting pipelines have zero runtime dependency on AI services (`ADR-009`).
2. **Human-in-the-Loop Mandatory:** All AI outputs are labeled `is_ai_generated=True`. They are advisory only and cannot be included in formal court deliverables without explicit investigator approval.
3. **Traceability:** [`FR-AI-001`](file:///d:/TTI/docs/product/product_baseline/functional_requirements.md#fr-ai-001), [`ADR-009`](file:///d:/TTI/docs/architecture/gate_4a/architecture_decision_register.md#adr-009).

---

*Next Interface Specification:* [`error_and_pagination_conventions.md`](file:///d:/TTI/docs/architecture/gate_4b_2/error_and_pagination_conventions.md)
