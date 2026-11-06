# TTI Non-Functional Requirements Specification

**Document Reference:** `TTI-DOC-BSL-NFR-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Product Baseline & Release 1 Scope  
**Author:** Product Research & Architecture Team  
**Date:** 2026-10-28  
**Governance Status:** `PROPOSED PRODUCT BASELINE — PENDING STAKEHOLDER REVIEW`  
**Predecessor Documents:**
- [`docs/security_baseline.md`](file:///d:/TTI/docs/security_baseline.md)
- [`docs/architecture.md`](file:///d:/TTI/docs/architecture.md)
- [`docs/product/gate_3b/assumptions_and_constraints.md`](file:///d:/TTI/docs/product/gate_3b/assumptions_and_constraints.md)

---

## 1. Governance & Validation Status Definitions

Non-functional requirements (NFRs) define the operational quality attributes, performance constraints, and architectural invariants of TTI. In strict accordance with engineering governance, each target is labeled with its validation status:

- **`ARCHITECTURAL INVARIANT`**: A mandatory security, compliance, or structural rule that is enforced by code construction and cannot be breached.
- **`PROPOSED TARGET — PENDING LOAD VALIDATION`**: A quantitative performance, scale, or latency target derived from engineering estimations that must be benchmarked and validated during load testing before formal SLA commitment.
- **`ENGINEERING RECOMMENDATION`**: A design pattern or reliability target recommended by architecture based on competitor research and operational best practices.

---

## 2. Non-Functional Requirements Summary Table

| Requirement ID | Domain | Attribute Summary | Target Metric / Rule | Validation Status |
| :--- | :--- | :--- | :--- | :---: |
| **`NFR-SEC-001`** | Security | Multi-Tenant Data & Directory Isolation | Zero cross-tenant leakage; isolated caches  | `ARCHITECTURAL INVARIANT` |
| **`NFR-SEC-002`** | Security | Cryptographic Hashing of Ingested Payloads | SHA-256 calculated on raw JSON upon ingress | `ARCHITECTURAL INVARIANT` |
| **`NFR-SEC-003`** | Security | Input Sanitization & Attack Neutralization | 100% of text payloads sanitized prior to DB | `ARCHITECTURAL INVARIANT` |
| **`NFR-SEC-004`** | Security | Encryption at Rest & Secret Management | Zero plaintext credentials in git; AES-256 DB | `ARCHITECTURAL INVARIANT` |
| **`NFR-SEC-005`** | Security | Session Token Lifecycle & Inactivity Timeout | JWT expiry 15m; 30m idle session timeout | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-PERF-001`**| Performance | Thread View Sliding-Window Render Latency | < 300 ms for 50-message cursor fetch | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-PERF-002`**| Performance | Full-Text Search Execution Latency | < 1,500 ms across 2,000,000 indexed messages | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-PERF-003`**| Performance | Real-Time Watchlist Evaluation Throughput | < 100 ms match latency per incoming message | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-PERF-004`**| Performance | Report Package Assembly & Zip Time | < 5,000 ms for 20-message + screenshot bundle| `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-PERF-005`**| Performance | Headless Screenshot Capture Latency | < 2,500 ms per dual-scope screenshot pair | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-REL-001`** | Reliability | API Service Availability & Uptime | 99.5% uptime during business operating hours | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-REL-002`** | Reliability | Graceful Degraded Mode on Telegram Throttling| Zero worker crash on FLOOD_WAIT_X | `ARCHITECTURAL INVARIANT` |
| **`NFR-REL-003`** | Reliability | Message Ingestion Queue Durability | Redis/Celery queue zero message loss on restart| `ENGINEERING RECOMMENDATION` |
| **`NFR-SCA-001`** | Scalability | Release 1 Channel Ingestion Capacity | Proposed 500-1,500 (Growth) / 100-300 (Boot)| `PROPOSED TARGET — BUDGET DEPENDENT`  |
| **`NFR-SCA-002`** | Scalability | Release 1 Storage Throughput Capacity | ~1,000,000 messages / month (~500 GB media) | `PROPOSED TARGET — PENDING VALIDATION` |
| **`NFR-MNT-001`** | Maintainability| Database Migration Defensibility | 100% Alembic migration reversibility | `ARCHITECTURAL INVARIANT` |
| **`NFR-MNT-002`** | Maintainability| Automated Test Coverage Floor | >= 80% line coverage on backend core/ingest | `ENGINEERING RECOMMENDATION` |
| **`NFR-MNT-003`** | Maintainability| Programmatic API Contract Compliance | 100% OpenAPI 3.1 schema validation | `ARCHITECTURAL INVARIANT` |
| **`NFR-OBS-001`** | Observability | Structured Logging & Query Sanitization | JSON logs with tenant_id; query text redacted| `ARCHITECTURAL INVARIANT` |
| **`NFR-OBS-002`** | Observability | Subsystem Health Diagnostic Probes | HTTP /health probe checking DB, Redis, Disk | `ARCHITECTURAL INVARIANT` |
| **`NFR-OBS-003`** | Observability | Immutable Security & Investigation Audit Trail| Tamper-evident append-only audit event log | `ARCHITECTURAL INVARIANT` |

---

## 3. Detailed Non-Functional Requirements

---

### 3.1 Security & Compliance Targets

#### `NFR-SEC-001`: Multi-Tenant Data & Directory Isolation
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** The platform must enforce strict logical and physical isolation between customer tenants across database tables, storage directories, caching layers, and API endpoints, with fail-closed behavior when tenant context is absent.
- **Target Metrics & Verification:**
  - Database queries for customer cases, notes, watchlists, and search history must mandate a non-nullable `tenant_id` filter; requests lacking authenticated tenant context must fail closed (HTTP 401 Unauthorized or HTTP 403 Forbidden).
  - All tenant-scoped Redis cache entries, user session buffers, and background alert jobs must enforce cryptographic tenant key namespacing: `tenant:{tenant_id}:{subsystem}:{key}`. Shared public threat caches must use `public:threat:{key}` and contain zero tenant annotations.
  - Evidence files must reside in `/evidence_store/{tenant_id}/`. Automated path traversal tests injecting `../` or encoded `%2e%2e%2f` must return HTTP 400/403 and fail closed.
  - Automated CI test suites must include adversarial cross-tenant access assertions (e.g., verifying that Tenant B receives HTTP 404 when querying Tenant A's Case ID, and zero cross-tenant cache hit leakage).
  - Cross-tenant data leakage rate: **Zero occurrences (0.00%)**.

#### `NFR-SEC-002`: Cryptographic Hashing of Ingested Payloads
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** Every raw message payload and downloaded media asset must have an immutable cryptographic hash computed immediately upon ingestion.
- **Target Metrics & Verification:**
  - Algorithm: **SHA-256** (FIPS 180-4 compliant).
  - Storage: Non-nullable `sha256_hash` column populated during initial insert transaction.
  - Re-verification check: Hash of stored artifact must match initial digest with zero divergence.

#### `NFR-SEC-003`: Input Sanitization & Threat Neutralization
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** 100% of untrusted external text payloads must pass through the centralized `InputSanitizer` prior to database indexing.
- **Target Metrics & Verification:**
  - Strip 100% of ASCII control characters (`\x00`–`\x1F`, preserving `\r`, `\n`, `\t`).
  - Redact 100% of `<script>`, `<iframe>`, and `<object>` tags from rendered views.
  - Defang 100% of `javascript:`, `data:`, and `file:` URIs.
  - Enforce a maximum message text ceiling of 1,000,000 characters to prevent memory exhaustion DoS.

#### `NFR-SEC-004`: Encryption at Rest & Secret Management
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** Zero credentials committed to version control; sensitive persistent data encrypted at rest.
- **Target Metrics & Verification:**
  - Pre-commit scanning must verify zero API secrets, Telegram session tokens, or private keys exist in the repository.
  - Database storage volumes housing evidence and case notes must utilize AES-256 block-level encryption (LUKS / AWS EBS Encryption).

#### `NFR-SEC-005`: Session Token Lifecycle & Inactivity Timeout
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Enforce strict session token expiration and idle timeouts for user interfaces.
- **Target Metrics & Verification:**
  - JWT access tokens expire after **15 minutes**.
  - Refresh tokens expire after **8 hours** with single-use rotation.
  - Client interface automatically locks after **30 minutes of analyst inactivity**, requiring re-authentication to resume case exploration.

---

### 3.2 Performance & Latency Targets

#### `NFR-PERF-001`: Thread View Sliding-Window Render Latency
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Rapid cursor-based retrieval of adjacent message context to ensure seamless investigation.
- **Target Metric:** Fetching and rendering an adjacent sliding window of 50 messages must complete with a **p95 latency < 300 milliseconds** under a simulated load of 50 concurrent active analyst sessions.

#### `NFR-PERF-002`: Full-Text Search Execution Latency
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Interactive search response times across historical message archives.
- **Target Metric:** Full-text keyword searches across a database indexing 2,000,000 Telegram messages must return the first page of 20 results with a **p95 latency < 1,500 milliseconds**.

#### `NFR-PERF-003`: Real-Time Watchlist Evaluation Throughput
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Inline evaluation of incoming messages against active organizational watchlists.
- **Target Metric:** Evaluating an incoming message against 500 active keyword/regex watchlist rules must complete with a **p99 latency < 100 milliseconds** to prevent ingestion queue backlog.

#### `NFR-PERF-004`: Report Package Assembly & Zip Compression Time
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Compiling the approved `REP-TXT-SCREEN-001` package.
- **Target Metric:** Generating the structured UTF-8 TXT report, reading 20 supporting PNG screenshot files, computing `manifest.json` SHA-256 hashes, and building the final `.zip` bundle must complete with a **p95 latency < 5,000 milliseconds**.

#### `NFR-PERF-005`: Headless Screenshot Capture Latency
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Sandboxed browser rendering and capturing of evidentiary screenshots.
- **Target Metric:** Rendering and capturing a dual-scope pair (one focused individual-message screenshot + one thread-context screenshot) using the headless Playwright container must complete with a **p95 latency < 2,500 milliseconds**.

---

### 3.3 Reliability & Availability Targets

#### `NFR-REL-001`: API Service Availability & Uptime
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION`
- **Specification:** Uptime availability for core web APIs and search surfaces.
- **Target Metric:** Target **99.5% availability** during business operating hours (excluding scheduled maintenance windows announced 48 hours in advance).

#### `NFR-REL-002`: Graceful Degraded Mode on Telegram Throttling
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** Ingestion workers must never crash or terminate when encountering platform rate limits.
- **Target Metric:** 100% of Telegram `FLOOD_WAIT_X` exceptions must be handled cleanly via automated backoff and sleep scheduling. Zero worker process terminations due to unhandled platform flood exceptions.

#### `NFR-REL-003`: Message Ingestion Queue Durability
- **Classification:** `ENGINEERING RECOMMENDATION`
- **Specification:** Buffer incoming message bursts using Redis/Celery queue persistence.
- **Target Metric:** Queued messages must be persisted to disk (AOF or RDB snapshots). If an ingestion worker node crashes, queued messages must remain in the broker and resume processing within 60 seconds of worker recovery with zero message loss.

---

### 3.4 Scalability & Capacity Targets

#### `NFR-SCA-001`: Release 1 Channel Ingestion Capacity
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION & BUDGET APPROVAL` (Dependent on `DEC-04` & `DEC-11`)
- **Specification:** Concurrent channel monitoring capacity for Release 1 MVP, strictly conditional on approved operational expenditure.
- **Target Metric:** Sizing model proposes **500 to 1,500 Telegram channels and supergroups** if the `Growth Tier` budget ($1,500–$3,500/mo) is authorized by leadership; if constrained to `Bootstrap Tier` (<$1,000/mo), the target will scale to **100 to 300 channels**. Capacity must be confirmed via measured load tests on reference crawler workers before production commitment.

#### `NFR-SCA-002`: Release 1 Storage Throughput Capacity
- **Classification:** `PROPOSED TARGET — PENDING LOAD VALIDATION` (Dependent on `DEC-04` & `DEC-11`)
- **Specification:** Storage throughput and capacity targets for Release 1 MVP.
- **Target Metric:** Sizing model plans for sustaining an ingestion velocity of **~1,000,000 messages per month**, with an initial allocated media vault volume of **500 GB** for screenshots and evidence attachments, subject to load testing and screenshot quota policies.

---

### 3.5 Maintainability & Code Quality Targets

#### `NFR-MNT-001`: Database Migration Defensibility
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** All database schema changes must be managed via version-controlled Alembic migrations.
- **Target Metric:** 100% of Alembic migration scripts must implement valid, non-destructive `upgrade()` and `downgrade()` functions. Migrations must be verified in automated CI tests prior to deployment.

#### `NFR-MNT-002`: Automated Test Coverage Floor
- **Classification:** `ENGINEERING RECOMMENDATION`
- **Specification:** Test coverage across critical business logic and ingestion security boundaries.
- **Target Metric:** The codebase must maintain a minimum of **80% statement line coverage** across `backend/app/ingestion/`, `backend/app/evidence/`, `backend/app/reports/`, and `backend/app/api/`.

#### `NFR-MNT-003`: Programmatic API Contract Compliance
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** REST API endpoints must strictly adhere to the OpenAPI 3.1 specification.
- **Target Metric:** 100% of endpoint request payloads and response bodies must validate against Pydantic schema contracts. Zero unvalidated JSON dictionary returns.

---

### 3.6 Observability & Diagnostic Targets

#### `NFR-OBS-001`: Structured JSON Logging with Tenant Context & Query Sanitization
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** Application logging must output machine-parseable structured JSON with mandatory sanitization of sensitive investigative queries and notes.
- **Target Metric:** 100% of application log records must output valid JSON containing: `timestamp` (ISO-8601 UTC), `level`, `tenant_id`, `trace_id`, `subsystem`, and `message`. Raw search query text, suspect indicators, and analyst case notes must be redacted from logs; only query execution metrics and cryptographic query hashes may be emitted to prevent unauthorized exposure in centralized log repositories.

#### `NFR-OBS-002`: Subsystem Health Diagnostic Probes
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** Health endpoints to enable continuous orchestration and automated failure recovery.
- **Target Metric:** The system must expose `GET /api/v1/health` evaluating: database connectivity, Redis broker responsiveness, evidence filesystem writeability, and collector worker process status. Must respond in < 150 ms.

#### `NFR-OBS-003`: Immutable Security & Investigation Audit Trail
- **Classification:** `ARCHITECTURAL INVARIANT`
- **Specification:** Comprehensive, tamper-evident recording of all sensitive actions.
- **Target Metric:** The platform must write an immutable audit log entry for: user authentication, search query execution, password unmasking events, case evidence tagging, report generation, and report export approval. Audit records must be stored in an append-only database table.
