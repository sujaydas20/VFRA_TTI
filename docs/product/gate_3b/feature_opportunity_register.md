# TTI Feature Opportunity Register

**Document Reference:** `TTI-DOC-PRD-OPP-001`  
**Product:** Telegram Threat Intelligence (TTI)  
**Lifecycle Stage:** Gate 3B — Stakeholder Alignment  
**Role:** Senior Product Analyst  
**Date:** 2026-10-28  
**Status:** **ACTIVE REGISTER — PROPOSED — PENDING VFRA APPROVAL**  

---

## 1. Register Overview & Governance Model

This register consolidates all candidate feature opportunities, functional enhancements, and reporting workflows identified during competitor benchmarking (Gates 2 through 3A) and customer workflow modeling (Gate 3B). 

> [!IMPORTANT]
> **Governance Rule:** In strict accordance with project rules, every capability listed in this register remains categorized as **`PROPOSED — PENDING VFRA APPROVAL`**. Inclusion in this register does **not** constitute an approved requirement, design baseline, or architectural commitment.

---

## 2. Feature Opportunity Master Table

| Feature ID | Feature Name | Target Subsystem | Proposed Category | Predecessor / Benchmark | Status | Priority for Review |
| :---: | :--- | :--- | :--- | :--- | :---: | :---: |
| **`REP-TXT-SCREEN-001`** | **TXT Report with Dual-Scope Screenshot Evidence** | `backend/app/reports/` & `evidence/` | Investigation Reporting & Evidence | Law Enforcement & CTI Deliverable | **`APPROVED BY VFRA`** | **Confirmed** |
| `OPP-001` | Continuous Cursor-Based Thread Viewer | `connectors/telegram/` & `frontend/` | Core Ingestion & Navigation | StealthMole Scroll Penalty (`Slide 51`) | `PROPOSED — PENDING VFRA APPROVAL` | High |
| `OPP-002` | Recursive AST Boolean Search Engine | `backend/app/api/` | Search & Discovery | StealthMole 3-OR Ceiling (`Slide 49`) | `PROPOSED — PENDING VFRA APPROVAL` | High |
| `OPP-003` | OpenAPI 3.1 REST Endpoints & Webhooks | `backend/app/api/v1/` | Integration & Automation | Recorded Future Connect API (`EVID-RF-001`) | `PROPOSED — PENDING VFRA APPROVAL` | High |
| `OPP-004` | Enterprise SAML 2.0 / OIDC Single Sign-On | `backend/app/core/` | Security & Access Control | Industry Standard Baseline | `PROPOSED — PENDING VFRA APPROVAL` | Medium |
| `OPP-005` | Multi-Tenant Data & Case Isolation | `backend/app/database/` | Architecture & Tenancy | ShadowDragon CJIS Alignment (`EVID-SD-009`)| `PROPOSED — PENDING VFRA APPROVAL` | High |
| `OPP-006` | Cryptographic Evidence Ledger (SHA-256) | `backend/app/evidence/` | Forensic Chain of Custody | Hunchly & Maltego Evidence (`EVID-MAL-003`)| `PROPOSED — PENDING VFRA APPROVAL` | High |
| `OPP-007` | Standardized STIX 2.1 & MISP Exporters | `backend/app/reports/` | Integration & Interoperability | Intel 471 & Recorded Future TAXII | `PROPOSED — PENDING VFRA APPROVAL` | Medium |
| `OPP-008` | Dual-Tier OCR & Multimodal Vision Triage | `backend/app/ai/` | Automated Enrichment | StealthMole Image Processing (`Slide 8`) | `PROPOSED — PENDING VFRA APPROVAL` | Medium |

---

## 3. Detailed Feature Specifications

---

### `REP-TXT-SCREEN-001`: Structured TXT Report with Dual-Scope Screenshot Evidence

* **Requirement Statement:** *Every applicable investigation report must support a TXT report accompanied by both relevant-message screenshots and thread-context screenshots, subject to source availability and authorized access.*
* **Status:** `APPROVED BY VFRA`
* **Approval Basis:** Stakeholder confirmation supplied by the project owner.
* **Scope Definition:** Mandatory reporting baseline covering structured TXT report, relevant individual-message screenshots, and thread-context screenshots under a common investigation reference.
* **Pending Decisions:** Associated operational capture modality (manual vs. automated vs. hybrid), storage retention schedules, and formal evidence/timestamping standards remain unapproved pending stakeholder decisions.
* **Target Audience:** Law enforcement investigators, corporate threat intelligence analysts, and VFRA managed intelligence specialists.
* **Problem Solved:** Current market offerings either provide raw JSON/Excel dumps (StealthMole) that lack visual corroboration, or heavyweight PDF reports that cannot be easily parsed, ingested into case-management databases, or verified against underlying conversational context.

#### Acceptance Criteria to Validate
1. **Shared Report Reference:** The structured TXT report and all associated screenshots must share a common, unique report/investigation reference identifier (e.g., `TTI-REP-2026-0042`).
2. **Dual-Scope Screenshot Distinction:** The platform must clearly distinguish between:
   - *Individual-Message Screenshots (`SCR-INDIV-<id>.png`):* Focused captures of the specific evidentiary message, handle, and media.
   - *Thread-Context Screenshots (`SCR-THREAD-<id>.png`):* Panoramic captures showing the surrounding chronological conversation thread (preceding and succeeding messages), where available and authorized.
3. **Internal Cross-Referencing:** Entries and narrative findings within the TXT report must explicitly reference their supporting screenshot identifiers.
4. **Limitation & Incomplete Data Logging:** Missing metadata fields (e.g., masked sender IDs, unavailable forward provenance) and capture limitations (e.g., deleted messages, media download timeouts) must be explicitly documented in the report header and entries.
5. **Pre-Delivery Review Gate:** Authorized users must be provided a pre-delivery review workflow to inspect the complete assembled package (TXT report + screenshots) for accuracy, completeness, and sensitive third-party PII redaction before authorized export or delivery.

#### Technical & Operational Considerations
* **File System & Storage Packaging:** The deliverable should be packaged as a single standardized bundle (e.g., a `.zip` archive containing the `report.txt` and an `assets/` directory containing the referenced `.png` screenshots).
* **Storage Footprint:** While TXT reports consume negligible storage (<50 KB), high-resolution screenshots consume 1–5 MB per capture. Storage capacity planning must account for screenshot quotas per case.
* **Access Control:** Access to screenshots must be restricted to authorized users assigned to the parent case via RBAC.
* **Legal Admissibility Guardrail:**
  > [!CAUTION]
  > **Legal Disclaimer:** Screenshots alone do **NOT** independently establish authenticity or legal admissibility in court. They serve strictly as visual corroboration to accompany underlying message records, network headers, and cryptographic SHA-256 hashes.

---

### `OPP-001`: Continuous Cursor-Based Thread Viewer

* **Requirement Statement:** *TTI should provide an unmetered, sliding-window conversational thread viewer allowing investigators to navigate historical Telegram message contexts smoothly.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Replaces StealthMole's aggressive micro-metering penalty (**1 query consumed per 10 messages scrolled**, `Slide 51`).
* **Core Value:** Preserves conversational narrative, allowing analysts to read threat actor coordination in context rather than viewing fragmented single-message query hits.

---

### `OPP-002`: Recursive AST Boolean Search Engine

* **Requirement Statement:** *TTI should implement an unconstrained Abstract Syntax Tree (AST) Boolean search engine supporting arbitrary nested grouping `((A OR B) AND (C NOT D))` across message bodies and indicator attributes.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Breaks StealthMole's documented constraint capping Boolean queries at **3 `OR` operators and 5 total operators** (`Slide 49`).

---

### `OPP-003`: OpenAPI 3.1 REST Endpoints & Webhooks

* **Requirement Statement:** *TTI should provide fully documented OpenAPI 3.1 REST endpoints and outbound webhook dispatchers for automated alert triage and SIEM/SOAR ingestion.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Solves the major architectural void in StealthMole v3.3 (which documents zero REST APIs) and matches Recorded Future's Connect API standards.

---

### `OPP-004`: Enterprise SAML 2.0 / OIDC Authentication

* **Requirement Statement:** *TTI should support enterprise identity federation via SAML 2.0 and OpenID Connect (OIDC) for Okta, Microsoft Entra ID, and government identity gateways.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Standard enterprise security baseline verified across Recorded Future (`EVID-RF-005`), Intel 471, and ShadowDragon.

---

### `OPP-005`: Multi-Tenant Data & Case Isolation

* **Requirement Statement:** *TTI should enforce strict logical and database isolation separating public threat intelligence streams from private customer cases, notes, watchlists, and search audit trails.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Essential for Law Enforcement CJIS alignment and corporate confidentiality.

---

### `OPP-006`: Cryptographic Evidence Ledger (SHA-256)

* **Requirement Statement:** *TTI should calculate and record immutable SHA-256 hashes for all raw ingested messages, downloaded media files, and generated report packages upon creation.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Matches the forensic integrity benchmark established by Hunchly and Maltego Evidence (`EVID-MAL-003`), overcoming StealthMole's unverified file exports.

---

### `OPP-007`: Standardized STIX 2.1 & MISP Exporters

* **Requirement Statement:** *TTI should support exporting threat indicators, actor profiles, and incident dossiers in standardized STIX 2.1 JSON and MISP formats.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Aligns with modern Threat Intelligence Platform (TIP) interoperability standards demonstrated by Recorded Future and Intel 471.

---

### `OPP-008`: Dual-Tier OCR & Multimodal Vision Triage

* **Requirement Statement:** *TTI should implement deterministic CPU-based OCR (Tesseract) as Tier 1 for bulk image text extraction, selectively routing high-priority candidates to vision VLMs for deep semantic triage.*
* **Status:** `PROPOSED — PENDING VFRA APPROVAL`
* **Benchmark:** Optimizes GPU compute costs while ensuring full text extraction from screenshot dumps and contraband flyers posted in Telegram channels.