# TTI Research Gate 3 — Competitor Deep Dive Completion Report

**Document Reference:** `TTI-DOC-RES-003-REPORT`  
**Audit Target:** Competitor Research Deep Dive (`docs/research/competitors/`)  
**Platforms Audited:** Recorded Future, Maltego, Intel 471 (TITAN / Verity471), ShadowDragon (Horizon / SocialNet), StealthMole (v3.3 Baseline)  
**Role:** Senior Product Research Analyst & Threat Intelligence Platform Architect  
**Date:** 2026-10-28  
**Status:** Research Complete; Awaiting Human Owner Review  

---

## 1. Executive Verdict

### Verdict: **PASS**

### Summary Justification
The Competitor Deep Dive for Research Gate 3 has been completed in full compliance with the research methodology and governance framework (`TTI-DOC-RES-003-METH`):
1. **Comprehensive Source-Backed Documentation:** All four target platforms—**Recorded Future**, **Maltego**, **Intel 471**, and **ShadowDragon**—have been investigated across all 12 mandatory investigation areas, producing 24 modular research documents plus 3 cross-platform governance and comparison deliverables (totaling 27 newly authored files).
2. **Dedicated Evidence Registers:** Each of the four competitors possesses an independent, traceable evidence register linking every technical finding to official product manuals, developer API references, GitHub SDK repositories, and certified partner specifications.
3. **Strict Non-Assumed Absence Rule:** Silence in reviewed documentation was rigorously classified as `UNKNOWN / NOT DOCUMENTED IN REVIEWED SOURCES` rather than claimed as verified absence.
4. **TTI Proposal Discipline:** All candidate architectural opportunities (`OPP-001` through `OPP-008`) remain strictly categorized as **`STATUS: PROPOSED, NOT APPROVED`**, complete with balanced evaluations of implementation costs, operational overhead, and legal/privacy risks.
5. **Zero Implementation or Code Changes:** No application code, test suites, database migrations, or collection connectors were altered or activated.

---

## 2. Repository & Deliverables Verification

### 2.1 Git Repository Verification
- **Branch:** `master`
- **Predecessor Commit:** `05eec4d` (`docs(audit): complete Gate 2A independent quality audit and targeted corrections`)
- **Working Tree State:** All 27 research documents created and staged under `docs/research/competitors/`.

### 2.2 Complete Deliverables Inventory (27 Documents)

| Competitor / Domain | Directory Path | Deliverables Generated |
| :--- | :--- | :--- |
| **Governance & Methods** | `docs/research/competitors/` | [`research_methodology.md`](file:///D:/TTI/docs/research/competitors/research_methodology.md), [`cross_platform_comparison.md`](file:///D:/TTI/docs/research/competitors/cross_platform_comparison.md), [`gate_3_report.md`](file:///D:/TTI/docs/research/competitors/gate_3_report.md) |
| **Recorded Future** | `docs/research/competitors/recorded_future/` | [`product_overview.md`](file:///D:/TTI/docs/research/competitors/recorded_future/product_overview.md), [`module_inventory.md`](file:///D:/TTI/docs/research/competitors/recorded_future/module_inventory.md), [`workflows_and_integrations.md`](file:///D:/TTI/docs/research/competitors/recorded_future/workflows_and_integrations.md), [`security_and_governance.md`](file:///D:/TTI/docs/research/competitors/recorded_future/security_and_governance.md), [`limitations_and_unknowns.md`](file:///D:/TTI/docs/research/competitors/recorded_future/limitations_and_unknowns.md), [`evidence_register.md`](file:///D:/TTI/docs/research/competitors/recorded_future/evidence_register.md) |
| **Maltego** | `docs/research/competitors/maltego/` | [`product_overview.md`](file:///D:/TTI/docs/research/competitors/maltego/product_overview.md), [`module_inventory.md`](file:///D:/TTI/docs/research/competitors/maltego/module_inventory.md), [`workflows_and_integrations.md`](file:///D:/TTI/docs/research/competitors/maltego/workflows_and_integrations.md), [`security_and_governance.md`](file:///D:/TTI/docs/research/competitors/maltego/security_and_governance.md), [`limitations_and_unknowns.md`](file:///D:/TTI/docs/research/competitors/maltego/limitations_and_unknowns.md), [`evidence_register.md`](file:///D:/TTI/docs/research/competitors/maltego/evidence_register.md) |
| **Intel 471** | `docs/research/competitors/intel_471_titan/` | [`product_overview.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/product_overview.md), [`module_inventory.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/module_inventory.md), [`workflows_and_integrations.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/workflows_and_integrations.md), [`security_and_governance.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/security_and_governance.md), [`limitations_and_unknowns.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/limitations_and_unknowns.md), [`evidence_register.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/evidence_register.md) |
| **ShadowDragon** | `docs/research/competitors/shadowdragon_horizon/` | [`product_overview.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/product_overview.md), [`module_inventory.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/module_inventory.md), [`workflows_and_integrations.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/workflows_and_integrations.md), [`security_and_governance.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/security_and_governance.md), [`limitations_and_unknowns.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/limitations_and_unknowns.md), [`evidence_register.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/evidence_register.md) |

---

## 3. High-Level Synthesis of Competitor Research Findings

```
+----------------------------------------------------------------------------------------------------+
|                                    COMPETITOR ARCHITECTURAL MATRIX                                 |
+-------------------+--------------------+------------------------+----------------------------------+
| Platform          | Primary Paradigm   | Telegram Ingestion     | Core Strength / Benchmark        |
+-------------------+--------------------+------------------------+----------------------------------+
| StealthMole       | Closed CTI Portal  | Curated by OSINT team  | Stealer forensics & reverse pass |
| Recorded Future   | Knowledge Graph    | Automated + Insikt NLP | Intelligence Cards & Connect API |
| Maltego           | Link Graph Engine  | On-demand transforms   | Open transforms, Hunchly & Evidence|
| Intel 471         | Cyber Underground  | Undercover HUMINT bots | Streaming API & stealer telemetry|
| ShadowDragon      | OSINT Attribution  | Public channel mapping | Hundreds of sites, 140+ jurisdictions |
+-------------------+--------------------+------------------------+----------------------------------+
```

1. **StealthMole (Baseline):** Strongest in granular host-level stealer telemetry (NetBIOS name, local disk infection path) and reverse password querying (`password:<value>`). Severely handicapped by aggressive query micro-metering (**1 query per 10 messages scrolled**) and lack of documented REST APIs.
2. **Recorded Future:** Enterprise standard for macro-scale entity resolution, dynamic risk scoring (0–99), and SIEM/SOAR automation via the Connect API and STIX/TAXII. Weaker in narrative, continuous conversational chat reading.
3. **Maltego:** Benchmark for visual node-link analysis, court-ready forensic captures (Hunchly with SHA-256 and timestamps), and deep social network harvesting (Maltego Evidence). Lacks an internal continuous crawler database, relying entirely on external transform APIs.
4. **Intel 471 (TITAN / Verity471):** Benchmark for deep cybercrime syndicate tracking and real-time infostealer credential streaming (`/indicators/stream`). Combines automated bots with undercover human operators. Transitioning from legacy TITAN (`api.intel471.com/v1`) to Verity471 (`api.intel471.cloud`).
5. **ShadowDragon (Horizon / SocialNet):** Benchmark for cross-platform identity resolution across hundreds of social networks and 140+ jurisdictional corporate registries, unmasking threat actors behind pseudonymous Telegram `@handles`.

---

## 4. Synthesis of TTI Candidate Opportunities (Status: Proposed, Not Approved)

All candidate opportunities derived from competitor analysis are documented below. None are approved requirements:

| Proposal ID | Target TTI Subsystem | Candidate Capability | Competitor Justification & Benchmark | Status |
| :---: | :--- | :--- | :--- | :---: |
| **`OPP-001`** | `backend/app/connectors/telegram/` | **Continuous Cursor-Based Thread Viewer** | Rejects StealthMole’s scroll penalty (1 query per 10 msgs); fills the narrative chat reading void left by Recorded Future’s entity-snippet focus. | `PROPOSED, NOT APPROVED` |
| **`OPP-002`** | `backend/app/api/` | **Recursive AST Boolean Engine** | Breaks StealthMole’s rigid 3-`OR` / 5-operator ceiling, allowing unconstrained multi-indicator compound queries. | `PROPOSED, NOT APPROVED` |
| **`OPP-003`** | `backend/app/api/v1/` | **OpenAPI 3.1 REST Endpoints & Webhooks** | Matches Recorded Future and Intel 471 programmatic maturity, overcoming StealthMole’s web-portal-only constraint. | `PROPOSED, NOT APPROVED` |
| **`OPP-004`** | `backend/app/core/` | **Pluggable Enterprise SAML 2.0 / OIDC** | Adopts universal enterprise IAM baseline verified across Recorded Future, Intel 471, and ShadowDragon. | `PROPOSED, NOT APPROVED` |
| **`OPP-005`** | `backend/app/database/` | **Multi-Tenant Row-Level Security (RLS)** | Ensures strict logical tenant isolation in PostgreSQL, protecting customer watchlists and investigation notes. | `PROPOSED, NOT APPROVED` |
| **`OPP-006`** | `backend/app/evidence/` | **Cryptographic Forensic Store (SHA-256)** | Emulates Hunchly and Maltego Evidence best practices by generating immutable SHA-256 hashes and timestamp receipts for legal defensibility. | `PROPOSED, NOT APPROVED` |
| **`OPP-007`** | `backend/app/reports/` | **Standardized STIX 2.1 & MISP Exporters** | Replaces Excel-only exports with machine-readable CTI JSON schemas compatible with modern TIPs. | `PROPOSED, NOT APPROVED` |
| **`OPP-008`** | `backend/app/ai/` | **Dual-Tier Deterministic OCR + Vision VLM** | Tier 1 local Tesseract OCR extracts text from screenshots; Tier 2 vision LLMs used selectively to control GPU/token costs. | `PROPOSED, NOT APPROVED` |

---

## 5. Unresolved Questions Requiring Human Owner Alignment

Before transitioning to the TTI Product Requirements Document (PRD) and Architecture Specification, the following strategic questions require executive decisions:
1. **Target Market Focus:** Will TTI focus on corporate security & SOC alert triage (competing with Recorded Future / Intel 471) or law enforcement & forensic investigations (competing with Maltego / ShadowDragon)?
2. **Collection Ingestion Strategy:** Will TTI rely on automated MTProto client pools, purchase commercial data aggregator feeds, or develop a hybrid model?
3. **Forensic Timestamping Standards:** Is an internal cryptographic ledger sufficient for initial releases, or must TTI integrate with a certified external RFC 3161 Trusted Timestamp Authority (TSA)?
4. **Credential Handling Boundaries:** Does VFRA intend to store and query plaintext stealer passwords (like StealthMole and Intel 471), and what are the insurance and compliance implications?

---

## 6. Gate 3 Conclusion & Next Action Boundary

- **Gate 3 Status:** **COMPLETE & PASSED**.
- **Governance Mandate:** In strict adherence to project instructions, **work on the TTI PRD, SRS, or final system architecture must NOT begin until this Gate 3 Competitor Deep Dive is formally reviewed and approved by the human project owner.**

*Awaiting human review, feedback, and formal sign-off.*
