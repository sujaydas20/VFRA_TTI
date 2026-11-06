# Maltego — Comprehensive Evidence Register & Verification Audit

**Reference:** `TTI-DOC-RES-003-MAL-06`  
**Target Platform:** Maltego Graph, Maltego Evidence, Transform Hub  
**Vendor:** Maltego Technologies GmbH (Munich, Germany)  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Evidence Register Table

| Evidence ID | Functional Domain | Primary Source URL / Document | Verified Capability / Technical Specification | Source Evidence Excerpt / Parameter | Status | Cross-Reference File |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `EVID-MAL-001` | Core Platform | [Maltego Product Overview](https://docs.maltego.com/) | Interactive node-link link analysis graphing engine supporting entities and directional edges. | Visual representation of interconnected entities with organic, hierarchical, and circular layout modes. | `VERIFIED` | `product_overview.md` |
| `EVID-MAL-002` | Transform Engine | [Maltego Transform Architecture](https://docs.maltego.com/) | Transform Hub architecture executing queries from local scripts or remote transform servers. | Input/Output contract: takes input entity properties, queries external API, emits output entities to graph. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-MAL-003` | Forensic Integrity | [Hunchly Documentation](https://hunch.ly/) / [Maltego Evidence](https://docs.maltego.com/) | Forensic web capture and social harvesting: Hunchly computes automated SHA-256 content hashes and timestamps; Maltego Evidence harvests structured social trees. | Court-ready preservation of volatile web pages, social profiles, and threads with verifiable chain of custody. | `VERIFIED` | `module_inventory.md` |
| `EVID-MAL-004` | Real-Time Monitoring | [Maltego Monitor Overview](https://www.maltego.com/products/maltego-monitor/) | Real-time social listening, crowd monitoring, and geofenced crisis alerting dashboard. | Streaming ingestion of public social media posts and crisis event clustering. | `VERIFIED` | `module_inventory.md` |
| `EVID-MAL-005` | Messaging Integrations | [Maltego Transform Hub](https://www.maltego.com/transform-hub/) | Third-party Telegram querying enabled via commercial partners (Social Links, ShadowDragon). | Transforms query Telegram handles, channels, user IDs, and linked phone numbers on demand. | `VERIFIED` | `module_inventory.md` |
| `EVID-MAL-006` | Developer SDK | [GitHub: maltego-trx](https://github.com/paterva/maltego-trx) | Official Python SDK (`maltego-trx`) for rapid local and server-side transform development. | Python classes (`DiscoverableTransform`, `MaltegoMsg`, `MaltegoTransform`) for custom integrations. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-MAL-007` | Graph File Standard | [Maltego File Formats](https://docs.maltego.com/) | Proprietary `.mtgx` zipped archive containing XML graph topology and entity attachments. | Standard offline container format for storing and sharing multi-analyst link graphs. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-MAL-008` | Enterprise SSO | [Maltego Enterprise Admin Guide](https://docs.maltego.com/) | SAML 2.0 Single Sign-On and multi-user graph collaboration server in Enterprise edition. | Centralized authentication and concurrent graph editing with node locking. | `VERIFIED` | `security_and_governance.md` |
| `EVID-MAL-009` | Graph Quota Limits | [Maltego Edition Comparison](https://docs.maltego.com/) | Community Edition (CE) capped at 10,000 entities and 24 results per transform. | Tiered graph size ceilings enforced in free and legacy commercial editions. | `VERIFIED` | `product_overview.md` |
| `EVID-MAL-010` | Automated Macros | [Maltego Machines Documentation](https://docs.maltego.com/) | Maltego Machines engine executing multi-step chained transform sequences automatically. | Pre-configured and user-authored XML macros automating multi-hop reconnaissance. | `VERIFIED` | `module_inventory.md` |

---

## 2. Register of Unverified Vendor Claims & Market Unknowns

| Tracking ID | Marketed Capability / Area | Source Claim in Literature | Audit Finding | Classification |
| :--- | :--- | :--- | :--- | :---: |
| `UNVER-MAL-001` | **All-in-One Data Access** | Marketing claims "one-stop access to all internet threat data." | Access requires third-party API keys or purchasing separate Maltego Data Credits. | `VENDOR CLAIM` |
| `UNVER-MAL-002` | **Proprietary Threat Database** | Assumed by some users to store historical dark-web archives. | Maltego stores no central crawler database; it is strictly an analytical visualization client. | `INFERENCE / UNVERIFIED` |
| `UNVER-MAL-003` | **Native Telegram Crawling** | Marketing references Telegram threat hunting. | Telegram intelligence is entirely dependent on third-party transform partners. | `VERIFIED-DEPENDENCY` |
| `UNVER-MAL-004` | **Voice Note Transcription** | General OSINT claims regarding messaging intelligence. | Voice message transcription is not documented in standard Maltego transforms. | `NOT-DOCUMENTED` |

---

## 3. TTI Candidate Architectural Proposals (Proposed, Not Approved)

| Opportunity ID | Documented Maltego Baseline | Target TTI Subsystem | TTI Proposed Architecture Countermeasure | Proposal Status |
| :--- | :--- | :--- | :--- | :---: |
| `OPP-MAL-001` | Relies on third-party APIs for Telegram; no central continuous archive | `backend/app/ingestion/` | Autonomous continuous ingestion buffer capturing historical Telegram channels directly | `PROPOSED, NOT APPROVED` |
| `OPP-MAL-002` | Forensic standards demonstrated in Hunchly and Maltego Evidence (SHA-256 + timestamps) | `backend/app/evidence/` | Implement cryptographic evidence receipts (`LocalEvidenceStore`) with SHA-256 hashes | `PROPOSED, NOT APPROVED` |
| `OPP-MAL-003` | `.mtgx` and GraphML export formats standard in link analysis | `backend/app/reports/` | Multi-format export serializer supporting GraphML and `.mtgx` for interoperability | `PROPOSED, NOT APPROVED` |
| `OPP-MAL-004` | Open transform architecture via Python SDK (`maltego-trx`) | `backend/app/connectors/` | Extensible modular connector interfaces enabling custom data providers | `PROPOSED, NOT APPROVED` |

---

## 4. Audit Sign-off
- **Audit Date:** 2026-10-28
- **Auditor Role:** Senior Product Research Analyst & Threat Intelligence Architect
- **Primary Evidence Items Verified:** 10 verified items (`EVID-MAL-001` to `EVID-MAL-010`)
- **Unverified Market Claims Cataloged:** 4 items (`UNVER-MAL-001` to `UNVER-MAL-004`)
- **Verification Verdict:** Verified against official product documentation, developer GitHub repositories, and Transform Hub integration specifications.
