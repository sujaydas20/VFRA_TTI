# Recorded Future — Comprehensive Evidence Register & Verification Audit

**Reference:** `TTI-DOC-RES-003-RF-06`  
**Target Platform:** Recorded Future Intelligence Cloud  
**Vendor:** Recorded Future, Inc. (Somerville, MA, USA / Mastercard)  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Evidence Register Table

| Evidence ID | Functional Domain | Primary Source URL / Document | Verified Capability / Technical Specification | Source Evidence Excerpt / Parameter | Status | Cross-Reference File |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `EVID-RF-001` | Core Platform | [Recorded Future Platform Docs](https://docs.recordedfuture.com/) | Intelligence Graph® ontology modeling entities, events, sources, and dynamic risk scores. | Proprietary knowledge graph structuring clear web, dark web, and technical telemetry into entities. | `VERIFIED` | `product_overview.md` |
| `EVID-RF-002` | API Architecture | [Recorded Future Connect API](https://docs.recordedfuture.com/) | REST API interface supporting programmatic enrichment and entity lookups. | Base URL: `https://api.recordedfuture.com/v2/`; Auth via HTTP header `X-RFToken: <token>`. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-RF-003` | CTI Protocols | [Recorded Future TAXII Docs](https://docs.recordedfuture.com/) | Native TAXII 2.1 server supporting STIX 2.1 indicator bundles. | Outbound STIX 2.1 bundle formatting for Indicators, Threat Actors, and Sightings. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-RF-004` | Entity Dossiers | [Recorded Future Intelligence Cards](https://docs.recordedfuture.com/) | Intelligence Cards™ displaying real-time risk scores (0–99), triggered risk rules, and sightings. | Consolidated single-pane-of-glass entity dossiers with evidence strings and source references. | `VERIFIED` | `module_inventory.md` |
| `EVID-RF-005` | Messaging Collection | [Recorded Future Threat Intelligence](https://www.recordedfuture.com/) | Ingestion of underground forums and messaging channels including Telegram. | Continuous monitoring of closed cybercrime channels; NLP multi-language entity extraction. | `VERIFIED` | `module_inventory.md` |
| `EVID-RF-006` | Identity Intel | [Recorded Future Identity Intelligence](https://www.recordedfuture.com/) | Detection of corporate credentials exfiltrated by info-stealer malware and combo lists. | Structured credential exposure alerts with victim host, infection date, and compromised domain. | `VERIFIED` | `module_inventory.md` |
| `EVID-RF-007` | SecOps Integration | [Recorded Future SOAR Integration](https://docs.recordedfuture.com/) | Pre-built integrations and SOAR playbooks for Splunk, Microsoft Sentinel, and Cortex XSOAR. | Automated sub-second IOC lookups and firewall blocklist push automation. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-RF-008` | Identity Governance | [Recorded Future Support Portal](https://support.recordedfuture.com/) | Enterprise SAML 2.0 Single Sign-On and SCIM user provisioning. | Integration with Okta, Microsoft Entra ID (Azure AD), PingFederate, and OneLogin. | `VERIFIED` | `security_and_governance.md` |
| `EVID-RF-009` | Graph Integration | [Maltego Transform Hub - Recorded Future](https://www.maltego.com/transform-hub/) | Official Maltego transforms enabling visual link analysis of RF entities. | Transforms convert IP, Domain, and Hash entities directly into Recorded Future risk cards. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-RF-010` | Vulnerability Intel | [Recorded Future Vulnerability Docs](https://docs.recordedfuture.com/) | Real-time risk prioritization of CVEs based on active weaponization chatter. | Risk rules evaluate dark-web exploit broker auctions and weaponization proof drops. | `VERIFIED` | `module_inventory.md` |

---

## 2. Register of Unverified Vendor Claims & Market Unknowns

| Tracking ID | Marketed Capability / Area | Source Claim in Literature | Audit Finding | Classification |
| :--- | :--- | :--- | :--- | :---: |
| `UNVER-RF-001` | **Automated Ingestion Coverage** | Marketing claims "complete coverage of all underground cybercrime channels." | Exact channel count, private invite-only channel bypass methods, and proxy cluster topology are proprietary. | `VENDOR CLAIM` |
| `UNVER-RF-002` | **Real-Time Zero-Day Detection** | Vendor claims predictive detection of emerging zero-days. | Relies on historical exploit chatter and forum broker bids; cannot predict undisclosed flaws without telemetry. | `VENDOR CLAIM` |
| `UNVER-RF-003` | **Voice Message Transcription** | General AI claims regarding multimodal processing. | Text NLP is documented; automated speech-to-text transcription of Telegram voice notes is not documented. | `NOT-DOCUMENTED` |
| `UNVER-RF-004` | **Raw Chat Historical Retention** | Data lake claims to store petabytes of historical threat data. | Specific retention windows for raw, unmodified Telegram message text and deleted posts are not documented. | `NOT-DOCUMENTED` |

---

## 3. TTI Candidate Architectural Proposals (Proposed, Not Approved)

| Opportunity ID | Documented Recorded Future Baseline | Target TTI Subsystem | TTI Proposed Architecture Countermeasure | Proposal Status |
| :--- | :--- | :--- | :--- | :---: |
| `OPP-RF-001` | Entity extraction focus; lacks continuous chronological chat reading | `backend/app/connectors/telegram/` | Dedicated cursor-based thread reconstruction viewer allowing continuous contextual chat reading | `PROPOSED, NOT APPROVED` |
| `OPP-RF-002` | Mature REST Connect API with `X-RFToken` header | `backend/app/api/v1/` | Clean OpenAPI 3.1 REST endpoints with JWT/API-key service accounts for SIEM/SOAR ingestion | `PROPOSED, NOT APPROVED` |
| `OPP-RF-003` | Native STIX 2.1 / TAXII 2.1 export formats | `backend/app/reports/` | Standardized STIX 2.1 JSON serializers for threat actors, sightings, and indicators | `PROPOSED, NOT APPROVED` |
| `OPP-RF-004` | Unified Identity Intelligence vs. fragmented credential tables | `backend/app/ingestion/` | Normalized credential data model unifying stealer logs, combo lists, and breach dumps | `PROPOSED, NOT APPROVED` |

---

## 4. Audit Sign-off
- **Audit Date:** 2026-10-28
- **Auditor Role:** Senior Product Research Analyst & Threat Intelligence Architect
- **Primary Evidence Items Verified:** 10 verified items (`EVID-RF-001` to `EVID-RF-010`)
- **Unverified Market Claims Cataloged:** 4 items (`UNVER-RF-001` to `UNVER-RF-004`)
- **Verification Verdict:** Verified against official product documentation, developer API references, and published integration guides.
