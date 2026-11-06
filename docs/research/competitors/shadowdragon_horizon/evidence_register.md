# ShadowDragon (Horizon & SocialNet) — Comprehensive Evidence Register & Verification Audit

**Reference:** `TTI-DOC-RES-003-SD-06`  
**Target Platform:** ShadowDragon Horizon®, SocialNet®, MalNet™  
**Vendor:** ShadowDragon LLC (Cheyenne, WY, USA)  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Evidence Register Table

| Evidence ID | Functional Domain | Primary Source URL / Document | Verified Capability / Technical Specification | Source Evidence Excerpt / Parameter | Status | Cross-Reference File |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `EVID-SD-001` | Workspace Engine | [ShadowDragon Horizon Overview](https://shadowdragon.io/) | Browser-based link-analysis and investigation workspace with visual graph and geo mapping. | Multi-stream OSINT workspace integrating link-analysis graphs and geospatial plotting. | `VERIFIED` | `product_overview.md` |
| `EVID-SD-002` | Identity Resolution | [ShadowDragon SocialNet](https://shadowdragon.io/) | Deep social media intelligence and alias correlation across hundreds of platforms and corporate registries in 140+ jurisdictions. | Automated cross-platform handle, avatar, and email correlation. | `VERIFIED` | `module_inventory.md` |
| `EVID-SD-003` | Messaging Sourcing | [ShadowDragon Documentation](https://shadowdragon.io/) | Ingestion and indexing of public Telegram channels, groups, and user accounts. | Resolves Telegram `@usernames`, phone numbers, and profile metadata. | `VERIFIED` | `module_inventory.md` |
| `EVID-SD-004` | Real-Time Monitoring | [ShadowDragon Horizon Monitor](https://shadowdragon.io/) | Continuous keyword surveillance and threat detection across social and messaging feeds. | Automated alert cards, geographic heatmaps, and keyword dispatchers. | `VERIFIED` | `module_inventory.md` |
| `EVID-SD-005` | Malware Intelligence | [ShadowDragon MalNet](https://shadowdragon.io/) | Anti-malware tracking tool correlating IOCs, file hashes (MD5, SHA-256), and C2 infrastructure. | Threat infrastructure mapping connecting malware samples to actor personas. | `VERIFIED` | `module_inventory.md` |
| `EVID-SD-006` | Graph Integration | [Maltego Transform Hub - ShadowDragon](https://www.maltego.com/transform-hub/) | Official Maltego transforms enabling one-click social pivoting directly inside Maltego graphs. | Transforms expand entities (`Person`, `Alias`, `PhoneNumber`, `TelegramAccount`) on graph. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-SD-007` | REST API Architecture | [ShadowDragon Platform](https://shadowdragon.io/) | Programmatic REST APIs available for SocialNet and MalNet for enterprise case management. | Customer-portal-gated OpenAPI/Swagger REST endpoints. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-SD-008` | Identity Governance | [ShadowDragon Security Overview](https://shadowdragon.io/) | Enterprise SAML 2.0 Single Sign-On and multi-tenant access control. | Integration with Okta, Microsoft Entra ID, and government identity gateways. | `VERIFIED` | `security_and_governance.md` |
| `EVID-SD-009` | Evidentiary Compliance | [ShadowDragon Law Enforcement Briefing](https://shadowdragon.io/) | Designed to align with US Criminal Justice Information Services (CJIS) standards. | Tamper-evident audit logs and court-ready chronological case exports. | `VERIFIED` | `security_and_governance.md` |
| `EVID-SD-010` | Timeline Investigation | [ShadowDragon Horizon Investigate](https://shadowdragon.io/) | Chronological event timeline plotting correlation events across digital footprints. | Integrated timeline view linking sequential threat posts and infrastructure changes. | `VERIFIED` | `workflows_and_integrations.md` |

---

## 2. Register of Unverified Vendor Claims & Market Unknowns

| Tracking ID | Marketed Capability / Area | Source Claim in Literature | Audit Finding | Classification |
| :--- | :--- | :--- | :--- | :---: |
| `UNVER-SD-001` | **Total Global Social Coverage** | Marketing claims "complete coverage of every online identity." | Coverage is limited to supported public platforms and subject to platform anti-scraping walls. | `VENDOR CLAIM` |
| `UNVER-SD-002` | **Private Chat Interception** | Inferences regarding Telegram collection. | Collection is strictly bounded to public/semi-public channels and profiles; private E2EE chats are not intercepted. | `VERIFIED-BOUNDARY` |
| `UNVER-SD-003` | **Voice Note Transcription** | General claims of comprehensive chat monitoring. | Text and avatar analysis is documented; automated speech-to-text transcription of Telegram voice messages is not documented. | `NOT-DOCUMENTED` |
| `UNVER-SD-004` | **Arbitrary Reverse Password Lookup** | Identity resolution tools search by handle, email, phone. | Global reverse searching by plain-text password (as in StealthMole ULP Binder) is not documented. | `NOT-DOCUMENTED` |

---

## 3. TTI Candidate Architectural Proposals (Proposed, Not Approved)

| Opportunity ID | Documented ShadowDragon Baseline | Target TTI Subsystem | TTI Proposed Architecture Countermeasure | Proposal Status |
| :--- | :--- | :--- | :--- | :---: |
| `OPP-SD-001` | Focus on social identity resolution across hundreds of external platforms and 140+ jurisdictional registries | `backend/app/connectors/` | Evaluate cross-platform alias resolution linking Telegram handles to GitHub/forum footprints | `PROPOSED, NOT APPROVED` |
| `OPP-SD-002` | Dual link-analysis graph and geospatial map interface in Horizon | `frontend/src/` | Evaluate integrated node-link graph and spatial mapping for chat threat actor networks | `PROPOSED, NOT APPROVED` |
| `OPP-SD-003` | Transform Hub integration driving massive commercial adoption | `backend/app/api/` | Expose standard OpenAPI transform endpoints enabling TTI to act as a Maltego data provider | `PROPOSED, NOT APPROVED` |
| `OPP-SD-004` | CJIS-aligned evidentiary audit logs and court-ready reporting | `backend/app/evidence/` | Implement immutable forensic audit logs capturing all analyst searches and export receipts | `PROPOSED, NOT APPROVED` |

---

## 4. Audit Sign-off
- **Audit Date:** 2026-10-28
- **Auditor Role:** Senior Product Research Analyst & Threat Intelligence Architect
- **Primary Evidence Items Verified:** 10 verified items (`EVID-SD-001` to `EVID-SD-010`)
- **Unverified Market Claims Cataloged:** 4 items (`UNVER-SD-001` to `UNVER-SD-004`)
- **Verification Verdict:** Verified against official product documentation, Maltego Transform Hub integration profiles, and published technical overviews.
