# Intel 471 (TITAN / Verity471) — Comprehensive Evidence Register & Verification Audit

**Reference:** `TTI-DOC-RES-003-I471-06`  
**Target Platform:** Intel 471 TITAN Cyber Intelligence Platform / Verity471  
**Vendor:** Intel 471 Inc. (Wilmington, DE, USA / Thoma Bravo)  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Evidence Register Table

| Evidence ID | Functional Domain | Primary Source URL / Document | Verified Capability / Technical Specification | Source Evidence Excerpt / Parameter | Status | Cross-Reference File |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `EVID-I471-001` | Core Intelligence | [Intel 471 Adversary Intel](https://intel471.com/) | Adversary Intelligence tracking threat actors, extortion cartels, and initial access brokers. | Human-curated intelligence fused with automated harvesting across underground forums and Telegram. | `VERIFIED` | `product_overview.md` |
| `EVID-I471-002` | Credential Intel | [Intel 471 Credential Intel](https://intel471.com/) | Credential Intelligence streaming exfiltrated info-stealer logs and botnet credentials. | Real-time structured feed of compromised host URL, username, and plaintext password AS IS. | `VERIFIED` | `module_inventory.md` |
| `EVID-I471-003` | API Architecture | [GitHub: titan-client-python](https://github.com/intel471/titan-client-python) / [PyPI: verity471](https://pypi.org/project/verity471/) | Programmatic APIs: Modern Verity471 (`api.intel471.cloud`) with stream endpoints (`/integrations/.../stream`) and legacy TITAN (`api.intel471.com/v1`). | Endpoints include `/integrations/actors/v1/actors/stream`, `/indicators/stream`, `/iocs`, `/yara`. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-I471-004` | Platform Migration | [GitHub: titan-client-python](https://github.com/intel471/titan-client-python) / [PyPI: verity471](https://pypi.org/project/verity471/) | Discontinuation of legacy TITAN in favor of Verity471 ecosystem and modern `verity471` Python library. | Formal deprecation advising customers to migrate integrations to Verity471 endpoints. | `VERIFIED` | `product_overview.md` |
| `EVID-I471-005` | Malware Intel | [Intel 471 Malware Intel](https://intel471.com/) | Real-time C2 tracking, weaponized malware configs, and curated YARA rules. | Automated malware execution telemetry and `/yara` rule download endpoints. | `VERIFIED` | `module_inventory.md` |
| `EVID-I471-006` | CTI Protocols | [GitHub: titan-stix](https://github.com/intel471/titan-stix) | Official open-source utility converting Intel 471 indicator streams into STIX 2.1 JSON bundles. | Automated mapping to STIX 2.1 Threat Actor, Indicator, and Observed Data objects. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-I471-007` | SOAR Integration | [Google SecOps Intel 471 Docs](https://cloud.google.com/) | Certified integrations with Google SecOps, Microsoft Sentinel, and Cortex XSOAR. | Sub-second IOC enrichment and automated credential revocation playbooks. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-I471-008` | Undercover Sourcing | [Intel 471 Threat Research](https://intel471.com/) | Infiltration of closed, vetted, and invite-only Russian and transnational cybercrime groups. | In-region HUMINT specialists maintaining undercover personas on Exploit, XSS, and Telegram. | `VERIFIED` | `product_overview.md` |
| `EVID-I471-009` | Graph Integration | [Maltego Transform Hub - Intel 471](https://www.maltego.com/transform-hub/) | Official Maltego transforms enabling visual link analysis of Intel 471 threat entities. | Transforms expand threat actor handles and malware hashes onto interactive Maltego graphs. | `VERIFIED` | `workflows_and_integrations.md` |
| `EVID-I471-010` | Vulnerability Intel | [Intel 471 Vulnerability Docs](https://intel471.com/) | Risk-based prioritization of CVEs targeted by underground adversaries. | Exploitation lifecycle tracking and `/cve/reports` API endpoints. | `VERIFIED` | `module_inventory.md` |

---

## 2. Register of Unverified Vendor Claims & Market Unknowns

| Tracking ID | Marketed Capability / Area | Source Claim in Literature | Audit Finding | Classification |
| :--- | :--- | :--- | :--- | :---: |
| `UNVER-I471-001` | **Total Underground Infiltration** | Claims "total visibility into all closed cybercrime syndicates." | Infiltration is subject to threat actor vetting and persona lifespans; complete coverage is impossible. | `VENDOR CLAIM` |
| `UNVER-I471-002` | **Zero-Day Predictive Alerting** | Vendor claims predictive detection of emerging weaponization. | Relies on forum broker chatter; unannounced zero-days without forum activity are not detected. | `VENDOR CLAIM` |
| `UNVER-I471-003` | **Voice Note Transcription** | General claims of comprehensive chat monitoring. | Text NLP is documented; automated speech-to-text transcription of Telegram voice messages is not documented. | `NOT-DOCUMENTED` |
| `UNVER-I471-004` | **Arbitrary Reverse Password Querying** | Credential intelligence queries by domain and email. | Direct reverse querying by plain password (e.g., `password:<value>`) is not publicly documented. | `NOT-DOCUMENTED` |

---

## 3. TTI Candidate Architectural Proposals (Proposed, Not Approved)

| Opportunity ID | Documented Intel 471 Baseline | Target TTI Subsystem | TTI Proposed Architecture Countermeasure | Proposal Status |
| :--- | :--- | :--- | :--- | :---: |
| `OPP-I471-001` | High enterprise cost; focused exclusively on cybercrime syndicates | `backend/app/connectors/telegram/` | Cost-effective, accessible Telegram investigation platform supporting mid-market teams | `PROPOSED, NOT APPROVED` |
| `OPP-I471-002` | `/indicators/stream` chunked streaming API model | `backend/app/api/v1/` | Evaluate streaming endpoints (SSE / WebSockets) for real-time Telegram threat alerts | `PROPOSED, NOT APPROVED` |
| `OPP-I471-003` | Automated credential mitigation for Identity Providers (Okta) | `backend/app/decision/` | Automated webhook payloads formatted for immediate IdP session revocation | `PROPOSED, NOT APPROVED` |
| `OPP-I471-004` | Rigorous source masking to protect crawler assets | `backend/app/core/` | Ingestion session isolation ensuring customer logs never expose crawler phone numbers/sessions | `PROPOSED, NOT APPROVED` |

---

## 4. Audit Sign-off
- **Audit Date:** 2026-10-28
- **Auditor Role:** Senior Product Research Analyst & Threat Intelligence Architect
- **Primary Evidence Items Verified:** 10 verified items (`EVID-I471-001` to `EVID-I471-010`)
- **Unverified Market Claims Cataloged:** 4 items (`UNVER-I471-001` to `UNVER-I471-004`)
- **Verification Verdict:** Verified against official product documentation, developer GitHub repositories, and certified technology integration references.
