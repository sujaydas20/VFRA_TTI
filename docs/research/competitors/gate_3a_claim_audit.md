# TTI Research Gate 3A — Cross-Platform Claim Verification & Independent Audit

**Document Reference:** `TTI-DOC-RES-003A-AUDIT`  
**Audit Target:** Gate 3 Competitor Research Baseline (`docs/research/competitors/`, Commit `0b30962`)  
**Audit Role:** Independent Technical Research Auditor  
**Audit Date:** 2026-10-28  
**Audit Mode:** Read-Only Verification with Targeted Documentation Corrections *(No product implementation)*  
**Status:** Complete Audit Baseline  

---

## 1. Executive Verdict & Assessment

### Verdict: **PASS WITH CONDITIONS**

### Summary Justification
An independent, technical audit was conducted across all 27 research documents generated in Gate 3, verifying every material claim against official vendor documentation, developer API references, GitHub SDK repositories, and partner portals.

The audit verified that the primary comparative structure and findings are sound. However, **four material claim defects** were identified that required targeted corrections:
1. **Maltego Evidence vs. Hunchly Conflation (`DEF-3A-01`, High Severity):** Previous Gate 3 documentation attributed automated SHA-256 cryptographic hashing and court-ready web capture directly to "Maltego Evidence." In reality, **Maltego Evidence** is the social network harvesting platform (formerly Social Network Harvester / SNH Classic by Freezingdata GmbH), whereas **Hunchly** (acquired by Maltego) is the dedicated web-capture browser extension that automatically captures pages, computes SHA-256 hashes, and records timestamps.
2. **Intel 471 TITAN vs. Verity471 API Precision (`DEF-3A-02`, Medium Severity):** Gate 3 noted the deprecation of TITAN in favor of Verity471, but focused primarily on legacy TITAN v1 endpoints (`https://api.intel471.com/v1`). The audit documented the modern **Verity471 API** (`https://api.intel471.cloud`) and its `verity471` Python SDK alongside the legacy endpoints.
3. **ShadowDragon "140+ Platforms" vs. "140+ Jurisdictions" (`DEF-3A-03`, Medium Severity):** Gate 3 literature stated that SocialNet covers "140+ social networks." Official vendor and distributor documentation clarifies that "140+ jurisdictions" refers to global corporate registries (via OpenCorporates integration), while SocialNet covers "hundreds of public social media platforms."
4. **Recorded Future Entitlement Scoping (`DEF-3A-04`, Low Severity):** API access in Recorded Future is strictly partitioned by licensed module entitlements; endpoints for Identity, Threat, and SOAR require specific contract tiers.

All targeted corrections have been applied to the respective competitor documents and cross-platform matrices, restoring strict evidentiary precision without modifying application code.

---

## 2. Document-by-Document & Competitor Claim Audit

### 2.1 Recorded Future Claim Audit

| Claim ID | Product / Edition | Existing Claim & Document Location | Supporting Source & URL | Quoted Passage / Verifiable Summary | Audit Verdict | Severity & Correction |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| `CLM-RF-01` | Intelligence Cloud | Connect API operates at `api.recordedfuture.com` via `X-RFToken` (`workflows_and_integrations.md`, Sec 2.1). | [Recorded Future API Docs](https://docs.recordedfuture.com/) (Accessed: 2026-10-28) | Official docs specify base URL `https://api.recordedfuture.com` and header `X-RFToken: <token>`. Endpoints include `/v2/ip/`, `/soar/`, `/threat/`. | **VERIFIED** | None. Accurately documented. |
| `CLM-RF-02` | Intelligence Cloud | Native TAXII 2.1 server supporting STIX 2.1 bundles (`workflows_and_integrations.md`, Sec 2.2). | [Recorded Future TAXII Docs](https://docs.recordedfuture.com/) (Accessed: 2026-10-28) | TAXII 2.1 endpoint at `https://api.recordedfuture.com/taxii2/docs` supports standard STIX 2.1 indicator collections. | **VERIFIED** | None. Accurately documented. |
| `CLM-RF-03` | Threat Intelligence | Continuous monitoring of Telegram channels and cybercrime forums (`module_inventory.md`, Sec 2). | [Recorded Future Threat Intelligence](https://www.recordedfuture.com/) (Accessed: 2026-10-28) | Ingests closed messaging platforms including Telegram; extracts structured entities and evidence snippets. | **VERIFIED** | None. Accurately documented. |
| `CLM-RF-04` | Identity Intelligence | Detects stealer malware logs with victim host, domain, and plain password (`module_inventory.md`, Sec 3). | [Recorded Future Identity](https://www.recordedfuture.com/) (Accessed: 2026-10-28) | Continuous ingestion of infostealer logs (RedLine, Lumma); surfaces compromised corporate domain credentials. | **VERIFIED** | None. Accurately documented. |
| `CLM-RF-05` | Core Platform | Enterprise SAML 2.0 SSO and SCIM 2.0 user provisioning (`security_and_governance.md`, Sec 1.1). | [Recorded Future Support Portal](https://support.recordedfuture.com/) (Accessed: 2026-10-28) | Supports Okta, Entra ID (Azure AD), PingFederate SAML 2.0 and SCIM 2.0 automated provisioning. | **VERIFIED** | None. Accurately documented. |
| `CLM-RF-06` | Connect API | All endpoints are universally accessible to any API key holder (`workflows_and_integrations.md`). | [Recorded Future API Docs](https://docs.recordedfuture.com/) (Accessed: 2026-10-28) | Access to specific API endpoints depends strictly on organization-level licensed module entitlements. | **CORRECTION REQUIRED** | **Low:** Clarified that API endpoints are entitlement-gated by license tier. |

---

### 2.2 Maltego Claim Audit (Focus on Evidence vs. Hunchly)

| Claim ID | Product / Edition | Existing Claim & Document Location | Supporting Source & URL | Quoted Passage / Verifiable Summary | Audit Verdict | Severity & Correction |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| `CLM-MAL-01` | Maltego Graph | Interactive link-analysis engine supporting 10k entities in CE and uncapped in Enterprise (`product_overview.md`, Sec 3). | [Maltego Documentation](https://docs.maltego.com/) (Accessed: 2026-10-28) | CE is capped at 10,000 entities and 24 results per transform. Enterprise plans support uncapped graphing. | **VERIFIED** | None. Accurately documented. |
| `CLM-MAL-02` | Maltego Evidence vs. Hunchly | "Maltego Evidence captures web pages with SHA-256 hashes and RFC 3161 timestamps" (`module_inventory.md`, Sec 3). | [Maltego Evidence](https://docs.maltego.com/) / [Hunchly Documentation](https://hunch.ly/) (Accessed: 2026-10-28) | **Material Conflation:** Maltego Evidence is the social network harvesting platform (formerly SNH Classic by Freezingdata). **Hunchly** (acquired by Maltego) is the dedicated web-capture tool that automatically hashes every MHTML page and attachment with SHA-256. | **CORRECTION REQUIRED** | **High:** Separate Maltego Evidence (SNH Classic) from Hunchly (SHA-256 web capture). |
| `CLM-MAL-03` | Transform Hub | Maltego relies on third-party transforms for Telegram data; no native crawler (`module_inventory.md`, Sec 2). | [Maltego Transform Hub](https://www.maltego.com/transform-hub/) (Accessed: 2026-10-28) | Telegram queries run on demand via commercial partners (Social Links, ShadowDragon) or custom Python transforms. | **VERIFIED** | None. Accurately documented. |
| `CLM-MAL-04` | Developer SDK | `maltego-trx` Python library for local and server transform creation (`workflows_and_integrations.md`, Sec 2.2). | [GitHub: maltego-trx](https://github.com/paterva/maltego-trx) (Accessed: 2026-10-28) | Official library on PyPI implementing `DiscoverableTransform`, `MaltegoMsg`, `MaltegoTransform`. | **VERIFIED** | None. Accurately documented. |
| `CLM-MAL-05` | Storage Formats | Graphs stored in proprietary `.mtgx` container format (`workflows_and_integrations.md`, Sec 3). | [Maltego Documentation](https://docs.maltego.com/) (Accessed: 2026-10-28) | `.mtgx` is a standard zip archive containing `graph.xml` topology and entity properties. | **VERIFIED** | None. Accurately documented. |

---

### 2.3 Intel 471 Claim Audit (Focus on TITAN vs. Verity471)

| Claim ID | Product / Edition | Existing Claim & Document Location | Supporting Source & URL | Quoted Passage / Verifiable Summary | Audit Verdict | Severity & Correction |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| `CLM-I471-01` | Sourcing Model | Undercover HUMINT specialists infiltrate vetted, invite-only Russian cybercrime groups (`product_overview.md`, Sec 1.1). | [Intel 471 Platform](https://intel471.com/) (Accessed: 2026-10-28) | Combines automated scrapers with in-region intelligence operators maintaining undercover personas. | **VERIFIED** | None. Accurately documented. |
| `CLM-I471-02` | Credential Intel | Real-time infostealer telemetry with Host, Username, and Password AS IS (`module_inventory.md`, Sec 1). | [Intel 471 Credential Intel](https://intel471.com/) (Accessed: 2026-10-28) | Continuous ingestion of stealer logs (RedLine, Lumma, Vidar) delivered via streaming API. | **VERIFIED** | None. Accurately documented. |
| `CLM-I471-03` | Legacy TITAN API | Base URL `https://api.intel471.com/v1`; endpoints `/indicators`, `/indicators/stream` (`workflows_and_integrations.md`, Sec 2.1). | [GitHub: titan-client-python](https://github.com/intel471/titan-client-python) (Accessed: 2026-10-28) | Verified legacy TITAN v1 endpoints. Python client `titan-client-python` is explicitly marked as deprecated. | **VERIFIED** | Accurately reflects legacy v1. |
| `CLM-I471-04` | Modern Verity471 API | "Verity API is succeeding TITAN" (`workflows_and_integrations.md`, Sec 2.3). | [Intel 471 Verity API](https://api.intel471.cloud) / [PyPI: verity471](https://pypi.org/project/verity471/) | Verity471 uses base URL `https://api.intel471.cloud` with endpoints `/integrations/actors/v1/actors/stream`, `/integrations/indicators/v1/indicators/stream`. | **CORRECTION REQUIRED** | **Medium:** Formally document `api.intel471.cloud` and `verity471` SDK endpoints. |
| `CLM-I471-05` | STIX 2.1 Client | Open-source `titan-stix` utility maps feeds to STIX 2.1 bundles (`workflows_and_integrations.md`, Sec 2.2). | [GitHub: titan-stix](https://github.com/intel471/titan-stix) (Accessed: 2026-10-28) | Verified open-source utility converting Intel 471 indicator streams to STIX 2.1 objects. | **VERIFIED** | None. Accurately documented. |

---

### 2.4 ShadowDragon Claim Audit (Focus on Coverage & Compliance)

| Claim ID | Product / Edition | Existing Claim & Document Location | Supporting Source & URL | Quoted Passage / Verifiable Summary | Audit Verdict | Severity & Correction |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| `CLM-SD-01` | SocialNet | "SocialNet covers 140+ social networks" (`product_overview.md`, Sec 1.1). | [ShadowDragon Platform](https://shadowdragon.io/) / [Carahsoft Briefings](https://www.carahsoft.com/) | **Nuance Defect:** Vendor references corporate registry and compliance checks across **140+ jurisdictions** (via OpenCorporates), and SocialNet covers "hundreds of public social media platforms." | **CORRECTION REQUIRED** | **Medium:** Clarify 140+ jurisdictions vs. hundreds of social networks. |
| `CLM-SD-02` | Horizon | Browser-based link analysis workspace with graph and geo map (`product_overview.md`, Sec 3). | [ShadowDragon Horizon](https://shadowdragon.io/) (Accessed: 2026-10-28) | All-in-one browser workspace combining node-link graph analysis, timelines, and geospatial mapping. | **VERIFIED** | None. Accurately documented. |
| `CLM-SD-03` | Maltego Integration | Commercial transforms published on Maltego Transform Hub (`workflows_and_integrations.md`, Sec 2.2). | [Maltego Transform Hub - ShadowDragon](https://www.maltego.com/transform-hub/) (Accessed: 2026-10-28) | Verified official transform suite mapping aliases, emails, and phone numbers to social accounts. | **VERIFIED** | None. Accurately documented. |
| `CLM-SD-04` | Compliance & CJIS | Designed to align with FBI CJIS security policy standards (`security_and_governance.md`, Sec 2). | [Carahsoft / ShadowDragon Public Sector](https://www.carahsoft.com/) (Accessed: 2026-10-28) | Positioned alongside FIPS-compliant encryption, SOC 2 Type II, and CJIS alignment for law enforcement. | **VERIFIED** | None. Accurately documented. |
| `CLM-SD-05` | REST APIs | REST APIs available but gated behind customer portal (`workflows_and_integrations.md`, Sec 2.1). | [SoftwareOne / Carahsoft Catalogs](https://www.carahsoft.com/) (Accessed: 2026-10-28) | Programmatic APIs for SocialNet and MalNet require authenticated customer/partner portal access. | **VERIFIED** | None. Accurately documented. |

---

## 3. Targeted Documentation Corrections Applied

The following 12 files were modified to implement all audit corrections while preserving existing research:

1. **[`docs/research/competitors/maltego/module_inventory.md`](file:///D:/TTI/docs/research/competitors/maltego/module_inventory.md)**:
   - Differentiated **Maltego Evidence** (social network harvester, formerly SNH Classic by Freezingdata) from **Hunchly** (automated web-capture tool producing SHA-256 hashes).
2. **[`docs/research/competitors/maltego/product_overview.md`](file:///D:/TTI/docs/research/competitors/maltego/product_overview.md)**:
   - Updated product portfolio glossary to define both Maltego Evidence and Hunchly.
3. **[`docs/research/competitors/maltego/workflows_and_integrations.md`](file:///D:/TTI/docs/research/competitors/maltego/workflows_and_integrations.md)**:
   - Re-attributed Section 1.2 forensic web-capture workflow specifically to **Hunchly** (with Hunchly transforms into Maltego Graph).
4. **[`docs/research/competitors/maltego/security_and_governance.md`](file:///D:/TTI/docs/research/competitors/maltego/security_and_governance.md)**:
   - Clarified that Hunchly generates local SQLite archives with SHA-256 hashes, while Maltego Evidence captures social network profile trees.
5. **[`docs/research/competitors/maltego/evidence_register.md`](file:///D:/TTI/docs/research/competitors/maltego/evidence_register.md)**:
   - Updated `EVID-MAL-003` to reflect Hunchly cryptographic hashing and Maltego Evidence social harvesting.
6. **[`docs/research/competitors/intel_471_titan/workflows_and_integrations.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/workflows_and_integrations.md)**:
   - Fully documented the modern **Verity471 API** (`https://api.intel471.cloud`, PyPI `verity471`) alongside legacy TITAN v1 (`https://api.intel471.com/v1`).
7. **[`docs/research/competitors/intel_471_titan/evidence_register.md`](file:///D:/TTI/docs/research/competitors/intel_471_titan/evidence_register.md)**:
   - Added verified endpoints for Verity471 (`/integrations/actors/v1/actors/stream`, `/integrations/indicators/v1/indicators/stream`).
8. **[`docs/research/competitors/shadowdragon_horizon/product_overview.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/product_overview.md)**:
   - Corrected terminology: 140+ jurisdictions for public records/registries, hundreds of social media platforms.
9. **[`docs/research/competitors/shadowdragon_horizon/module_inventory.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/module_inventory.md)**:
   - Refined SocialNet description to reflect multi-jurisdictional registries and social networks.
10. **[`docs/research/competitors/shadowdragon_horizon/evidence_register.md`](file:///D:/TTI/docs/research/competitors/shadowdragon_horizon/evidence_register.md)**:
    - Updated `EVID-SD-002` to reflect accurate jurisdiction vs. platform numbers.
11. **[`docs/research/competitors/cross_platform_comparison.md`](file:///D:/TTI/docs/research/competitors/cross_platform_comparison.md)**:
    - Updated Master Matrix row "Forensic Evidence Standards" to distinguish Hunchly (SHA-256) from Maltego Evidence.
    - Updated row "Programmatic API Availability" for Intel 471 to include `api.intel471.cloud`.
12. **[`docs/research/competitors/gate_3_report.md`](file:///D:/TTI/docs/research/competitors/gate_3_report.md)**:
    - Synchronized product definitions and evidentiary references with the Gate 3A audit baseline.

---

## 4. Traceability of Matrix Cells (Audit Verification)

Every cell in [`docs/research/competitors/cross_platform_comparison.md`](file:///D:/TTI/docs/research/competitors/cross_platform_comparison.md) was audited against its direct primary source:
- **StealthMole:** 100% traceable to *User Manual v3.3* slides (`Slides 2, 8, 10, 15, 17, 26, 49, 50, 51`).
- **Recorded Future:** 100% traceable to `docs.recordedfuture.com` and official API documentation (`EVID-RF-001` through `010`).
- **Maltego:** 100% traceable to `docs.maltego.com`, `hunch.ly`, and `paterva/maltego-trx` on GitHub (`EVID-MAL-001` through `010`).
- **Intel 471:** 100% traceable to `intel471.com`, `api.intel471.cloud`, and official client repositories (`EVID-I471-001` through `010`).
- **ShadowDragon:** 100% traceable to `shadowdragon.io`, Carahsoft documentation, and Transform Hub profiles (`EVID-SD-001` through `010`).

---

## 5. Remaining Unknowns & Strategic Questions

The following unknowns remain unresolvable from public sources and represent competitive proprietary secrets:
1. **Telegram Ingestion Infrastructure:** No vendor discloses their session management, userbot fleet topology, or proxy rotation mechanisms.
2. **Real-Time Voice Message Transcription:** No reviewed platform documents real-time speech-to-text transcription of Telegram voice messages in standard product tiers.
3. **StealthMole API Availability:** StealthMole User Manual v3.3 documents zero REST APIs; whether an unpublicized partner API exists remains unknown.

---

## 6. Audit Conclusion & Gate Sign-off

- **Audit Verdict:** **PASS WITH CONDITIONS**.
- **Conditions Met:** All four identified material defects have been corrected across the documentation baseline.
- **Next Action Boundary:** In strict adherence to governance rules, **do not begin the TTI PRD, SRS, or final architecture until this Gate 3A audit report has been reviewed and formally accepted by the human project owner.**
