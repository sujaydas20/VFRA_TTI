# ShadowDragon (Horizon & SocialNet) — Product Limitations, Unknowns & Operational Trade-offs

**Reference:** `TTI-DOC-RES-003-SD-05`  
**Target Platform:** ShadowDragon Horizon®, SocialNet®  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Documented Product Constraints & Operational Trade-offs

### 1.1 Open OSINT Focus vs. Deep Undercover Infiltration
- **Documented Boundary (`VERIFIED`):** ShadowDragon excels at indexing open-source and semi-public digital footprints across social media, forums, and Telegram. Unlike Intel 471, it does not specialize in long-term undercover HUMINT infiltration of vetted Russian cybercrime syndicates.
- **Operational Impact:** Highly effective for threat actor attribution and online identity resolution, but less applicable for tracking closed private ransomware negotiation portals that do not expose public social traces.

### 1.2 Gated Technical Documentation
- **Documented Constraint (`VERIFIED`):** Detailed REST API endpoints, Swagger definitions, and technical developer specifications are strictly gated behind the official **ShadowDragon Customer Portal** and authorized government partner directories (Carahsoft, SoftwareOne).
- **Audit Impact:** Full endpoint parameter auditing is restricted to verified commercial or government license holders.

### 1.3 Vulnerability to Social Media Platform Churn
- **Documented Operational Dependency (`INFERENCE`):** Because SocialNet queries 140+ third-party social networks, it is subject to platform API changes, anti-scraping protections (e.g., Cloudflare, CAPTCHAs), and policy shifts enacted by external social media networks (e.g., Twitter/X API restrictions).

---

## 2. Capabilities Not Documented in Reviewed Sources (Explicit Unknowns)

To adhere strictly to Gate 3 standards, the following aspects are classified as **UNKNOWN / NOT DOCUMENTED IN REVIEWED SOURCES**:

| Architectural Dimension | Documented Status | Technical & Architectural Unknown |
| :--- | :--- | :--- |
| **Telegram Ingestion Infrastructure** | *Not documented in public technical documentation*. | The exact architecture used to monitor Telegram channels (e.g., MTProto client pools, automated userbot networks, or residential proxies) is proprietary and undisclosed. |
| **Voice / Audio Message Transcription** | *Not documented in reviewed sources*. | Public documentation highlights profile correlation, text matching, and avatar analysis; automated transcription of Telegram voice messages is not documented. |
| **Direct Reverse Password Lookup** | *Not documented in reviewed sources*. | Searching by username, phone number, and email is documented; whether an analyst can execute a global reverse plain-text password query (`password:<value>`) is not documented. |

---

## 3. Operational Dependencies

1. **Third-Party Platform Upgrades:** Ingesting data from dynamic social platforms requires continuous engineering updates to bypass UI changes, login walls, and bot mitigations.
2. **Cloud SaaS Availability:** Horizon relies on high-availability cloud infrastructure; air-gapped on-premises deployments require specialized government defense contracts.
