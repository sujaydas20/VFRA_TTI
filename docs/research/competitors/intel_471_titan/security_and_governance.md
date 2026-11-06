# Intel 471 (TITAN / Verity471) — Security, Governance & Source OPSEC

**Reference:** `TTI-DOC-RES-003-I471-04`  
**Target Platform:** Intel 471 TITAN / Verity471  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Authentication, Access Governance & Multi-Tenancy

- **Enterprise Single Sign-On (SSO):** Supports **SAML 2.0** federation across enterprise IdPs (Okta, Microsoft Entra ID) with mandatory Multi-Factor Authentication (`VERIFIED`, [Intel 471 Platform](https://intel471.com/)).
- **Role-Based Access Control (RBAC):** Restricts access to sensitive threat actor reports, credential telemetry streams, and API token generation based on organizational user roles.
- **Multi-Tenant SaaS Isolation:** Cloud platform enforces logical tenant isolation, ensuring customer watchlist terms, notification settings, and API activity logs remain strictly confidential.
- **Cryptographic Encryption:**
  - *Data at Rest:* Encrypted with AES-256.
  - *Data in Transit:* Enforced TLS 1.3 across all portal interactions and API streams.

---

## 2. Undercover Sourcing OPSEC & Legal Boundaries

Intel 471 operates within strict operational security (OPSEC) and legal boundaries necessitated by its human intelligence infiltration model:

### 2.1 Protection of Human Infiltration Assets
- Because Intel 471 researchers operate undercover within Tier 1 Russian, Chinese, and transnational cybercrime groups, the platform employs strict source masking.
- Raw message transcripts are sanitized to prevent threat actors from identifying which forum persona or Telegram group account served as the collection node, preventing retaliatory actor targeting.

### 2.2 Legal & Regulatory Boundaries in Undercover Operations
- **Strict Observer Role:** Analysts observe, record, and extract threat data without inciting, facilitating, or participating in criminal acts (adhering to US Department of Justice / European cybercrime investigative guidelines).
- **Prohibition on Purchasing Stolen Corporate Assets:** Intelligence is gathered via automated exfiltration log scraping and forum indexing; vendors generally avoid paying ransoms or bidding on proprietary stolen corporate IP to avoid violating sanctions (e.g., OFAC regulations).

---

## 3. Compliance, Privacy & Credential Handling

- **SOC 2 Type II Certified:** Undergoes annual independent audits covering security, availability, and confidentiality controls.
- **GDPR / Privacy Compliance:** Ingesting plaintext passwords and personal usernames extracted from infostealers constitutes processing of compromised personal data. Intel 471 processes this data under legitimate security interest provisions, restricting access strictly to enterprise security teams for defensive remediation.

---

## 4. Key Architectural Lessons for TTI

1. **Investigator Identity Protection (`OPP-004`, PROPOSED, NOT APPROVED):** When TTI ingests sensitive or private Telegram channels, the identity of the crawler session or collector phone number must be strictly isolated from customer-facing audit logs to prevent source burn.
2. **OFAC / Legal Compliance Safeguards:** TTI must not implement automated features that facilitate purchasing data or paying ransoms on Telegram.
3. **Pluggable Identity Federation:** SAML 2.0 / OIDC support is a prerequisite for enterprise security team adoption.
