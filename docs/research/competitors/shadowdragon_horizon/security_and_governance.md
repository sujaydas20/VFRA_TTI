# ShadowDragon (Horizon & SocialNet) — Security, Governance & Compliance

**Reference:** `TTI-DOC-RES-003-SD-04`  
**Target Platform:** ShadowDragon Horizon®, SocialNet®  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Authentication, Access Governance & Tenant Isolation

- **Enterprise Authentication:** Horizon supports enterprise **SAML 2.0 Single Sign-On (SSO)** across Okta, Microsoft Entra ID, and government identity gateways (`VERIFIED`, [ShadowDragon Platform](https://shadowdragon.io/)).
- **Role-Based Access Control (RBAC):** Configurable permission boundaries separating administrators, senior investigators, and read-only auditors.
- **Tenant Isolation:** Multi-tenant cloud SaaS platform with logically partitioned case repositories, search histories, and watchlist definitions.
- **Encryption Standards:**
  - *Data at Rest:* Encrypted using AES-256.
  - *Data in Transit:* Enforced TLS 1.3 across all browser sessions and API communication.

---

## 2. Law Enforcement, Defense & Evidentiary Standards

Because ShadowDragon is widely utilized by law enforcement agencies, defense departments, and corporate fraud teams, its platform design aligns with strict evidentiary requirements:
- **CJIS Alignment:** Designed to meet US Criminal Justice Information Services (CJIS) security policy standards for handling criminal investigative data.
- **Audit Trails:** Immutable, tamper-evident audit logs recording which investigator initiated an alias query, the search timestamp, and exported case reports.
- **Non-Invasive OSINT Stance:** ShadowDragon operates within legal open-source intelligence boundaries by aggregating publicly or semi-publicly accessible information, avoiding active malware delivery or unauthorized system intrusion.

---

## 3. Privacy & Regulatory Considerations (GDPR / CCPA)

- **Handling of Social Media PII:** Indexing personal usernames, avatars, and linked social media accounts constitutes processing of personal data under the European General Data Protection Regulation (GDPR).
- **Legitimate Interest & Law Enforcement Exemptions:** Corporate users must rely on legitimate interest provisions (preventing fraud, mitigating cyber threats); law enforcement agencies operate under specialized statutory exemptions.
- **Data Minimization & Redaction:** Case exports allow investigators to redact extraneous bystander PII before sharing reports with external legal or regulatory authorities.

---

## 4. Key Architectural Lessons for TTI

1. **Evidentiary Audit Logging (`OPP-006`, PROPOSED, NOT APPROVED):** Every action performed in TTI (channel views, thread searches, entity exports) must generate an immutable audit log to maintain chain-of-custody integrity.
2. **Strict Compliance Safeguards:** TTI must establish clear operational boundaries ensuring collection does not cross into unauthorized interception of private end-to-end encrypted Telegram chats (Secret Chats).
