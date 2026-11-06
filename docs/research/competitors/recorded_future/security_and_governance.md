# Recorded Future — Security, Governance & Compliance

**Reference:** `TTI-DOC-RES-003-RF-04`  
**Target Platform:** Recorded Future Intelligence Cloud  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Authentication, Identity & Access Management (IAM)

Recorded Future implements mature enterprise identity governance standards (`VERIFIED`, [Recorded Future Support Portal](https://support.recordedfuture.com/)):

### 1.1 Single Sign-On (SAML 2.0)
- Supports enterprise SAML 2.0 identity providers (IdPs), including **Okta**, **Microsoft Entra ID (Azure AD)**, **PingFederate**, and **OneLogin**.
- Enforces mandatory Multi-Factor Authentication (MFA) at the corporate IdP level.
- Automated user provisioning and deprovisioning via **SCIM 2.0** (`VERIFIED`).

### 1.2 Role-Based Access Control (RBAC)
- **Organization Administrator:** Full tenant control, API token issuance, SSO configuration, user role assignment, and audit log inspection.
- **Analyst:** Full access to search portals, Intelligence Cards, alert configuration, and export functions.
- **Restricted / Read-Only User:** View-only access to pre-configured executive dashboards and reports without query manipulation.
- **Module Entitlements:** Access to specific suites (e.g., Identity Intelligence, Attack Surface Intelligence) is segregated by license key; unauthorized users cannot query restricted datasets.

---

## 2. Multi-Tenancy & Data Security Architecture

- **Deployment Model:** Multi-tenant cloud SaaS hosted primarily on **Amazon Web Services (AWS)** (`VERIFIED`).
- **Data Segregation:** Customer organizational workspaces, custom watchlists, saved alerts, and user profiles are logically partitioned within the multitenant architecture.
- **Encryption Standards:**
  - *Data at Rest:* Encrypted using industry-standard **AES-256**.
  - *Data in Transit:* Enforced **TLS 1.2 / TLS 1.3** across all web portal access and API endpoints.
- **API Token Security:** API tokens (`X-RFToken`) are tied to specific user service accounts with defined expiration dates, IP allowlisting restrictions, and revocable administrative controls.

---

## 3. Compliance, Privacy & Regulatory Commitments

Recorded Future maintains comprehensive global compliance certifications (`VERIFIED` via official trust center):
- **SOC 2 Type II:** Annual third-party security, availability, and confidentiality audit reports.
- **ISO/IEC 27001:** Information Security Management System (ISMS) certified.
- **GDPR / CCPA Alignment:** Formal Data Processing Agreements (DPA) incorporating Standard Contractual Clauses (SCC) for cross-border threat intelligence transfer.
- **Handling of Leaked PII:** In its Identity Intelligence module, plain-text passwords and exposed credentials exfiltrated by stealer malware are handled under strict security controls to prevent unauthorized secondary credential stuffing. Access requires explicit administrative entitlement.

---

## 4. Key Architectural Lessons for TTI

1. **Pluggable SAML 2.0 / OIDC is Essential (`OPP-004`, PROPOSED, NOT APPROVED):** Enterprise buyers will not adopt a platform relying solely on username/password authentication. TTI must ensure its authentication service in `backend/app/core/` supports pluggable OAuth2/OIDC from Phase 1.
2. **Tenant Logical Isolation (`OPP-005`, PROPOSED, NOT APPROVED):** TTI must implement strict Row-Level Security (RLS) or tenant schema segregation in PostgreSQL to ensure customer watchlists and investigation notes never cross organizational boundaries.
3. **Audit Log Non-Repudiation:** Record immutable administrative audit logs capturing who queried which indicator or threat actor, when, and what was exported.
