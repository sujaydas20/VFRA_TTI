# StealthMole — Compromised Credential Search Deep Dive

**Reference:** `TTI-DOC-RES-002-SM-05`  
**Primary Source:** *StealthMole — User Manual v3.3* (December 2024 / March 2025; Pages 25–36)  
**Document Status:** Grounded Module Deep Dive (Audited Baseline)  
**Citation Convention:** Dual reference standard: `Slide X (PDF p. Y)`.  
**Modules Covered:**
- Module 07: Compromised Data Set (Slides 25–27 / PDF pp. 26–28)
- Module 08: Combo Binder (Slides 28–30 / PDF pp. 29–31)
- Module 09: Credential Lookout (Slides 31–33 / PDF pp. 32–34)
- Module 10: ULP Binder (Slides 34–36 / PDF pp. 35–37)

---

## 1. Module 07: Compromised Data Set (Device-Level Info-Stealer Logs)

### 1.1 Purpose & Problem Statement
Info-stealer malware (such as RedLine, Lumma, Raccoon, and Vidar) infects corporate and consumer endpoints, exfiltrating browser autofill databases, active session cookies, local files, and system profiles. Compromised Data Set identifies data leaked from compromised devices and exposed on the dark web, allowing enterprises to revoke compromised sessions and prevent account takeovers (*User Manual v3.3, p. 25*).

### 1.2 Documented Inputs & Search Syntax (*p. 27*)
- `domain:target.com` (Search victim login site Host).
- `url:target.com/vpn/` (Target specific sensitive enterprise login endpoints).
- `email:analyst@target.com` (Search specific compromised user email/account).
- `ip:123.45.67.89` (Search by compromised victim IP address).
- `country:SG` (Filter victim IP geolocation by ISO-3166 country code).
- Temporal filters: `after:YYYY-MM-DD`, `before:YYYY-MM-DD`.
- Combined boolean expressions: `domain:corp.com url:/vpn after:2023-01-01 before:2024-01-01`.

### 1.3 Result Fields & Data Schema (*p. 26*)
The module structures stealer telemetry into rich forensic fields:

| Field Name | Description in Manual | Evidentiary Note |
| :--- | :--- | :--- |
| **Host** | Login site URL or domain accessed by the victim. | Plaintext host |
| **User** | Compromised user account, email, or login ID. | Plaintext username |
| **Password** | Leaked password string. | Provided **"AS IS"** (unmodified) |
| **Compromised Date** | Date and timestamp data was exported from device(s). | Forensic timestamp |
| **Victim IP** | External IP address of the compromised device. | IPv4/IPv6 |
| **Victim IP (Country)**| Geolocation country associated with the victim IP. | Country flag / code |
| **Victim Computer Username**| Local OS account username of the compromised machine. | System profile |
| **Victim Computer Machine Name**| NetBIOS / Hostname of the compromised device. | System identifier |
| **Stealer Path** | File penetration path of the info-stealer on disk. | Infection vector |
| **Stealer Type** | Malware family classification (e.g., RedLine, Vidar). | Malware taxonomy |
| **Screenshot** | Desktop screenshot captured by malware. | **Investigation License only** |
| **Webcam** | Webcam photo of victim captured at execution. | **Investigation License only** |
| **FileTree** | Directory listing of exfiltrated user files. | Leaked file hierarchy |

### 1.4 Exports & Licensing (*p. 26*)
- **Excel Export**: Allows bulk downloading of credential records into `.xlsx` spreadsheets (deducts queries upon export).
- **Leaked File Downloads**: Downloading the actual exfiltrated archive files is strictly reserved for **Investigation License** holders (*p. 26*).

---

## 2. Module 08: Combo Binder (Aggregated Combos)

### 2.1 Purpose & Problem Statement
Cybercriminals aggregate billions of leaked email:password combinations from disparate breaches into consolidated "combo lists" used to execute automated credential-stuffing attacks. Combo Binder searches aggregated combo dumps to detect exposed employee credentials (*User Manual v3.3, p. 28*).

### 2.2 Inputs, Result Fields & Exports (*pp. 29–30*)
- **Inputs**: `domain:company.com`, `email:user@domain.com`, `id:username`, temporal filters (`after:`, `before:`), boolean logic (`NOT`, `OR`).
- **Result Schema**:
  - `User`: Leaked username or email address.
  - `Password`: Plaintext leaked password string (provided "AS IS").
  - `Leaked Date`: Timestamp recording when the record was cataloged.
- **Export**: Generates Excel spreadsheets (*p. 29*).

---

## 3. Module 09: Credential Lookout (Database Breach Records)

### 3.1 Purpose & Problem Statement
When corporate SQL databases or third-party SaaS vendors are compromised, threat actors publish the underlying database dumps on underground forums. Credential Lookout traces enterprise email domains across known database breach incidents (*User Manual v3.3, p. 31*).

### 3.2 Inputs & Specialized Result Fields (*pp. 32–33*)
- **Inputs**: `domain:company.com`, `email:target@company.com`, `after:`, `before:`.
- **Result Schema**:
  - `Domain`: Domain name of the compromised email address.
  - `Email`: Specific leaked email account.
  - `Password`: Leaked password string (provided "AS IS"; notes: "it may include encoded or hashed text") (*p. 32*).
  - `Leaked Date`: Timestamp of detected publication.
  - `Leaked From`: **Source identifier** naming the breached service or underground database release (e.g., `Apollo Breach Archive`, `Breached.vc Forum Dump`).
- **Export**: Generates Excel reports (*p. 32*).

---

## 4. Module 10: ULP Binder (URL:Login:Password Collections)

### 4.1 Purpose & Problem Statement
ULP logs represent the direct text output generated by stealer malware parsers, formatted strictly as `URL:Login:Password`. Threat actors distribute massive ULP text archives on Telegram and dark-web channels. ULP Binder indexes these raw stealer records for rapid searching (*User Manual v3.3, p. 34*).

### 4.2 Inputs & Unique Capabilities (*pp. 35–36*)
- **Inputs**: `domain:target.com`, `email:user@target.com`, `id:username`.
- **Reverse Password Querying (*p. 36*)**: ULP Binder uniquely supports direct querying by password:  
  `password:StealthMoleExample`  
  *(Enables threat hunters to search for compromised accounts sharing a known hardcoded password or default credential).*
- **Result Schema**: `Host` (login site), `User` (account ID/email), `Password` (plaintext string), `Leaked Date`.
- **Export**: Generates Excel spreadsheets (*p. 35*).

---

## 5. Query Consumption Model Across Credential Modules (*p. 52*)

For Compromised Data Set (CDS), Combo Binder (CB), Credential Lookout (CL), and ULP Binder (UB):
1. **Keyword Search**: Consumes 1 query per search submission.
2. **Pagination**: Consumes 1 query when clicking the Next/Previous page buttons.
3. **Data Export**: **Consumes queries based on the number of pages exported** (*User Manual v3.3, p. 52*).

---

## 6. Fictional Credential Investigation Walkthrough

1. **Scenario**: An organization's SOC observes anomalous login attempts against its Okta single sign-on (SSO) portal: `https://sso.acme-corp.com`.
2. **Step 1**: The analyst opens **Compromised Data Set** and searches `domain:acme-corp.com url:/sso`.
3. **Step 2**: The search returns 18 infected devices. One record shows a victim machine named `FIN-LAPTOP-04` with victim IP in London, infected by `Lumma Stealer` on `2024-11-12`.
4. **Step 3**: The analyst exports the 18 records to Excel to coordinate emergency password resets and revoke active session cookies with IT Security.
5. **Step 4**: The analyst pivots to **ULP Binder** and searches `domain:acme-corp.com`, discovering an additional 42 corporate accounts leaked in Telegram stealer channels.

---

## 7. Potential Relevance & Candidate Proposals for TTI (Proposed, Not Approved)

1. **TTI Candidate Proposal (Unified Credential Exposure Schema, `OPP-007`)**: StealthMole divides credential searching across 4 separate modules (CDS, CB, CL, UB) with overlapping fields. TTI should evaluate unifying credential exposures into a single cohesive data model (`NormalizedCredentialItem`) with clear source badges indicating whether the record originated from a stealer log, combo list, or database breach dump. Status: `PROPOSED, NOT APPROVED`.
2. **TTI Candidate Proposal (Reverse Password Pivot Protection)**: While `password:` search is powerful for analysts, it poses severe privacy and credential-stuffing risks if exposed to unauthorized users. TTI should evaluate requiring explicit Role-Based Access Control (RBAC) permissions before enabling reverse password search. Status: `PROPOSED, NOT APPROVED`.
3. **TTI Candidate Proposal (Raw Payload Isolation)**: Storing plaintext passwords and stealer logs requires strict compliance safeguards. TTI must evaluate ensuring credential logs are stored in segregated, tenant-isolated tables with encrypted-at-rest requirements and strict export audit logs. Status: `PROPOSED, NOT APPROVED`.
