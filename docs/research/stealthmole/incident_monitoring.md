# StealthMole — Incident Monitoring Modules Deep Dive

**Reference:** `TTI-DOC-RES-002-SM-06`  
**Primary Source:** *StealthMole — User Manual v3.3* (December 2024 / March 2025; Pages 37–44)  
**Document Status:** Grounded Module Deep Dive (Audited Baseline)  
**Citation Convention:** Dual reference standard: `Slide X (PDF p. Y)`.  
**Modules Covered:**
- Module 11: Ransomware Monitoring (Slides 37–38 / PDF pp. 38–39)
- Module 12: Leaked Monitoring (Slides 39–40 / PDF pp. 40–41)
- Module 13: Government Monitoring (Slides 41–42 / PDF pp. 42–43)
- Module 14: Defacement Alert (Slides 43–44 / PDF pp. 44–45)

---

## 1. Module 11: Ransomware Monitoring

### 1.1 Purpose & Problem Statement
Ransomware cartels (such as LockBit, BlackCat/ALPHV, Play, and Akira) operate dedicated leak blogs on the Tor network and mirror announcements across Telegram broadcast channels to extort victims. Security teams must rapidly detect if their organization, subsidiaries, or critical supply chain vendors have been posted as victims. Ransomware Monitoring provides a near-real-time feed of claimed victims and extortion proofs (*User Manual v3.3, p. 37*).

### 1.2 Documented Fields & Data Schema (*p. 38*)
- **Total Counter**: Top-level metric display showing total matching victim records (`N Victims`).
- **Result Table Fields**:
  - `*Claimed* Victim`: Name of the targeted company or institution (prefixed with "Claimed" to indicate vendor attribution caution).
  - `Ransomware Gang`: Name of the responsible ransomware cartel or affiliate.
  - `Detection Date`: Timestamp when StealthMole crawlers identified the publication.
  - `Ransomware URL`: Direct URL link to the extortion post or proof archive.
  - `Victim Site`: Official corporate domain of the victim organization.
  - `Victim Country`: Country location of the victim entity.
  - `Industrial Sector`: Industry vertical (e.g., Healthcare, Financial Services, Manufacturing, Energy).

---

## 2. Module 12: Leaked Monitoring (Private Sector Corporate Leaks)

### 2.1 Purpose & Problem Statement
Beyond ransomware, cybercriminals sell intellectual property, confidential email archives, customer PII, and internal source code on underground hacker forums and paste sites. Leaked Monitoring tracks and alerts on data breaches specifically affecting corporations and private commercial enterprises (*User Manual v3.3, p. 39*).

### 2.2 Documented Fields & Data Schema (*p. 40*)
- `N Victims`: Total number of search results matching the query.
- `Leak Title`: Headline or thread title assigned to the breach event (e.g., `Fintech Corp 2024 Source Code & DB Dump`).
- `Bad Actor`: Handle, alias, or forum identity of the threat actor publishing or selling the data.
- `Detection Date`: Date and timestamp of initial crawler detection.
- `Source URL`: Hyperlink to the dark-web forum thread, leak blog, or paste source.

---

## 3. Module 13: Government Monitoring (Public Sector & Critical Infrastructure)

### 3.1 Purpose & Problem Statement
State-sponsored APTs, hacktivists, and opportunistic cybercriminals frequently target municipal databases, military contractors, healthcare systems, and ministry portals. Government Monitoring provides a curated intelligence feed of leaks targeting public sector institutions and government agencies (*User Manual v3.3, p. 41*).

### 3.2 Documented Fields & Data Schema (*p. 42*)
- `N Victims`: Total matching breach events.
- `Leak Title`: Title describing the government agency leak or document dump.
- `Bad Actor`: Attributed hacktivist group or cybercriminal persona.
- `Detection Date`: Timestamp of discovery.
- `Source URL`: Direct link to the underground posting.

---

## 4. Module 14: Defacement Alert (Website Defacement Surveillance)

### 4.1 Purpose & Problem Statement
Hacktivists and politically motivated threat actors frequently breach web servers to replace homepages with political propaganda, extortion banners, or malicious redirects, causing severe reputational damage. Defacement Alert monitors and verifies compromised websites (*User Manual v3.3, p. 43*).

### 4.2 Documented Inputs & Verification Mechanics (*p. 44*)
- **Search Inputs**:
  - `domain:target.gov` (Filter by defaced website domain).
  - `id:hacker_alias` (Filter by responsible threat actor / hacktivist handle).
- **Result Table Fields**:
  - `Defaced URL`: Full URL address of the compromised page.
  - `Bad Actor`: Name of the individual hacker or collective claiming responsibility.
  - `Detection Date`: Date and timestamp of detection.
  - `*Claimed* Victim Country`: Country of the victim organization.
  - **AI Verified**: Boolean indicator / badge verifying that StealthMole's automated AI vision engine analyzed the rendered webpage and confirmed actual visual defacement rather than a false positive (*p. 44*).

---

## 5. Fictional Incident Monitoring Investigation Walkthrough

1. **Scenario**: A national financial intelligence agency monitors threats against regional payment infrastructure during an election cycle.
2. **Step 1**: The analyst opens **Ransomware Monitoring** and filters by `Industrial Sector: Financial Services`. The feed reveals a regional payment processor was listed by a ransomware group 4 hours prior.
3. **Step 2**: The analyst clicks the `Ransomware URL` to view the proof post, noting the ransomware group's Telegram contact link.
4. **Step 3**: The analyst pivots to **Defacement Alert** and searches `domain:regional-bank.com`. An alert appears with an `AI Verified` badge showing the bank's staging server was defaced 30 minutes ago by a hacktivist group.
5. **Step 4**: The analyst adds both threat actor handles to their active case canvas to cross-correlate their infrastructure links.

---

## 6. Potential Relevance & Candidate Proposals for TTI (Proposed, Not Approved)

1. **TTI Candidate Proposal (Ransomware Leak Feed Correlation)**: Ransomware groups increasingly mirror their Tor leak sites directly into public Telegram broadcast channels (e.g., posting victim logos and sample data). TTI should evaluate ingesting and correlating Telegram ransomware announcement channels directly into a structured incident feed. Status: `PROPOSED, NOT APPROVED`.
2. **TTI Candidate Proposal ("Claimed" vs. "Verified" Taxonomy)**: StealthMole’s explicit labeling of `*Claimed* Victim` (*Slides 38, 44*) is an excellent analytical best practice that avoids premature attribution. TTI should incorporate this taxonomy into all ingested threat alerts. Status: `PROPOSED, NOT APPROVED`.
3. **TTI Candidate Proposal (AI Defacement Verification Analogy, `OPP-008`)**: StealthMole’s `AI Verified` badge for defacements demonstrates the utility of automated image classification. In TTI, an analogous automated AI verification pipeline could inspect screenshots posted in Telegram channels to verify whether an attached image represents a genuine database schema dump or synthetic noise before alerting analysts. Status: `PROPOSED, NOT APPROVED`.
