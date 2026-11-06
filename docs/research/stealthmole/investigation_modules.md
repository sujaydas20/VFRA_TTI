# StealthMole — Investigation Suite Deep Dive

**Reference:** `TTI-DOC-RES-002-SM-04`  
**Primary Source:** *StealthMole — User Manual v3.3* (December 2024 / March 2025; Pages 15–24)  
**Document Status:** Grounded Module Deep Dive (Audited Baseline)  
**Citation Convention:** Dual reference standard: `Slide X (PDF p. Y)`.  
**Modules Covered:**
- Module 03: Darkweb Tracker PRO (Slides 15–16 / PDF pp. 16–17)
- Module 04: Telegram Tracker (Slides 17–19 / PDF pp. 18–20)
- Module 05: Face Finder (Slides 20–22 / PDF pp. 21–23)
- Module 06: Indicators of Leakage (Slides 23–24 / PDF pp. 24–25)

---

## 1. Module 03: Darkweb Tracker PRO

### 1.1 Purpose & Problem Statement
Darkweb Tracker PRO is designed to monitor, trace, and profile observables and malicious activities scattered across Tor (.onion) hidden services, I2P networks, and deep-web forums (*User Manual v3.3, p. 15*). It addresses the difficulty investigators face in accessing and searching ephemeral, hostile, and volatile dark-web infrastructure.

### 1.2 Documented Inputs, Indicators & Operators
- **Search Bar Inputs**: Plain keywords or structured indicator expressions.
- **Supported Indicators (*pp. 45–48*)**:
  - `tor:` (Tor Domain), `torurl:` (Full Tor URL), `i2p:` (I2P Domain), `i2purl:` (I2P URL).
  - `domain:`, `url:`, `ip:` (Network observables).
  - `serverstatus:`, `sshkey:`, `sslkey:`, `pgp:` (Infrastructure fingerprints).
  - `analyticsid:`, `adsense:` (Tracking tags).
  - `hash:`, `ioc:`, `malware:`, `cve:` (Technical threat indicators).
- **Operators (*p. 49*)**: `AND`, `OR` (max 3), `NOT` (max 5 combined boolean operators), `site:` (exact domain match), `inurl:` (pattern match).

### 1.3 UI Components & Inspection Views (*p. 16*)
- **Information Category Header**: Top horizontal row of category icons. Each icon displays a badge showing the **total result count** for that category.
- **Detail View Window**: Right-hand inspection panel supporting 3 viewing options:
  - *Snapshot*: Historical previous snapshots of the onion/web page.
  - *View text in preview*: Extracted text content rendered cleanly.
  - *View HTML in preview*: Rendered HTML layout.
  - *View source*: Raw HTML source code opened in a new browser tab.
  - *URL in this page*: Extracted list of all hyperlinks found on the scraped page.
  - *Data from*: Originating URLs or referring links linking to this content.
  - *Custom Info*: Allows the analyst to add a *Custom Tag* (new node) or *Text Area* (custom note) directly onto the Canvas.
- **License Restriction**: Thumbnail previews of dark-web pages require an **Investigation License** (*p. 16*).

### 1.4 Query Consumption
- Consumes 1 query when a keyword search is submitted (*p. 50*).
- Consumes 1 query when a category icon is clicked (*p. 50*).
- Consumes 1 query when a result row is clicked to open the Detail View (*p. 50*).
- Consumes 1 query per Next/Previous page navigation (*p. 50*).

---

## 2. Module 04: Telegram Tracker

### 2.1 Purpose & Problem Statement
Threat actors frequently utilize Telegram channels and groups to distribute stolen corporate databases, negotiate ransomware payouts, share malware builds, and coordinate DDoS attacks. Telegram Tracker collects, parses, and structures message traffic from public/semi-public Telegram groups and channels curated by OSINT specialists (*User Manual v3.3, p. 17*).

### 2.2 Inputs & Indicators
- Plain text keywords (e.g., brand name, executive name, CVE identifier).
- Specialized Telegram Indicators (*p. 48*):
  - `telegram:` (Generic Telegram link search).
  - `telegram.user:` (Search by Telegram numeric User ID).
  - `telegram.channel:` (Search by Telegram Channel ID).
  - `telegram.message:` (Search by specific Telegram Message ID).

### 2.3 UI Components & Detail Views (*pp. 18–19*)
- **Category Summary Bar**: Displays category icons with numerical hit counters.
- **Channel / Group Media Preview**: Displays the profile photo and header of the target channel/group.
- **Message Thread Preview Window**: Renders historical chat messages chronologically surrounding the matched keyword.
- **Full Message Viewer**: Displays raw text, timestamp, sender handle, views counter, and reply-to metadata.
- **Enrichment Features (*p. 19*)**:
  - **GPS Tagging**: Extracts and displays location coordinates embedded within media attachments or channel metadata.
  - **AI Captioning**: Automatically generates an English text description of images attached to chat messages (e.g., "Photograph of government identity card on wooden surface").

### 2.4 Query Consumption Mechanics (*p. 51*)
- Search submission: **1 query consumed**.
- Category selection: **1 query consumed**.
- Clicking a message to open Detail View: **1 query consumed**.
- Next/Previous page: **1 query consumed**.
- **Chat Scrolling**: Scrolling up or down to read conversation context consumes **1 query per 10 messages scrolled** (*p. 51*).

### 2.5 Fictional Telegram Investigation Walkthrough
1. **Analyst Action**: An analyst suspects credentials for `fictional-bank.com` are circulating on Telegram.
2. **Search**: Enters `telegram.channel:198273645 domain:fictional-bank.com`.
3. **Hit**: 4 messages returned in result list. (Consumes 1 query).
4. **Detail Click**: Analyst clicks Message #102. (Consumes 1 query).
5. **Thread Preview**: The thread viewer shows a broker offering 5,000 corporate logins. Attached image shows a desktop screenshot.
6. **AI Caption**: AI caption reads "Table of login credentials for online banking portal".
7. **Context Scroll**: The analyst scrolls up 30 messages to see who requested the dump. (Consumes 3 queries).
8. **Add to Canvas**: Analyst right-clicks the seller's handle, adding a Node to their active case canvas.

---

## 3. Module 05: Face Finder

### 3.1 Purpose & Problem Statement
Threat actors, compromised victims, and illicit sellers frequently post photos, selfies, passport scans, or avatar images on dark-web forums and Telegram channels. Face Finder uses AI facial recognition to identify suspects across historical dark-web and messaging media (*User Manual v3.3, p. 20*).

### 3.2 Inputs & Invocation Methods (*p. 21*)
1. **Search from Canvas Node**: Right-clicking an existing image node on the Canvas and selecting `Conjunction Search -> Face Finder`.
2. **Direct Image Upload**: Dragging-and-dropping a local JPEG/PNG image directly into the Face Finder module screen.
3. **Indicator Search**: Querying by image filename or image hash using `face:` (*Slide 48 / PDF p. 49*, e.g., `face:profile_photo.jpg` or `face:<image_hash>`).

### 3.3 Output & Similarity Matching (*Slide 22 / PDF p. 23*)
- Results display candidate images with a **Similarity Percentage** (e.g., `Similarity: 94.2%`).
- Detail view lists originating dark-web page URL, Telegram channel link, and discovery timestamp.

### 3.4 Limitations & Unknowns
- Biometric model training data, accuracy benchmarks, and false-positive rates: *Not documented in the reviewed source*.
- Threshold controls (e.g., setting minimum confidence slider): *Not documented in the manual*.

---

## 4. Module 06: Indicators of Leakage (IoL)

### 4.1 Purpose & Problem Statement
Instead of combing through raw unstructured chat text, incident responders need verified threat intelligence sets tied to specific breach events, APT campaigns, or underground data drops. Indicators of Leakage provides structured, pre-tagged threat dossiers (*Slide 23 / PDF p. 24*).

### 4.2 Inputs & Syntax (*Slides 24, 48 / PDF pp. 25, 49*)
- `iol:tag_name`: Retrieves all data points linked to a specific curated breach incident (e.g., `iol:telecom_leak_2024`).
- `in:iol:keyword`: Executes a full-text search strictly within the boundaries of a tagged IoL dataset.

### 4.3 Outputs & Detail View
- Displays breach metadata: breach date, affected sector, victim organization, source threat actor, and associated IOCs.

---

## 5. Potential Relevance & Candidate Proposals for TTI (Proposed, Not Approved)

1. **TTI Candidate Proposal (Thread Reconstruction vs. Scroll Consumption, `OPP-001`, `OPP-005`)**: StealthMole’s per-10-message query consumption creates investigative friction. TTI should evaluate providing smooth, unmetered chronological thread reconstruction for authorized workspaces under predictable capacity tiers. Status: `PROPOSED, NOT APPROVED`.
2. **TTI Candidate Proposal (AI Attachment Captioning & OCR, `OPP-008`)**: StealthMole’s AI image captioning (*Slide 19*) is a valuable capability. TTI should evaluate dual-tier deterministic OCR and multimodal summarization for image attachments without executing live autonomous actions. Status: `PROPOSED, NOT APPROVED`.
3. **TTI Candidate Proposal (Facial Recognition Evaluation, `DEC-004`)**: Face Finder demonstrates the utility of biometric search in OSINT; however, facial recognition carries severe privacy, regulatory (GDPR/EU AI Act), and data-retention liabilities. *Recommendation*: Treat facial recognition as an optional future plugin requiring explicit legal clearance, not a core Phase 2 requirement. Status: `PROPOSED, NOT APPROVED`.
4. **TTI Candidate Proposal (Incident Dossier Tagging)**: TTI should evaluate implementing an incident grouping construct analogous to Indicators of Leakage (`IoL`), enabling analysts to group disparate Telegram messages under a single threat campaign tag. Status: `PROPOSED, NOT APPROVED`.
