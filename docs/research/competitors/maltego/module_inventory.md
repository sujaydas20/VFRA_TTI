# Maltego — Complete Module Inventory

**Reference:** `TTI-DOC-RES-003-MAL-02`  
**Target Platform:** Maltego Graph, Maltego Evidence, Maltego Monitor  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Module Inventory Table

| Module / Component | Primary Purpose | Documented Inputs / Triggers | Key Outputs & Detail Views | Data Sourcing | StealthMole Overlap | TTI Relevance (Proposed, Not Approved) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Maltego Graph (Desktop & Web)** | Interactive node-link relationship mapping and entity investigation. | Seed entities (IP, Domain, Hash, Person, Email, Telegram ID). | Relational graph, Entity Detail Window, Property Palette, Timeline View. | Ingested on demand via Transforms from third-party APIs. | Direct conceptual equivalent to StealthMole Canvas (`Slides 8–9`). | [TTI-PROPOSED] Graph link-analysis workspace for actor and forward connections. |
| **Maltego Evidence (formerly SNH Classic)** | Automated social network harvesting and profile/media extraction. | Social media profile URLs (Facebook, Instagram, X/Twitter, Telegram). | Structured profile trees, friendship graphs, downloaded media archives, metadata reports. | Automated browser-based extraction engine (formerly Social Network Harvester by Freezingdata GmbH). | Overlaps with StealthMole SNS/Messenger lookups, but maps full relational networks. | [TTI-PROPOSED] Structured social profile extraction and channel member graph mapping. |
| **Hunchly (Maltego Ecosystem)** | Forensic web capture with cryptographic chain of custody. | Visited web pages, URLs, and media drops (browser extension). | Case-managed encrypted SQLite archive, MHTML snapshots, SHA-256 content hashes, timestamps. | Local browser extension capturing raw web traffic and rendering artifacts during live browsing. | Overlaps with StealthMole Snapshot, adding tamper-evident cryptographic verification. | [TTI-PROPOSED] Immutable forensic evidence receipts with SHA-256 hashes (`OPP-006`). |
| **Maltego Monitor** | Real-time social listening, crowd monitoring, and crisis alerting. | Keywords, geofences, hashtags, monitored accounts. | Real-time stream cards, sentiment metrics, geographic clusters, alert digests. | Public social media APIs and specialized messaging feeds. | Overlaps with MoleSight alerting widgets and Incident Monitoring. | [TTI-PROPOSED] Real-time alert stream for monitored channel keywords. |
| **Transform Hub** | Marketplace enabling one-click installation of data integrations. | API keys and vendor authentication tokens. | Transforms library, custom entity types, data credit meters. | 100+ partner APIs (VirusTotal, Shodan, Recorded Future, Intel 471). | No equivalent in StealthMole (StealthMole is a closed proprietary database). | [TTI-PROPOSED] Modular connector architecture supporting third-party transforms. |
| **Maltego Machines** | Automated execution of multi-step transform workflows. | Seed entity selected on graph. | Automated expansion of multi-hop network graphs. | Chained transforms defined via XML/script macros. | No direct equivalent in StealthMole (StealthMole requires manual right-click search). | [TTI-PROPOSED] Automated investigative playbooks for newly detected Telegram threats. |
| **Maltego TRX Python SDK** | Developer SDK for building custom local or server transforms. | Python code consuming `MaltegoTransform` classes. | Custom entities and custom properties emitted to graph. | Internal enterprise databases, private APIs, custom scrapers. | StealthMole does not offer a public developer SDK. | [TTI-PROPOSED] Extensible connector API enabling custom user transforms. |

---

## 2. Deep Dive: Telegram Investigation Mechanics in Maltego

Unlike platforms that operate centralized internal message crawlers, Maltego investigates Telegram through **Transform Hub Partners** (`VERIFIED`, [Maltego Transform Hub](https://www.maltego.com/transform-hub/)):

### 2.1 Third-Party Transform Ecosystem
- **Social Links (Paterva/Maltego Partner):** Offers dedicated Telegram transforms that take a phone number, username, or user ID and query Telegram databases for:
  - Associated group/channel memberships.
  - Historical profile avatar photos.
  - Linked social media aliases (cross-platform pivot).
- **ShadowDragon SocialNet:** Provides transforms mapping Telegram aliases to dark-web forum accounts and email addresses.
- **Custom Local Transforms via Maltego TRX:** Enterprise users can write custom Python transforms using `maltego-trx` to query private internal Telethon/Pyrogram databases directly onto the Maltego graph.

### 2.2 Operational Trade-off: On-Demand Querying vs. Bulk Ingestion
- **Transform Execution Model:** In Maltego, data is queried **on-demand** when an analyst right-clicks an entity and runs a transform.
- **Quota Consumption:** Running a transform consumes third-party API credits (e.g., Social Links credits or Shodan credits). If an investigator runs a broad transform returning 1,000 entities, API quotas can deplete rapidly.
- **Absence of Centralized Search:** Maltego cannot execute an arbitrary full-text query across all past Telegram messages unless a specific third-party transform provider exposes that search endpoint.

---

## 3. Deep Dive: Forensic Web Capture & Evidence Preservation (Hunchly & Maltego Evidence)

Within the Maltego investigative ecosystem, two complementary tools provide forensic capture and social harvesting (`VERIFIED`, [Maltego Evidence](https://docs.maltego.com/), [Hunchly Documentation](https://hunch.ly/)):
1. **The Forensic Problem:** Investigators collecting evidence from volatile social media platforms (Telegram, Twitter, dark forums) face legal challenges if defense attorneys argue that screenshots were fabricated or modified with developer tools.
2. **Hunchly (Automated Cryptographic Web Capture):** Acquired by Maltego, Hunchly is a specialized browser extension that runs transparently during online investigations:
   - Automatically archives every visited page, image, and document into an encrypted local SQLite database.
   - Computes **SHA-256 cryptographic hashes** for every stored page, raw MHTML file, and attachment.
   - Embeds verifiable timestamps and URL metadata into court-admissible audit reports.
   - Exports captured entities directly into Maltego Graph via official Hunchly transforms.
3. **Maltego Evidence (Social Network Harvesting):** Developed by Freezingdata GmbH (acquired by Maltego as Social Network Harvester / SNH Classic), this dedicated tool:
   - Executes deep automated extractions across social platforms (Facebook, Instagram, Twitter/X, VK, Telegram).
   - Extracts complete profile trees, followers, friend connections, comments, and media galleries.
   - Organizes relational social data into structured cases ready for export into Maltego Graph.
4. **Relevance for TTI:** This highlights a major gap in StealthMole (which only outputs standard Excel files without cryptographic proof) and serves as the primary inspiration for TTI’s candidate `LocalEvidenceStore` (`OPP-006`).
