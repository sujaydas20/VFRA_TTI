# StealthMole — Complete Module Inventory (All 14 Modules)

**Reference:** `TTI-DOC-RES-002-SM-02`  
**Primary Source:** *StealthMole — User Manual v3.3* (December 2024 / March 2025; `D:\StealthMole - User Manual v3.3.pdf`, 53 physical PDF pages, 52 presentation slides)  
**Document Status:** Complete Audit Matrix (Post-Gate 2A Independent Audit)  
**Citation Convention:** Dual reference standard: `Slide X (PDF p. Y)` (where physical PDF page is `Slide + 1`).

---

## 1. Master Module Inventory Table

| # | Module Name | Suite / Category | Business Purpose | Manual Slide (PDF Page) | Supported Inputs / Search Fields | Key Outputs / Detail Views | Export & License Tiers | TTI Candidate Relevance (Proposed, Not Approved) |
| :---: | :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **01** | **Platform & Case Management** | Core Platform | Manage profiling cases, user quotas, account profile, module list. | Slides 2–9 (pp. 3–10) | Case Title, Search Keywords. | List of cases (Title, Node count, Created, Updated), Statistics. | Exports / License: N/A (Standard account management). | [TTI-PROPOSED] Case management and investigation workspace organization. |
| **02** | **MoleSight** | Executive Analytics | Custom executive dashboard, monitoring widgets, and email alerts. | Slides 12–14 (pp. 13–15) | Module Source, Output Type, Term (timeframe), Search Keyword. | Visual chart blocks, metric counters, list widgets, email alerts. | Email notification toggle per block; Exports not documented. | [TTI-PROPOSED] Executive dashboard and customizable alerting widgets. |
| **03** | **Darkweb Tracker PRO** | Investigation Suite | Trace, profile, and monitor observables across Tor, I2P, and Deep Web. | Slides 15–16 (pp. 16–17) | 40+ indicators (`tor:`, `torurl:`, `i2p:`, `domain:`, `ip:`, `hash:`, etc.). | Category icons with counts, HTML/Text snapshot, URL list, Linked sources, Custom tags. | Live thumbnail preview requires **Investigation License**; Exports not documented. | [TTI-PROPOSED] Modular dark-web source connector and HTML snapshot storage. |
| **04** | **Telegram Tracker** | Investigation Suite | Track and investigate cybercrimes across curated Telegram channels and groups. | Slides 17–19 (pp. 18–20) | Keywords, `telegram.user:`, `telegram.channel:`, `telegram.message:`. | Channel/Group photo preview, message thread preview, full message text, GPS, AI caption. | No license gate documented; Query consumed per 10 messages scrolled; Exports not documented. | [TTI-PROPOSED] Core reference for message ingestion, thread viewer, and media previews. |
| **05** | **Face Finder** | Investigation Suite | Facial recognition search across dark-web and Telegram media. | Slides 20–22 (pp. 21–23) | Local image upload, or conjunction search from canvas image node. | Face similarity percentage, matching source links, category breakdown. | Exports / License: Not documented in User Manual v3.3. | [TTI-PROPOSED] Potential biometric search candidate; privacy/GDPR trade-offs require review. |
| **06** | **Indicators of Leakage (IoL)** | Investigation Suite | Curated intelligence sets linked to specific breaches and incidents. | Slides 23–24 (pp. 24–25) | `iol:`, `in:iol:`, incident keywords. | Category breakdown, breach descriptions, linked indicator datasets. | Exports / License: Not documented in User Manual v3.3. | [TTI-PROPOSED] Curated incident tagging and breach campaign aggregation. |
| **07** | **Compromised Data Set** | Compromised Credentials | Detect data leaked from devices compromised by info-stealers. | Slides 25–27 (pp. 26–28) | `domain:`, `url:`, `email:`, `ip:`, `country:`, `after:`, `before:`. | Host, User, Password (AS IS), Compromised Date, Victim IP/Country, Computer Name, Stealer Path/Type. | **Excel Export** (deducts queries); Leaked file downloads, Screenshots & Webcam require **Investigation License**. | [TTI-PROPOSED] Compromised host and stealer log attribute tracking. |
| **08** | **Combo Binder** | Compromised Credentials | Detect and search lists of aggregated username/password combo lists. | Slides 28–30 (pp. 29–31) | `domain:`, `email:`, `id:`, `after:`, `before:`, boolean operators. | User (email/username), Password (AS IS), Leaked Date. | **Excel Export**; Query consumed on export; License gate not documented. | [TTI-PROPOSED] Mass credential dump and combo list search. |
| **09** | **Credential Lookout** | Compromised Credentials | Enterprise leaked account discovery from database leaks and breach dumps. | Slides 31–33 (pp. 32–34) | `domain:`, `email:`, `after:`, `before:`, boolean operators. | Domain, Email, Password (AS IS / encoded), Leaked Date, Leaked Source/Database name. | **Excel Export**; Query consumed on export; License gate not documented. | [TTI-PROPOSED] Domain-level corporate exposure monitoring. |
| **10** | **ULP Binder** | Compromised Credentials | Search collections of URL-Login-Password logs from stealer malware. | Slides 34–36 (pp. 35–37) | `domain:`, `email:`, `password:`, `id:`, `after:`, `before:`. | Host, User, Password (AS IS), Leaked Date. | **Excel Export**; Query consumed on export; License gate not documented. | [TTI-PROPOSED] Normalized stealer log credential database. |
| **11** | **Ransomware Monitoring** | Incident Monitoring | Real-time monitoring of ransomware gangs, claimed victims, and proof links. | Slides 37–38 (pp. 38–39) | Keywords, victim search, gang name. | Total victims count, Claimed Victim, Ransomware Gang, Detection Date, Proof URL, Victim Site, Country, Industry. | Exports / License: Not documented in User Manual v3.3. | [TTI-PROPOSED] Ransomware victim tracking and threat cartel intelligence. |
| **12** | **Leaked Monitoring** | Incident Monitoring | Tracking private sector corporate data breaches across dark web. | Slides 39–40 (pp. 40–41) | Keywords, company name, domain. | Total count, Leak Title, Bad Actor ID, Detection Date, Source URL. | Exports / License: Not documented in User Manual v3.3. | [TTI-PROPOSED] Corporate data leak and breach feed. |
| **13** | **Government Monitoring** | Incident Monitoring | Monitoring dark-web leaks targeting public sector and government entities. | Slides 41–42 (pp. 42–43) | Keywords, agency name, country. | Total count, Leak Title, Bad Actor ID, Detection Date, Source URL. | Exports / License: Not documented in User Manual v3.3. | [TTI-PROPOSED] Public sector and critical infrastructure leak alerts. |
| **14** | **Defacement Alert** | Incident Monitoring | Monitoring website defacements executed by hacktivists and cybercriminals. | Slides 43–44 (pp. 44–45) | `domain:`, `id:` (bad actor name). | Defaced URL, Bad Actor, Detection Date, Claimed Victim Country, AI Verified badge. | Exports / License: Not documented in User Manual v3.3. | [TTI-PROPOSED] Website defacement and hacktivist campaign tracking. |

---

## 2. Shared Subsystem Inventory

In addition to the 14 module groups, *User Manual v3.3* documents 4 platform-wide shared subsystems:

1. **Visual Canvas Subsystem (*Slides 8–9 / PDF pp. 9–10*)**:
   - Node-link analysis workspace displaying entities as nodes (keyword node in red, selected node in green).
   - Canvas controllers: Full-screen, zoom in/out, auto-zoom to fit.
   - Graph mode algorithms: Physics layout (force-directed), Hierarchical layout (tree), Preset layout.
   - Custom annotations: Custom edges with draggable links and custom text labels; custom note text areas.
2. **Geospatial Dark Map Subsystem (*Slides 10–11 / PDF pp. 11–12*)**:
   - Replaces the Canvas with a global map interface.
   - Markers: Red pins for active search results, dark-blue pins for saved case nodes, custom user GPS pins.
   - Layers: View IP, View Image, View Telegram User, View Telegram Channel, View GPS.
   - Radius search: Context menu trigger querying `gps:lat,long,radius`.
3. **Advanced Indicator & Search Syntax Subsystem (*Slides 45–49 / PDF pp. 46–50*)**:
   - Standardized indicator palette across 13 categories (Network, Intelligence, Personal, Wallet, SNS, Messenger, Cloud, File, Location, Hash/IOC, Telegram, Face, IoL).
   - Boolean operators: `AND`, `OR` (up to 3 OR operators), `NOT` (up to 5 total boolean operators per query), `site:`, `inurl:`.
4. **Metered Query Consumption Subsystem (*Slides 50–52 / PDF pp. 51–53*)**:
   - Differentiates query consumption across Darkweb Tracker, Telegram Tracker, and Credential Search modules.
   - Explicitly meters chat reading: **1 query per 10 messages scrolled** in Telegram Tracker (*Slide 51*).
   - Note: Query consumption for Incident Monitoring (Ransomware, Leaked, Government, Defacement), Face Finder, and IoL is not documented in Appendix 3.
