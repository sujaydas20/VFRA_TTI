# ShadowDragon (Horizon & SocialNet) — Complete Module Inventory

**Reference:** `TTI-DOC-RES-003-SD-02`  
**Target Platform:** ShadowDragon Horizon®, SocialNet®, MalNet™  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Master Module Inventory Table

| Module / Tool | Primary Purpose | Supported Inputs & Identifiers | Key Outputs & Detail Views | Data Sourcing | StealthMole Overlap | TTI Relevance (Proposed, Not Approved) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Horizon Investigate** | Visual link analysis, entity correlation, and timeline investigation. | Seed observables (alias, phone, email, name, Telegram handle). | Interactive node-link graph, entity dossier, timeline event feed, geo map. | Integrated queries across SocialNet, MalNet, and open OSINT feeds. | Overlaps directly with StealthMole Canvas (`Slides 8–9`) and Dark Map (`Slides 10–11`). | [TTI-PROPOSED] Unified link-analysis and timeline workspace for chat investigations. |
| **Horizon Monitor** | Continuous keyword surveillance and threat detection across social feeds. | Target keywords, brand terms, hashtags, executive names. | Real-time alert cards, geographical heatmaps, notification digests. | Continuous scraping of public social media, forums, and chat networks. | Overlaps with MoleSight block alerts and Incident Monitoring suites. | [TTI-PROPOSED] Continuous keyword watcher and alert dispatcher for Telegram threads. |
| **SocialNet®** | Deep social media profiling and identity resolution across platforms. | Username, alias, email address, phone number, real name, avatar. | Correlated social profiles, historical aliases, shared profile pictures, friend networks. | Hundreds of social platforms, corporate registries across 140+ jurisdictions, Telegram, and dark web. | Overlaps with StealthMole SNS/Messenger indicators (`telegram:`, `twitter:`, etc.). | [TTI-PROPOSED] Cross-platform identity resolution linking Telegram users to external profiles. |
| **MalNet™** | Threat intelligence and anti-malware infrastructure correlation. | File hashes (MD5, SHA-1, SHA-256), IP addresses, C2 domains. | Infrastructure link graphs, malware family tags, passive DNS history. | Malware execution sandboxes, DNS telemetry, dark-web paste feeds. | Overlaps with StealthMole `hash:`, `ioc:`, and `malware:` indicators. | [TTI-PROPOSED] Malware infrastructure association for malicious files posted on Telegram. |
| **Maltego Transforms** | Commercial transform suite published on the Maltego Transform Hub. | Maltego entities (`Person`, `Alias`, `Email`, `PhoneNumber`, `TelegramAccount`). | Emits connected social profiles, groups, and phone numbers directly onto Maltego graphs. | Cloud queries routed to ShadowDragon API backend. | No direct equivalent in StealthMole (StealthMole is a closed platform). | [TTI-PROPOSED] Providing TTI transforms for Maltego on the Transform Hub. |

---

## 2. Deep Dive: Telegram Investigation Mechanics in SocialNet

ShadowDragon approaches Telegram through the lens of **person-centric OSINT and identity attribution** (`VERIFIED`, [ShadowDragon SocialNet](https://shadowdragon.io/)):

### 2.1 Supported Telegram Identifiers
- **Username / Alias:** Inputting a Telegram `@username` triggers automated cross-referencing against hundreds of public platforms and corporate registries across 140+ jurisdictions to identify where the same handle appears on GitHub, Twitter/X, Russian forums, or hacker paste sites.
- **Phone Number:** Resolves registered Telegram accounts associated with phone numbers surfaced in breach dumps or law enforcement subpoenas.
- **Channel / Group Surveillance:** Monitors public broadcast channels and group chats for threat actor chatter, extracted media, and profile updates.

### 2.2 Cross-Platform Identity Resolution
- Cybercriminals frequently reuse avatars, usernames, or contact handles across both illicit (Telegram, Tor forums) and legitimate (GitHub, gaming platforms, developer forums) platforms.
- SocialNet’s correlation algorithms analyze handle reuse, avatar image similarity, and profile metadata to bridge a pseudonymous Telegram threat actor to a real-world physical individual.

---

## 3. Comparison with StealthMole and Maltego

| Dimension | ShadowDragon (SocialNet / Horizon) | StealthMole (User Manual v3.3) | Maltego |
| :--- | :--- | :--- | :--- |
| **Platform Model** | Dedicated social media OSINT and identity resolution suite. | Closed proprietary CTI database with 14 modular search tables. | General-purpose link-analysis graphing engine powered by external transforms. |
| **Identity Resolution** | **Extensive across hundreds of platforms & 140+ jurisdictions**; automated cross-alias correlation. | Basic indicator search (`email:`, `id:`, `tel:`, `twitter:`); manual canvas linking. | Dependent on installed transforms (e.g., Social Links, ShadowDragon). |
| **Telegram Ingestion** | Ingests public/semi-public channels and profiles for identity attribution. | Ingests curated channels via OSINT specialists; metered at 1 query per 10 msgs scrolled. | No native ingestion; relies on third-party transform APIs per query. |
| **Deployment Mode** | Cloud SaaS (Horizon) + API for external link tools. | Cloud web portal; no public API documented in manual. | Desktop Java client (`.mtgx`) + Cloud web edition. |
