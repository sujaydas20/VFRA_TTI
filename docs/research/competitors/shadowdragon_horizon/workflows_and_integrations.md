# ShadowDragon (Horizon & SocialNet) — Workflows & Integrations

**Reference:** `TTI-DOC-RES-003-SD-03`  
**Target Platform:** ShadowDragon Horizon®, SocialNet®, MalNet™  
**Status:** Competitor Research Baseline (Audited)  
**Access Date:** 2026-10-28  

---

## 1. Core Analyst Workflows

### 1.1 Threat Actor Identity Attribution Workflow
1. **Initial Indicator:** An investigator reviewing an unauthorized data sale on Telegram discovers a broker advertising stolen customer databases under the handle `@ghost_broker_99`.
2. **SocialNet Alias Pivot:** The analyst inputs `ghost_broker_99` into **SocialNet** (`VERIFIED`, [ShadowDragon SocialNet](https://shadowdragon.io/)).
3. **Cross-Platform Correlation:** The platform returns 4 matches across other platforms:
   - A GitHub profile with the same handle containing open-source repository commits.
   - A gaming forum profile showing historical registration in Eastern Europe.
   - An avatar photo matching an active Twitter/X account.
4. **Email & Identity Unmasking:** The GitHub commit history reveals a personal email address: `realname99@gmail.com`.
5. **Graph Visualization in Horizon:** The analyst opens **Horizon Investigate**, mapping the relationships between the Telegram channel, the GitHub commits, the email address, and the target organization.
6. **Evidentiary Export:** The analyst generates a court-ready investigation case report detailing the digital attribution chain.

### 1.2 Continuous Brand & Executive Monitoring in Horizon Monitor
1. **Watchlist Configuration:** A corporate security team inputs executive names, company trademarks, and sensitive product code names into **Horizon Monitor**.
2. **Automated Scanning:** The platform continuously monitors public social feeds, forums, paste sites, and public Telegram channels.
3. **Alert Dispatch:** An extortion threat mentioning the CEO’s personal phone number is posted on a Telegram broadcast channel; Horizon Monitor immediately dispatches an alert to the security operations team with geographic metadata and source links.

---

## 2. API Architecture & Partner Integrations

### 2.1 Programmatic REST API
- **API Availability (`VERIFIED`):** ShadowDragon provides programmatic REST APIs for both SocialNet and MalNet.
- **Access Boundary (`UNKNOWN / GATED`):** Detailed OpenAPI/Swagger schemas, API keys, and endpoint references are restricted behind the official **ShadowDragon Customer Portal** and authorized government partner directories (e.g., Carahsoft, SoftwareOne).
- **Primary API Capabilities:** Programmatic alias resolution, entity queries, and batch correlation feeds for ingestion into enterprise case management platforms.

### 2.2 Maltego Integration Ecosystem
- ShadowDragon maintains one of the most widely deployed commercial transform packages on the **Maltego Transform Hub** (`VERIFIED`, [Maltego Transform Hub - ShadowDragon](https://www.maltego.com/transform-hub/)):
  - Transforms take standard Maltego entities (`Person`, `Alias`, `Email`, `PhoneNumber`) and expand them into rich social networks and messaging entities.
  - Enables seamless visual correlation between network infrastructure (IPs, domains) and human threat actors on a single Maltego graph.

---

## 3. Key Architectural Lessons for TTI

1. **Cross-Platform Alias Correlation as a Differentiator (`OPP-SD-001`, PROPOSED, NOT APPROVED):** Threat actors on Telegram do not exist in a vacuum. Evaluating correlation mechanisms between Telegram usernames and external public developer/social footprints provides high-value threat actor unmasking capabilities.
2. **Dual Link-Analysis & Geospatial Visualization (`OPP-SD-002`, PROPOSED, NOT APPROVED):** Horizon demonstrates that investigators require both relational graph views (who talks to whom) and spatial mapping (where are the physical clusters).
3. **Court-Ready Case Exporting:** Law enforcement and corporate investigation teams require clean, chronological case reports detailing the step-by-step digital trail.
