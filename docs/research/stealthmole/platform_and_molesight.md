# StealthMole — Platform, Case Management & MoleSight Deep Dive

**Reference:** `TTI-DOC-RES-002-SM-03`  
**Primary Source:** *StealthMole — User Manual v3.3* (December 2024 / March 2025; Pages 3–14)  
**Document Status:** Grounded Module Deep Dive (Audited Baseline)  
**Citation Convention:** Dual reference standard: `Slide X (PDF p. Y)`.  
**Modules Covered:**
- Module 01: Platform Core, Case Management, Canvas & Dark Map (Slides 2–11 / PDF pp. 3–12)
- Module 02: MoleSight Executive Dashboard (Slides 12–14 / PDF pp. 13–15)

---

## 1. Module 01: Platform Core & Case Management

### 1.1 Purpose and Business Problem
Investigators and intelligence analysts handle sprawling, fragmented evidence across dark-web sites, breach dumps, and Telegram channels. Platform Core provides a centralized, authenticated workspace to organize investigations into discrete "Cases," preserve node-and-edge profiling graphs, and track query consumption quotas (*User Manual v3.3, pp. 3–5*).

### 1.2 User Roles & Permissions
- **Standard Account**: Can create, save, load, and delete personal cases; configure active modules via the `+` service bar button; manage personal profile and password (*pp. 4–6*).
- **Investigation License**: Unlocks advanced forensics (downloading leaked files, viewing desktop/webcam snapshots, and thumbnail previews) (*pp. 16, 26*).
- **Multi-User Case Sharing**: The landing page includes `LOAD STEALTHMOLE'S CASES` and `LOAD MY CASES` (*p. 4*); enterprise team sharing of cases between different user accounts is not documented in the reviewed manual.

### 1.3 UI Components & Visual Layout
- **Landing Page (*p. 4*)**:
  - `CREATE NEW CASE`: Initializes a blank Canvas.
  - `STATISTICS`: Summary metrics of current figures.
  - `LOAD MY CASES`: Descending list of profiling cases displaying **Title**, **Node count**, **Created time**, and **Last update time**.
  - `SEARCH`: Keyword filter across saved cases.
  - `MENU`: Dropdown routing to *My Page*, *Dashboard (MoleSight)*, and *Logout*.
- **Workspace Navigation (*pp. 5–7*)**:
  - **Left Service Menu Bar**: Vertical icon dock of enabled modules. Active module is displayed in high-contrast color; inactive modules are grayed out.
  - **`+` Button (Module Manager)**: Modal dialog allowing users to add/remove modules from their quick-access dock. Unsubscribed modules render a `Buy` button routing to Contact Us (*p. 5*).
  - **Top Search Bar & Lightning Icon**: Search query input with a Lightning button opening the standard indicator selector palette (*pp. 6, 45*).
  - **Result List View (Collapsible)**: Left/middle panel displaying results, sort controls (alphabetical or created date), and pagination controls (*p. 6*).
  - **Detail View Window**: Right-hand inspection panel supporting 3 layout modes: *Dual* (split detail and preview), *Detail info only*, or *Preview only* (*p. 7*).

### 1.4 The Visual Canvas Subsystem (*pp. 8–9*)
- **Node Mechanics**: Entities from search results are added to the Canvas as visual Nodes.
  - The searched keyword is highlighted in **red text**.
  - Selected nodes are framed with a **green boundary box**.
- **Edge Mechanics**: Connections between nodes represent relational links.
  - Dragging from one node to another creates a custom edge.
  - Right-clicking an edge opens the Edge Menu: *Edit edge label*, *Change edge color*, or *Delete*.
- **Canvas Controls & Layout Algorithms**:
  - Canvas controllers: Full-screen toggle, Zoom In / Zoom Out, Auto-zoom to fit canvas.
  - Layout Algorithms:
    1. **Physics Layout**: Force-directed simulation where related nodes attract and non-related nodes repel.
    2. **Hierarchical Layout**: Structured tree diagram showing organizational or operational parent-child chains.
    3. **Preset Layout**: Fixed coordinate positioning.
- **Node Pivoting (Cross-Module Search)**:
  - Right-clicking any node opens the context menu: `Search` (allows running a secondary query on the node using any other module), `View Details`, or `View in New Window` (*p. 9*).

### 1.5 The Dark Map Geospatial Subsystem (*pp. 10–11*)
- **Trigger**: Clicking the `DM` toggle replaces the visual graph canvas with a global interactive map.
- **Indicators Displayed**:
  - Active search results: **Red pins**.
  - Saved case nodes: **Dark-blue pins**.
  - User custom GPS pins: Custom dropped markers.
- **Geocoded Data Categories**:
  - `DT [NETWORK INFO] IP`: Geocoded server/infrastructure IP.
  - `DT [LEAKED INFO] Leaked Image (GPS Included)`: Media extracted from breach archives containing EXIF GPS tags.
  - `DT, TT [FILE INFO] Image (GPS Included)`: Telegram or dark-web image files with GPS metadata.
  - `TT [TELEGRAM INFO] Telegram Channel (GPS Included)`: Telegram channels with geolocation attributes.
  - `TT [TELEGRAM INFO] Telegram User (GPS Included)`: Telegram user profiles broadcasting location.
- **Geospatial Radius Search**: Dropping a pin allows right-click context search formatted as `gps:latitude, longitude, radius` (e.g., `gps:1.28, 103.85, 100`) (*p. 48*).

### 1.6 Fictional Investigation Walkthrough
1. **Scenario**: An analyst investigates a suspected ransomware broker advertising on Telegram.
2. **Step 1**: The analyst clicks `CREATE NEW CASE`, naming it `Case-Alpha-Ransom`.
3. **Step 2**: The analyst searches for channel handle `telegram:@blackmarket_leaks`.
4. **Step 3**: The channel result is added to the Canvas as a Node (highlighted in red).
5. **Step 4**: The analyst right-clicks the channel node, selects `Search -> Telegram Tracker`, expanding 3 recent posts.
6. **Step 5**: An image attached to a post contains EXIF data. The analyst clicks the `DM` button to switch to Dark Map; the image is pinned to coordinates in Southeast Asia.
7. **Step 6**: The analyst right-clicks the pin, runs `gps:1.35, 103.81, 50`, uncovering another IP linked to the same geographical cluster.
8. **Step 7**: The analyst draws a custom labeled edge `Same Infrastructure Cluster` and saves the case.

---

## 2. Module 02: MoleSight (Executive Dashboard)

### 2.1 Purpose and Business Problem
Security operations center (SOC) managers and CISOs require aggregated visibility into threat trends, newly detected corporate leaks, and ransomware victims without manually executing queries every morning. MoleSight serves as the customizable dashboard and alerting interface (*User Manual v3.3, pp. 12–14*).

### 2.2 Dashboard Architecture & Widget Configuration
- **Block Concept**: MoleSight dashboards are organized into customizable visual cards termed **Blocks** (*p. 13*).
- **Create Block Configuration Modal (*p. 13*)**:
  1. **Title**: User-defined widget title (e.g., `Corporate Domain Stealer Exposures`).
  2. **Source Module**: Dropdown selecting the underlying data source (e.g., *Compromised Data Set*, *Telegram Tracker*, *Ransomware Monitoring*).
  3. **Output Data**: Target data metrics to aggregate.
  4. **Output Type**: Visualization format (line chart, bar chart, numerical metric, tabular feed).
  5. **Term**: Temporal window (past 24 hours, 7 days, 30 days, custom).
  6. **Input**: Search filter or target keyword (e.g., `domain:acme-corp.com`).
- **Notification Settings (*p. 13*)**:
  - Global notification toggle: Master switch enabling or disabling email delivery.
  - Block-level alerts: Individual toggle per widget to trigger an email notification when new matching records are detected.

### 2.3 Limitations & Unknowns
- Maximum widget capacity per dashboard: *Not documented in the reviewed source*.
- Webhook / SIEM push notifications: *Not documented in the manual* (only email notifications are illustrated, *p. 13*).
- Role-based dashboard sharing: *Not documented in the reviewed source*.

---

## 3. Potential Relevance & Candidate Proposals for TTI (Proposed, Not Approved)

1. **TTI Candidate Proposal (Case Profiling Workspaces)**: TTI should evaluate introducing persistent investigation cases where analysts can group monitored Telegram threads, save extracted threat actors, and record analyst notes. Status: `PROPOSED, NOT APPROVED`.
2. **TTI Candidate Proposal (Dashboard Widgets)**: An executive dashboard mirroring MoleSight's block model, allowing tenant admins to pin real-time metrics (e.g., *New Threats Detected Today*, *Quarantined Payloads*, *Active Connectors Status*). Status: `PROPOSED, NOT APPROVED`.
3. **TTI Candidate Proposal (Link Analysis Integration)**: While geospatial mapping is secondary for pure text channels, visual link analysis connecting Telegram channels, forward sources, and threat actor aliases provides immediate investigative value. Status: `PROPOSED, NOT APPROVED`.
