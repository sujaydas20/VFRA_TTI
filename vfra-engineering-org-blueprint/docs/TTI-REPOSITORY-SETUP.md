# TTI (Telegram Threat Intelligence) — Repository Setup & Migration Guide

This guide details the procedure for provisioning and onboarding the **Telegram Threat Intelligence (TTI)** repository as the primary private repository under the **VFRA Engineering** GitHub Organization.

---

## 1. Architectural & Engineering Baseline Adherence

The `tti` repository is initialized with the following verified architectural foundation:

| Subsystem / Requirement | Technology / Implementation | Governance Standard |
| :--- | :--- | :--- |
| **Backend API** | Python 3.12+ (tested on Python 3.13) with FastAPI | High-concurrency async REST API |
| **Frontend UI** | React 18 + TypeScript + Vite | Dark-slate cyber-defense dashboard |
| **Relational Database** | PostgreSQL 16 with SQLAlchemy 2.0 (asyncpg) | Universal `tenant_id` scoping via `TenantAwareModel` |
| **Database Migrations** | Alembic (async runner, initial migration `0001_initial_schema`) | Version-controlled schema migrations |
| **Cache & Task Broker** | Redis 7 | In-memory cache & future background task broker |
| **Local Orchestration**| Docker Compose (`docker-compose.yml`) | Reproducible multi-service developer environment |
| **Modular Connectors** | Abstract `BaseConnector` with `TelegramConnectorStub` & `DarkWebConnectorStub` | **Live collection strictly deactivated** in Phase 1 |
| **Evidence Segregation**| Dedicated `LocalEvidenceStore` with SHA-256 verification | Isolated from public static web assets |
| **Untrusted Ingestion**| `InputSanitizer` (Unicode NFC, null byte strip, script defang, ANSI strip) | Defense against hostile external payloads |

---

## 2. Step-by-Step Repository Provisioning

### Step 2.1: Create the Private Repository on GitHub
1. In the **VFRA Engineering** organization, click **New repository**.
2. Configure settings:
   - **Repository name**: `tti`
   - **Description**: `Telegram Threat Intelligence (TTI) — Threat Ingestion, Dark-Web Telemetry & Thread Intelligence Platform`
   - **Visibility**: **Private** (MANDATORY)
   - **Initialize repository with**: Do **NOT** check README, .gitignore, or license (these already exist in our verified local workspace).
3. Click **Create repository**.

### Step 2.2: Configure Team Permissions on `tti`
Navigate to **Settings &rarr; Collaborators and teams &rarr; Manage access &rarr; Add teams**:

| Team | Role / Permission | Rationale |
| :--- | :--- | :--- |
| `@vfra-engineering/core-maintainers` | **Admin** / **Maintain** | Manage repo settings, releases, and CI/CD |
| `@vfra-engineering/security-reviewers`| **Write** / **Triage** | Audit security PRs, codeowners reviews |
| `@vfra-engineering/backend-team` | **Write** | Develop backend services, DB models, connectors |
| `@vfra-engineering/frontend-team` | **Write** | Develop React/TS dashboard and UI components |
| `@vfra-engineering/qa-team` | **Write** / **Triage** | Manage test suites and issue triage |

---

## 3. Pushing the Local Codebase to GitHub

From the local project root (`D:\TTI`):

### Step 3.1: Verify Clean Git Tree & Exclusion of Secrets
```powershell
# Confirm .env and evidence files are not staged
git status
```
Ensure that `.env`, `.venv/`, `node_modules/`, and `evidence_store/` remain strictly ignored.

### Step 3.2: Configure GitHub Remote
Replace `<org-handle>` with `vfra-engineering` (or approved company handle):

```powershell
# Add remote origin
git remote add origin git@github.com:vfra-engineering/tti.git

# Or via HTTPS if SSH is not yet configured:
# git remote add origin https://github.com/vfra-engineering/tti.git
```

### Step 3.3: Push `main` and Establish `develop` Branch
```powershell
# Ensure local branch is named main
git branch -M main

# Push main branch to remote
git push -u origin main

# Create and push develop branch
git checkout -b develop
git push -u origin develop
```

### Step 3.4: Set Default Branch to `develop`
1. Go to repository **Settings &rarr; Branches**.
2. Switch default branch from `main` to `develop`.

---

## 4. Branch Protection Rules Configuration

Configure protection rules for both `main` and `develop` under **Settings &rarr; Branches &rarr; Add branch protection rule**:

### 4.1 Rule for `main`
- **Branch name pattern**: `main`
- [x] **Require a pull request before merging**
  - Minimum approvals required: **1**
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] Require review from Code Owners
- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - Required checks: `backend-test`, `frontend-build`
- [x] **Require linear history**
- [x] **Do not allow bypassing the above settings** (Enforce for administrators)
- [x] **Do not allow force pushes**
- [x] **Do not allow deletions**

### 4.2 Rule for `develop`
- **Branch name pattern**: `develop`
- Apply the same protection settings as `main` to ensure code entering integration is thoroughly reviewed and tested.

---

## 5. Path-Based Code Ownership (`CODEOWNERS`)

The repository includes path-based review assignments:
- Copy `vfra-engineering-org-blueprint/.github/CODEOWNERS.example` into `tti/.github/CODEOWNERS`.
- Any PR that touches `/backend/app/evidence/`, `/backend/app/core/security.py`, or `/backend/app/ingestion/sanitizer.py` will automatically require mandatory sign-off from `@vfra-engineering/security-reviewers`.

---

## 6. Pre-Collection Compliance & Operations Notice

> [!WARNING]
> **Strict Operational Boundary**:
> The `tti` repository is configured with inert connector stubs (`TelegramConnectorStub` and `DarkWebConnectorStub`).
> 
> **Do NOT configure live Telegram API credentials or live Tor SOCKS5 network circuits until:**
> 1. Written operational authorization has been granted by company leadership.
> 2. Phase 2 (Authentication & Tenant Provisioning) is implemented and verified.
> 3. Legal and compliance clearance is formally documented.
