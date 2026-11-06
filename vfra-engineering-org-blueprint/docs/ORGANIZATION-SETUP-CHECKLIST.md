# VFRA Engineering — GitHub Organization Setup Checklist

This document is a practical, step-by-step operational runbook for the **Organization Administrator** standing up the **VFRA Engineering** GitHub Organization.

> [!CAUTION]
> **Manual Confirmation Required**:
> These steps must be performed manually in the GitHub Web UI by an authorized company administrator.
> Do **NOT** register paid plans or publish company assets without explicit management approval.

---

## Phase 1: Pre-Registration Verification & Approvals

- [ ] **1.1 Executive Sponsor Approval**: Obtain formal management sign-off on creating the organization and selecting the billing tier (Free vs. Team vs. Enterprise).
- [ ] **1.2 Verify Username Availability**:
  - Preferred Handle: `vfra-engineering`
  - Fallback Handles (if preferred is taken): `vfra-technologies`, `vfra-corp-engineering`, `vfra-intel-eng`.
  - Check availability by navigating to: `https://github.com/organizations/plan` or attempting name entry.
- [ ] **1.3 Corporate Email Designation**: Designate a monitored corporate contact email for billing and ownership recovery (e.g., `engineering-admin@company.com`).
- [ ] **1.4 Designate Initial Owners**: Select **two** trusted senior engineers/leaders to act as primary Organization Owners (prevents single-owner lockouts).

---

## Phase 2: Organization Creation on GitHub

- [ ] **2.1 Navigate to Organization Creation**:
  - Sign in to GitHub with the primary admin personal account.
  - Navigate to **GitHub &rarr; Settings &rarr; Organizations &rarr; New Organization** (or visit `https://github.com/organizations/plan`).
- [ ] **2.2 Choose Plan**:
  - Select **Free** (for initial bootstrap) or **Team** (recommended for advanced branch protection, draft PRs, and team review requests).
- [ ] **2.3 Enter Organization Identity**:
  - **Organization account name**: `vfra-engineering` (or approved fallback)
  - **Contact email**: Corporate admin email
  - **Account belongs to**: My business or institution
- [ ] **2.4 Complete Creation**: Finish verification challenge and click **Create organization**.

---

## Phase 3: Mandatory Organization-Wide Security Settings

Immediately after organization creation, configure these critical security controls:

### 3.1 Two-Factor Authentication (2FA) Enforcement
- [ ] Go to: **Settings &rarr; Authentication security**.
- [ ] Check: **Require two-factor authentication for everyone in your organization**.
- [ ] Set grace period (e.g., 24–48 hours for onboarding existing team members) or enforce immediately.
- [ ] Click **Save**.

### 3.2 Member Privileges & Base Permissions
- [ ] Go to: **Settings &rarr; Member privileges**.
- [ ] **Base permissions**: Set to **No permission** (Mandatory least-privilege baseline).
  *(Members gain read/write access strictly via team assignments).*
- [ ] **Repository creation**: Uncheck public repository creation. Allow private repository creation **only** by Organization Owners or specific designated Maintainers.
- [ ] **Repository deletion and transfer**: Uncheck *Allow members to delete or transfer repositories* (strictly restricted to Owners).
- [ ] **Repository visibility change**: Uncheck *Allow members to change repository visibilities*.

### 3.3 Advanced Security & Code Analysis
- [ ] Go to: **Settings &rarr; Code security and analysis**.
- [ ] **Dependency graph**: Enable for all repositories.
- [ ] **Dependabot alerts**: Enable for all repositories.
- [ ] **Dependabot security updates**: Enable for all repositories.
- [ ] **Secret scanning**: Enable (where supported by plan tier).
- [ ] **Push protection**: Enable to prevent accidental credential commits.

---

## Phase 4: Team Topology Provisioning

Create the functional teams under **Teams &rarr; New Team**:

| Team Name | Handle | Description | Visibility |
| :--- | :--- | :--- | :--- |
| **Security Reviewers** | `@vfra-engineering/security-reviewers` | Mandatory security & isolation reviewers | Visible |
| **Core Maintainers** | `@vfra-engineering/core-maintainers` | Repository administrators & release leads | Visible |
| **Backend Team** | `@vfra-engineering/backend-team` | Python, FastAPI, DB, and Connector engineers | Visible |
| **Frontend Team** | `@vfra-engineering/frontend-team` | React, TypeScript, and UI dashboard engineers | Visible |
| **QA Team** | `@vfra-engineering/qa-team` | Test automation and QA verification engineers | Visible |

- [ ] Add the designated engineers to their corresponding teams.
- [ ] Ensure the second designated administrator is granted the **Owner** role under **People &rarr; Members**.

---

## Phase 5: Create Special `.github` Organization Health Repository

To standardize issue templates and community guidelines across all future repositories:

- [ ] Create a new repository named **`.github`** (Visibility: **Private** or Internal).
- [ ] Copy the templates from `vfra-engineering-org-blueprint/.github/`:
  - `.github/ISSUE_TEMPLATE/bug_report.yml`
  - `.github/ISSUE_TEMPLATE/feature_request.yml`
  - `PULL_REQUEST_TEMPLATE.md`
- [ ] Commit and push to `.github` repository on `main`.
  *(GitHub automatically applies these templates as defaults to all organization repositories lacking local overrides).*

---

## Phase 6: Readiness Sign-Off

- [ ] 2FA Enforced for all members.
- [ ] Base permissions set to None.
- [ ] Teams created and populated.
- [ ] Organization Owners verified (at least 2).
- [ ] Proceed to [`TTI-REPOSITORY-SETUP.md`](TTI-REPOSITORY-SETUP.md) to initialize the primary repository.
