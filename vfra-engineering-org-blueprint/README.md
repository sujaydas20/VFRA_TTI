# VFRA Engineering — GitHub Organization Blueprint

This directory contains the operational, architectural, and governance blueprint for establishing and managing the **VFRA Engineering** GitHub Organization (`vfra-engineering`).

---

## 1. Executive Summary & Purpose

The **VFRA Engineering** GitHub Organization serves as the centralized, secure, multi-project software engineering hub for VFRA. It provides an enterprise-grade collaborative environment with strict access controls, automated security safeguards, standardized Git workflows, and comprehensive auditability.

The **Telegram Threat Intelligence (TTI)** platform is designated as the first major private project repository hosted under this organization.

> [!IMPORTANT]
> **Operational Status**:
> This blueprint is a **local design and setup kit**. No organization has been registered or modified automatically. Step-by-step instructions for human administrators to verify username availability, obtain company approval, and configure GitHub settings are provided in [`docs/ORGANIZATION-SETUP-CHECKLIST.md`](docs/ORGANIZATION-SETUP-CHECKLIST.md).

---

## 2. Organization Identity

| Attribute | Proposal / Recommendation | Status |
| :--- | :--- | :--- |
| **Display Name** | `VFRA Engineering` | Recommended standard |
| **Suggested Handle** | `vfra-engineering` | Subject to company approval & availability check |
| **Primary Contact Email** | `engineering@vfra.local` (or company domain) | Requires company domain verification |
| **Default Repository Visibility** | **Private** | Mandatory baseline |
| **Billing / Subscription** | GitHub Free / Team / Enterprise | Decision requiring management approval |

---

## 3. Blueprint Kit Contents

```text
vfra-engineering-org-blueprint/
├── README.md                              # This blueprint overview and navigation guide
├── ORGANIZATION-CHARTER.md                # Mission, scope, ownership hierarchy, and governance
├── TEAM-STRUCTURE.md                      # Team topologies, RBAC permissions, and onboarding/offboarding
├── REPOSITORY-STANDARDS.md                # Naming conventions, visibility, secret isolation, and lifecycle
├── BRANCHING-STRATEGY.md                  # Main/develop branches, protection rules, and release tagging
├── SECURITY-POLICY.md                     # Vulnerability reporting, secrets management, and compliance boundaries
├── CONTRIBUTING.md                        # Standard developer contribution and code review workflow
├── PULL_REQUEST_TEMPLATE.md               # Standard pull request checklist template
├── .github/
│   ├── CODEOWNERS.example                 # Path-based code ownership and mandatory review routing
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.yml                 # GitHub Issue Form for structured defect tracking
│       └── feature_request.yml            # GitHub Issue Form for architectural improvements
└── docs/
    ├── ORGANIZATION-SETUP-CHECKLIST.md    # Manual step-by-step checklist to stand up the organization
    └── TTI-REPOSITORY-SETUP.md            # Step-by-step guide to migrate and protect the TTI repository
```

---

## 4. How to Use This Kit

1. **Review Charter & Team Roles**:
   Read [`ORGANIZATION-CHARTER.md`](ORGANIZATION-CHARTER.md) and [`TEAM-STRUCTURE.md`](TEAM-STRUCTURE.md) with engineering leadership to assign the initial Owners and Team Leads.
2. **Execute Organization Creation**:
   Follow the manual checklist in [`docs/ORGANIZATION-SETUP-CHECKLIST.md`](docs/ORGANIZATION-SETUP-CHECKLIST.md) to register the organization, enforce 2FA, configure base permissions, and create the team structure.
3. **Migrate the First Project (TTI)**:
   Follow [`docs/TTI-REPOSITORY-SETUP.md`](docs/TTI-REPOSITORY-SETUP.md) to create the private `tti` repository, push the verified Phase 1 codebase, and enable branch protections.
4. **Publish Organization Health Files**:
   Copy `.github/` templates to a special `.github` repository within the organization to apply default issue templates, PR templates, and community standards across all future repositories.
