# Contributing to TTI (Telegram Threat Intelligence)

Welcome to the **Telegram Threat Intelligence (TTI)** project. This project is maintained for private GitHub Organization repositories under strict security and architectural governance standards.

---

## 1. Non-Negotiable Engineering & Security Principles

All contributors must adhere to the following core tenets:

1. **No Credentials in Code**: Never commit API keys, tokens, session strings, private certificates, or `.env` files. Use environment variables defined in `.env.example`.
2. **Untrusted Input Ingestion**: All data from external sources (Telegram channels, forums, dark-web onion sites) is treated as untrusted and must pass through `InputSanitizer`.
3. **Multi-Tenancy by Design**: All client-owned tables, models, and evidence storage paths must explicitly incorporate `tenant_id`. Cross-tenant queries are prohibited.
4. **Physical Evidence Segregation**: Evidence storage must never be served or co-located inside the public frontend asset directory.
5. **No Autonomous Actions or Live Scraping**: Live scraping requires formal operational authorization. Live reinforcement learning or unrestricted autonomous triggers are prohibited in Phase 1 and 2.
6. **Backend-Enforced Authorization**: Access control and tenant boundaries must be validated server-side.

---

## 2. Git Workflow & Branch Strategy

We follow a structured Git branching strategy:

- `main`: Production-ready branch. Direct pushes are disabled. Releases and tags are created from here.
- `develop`: Primary integration branch for active development.
- Feature branches: `feature/<issue-number>-<short-description>` (e.g., `feature/42-telegram-rate-limiter`)
- Bugfix branches: `fix/<issue-number>-<short-description>` (e.g., `fix/18-null-byte-sanitizer`)
- Chore / Infrastructure: `chore/<description>` (e.g., `chore/bump-postgres-image`)

### Branch Lifecycle
1. Pull the latest `develop` branch:
   ```bash
   git checkout develop
   git pull origin develop
   ```
2. Create your working branch:
   ```bash
   git checkout -b feature/issue-10-new-connector
   ```
3. Commit your changes following Conventional Commits.
4. Push to origin and open a Pull Request against `develop`.

---

## 3. Commit Message Conventions

We enforce [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` A new feature or capability
- `fix:` A bug fix
- `docs:` Documentation updates only
- `test:` Adding or updating tests
- `refactor:` Code refactoring without behavior change
- `security:` Security fixes, credential scrub, or sandbox enhancements
- `chore:` Maintenance, dependency updates, CI/CD changes

**Format**:
```text
<type>(<scope>): <short summary in imperative mood>

[optional detailed body explaining context and security impact]

[optional issue reference: Fixes #123]
```

**Examples**:
```text
feat(connectors): add mock darkweb thread pagination stub
fix(sanitizer): strip ANSI terminal escape characters from untrusted payloads
security(evidence): enforce tenant UUID path isolation in LocalEvidenceStore
```

---

## 4. Pull Request & Review Process

1. All PRs must use the repository's [Pull Request Template](.github/pull_request_template.md).
2. All unit tests (`pytest`) and frontend builds (`npm run build`) must pass cleanly before requesting review.
3. Every PR requires at least **one approved review** from a code owner before merge.
4. Ensure commits are squashed or rebased linearly with clean commit messages upon merge.

---

## 5. Recommended GitHub Branch Protection Settings

For the private GitHub Organization repository administrator:

- **Branch pattern**: `main` and `develop`
- **Require a pull request before merging**: Checked
- **Require approvals**: Minimum 1 review required
- **Dismiss stale pull request approvals when new commits are pushed**: Checked
- **Require status checks to pass before merging**:
  - `backend-test` (Pytest)
  - `frontend-build` (Vite TSC build)
  - `security-scan` (Secret scanning & static analysis)
- **Require linear history**: Checked
- **Do not allow force pushes**: Checked
- **Do not allow deletions**: Checked
