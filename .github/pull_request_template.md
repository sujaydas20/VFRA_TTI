## Description
<!-- Provide a clear summary of the changes made and the problem being solved. -->

## Type of Change
- [ ] 🚀 New feature (non-breaking change adding functionality)
- [ ] 🐛 Bug fix (non-breaking change fixing an issue)
- [ ] 🔒 Security improvement / hardening
- [ ] 📝 Documentation update
- [ ] 🧪 Test suite additions
- [ ] 🏗️ Architecture / Infrastructure change

## Non-Negotiable Security Checklist
- [ ] **No credentials committed**: Verified that `.env`, API keys, private certs, or tokens are NOT included.
- [ ] **Untrusted Input**: Untrusted external data is validated and passed through `InputSanitizer`.
- [ ] **Tenant Isolation**: All database models, storage writes, and queries enforce `tenant_id` scoping.
- [ ] **Evidence Segregation**: Evidence storage paths are strictly separated from public static web assets.
- [ ] **No Live Scraping / Autonomous Actions**: Confirmed that Phase 1 inactive connector policy is preserved.
- [ ] **Backend Authorization**: Tenant context and permissions are verified on the server-side.

## Testing & Verification
<!-- Describe testing steps and include output. -->
- [ ] Backend tests passing: `pytest backend/tests`
- [ ] Frontend type check & build passing: `npm run build`
- [ ] Manual verification performed

## Linked Issues
Fixes #
