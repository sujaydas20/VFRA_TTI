## Summary of Changes
<!-- Provide a clear, concise summary of the purpose and scope of this pull request. -->

## Associated Issue
Closes #<!-- Issue number -->

## Type of Change
- [ ] 🚀 New feature (backwards-compatible addition)
- [ ] 🐛 Bug fix (backwards-compatible defect resolution)
- [ ] 🔒 Security fix or hardening
- [ ] 🏗️ Architecture / Infrastructure improvement
- [ ] 📝 Documentation update
- [ ] 🧪 Testing suite enhancement
- [ ] ⚠️ Breaking change (requires major version increment)

---

## Non-Negotiable Security Checklist
Please verify and confirm each item before requesting review:

- [ ] **No Hardcoded Credentials**: Verified that no API keys, private tokens, passwords, `.env` files, or certs are included in this PR.
- [ ] **Untrusted Input Handled**: Any external data from Telegram, forums, dark-web pages, or user forms is validated and passed through `InputSanitizer`.
- [ ] **Multi-Tenant Isolation Enforced**: All new database queries, entities, or storage interactions explicitly enforce `tenant_id` boundaries.
- [ ] **Evidence Storage Separation**: No raw evidence or collected dumps are placed in or served from frontend static directories.
- [ ] **No Unauthorized Live Collection**: Live scraping/collection remains deactivated unless accompanied by formal authorization clearance.
- [ ] **Backend Authorization**: Tenant context and permissions are verified on the backend, not assumed from frontend state.

---

## Local Verification & Testing
- [ ] Backend tests passing locally: `pytest backend/tests -v`
- [ ] Frontend build passing locally: `cd frontend && npm run build`
- [ ] Database migrations tested up and down (if models changed): `alembic upgrade head && alembic downgrade -1`
- [ ] New unit or integration tests added to cover changes

---

## Reviewer Routing (`CODEOWNERS`)
- [ ] Security Reviewer sign-off required (if modifying `security.py`, `evidence/`, `sanitizer.py`, or CI workflows)
- [ ] Domain Lead sign-off (Backend or Frontend lead)
