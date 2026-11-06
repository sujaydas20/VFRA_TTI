"""Phase 2: Telegram Bot Ingestion and Consent Subsystem

Revision ID: 0008_phase2_telegram_and_consent
Revises: 0007_phase1_system_jobs
Create Date: 2026-10-31

Canonical Reference:
- Physical Schema Design: Domain 4 (app.webhook_updates, app.telegram_subjects, app.consent_records, app.deletion_requests, app.consented_submissions)
- Security Invariants: Multi-tenant isolated, RLS-enforced, encrypted identities at rest with blind HMAC indexing
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0008_phase2_telegram_and_consent"
down_revision: Union[str, None] = "0007_phase1_system_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create Webhook Updates Table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.webhook_updates (
            update_id BIGINT PRIMARY KEY,
            update_type VARCHAR(32) NOT NULL,
            payload_hash VARCHAR(64) NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processed_at TIMESTAMPTZ,
            status VARCHAR(32) NOT NULL DEFAULT 'received'
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_webhook_updates_status ON app.webhook_updates(status)")

    # 2. Create Telegram Subjects Table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.telegram_subjects (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            telegram_user_id_hash VARCHAR(64) NOT NULL UNIQUE,
            encrypted_telegram_user_id TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_telegram_subjects_hash ON app.telegram_subjects(telegram_user_id_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_telegram_subjects_tenant ON app.telegram_subjects(tenant_id)")

    # 3. Create Consent Records Table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.consent_records (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            subject_id UUID NOT NULL REFERENCES app.telegram_subjects(id) ON DELETE CASCADE,
            consent_version VARCHAR(32) NOT NULL,
            purpose VARCHAR(128) NOT NULL,
            permitted_categories JSONB NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            chat_context JSONB NOT NULL DEFAULT '{}'::jsonb,
            granted_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_consent_records_subject ON app.consent_records(subject_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_consent_records_status ON app.consent_records(status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_consent_records_tenant ON app.consent_records(tenant_id)")

    # 4. Create Deletion Requests Ledger
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.deletion_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            subject_hash VARCHAR(64) NOT NULL,
            requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ,
            status VARCHAR(32) NOT NULL DEFAULT 'pending',
            deleted_counts JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_deletion_requests_hash ON app.deletion_requests(subject_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_deletion_requests_tenant ON app.deletion_requests(tenant_id)")

    # 5. Create Consented Submissions Table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.consented_submissions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            subject_id UUID NOT NULL REFERENCES app.telegram_subjects(id) ON DELETE CASCADE,
            submission_hash VARCHAR(64) NOT NULL,
            sanitized_text TEXT NOT NULL,
            detected_language VARCHAR(16),
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_consented_submissions_subject ON app.consented_submissions(subject_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_consented_submissions_tenant ON app.consented_submissions(tenant_id)")

    # 6. Enable Row Level Security (RLS)
    op.execute("ALTER TABLE app.telegram_subjects ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.consent_records ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.deletion_requests ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.consented_submissions ENABLE ROW LEVEL SECURITY")

    op.execute(
        """
        DO $$
        BEGIN
            DROP POLICY IF EXISTS p_tenant_telegram_subjects ON app.telegram_subjects;
            CREATE POLICY p_tenant_telegram_subjects ON app.telegram_subjects
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            DROP POLICY IF EXISTS p_tenant_consent_records ON app.consent_records;
            CREATE POLICY p_tenant_consent_records ON app.consent_records
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            DROP POLICY IF EXISTS p_tenant_deletion_requests ON app.deletion_requests;
            CREATE POLICY p_tenant_deletion_requests ON app.deletion_requests
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            DROP POLICY IF EXISTS p_tenant_consented_submissions ON app.consented_submissions;
            CREATE POLICY p_tenant_consented_submissions ON app.consented_submissions
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                DROP POLICY IF EXISTS p_platform_admin_telegram_subjects ON app.telegram_subjects;
                CREATE POLICY p_platform_admin_telegram_subjects ON app.telegram_subjects
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_consent_records ON app.consent_records;
                CREATE POLICY p_platform_admin_consent_records ON app.consent_records
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_deletion_requests ON app.deletion_requests;
                CREATE POLICY p_platform_admin_deletion_requests ON app.deletion_requests
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_consented_submissions ON app.consented_submissions;
                CREATE POLICY p_platform_admin_consented_submissions ON app.consented_submissions
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);
            END IF;
        END $$;
        """
    )

    # 7. Role Grants
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.webhook_updates TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.telegram_subjects TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.consent_records TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.deletion_requests TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.consented_submissions TO tti_app_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.webhook_updates TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.telegram_subjects TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.consent_records TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.deletion_requests TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.consented_submissions TO tti_platform_admin_role;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS app.consented_submissions CASCADE")
    op.execute("DROP TABLE IF EXISTS app.deletion_requests CASCADE")
    op.execute("DROP TABLE IF EXISTS app.consent_records CASCADE")
    op.execute("DROP TABLE IF EXISTS app.telegram_subjects CASCADE")
    op.execute("DROP TABLE IF EXISTS app.webhook_updates CASCADE")
