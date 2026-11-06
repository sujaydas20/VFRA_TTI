"""Phase 3: Threat Intelligence Core - Source Channels, Messages, Derived Content, Evidence Blobs, and Ingestion Jobs

Revision ID: 0005_phase3_threat_intel_core
Revises: 0004_phase1_tenant_rls
Create Date: 2026-10-29 18:00:00.000000

Implements:
- threat.source_channels: Registered and authorized intelligence feeds/channels.
- threat.source_messages: Normalized source messages and thread references.
- threat.derived_content_representations: Sanitized display & search text with applied filter flags.
- evidence.raw_evidence_blobs: Verbatim immutable raw payload pointers (never overwritten).
- app.ingestion_jobs: Ingestion batch status tracking.
- Row-Level Security (RLS) enforcement and least-privileged role grants for tti_app_role.
"""

from typing import Sequence, Union
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_phase3_threat_intel_core"
down_revision: Union[str, None] = "0004_phase1_tenant_rls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------------------------
    # 1. Create Core Threat Intelligence Tables
    # -------------------------------------------------------------------------

    # threat.source_channels
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS threat.source_channels (
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            channel_id VARCHAR(128) NOT NULL,
            channel_title VARCHAR(500) NOT NULL,
            channel_handle VARCHAR(255),
            source_type VARCHAR(50) NOT NULL,
            is_authorized BOOLEAN NOT NULL DEFAULT TRUE,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT pk_source_channels PRIMARY KEY (tenant_id, channel_id)
        );
        """
    )

    # threat.source_messages
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS threat.source_messages (
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            message_id VARCHAR(128) NOT NULL,
            channel_id VARCHAR(128) NOT NULL,
            source_sequence_id BIGINT NOT NULL,
            message_thread_id VARCHAR(128),
            sender_username VARCHAR(255),
            sender_native_id VARCHAR(128),
            broadcast_timestamp_utc TIMESTAMPTZ NOT NULL,
            reply_to_message_id VARCHAR(128),
            has_media BOOLEAN NOT NULL DEFAULT FALSE,
            ingested_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT pk_source_messages PRIMARY KEY (tenant_id, message_id),
            CONSTRAINT uq_source_messages_seq UNIQUE (tenant_id, channel_id, source_sequence_id)
        );
        """
    )

    # threat.derived_content_representations (Sanitized Display & Search Layer)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS threat.derived_content_representations (
            derived_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            source_message_id VARCHAR(128) NOT NULL,
            sanitized_message_text TEXT NOT NULL,
            content_sha256 VARCHAR(64) NOT NULL,
            sanitization_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
            transformation_timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_derived_content_message UNIQUE (tenant_id, source_message_id)
        );
        """
    )

    # evidence.raw_evidence_blobs (Immutable Raw Evidence Vault Pointers)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence.raw_evidence_blobs (
            raw_blob_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            source_message_id VARCHAR(128) NOT NULL,
            payload_sha256_hash VARCHAR(64) NOT NULL,
            byte_size BIGINT NOT NULL,
            payload_storage_locator VARCHAR(500) NOT NULL,
            ingestion_timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_raw_evidence_message UNIQUE (tenant_id, source_message_id),
            CONSTRAINT uq_raw_evidence_sha256 UNIQUE (tenant_id, payload_sha256_hash)
        );
        """
    )

    # app.ingestion_jobs (Batch Status & Provenance Tracking)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.ingestion_jobs (
            job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            source_reference VARCHAR(255) NOT NULL,
            source_type VARCHAR(50) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'RECEIVED',
            records_processed INTEGER NOT NULL DEFAULT 0,
            payload_sha256 VARCHAR(64) NOT NULL,
            error_message TEXT,
            submitted_by_user_id UUID REFERENCES iam.user_profiles(user_id) ON DELETE SET NULL,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at_utc TIMESTAMPTZ,
            CONSTRAINT ck_ingestion_jobs_status CHECK (status IN ('RECEIVED', 'PROCESSING', 'COMPLETED', 'FAILED', 'REJECTED'))
        );
        """
    )

    # -------------------------------------------------------------------------
    # 2. Performance & Retrieval Indexes
    # -------------------------------------------------------------------------
    op.execute("CREATE INDEX IF NOT EXISTS ix_source_messages_thread ON threat.source_messages (tenant_id, channel_id, message_thread_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_source_messages_broadcast ON threat.source_messages (tenant_id, broadcast_timestamp_utc DESC);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_derived_content_sha256 ON threat.derived_content_representations (tenant_id, content_sha256);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ingestion_jobs_tenant_created ON app.ingestion_jobs (tenant_id, created_at_utc DESC);")

    # -------------------------------------------------------------------------
    # 3. Enable & Force Row-Level Security
    # -------------------------------------------------------------------------
    tables_to_protect = [
        ("threat", "source_channels"),
        ("threat", "source_messages"),
        ("threat", "derived_content_representations"),
        ("evidence", "raw_evidence_blobs"),
        ("app", "ingestion_jobs"),
    ]

    for schema, table in tables_to_protect:
        op.execute(f"ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY;")

    # -------------------------------------------------------------------------
    # 4. Define Fail-Closed Tenant Isolation Policies for tti_app_role
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                -- threat.source_channels
                DROP POLICY IF EXISTS p_source_channels_isolation ON threat.source_channels;
                CREATE POLICY p_source_channels_isolation ON threat.source_channels
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- threat.source_messages
                DROP POLICY IF EXISTS p_source_messages_isolation ON threat.source_messages;
                CREATE POLICY p_source_messages_isolation ON threat.source_messages
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- threat.derived_content_representations
                DROP POLICY IF EXISTS p_derived_content_isolation ON threat.derived_content_representations;
                CREATE POLICY p_derived_content_isolation ON threat.derived_content_representations
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- evidence.raw_evidence_blobs
                DROP POLICY IF EXISTS p_raw_evidence_blobs_isolation ON evidence.raw_evidence_blobs;
                CREATE POLICY p_raw_evidence_blobs_isolation ON evidence.raw_evidence_blobs
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- app.ingestion_jobs
                DROP POLICY IF EXISTS p_ingestion_jobs_isolation ON app.ingestion_jobs;
                CREATE POLICY p_ingestion_jobs_isolation ON app.ingestion_jobs
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);
            END IF;
        END $$;
        """
    )

    # -------------------------------------------------------------------------
    # 5. Administrative Policies for tti_platform_admin_role
    # Note: evidence.raw_evidence_blobs has NO platform admin policy per DEC-21
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                DROP POLICY IF EXISTS p_platform_admin_channels ON threat.source_channels;
                CREATE POLICY p_platform_admin_channels ON threat.source_channels
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_messages ON threat.source_messages;
                CREATE POLICY p_platform_admin_messages ON threat.source_messages
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_derived ON threat.derived_content_representations;
                CREATE POLICY p_platform_admin_derived ON threat.derived_content_representations
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_jobs ON app.ingestion_jobs;
                CREATE POLICY p_platform_admin_jobs ON app.ingestion_jobs
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);
            END IF;
        END $$;
        """
    )

    # -------------------------------------------------------------------------
    # 6. Database Role Grants
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                GRANT USAGE ON SCHEMA threat, evidence, app TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON threat.source_channels TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON threat.source_messages TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON threat.derived_content_representations TO tti_app_role;
                -- Raw evidence: append-only, zero UPDATE or DELETE
                GRANT SELECT, INSERT ON evidence.raw_evidence_blobs TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON app.ingestion_jobs TO tti_app_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                GRANT USAGE ON SCHEMA threat, evidence, app TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON threat.source_channels TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON threat.source_messages TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON threat.derived_content_representations TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.ingestion_jobs TO tti_platform_admin_role;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    # 1. Revoke privileges
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                REVOKE ALL PRIVILEGES ON TABLE threat.source_channels, threat.source_messages,
                    threat.derived_content_representations, app.ingestion_jobs FROM tti_platform_admin_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                REVOKE ALL PRIVILEGES ON TABLE threat.source_channels, threat.source_messages,
                    threat.derived_content_representations, evidence.raw_evidence_blobs,
                    app.ingestion_jobs FROM tti_app_role;
            END IF;
        END $$;
        """
    )

    # 2. Drop Policies
    op.execute(
        """
        DO $$
        BEGIN
            DROP POLICY IF EXISTS p_source_channels_isolation ON threat.source_channels;
            DROP POLICY IF EXISTS p_source_messages_isolation ON threat.source_messages;
            DROP POLICY IF EXISTS p_derived_content_isolation ON threat.derived_content_representations;
            DROP POLICY IF EXISTS p_raw_evidence_blobs_isolation ON evidence.raw_evidence_blobs;
            DROP POLICY IF EXISTS p_ingestion_jobs_isolation ON app.ingestion_jobs;

            DROP POLICY IF EXISTS p_platform_admin_channels ON threat.source_channels;
            DROP POLICY IF EXISTS p_platform_admin_messages ON threat.source_messages;
            DROP POLICY IF EXISTS p_platform_admin_derived ON threat.derived_content_representations;
            DROP POLICY IF EXISTS p_platform_admin_jobs ON app.ingestion_jobs;
        END $$;
        """
    )

    # 3. Disable RLS
    tables = [
        ("app", "ingestion_jobs"),
        ("evidence", "raw_evidence_blobs"),
        ("threat", "derived_content_representations"),
        ("threat", "source_messages"),
        ("threat", "source_channels"),
    ]
    for schema, table in tables:
        op.execute(f"ALTER TABLE {schema}.{table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY;")

    # 4. Drop tables in reverse order
    op.execute("DROP TABLE IF EXISTS app.ingestion_jobs CASCADE;")
    op.execute("DROP TABLE IF EXISTS evidence.raw_evidence_blobs CASCADE;")
    op.execute("DROP TABLE IF EXISTS threat.derived_content_representations CASCADE;")
    op.execute("DROP TABLE IF EXISTS threat.source_messages CASCADE;")
    op.execute("DROP TABLE IF EXISTS threat.source_channels CASCADE;")
