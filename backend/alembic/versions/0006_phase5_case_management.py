"""Phase 5: Case Management Subsystem (FR-EVI-001, AC-REQ-004, Physical Schema Domain 3)

Revision ID: 0006_phase5_case_management
Revises: 0005_phase3_threat_intel_core
Create Date: 2026-10-29

Canonical Reference:
- Physical Schema Design: Domain 3 (app.investigative_cases, app.case_message_associations, app.case_notes)
- Requirements: FR-EVI-001, AC-REQ-004
- Decisions: DEC-05, DEC-14, DEC-17
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0006_phase5_case_management"
down_revision: Union[str, None] = "0005_phase3_threat_intel_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------------------------
    # 1. Create Case Management Tables (app schema)
    # -------------------------------------------------------------------------

    # app.investigative_cases
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.investigative_cases (
            case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            case_title VARCHAR(500) NOT NULL,
            case_reference VARCHAR(64) NOT NULL,
            internal_agency_ref VARCHAR(255),
            case_status VARCHAR(40) NOT NULL DEFAULT 'ACTIVE',
            lead_investigator_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE RESTRICT,
            description TEXT,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            closed_at_utc TIMESTAMPTZ,
            CONSTRAINT ck_case_status CHECK (case_status IN ('ACTIVE', 'PENDING_REVIEW', 'FINALIZED_LOCKED', 'ARCHIVED')),
            CONSTRAINT uq_case_reference UNIQUE (tenant_id, case_reference)
        );
        """
    )

    # app.case_message_associations (Bridge Entity linking shared messages to tenant cases)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.case_message_associations (
            association_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            case_id UUID NOT NULL REFERENCES app.investigative_cases(case_id) ON DELETE CASCADE,
            message_id VARCHAR(128) NOT NULL,
            investigator_tags JSONB NOT NULL DEFAULT '[]'::jsonb,
            analyst_annotation TEXT,
            pinned_by_user_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE RESTRICT,
            pinned_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_case_message UNIQUE (case_id, message_id),
            CONSTRAINT fk_case_assoc_message FOREIGN KEY (tenant_id, message_id)
                REFERENCES threat.source_messages (tenant_id, message_id) ON DELETE RESTRICT
        );
        """
    )

    # app.case_notes (Confidential analyst notes and hypotheses)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.case_notes (
            note_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            case_id UUID NOT NULL REFERENCES app.investigative_cases(case_id) ON DELETE CASCADE,
            author_user_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE RESTRICT,
            note_title VARCHAR(255) NOT NULL,
            note_content TEXT NOT NULL,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # -------------------------------------------------------------------------
    # 2. Performance & Retrieval Indexes
    # -------------------------------------------------------------------------
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigative_cases_tenant_created ON app.investigative_cases (tenant_id, created_at_utc DESC);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigative_cases_lead ON app.investigative_cases (tenant_id, lead_investigator_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_case_message_associations_case ON app.case_message_associations (tenant_id, case_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_case_message_associations_msg ON app.case_message_associations (tenant_id, message_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_case_notes_case ON app.case_notes (tenant_id, case_id, created_at_utc ASC);")

    # -------------------------------------------------------------------------
    # 3. Enable & Force Row-Level Security
    # -------------------------------------------------------------------------
    tables_to_protect = [
        ("app", "investigative_cases"),
        ("app", "case_message_associations"),
        ("app", "case_notes"),
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
                -- app.investigative_cases
                DROP POLICY IF EXISTS p_investigative_cases_isolation ON app.investigative_cases;
                CREATE POLICY p_investigative_cases_isolation ON app.investigative_cases
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- app.case_message_associations
                DROP POLICY IF EXISTS p_case_message_associations_isolation ON app.case_message_associations;
                CREATE POLICY p_case_message_associations_isolation ON app.case_message_associations
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- app.case_notes
                DROP POLICY IF EXISTS p_case_notes_isolation ON app.case_notes;
                CREATE POLICY p_case_notes_isolation ON app.case_notes
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);
            END IF;
        END $$;
        """
    )

    # -------------------------------------------------------------------------
    # 5. Administrative Policies for tti_platform_admin_role
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                DROP POLICY IF EXISTS p_platform_admin_cases ON app.investigative_cases;
                CREATE POLICY p_platform_admin_cases ON app.investigative_cases
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_case_messages ON app.case_message_associations;
                CREATE POLICY p_platform_admin_case_messages ON app.case_message_associations
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_case_notes ON app.case_notes;
                CREATE POLICY p_platform_admin_case_notes ON app.case_notes
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
                GRANT USAGE ON SCHEMA app TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.investigative_cases TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.case_message_associations TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.case_notes TO tti_app_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                GRANT USAGE ON SCHEMA app TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.investigative_cases TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.case_message_associations TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.case_notes TO tti_platform_admin_role;
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
                REVOKE ALL PRIVILEGES ON TABLE app.case_notes, app.case_message_associations,
                    app.investigative_cases FROM tti_platform_admin_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                REVOKE ALL PRIVILEGES ON TABLE app.case_notes, app.case_message_associations,
                    app.investigative_cases FROM tti_app_role;
            END IF;
        END $$;
        """
    )

    # 2. Drop Policies
    op.execute(
        """
        DO $$
        BEGIN
            DROP POLICY IF EXISTS p_investigative_cases_isolation ON app.investigative_cases;
            DROP POLICY IF EXISTS p_case_message_associations_isolation ON app.case_message_associations;
            DROP POLICY IF EXISTS p_case_notes_isolation ON app.case_notes;

            DROP POLICY IF EXISTS p_platform_admin_cases ON app.investigative_cases;
            DROP POLICY IF EXISTS p_platform_admin_case_messages ON app.case_message_associations;
            DROP POLICY IF EXISTS p_platform_admin_case_notes ON app.case_notes;
        END $$;
        """
    )

    # 3. Disable RLS
    tables = [
        ("app", "case_notes"),
        ("app", "case_message_associations"),
        ("app", "investigative_cases"),
    ]
    for schema, table in tables:
        op.execute(f"ALTER TABLE {schema}.{table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY;")

    # 4. Drop tables in reverse dependency order
    op.execute("DROP TABLE IF EXISTS app.case_notes CASCADE;")
    op.execute("DROP TABLE IF EXISTS app.case_message_associations CASCADE;")
    op.execute("DROP TABLE IF EXISTS app.investigative_cases CASCADE;")
