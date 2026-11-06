"""Phase 1: IAM Core - Tenant organizations, roles, user profiles, memberships, sessions, audit ledger, and credit models

Revision ID: 0003_phase1_iam_core
Revises: 0002_phase0_schemas_and_roles
Create Date: 2026-10-29 16:00:00.000000

Approved Engineering Decisions Implemented:
- DEC-14: Static code RBAC for Release 1; canonical roles seeded in iam.roles.
- DEC-15: In-place membership reactivation with UNIQUE (tenant_id, user_id).
- DEC-16: Runtime read-only access to iam.roles via database role grant boundaries.
- DEC-17: Minimal IAM audit ledger (audit.audit_event_records) pulled forward to Phase 1.
- DEC-18: Three-tier database role separation (tti_migration_role, tti_platform_admin_role, tti_app_role).
- DEC-19: Unmetered search/thread scrolling per FR-THR-001; heavy operations metered via app.tenant_credit_balances & app.credit_deduction_ledgers.
- DEC-20: Single active session via iam.active_user_sessions with UNIQUE (user_id); interactive session displacement supported.
- DEC-21: Zero ambient platform-admin access to customer evidence.
- DEC-22: Organization lifecycle begins in PENDING_APPROVAL with audit trail.
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003_phase1_iam_core"
down_revision: Union[str, None] = "0002_phase0_schemas_and_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------------------------
    # 1. Three-Tier Database Roles (DEC-18)
    # Ensure tti_migration_role and tti_platform_admin_role exist idempotently
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_migration_role') THEN
                BEGIN
                    CREATE ROLE tti_migration_role WITH NOLOGIN;
                EXCEPTION WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Insufficient privilege to create role tti_migration_role; skipping';
                END;
            END IF;

            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                BEGIN
                    CREATE ROLE tti_platform_admin_role WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
                EXCEPTION WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Insufficient privilege to create role tti_platform_admin_role; skipping';
                END;
            END IF;
        END $$;
        """
    )

    # -------------------------------------------------------------------------
    # 2. Table: iam.tenant_organizations (DEC-22, AC-REQ-002)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS iam.tenant_organizations (
            tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_name VARCHAR(255) NOT NULL,
            market_profile VARCHAR(50) NOT NULL,
            account_status VARCHAR(30) NOT NULL DEFAULT 'PENDING_APPROVAL',
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_tenant_organizations_name UNIQUE (organization_name),
            CONSTRAINT ck_tenant_organizations_market_profile CHECK (market_profile IN ('LAW_ENFORCEMENT', 'CORPORATE_SOC', 'MANAGED_SERVICE')),
            CONSTRAINT ck_tenant_organizations_account_status CHECK (account_status IN ('PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONED'))
        );
        """
    )

    # -------------------------------------------------------------------------
    # 3. Table: iam.roles (DEC-14, DEC-16)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS iam.roles (
            role_id VARCHAR(50) PRIMARY KEY,
            role_name VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            is_system_role BOOLEAN NOT NULL DEFAULT TRUE,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # Seed Canonical Roles
    op.execute(
        """
        INSERT INTO iam.roles (role_id, role_name, description, is_system_role)
        VALUES
            ('TENANT_ADMIN', 'Tenant Administrator', 'Tenant Organization Administrator with authority over user memberships and credit allocation', TRUE),
            ('INVESTIGATOR_LEAD', 'Lead Investigator', 'Lead Investigator with full case creation, evidence tagging, and reporting authority', TRUE),
            ('INVESTIGATOR', 'Investigator', 'Investigator with query execution, message pinning, and case note authoring privileges', TRUE),
            ('READ_ONLY_ANALYST', 'Read-Only Analyst', 'Read-only analyst restricted to search execution and report review', TRUE)
        ON CONFLICT (role_id) DO NOTHING;
        """
    )

    # -------------------------------------------------------------------------
    # 4. Table: iam.user_profiles (FR-TEN-002, NFR-SEC-005)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS iam.user_profiles (
            user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email_address VARCHAR(320) NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            account_state VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
            mfa_enforced BOOLEAN NOT NULL DEFAULT TRUE,
            mfa_secret_encrypted BYTEA NULL,
            last_login_utc TIMESTAMPTZ NULL,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_user_profiles_email UNIQUE (email_address),
            CONSTRAINT ck_user_profiles_account_state CHECK (account_state IN ('ACTIVE', 'LOCKED', 'INVITED'))
        );
        """
    )

    # -------------------------------------------------------------------------
    # 5. Table: iam.tenant_memberships (DEC-15, AC-REQ-001, AC-REQ-004)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS iam.tenant_memberships (
            membership_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            user_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE RESTRICT,
            assigned_role VARCHAR(50) NOT NULL REFERENCES iam.roles(role_id) ON DELETE RESTRICT,
            membership_status VARCHAR(30) NOT NULL DEFAULT 'PENDING_ACCEPTANCE',
            granted_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_tenant_memberships_tenant_user UNIQUE (tenant_id, user_id),
            CONSTRAINT ck_tenant_memberships_assigned_role CHECK (assigned_role IN ('TENANT_ADMIN', 'INVESTIGATOR_LEAD', 'INVESTIGATOR', 'READ_ONLY_ANALYST')),
            CONSTRAINT ck_tenant_memberships_membership_status CHECK (membership_status IN ('PENDING_ACCEPTANCE', 'ACTIVE', 'REVOKED'))
        );
        """
    )

    # -------------------------------------------------------------------------
    # 6. Table: iam.active_user_sessions (DEC-20, AC-REQ-006)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS iam.active_user_sessions (
            session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE CASCADE,
            active_tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            session_token_hash VARCHAR(64) NOT NULL,
            ip_address VARCHAR(45) NULL,
            user_agent TEXT NULL,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_activity_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at_utc TIMESTAMPTZ NOT NULL,
            CONSTRAINT uq_active_user_sessions_user_id UNIQUE (user_id),
            CONSTRAINT uq_active_user_sessions_token_hash UNIQUE (session_token_hash)
        );
        """
    )

    # -------------------------------------------------------------------------
    # 7. Table: audit.audit_event_records (DEC-17)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit.audit_event_records (
            audit_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE SET NULL,
            user_id UUID NULL REFERENCES iam.user_profiles(user_id) ON DELETE SET NULL,
            action_type VARCHAR(64) NOT NULL,
            target_identifier_hash VARCHAR(64) NULL,
            client_ip_address VARCHAR(45) NULL,
            correlation_id UUID NOT NULL DEFAULT gen_random_uuid(),
            details JSONB NULL,
            event_timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # -------------------------------------------------------------------------
    # 8. Table: app.tenant_credit_balances (DEC-19, AC-REQ-005)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.tenant_credit_balances (
            balance_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            allocated_credits INTEGER NOT NULL DEFAULT 0,
            consumed_credits INTEGER NOT NULL DEFAULT 0,
            balance_credits INTEGER NOT NULL DEFAULT 0,
            reset_frequency VARCHAR(30) NOT NULL DEFAULT 'MONTHLY',
            last_reset_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_tenant_credit_balances_tenant UNIQUE (tenant_id),
            CONSTRAINT ck_credit_balance_allocated_nonneg CHECK (allocated_credits >= 0),
            CONSTRAINT ck_credit_balance_consumed_nonneg CHECK (consumed_credits >= 0),
            CONSTRAINT ck_credit_balance_remaining_nonneg CHECK (balance_credits >= 0)
        );
        """
    )

    # -------------------------------------------------------------------------
    # 9. Table: app.credit_deduction_ledgers (DEC-19, AC-REQ-005)
    # -------------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.credit_deduction_ledgers (
            deduction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE RESTRICT,
            user_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE RESTRICT,
            action_type VARCHAR(64) NOT NULL,
            credits_consumed INTEGER NOT NULL,
            balance_after_deduction INTEGER NOT NULL,
            idempotency_key VARCHAR(128) NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'COMMITTED',
            reference_id VARCHAR(255) NULL,
            description TEXT NULL,
            details JSONB NULL,
            created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_credit_deductions_tenant_idempotency UNIQUE (tenant_id, idempotency_key),
            CONSTRAINT ck_credit_deductions_consumed_positive CHECK (credits_consumed > 0),
            CONSTRAINT ck_credit_deductions_balance_nonneg CHECK (balance_after_deduction >= 0),
            CONSTRAINT ck_credit_deductions_status CHECK (status IN ('COMMITTED', 'REFUNDED'))
        );
        """
    )

    # -------------------------------------------------------------------------
    # 10. Role Privilege Boundaries (DEC-16, DEC-17, DEC-18)
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            -- Read-only role catalog boundary (DEC-16)
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                GRANT SELECT ON iam.roles TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON iam.tenant_organizations TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON iam.user_profiles TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE ON iam.tenant_memberships TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON iam.active_user_sessions TO tti_app_role;
                -- Append-only audit ledger (DEC-17): zero UPDATE or DELETE grants
                GRANT SELECT, INSERT ON audit.audit_event_records TO tti_app_role;
                -- Credit management
                GRANT SELECT, UPDATE ON app.tenant_credit_balances TO tti_app_role;
                GRANT SELECT, INSERT ON app.credit_deduction_ledgers TO tti_app_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                GRANT USAGE ON SCHEMA iam, app, audit TO tti_platform_admin_role;
                GRANT SELECT ON iam.roles TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE ON iam.tenant_organizations TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE ON iam.user_profiles TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE ON iam.tenant_memberships TO tti_platform_admin_role;
                GRANT SELECT, DELETE ON iam.active_user_sessions TO tti_platform_admin_role;
                GRANT SELECT, INSERT ON audit.audit_event_records TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE ON app.tenant_credit_balances TO tti_platform_admin_role;
                GRANT SELECT, INSERT ON app.credit_deduction_ledgers TO tti_platform_admin_role;
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
                REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA iam, app, audit FROM tti_platform_admin_role;
                REVOKE USAGE ON SCHEMA iam, app, audit FROM tti_platform_admin_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                REVOKE ALL PRIVILEGES ON TABLE iam.roles, iam.tenant_organizations, iam.user_profiles,
                    iam.tenant_memberships, iam.active_user_sessions, audit.audit_event_records,
                    app.tenant_credit_balances, app.credit_deduction_ledgers FROM tti_app_role;
            END IF;
        END $$;
        """
    )

    # 2. Drop tables in strict reverse-dependency order
    op.execute("DROP TABLE IF EXISTS app.credit_deduction_ledgers CASCADE;")
    op.execute("DROP TABLE IF EXISTS app.tenant_credit_balances CASCADE;")
    op.execute("DROP TABLE IF EXISTS audit.audit_event_records CASCADE;")
    op.execute("DROP TABLE IF EXISTS iam.active_user_sessions CASCADE;")
    op.execute("DROP TABLE IF EXISTS iam.tenant_memberships CASCADE;")
    op.execute("DROP TABLE IF EXISTS iam.user_profiles CASCADE;")
    op.execute("DROP TABLE IF EXISTS iam.roles CASCADE;")
    op.execute("DROP TABLE IF EXISTS iam.tenant_organizations CASCADE;")

    # 3. Drop created roles idempotently
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                BEGIN
                    DROP ROLE tti_platform_admin_role;
                EXCEPTION WHEN others THEN
                    RAISE NOTICE 'Could not drop role tti_platform_admin_role; skipping';
                END;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_migration_role') THEN
                BEGIN
                    DROP ROLE tti_migration_role;
                EXCEPTION WHEN others THEN
                    RAISE NOTICE 'Could not drop role tti_migration_role; skipping';
                END;
            END IF;
        END $$;
        """
    )
