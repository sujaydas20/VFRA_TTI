"""Phase 1: Tenant-Isolation Row-Level Security (RLS) Policies (SEC-AUDIT-02 & SEC-AUDIT-06)

Revision ID: 0004_phase1_tenant_rls
Revises: 0003_phase1_iam_core
Create Date: 2026-10-29 17:00:00.000000

Remediates:
- SEC-AUDIT-02: Enforces database-level tenant isolation across all tenant-partitioned Phase 1 tables.
- SEC-AUDIT-06: Establishes fail-closed RLS context evaluation against app.current_tenant_id.

Table Classifications:
1. Tenant-Scoped Workspace & Financial:
   - iam.tenant_organizations: Scoped to active tenant for tti_app_role.
   - iam.tenant_memberships: Scoped to active tenant for tti_app_role.
   - iam.active_user_sessions: Scoped to active tenant for tti_app_role.
   - app.tenant_credit_balances: Scoped to active tenant for tti_app_role.
   - app.credit_deduction_ledgers: Scoped to active tenant for tti_app_role.
2. Privileged Audit Ledger:
   - audit.audit_event_records: Scoped to tenant for tti_app_role; platform-admin can query system-wide audit records.
3. Global Catalog / Identity:
   - iam.roles: Global system dictionary (no RLS; read-only table grant boundary per DEC-16).
   - iam.user_profiles: Identity master (no ambient cross-tenant queries; membership-gated at application tier).
"""

from typing import Sequence, Union
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_phase1_tenant_rls"
down_revision: Union[str, None] = "0003_phase1_iam_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------------------------
    # 1. Enable & Force Row-Level Security on Tenant-Partitioned Tables
    # -------------------------------------------------------------------------
    tables_to_protect = [
        ("iam", "tenant_organizations"),
        ("iam", "tenant_memberships"),
        ("iam", "active_user_sessions"),
        ("app", "tenant_credit_balances"),
        ("app", "credit_deduction_ledgers"),
        ("audit", "audit_event_records"),
    ]

    for schema, table in tables_to_protect:
        op.execute(f"ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY;")

    # -------------------------------------------------------------------------
    # 2. Define Fail-Closed Tenant Isolation Policies for tti_app_role
    #
    # Core Invariant:
    # When app.current_tenant_id is missing, empty, or invalid, NULLIF returns NULL.
    # Comparison `tenant_id = NULL` evaluates to UNKNOWN (false), failing closed.
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                -- iam.tenant_organizations
                DROP POLICY IF EXISTS p_tenant_organizations_isolation ON iam.tenant_organizations;
                CREATE POLICY p_tenant_organizations_isolation ON iam.tenant_organizations
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- iam.tenant_memberships
                DROP POLICY IF EXISTS p_tenant_memberships_isolation ON iam.tenant_memberships;
                CREATE POLICY p_tenant_memberships_isolation ON iam.tenant_memberships
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- iam.active_user_sessions
                DROP POLICY IF EXISTS p_active_user_sessions_isolation ON iam.active_user_sessions;
                CREATE POLICY p_active_user_sessions_isolation ON iam.active_user_sessions
                    FOR ALL TO tti_app_role
                    USING (active_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (active_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- app.tenant_credit_balances
                DROP POLICY IF EXISTS p_tenant_credit_balances_isolation ON app.tenant_credit_balances;
                CREATE POLICY p_tenant_credit_balances_isolation ON app.tenant_credit_balances
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- app.credit_deduction_ledgers
                DROP POLICY IF EXISTS p_credit_deductions_isolation ON app.credit_deduction_ledgers;
                CREATE POLICY p_credit_deductions_isolation ON app.credit_deduction_ledgers
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);

                -- audit.audit_event_records
                DROP POLICY IF EXISTS p_audit_records_isolation ON audit.audit_event_records;
                CREATE POLICY p_audit_records_isolation ON audit.audit_event_records
                    FOR ALL TO tti_app_role
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);
            END IF;
        END $$;
        """
    )

    # -------------------------------------------------------------------------
    # 3. Administrative Policies for tti_platform_admin_role
    #
    # Explicit Governance Invariant:
    # Platform administrators have administrative visibility to inspect and approve
    # newly registered organizations (DEC-22) and manage credit quotas without
    # ambient access to customer investigative case files or evidence (DEC-21).
    # -------------------------------------------------------------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                DROP POLICY IF EXISTS p_platform_admin_orgs ON iam.tenant_organizations;
                CREATE POLICY p_platform_admin_orgs ON iam.tenant_organizations
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_memberships ON iam.tenant_memberships;
                CREATE POLICY p_platform_admin_memberships ON iam.tenant_memberships
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_sessions ON iam.active_user_sessions;
                CREATE POLICY p_platform_admin_sessions ON iam.active_user_sessions
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_balances ON app.tenant_credit_balances;
                CREATE POLICY p_platform_admin_balances ON app.tenant_credit_balances
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_deductions ON app.credit_deduction_ledgers;
                CREATE POLICY p_platform_admin_deductions ON app.credit_deduction_ledgers
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_audit ON audit.audit_event_records;
                CREATE POLICY p_platform_admin_audit ON audit.audit_event_records
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    # 1. Drop Policies
    op.execute(
        """
        DO $$
        BEGIN
            DROP POLICY IF EXISTS p_tenant_organizations_isolation ON iam.tenant_organizations;
            DROP POLICY IF EXISTS p_tenant_memberships_isolation ON iam.tenant_memberships;
            DROP POLICY IF EXISTS p_active_user_sessions_isolation ON iam.active_user_sessions;
            DROP POLICY IF EXISTS p_tenant_credit_balances_isolation ON app.tenant_credit_balances;
            DROP POLICY IF EXISTS p_credit_deductions_isolation ON app.credit_deduction_ledgers;
            DROP POLICY IF EXISTS p_audit_records_isolation ON audit.audit_event_records;

            DROP POLICY IF EXISTS p_platform_admin_orgs ON iam.tenant_organizations;
            DROP POLICY IF EXISTS p_platform_admin_memberships ON iam.tenant_memberships;
            DROP POLICY IF EXISTS p_platform_admin_sessions ON iam.active_user_sessions;
            DROP POLICY IF EXISTS p_platform_admin_balances ON app.tenant_credit_balances;
            DROP POLICY IF EXISTS p_platform_admin_deductions ON app.credit_deduction_ledgers;
            DROP POLICY IF EXISTS p_platform_admin_audit ON audit.audit_event_records;
        END $$;
        """
    )

    # 2. Disable RLS
    tables = [
        ("audit", "audit_event_records"),
        ("app", "credit_deduction_ledgers"),
        ("app", "tenant_credit_balances"),
        ("iam", "active_user_sessions"),
        ("iam", "tenant_memberships"),
        ("iam", "tenant_organizations"),
    ]
    for schema, table in tables:
        op.execute(f"ALTER TABLE {schema}.{table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY;")
