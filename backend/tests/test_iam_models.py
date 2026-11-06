"""Phase 1 IAM SQLAlchemy ORM Model Contract Tests.

Validates:
- Explicit mapping of IAM entities to schema 'iam'.
- Correct registration in Base.metadata without modifying 'public' prototype tables.
- Primary keys, foreign key targets, and ON DELETE RESTRICT rules.
- Column types, unique constraints, and check constraints.
- In-memory relationship wiring between TenantOrganization, UserProfile, Role, and TenantMembership.
"""

import uuid
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, PrimaryKeyConstraint, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from app.database.base import Base
from app.database.models import (
    ActiveUserSession,
    AuditEvent,
    AuditEventRecord,
    CollectedThread,
    CreditDeductionLedger,
    RawArtifact,
    Role,
    Tenant,
    TenantCreditBalance,
    TenantMembership,
    TenantOrganization,
    UserProfile,
)


def test_iam_models_registered_in_metadata():
    """Verify IAM and associated governance entities are registered in Base.metadata."""
    table_keys = Base.metadata.tables.keys()

    assert "iam.tenant_organizations" in table_keys
    assert "iam.roles" in table_keys
    assert "iam.user_profiles" in table_keys
    assert "iam.tenant_memberships" in table_keys
    assert "iam.active_user_sessions" in table_keys
    assert "audit.audit_event_records" in table_keys
    assert "app.tenant_credit_balances" in table_keys
    assert "app.credit_deduction_ledgers" in table_keys


def test_public_prototype_tables_preserved_in_metadata():
    """Verify the four Release 0 prototype tables remain registered in public schema without modification."""
    table_keys = Base.metadata.tables.keys()

    # Prototype tables reside in default (public) schema
    assert "tenants" in table_keys
    assert "collected_threads" in table_keys
    assert "raw_artifacts" in table_keys
    assert "audit_events" in table_keys

    # Verify prototype Tenant model table is still public.tenants
    tenant_table = Base.metadata.tables["tenants"]
    assert tenant_table.schema is None
    assert "slug" in tenant_table.columns
    assert "is_active" in tenant_table.columns


def test_tenant_organizations_table_contract():
    """Verify iam.tenant_organizations schema, constraints, and column specifications."""
    table = Base.metadata.tables["iam.tenant_organizations"]

    assert table.schema == "iam"
    assert table.primary_key.columns.keys() == ["tenant_id"]
    assert isinstance(table.columns["tenant_id"].type, PG_UUID)

    # Check constraints
    ck_names = {ck.name for ck in table.constraints if isinstance(ck, CheckConstraint)}
    assert "ck_tenant_organizations_market_profile" in ck_names
    assert "ck_tenant_organizations_account_status" in ck_names

    # Unique constraint
    uq_cols = [
        set(uq.columns.keys())
        for uq in table.constraints
        if isinstance(uq, UniqueConstraint) and not isinstance(uq, PrimaryKeyConstraint)
    ]
    assert {"organization_name"} in uq_cols


def test_roles_table_contract():
    """Verify iam.roles schema, primary key, and system role defaults."""
    table = Base.metadata.tables["iam.roles"]

    assert table.schema == "iam"
    assert table.primary_key.columns.keys() == ["role_id"]
    assert "role_name" in table.columns
    assert "description" in table.columns
    assert "is_system_role" in table.columns
    assert table.columns["is_system_role"].server_default is not None


def test_user_profiles_table_contract():
    """Verify iam.user_profiles schema, credentials, MFA flags, and account state constraints."""
    table = Base.metadata.tables["iam.user_profiles"]

    assert table.schema == "iam"
    assert table.primary_key.columns.keys() == ["user_id"]
    assert isinstance(table.columns["user_id"].type, PG_UUID)

    # Unique on email_address
    uq_cols = [
        set(uq.columns.keys())
        for uq in table.constraints
        if isinstance(uq, UniqueConstraint) and not isinstance(uq, PrimaryKeyConstraint)
    ]
    assert {"email_address"} in uq_cols

    # Check constraint on account_state
    ck_names = {ck.name for ck in table.constraints if isinstance(ck, CheckConstraint)}
    assert "ck_user_profiles_account_state" in ck_names

    # Security columns present
    assert "password_hash" in table.columns
    assert "mfa_enforced" in table.columns
    assert "mfa_secret_encrypted" in table.columns
    assert "last_login_utc" in table.columns


def test_tenant_memberships_table_contract():
    """Verify iam.tenant_memberships foreign keys, deletion policy, and composite uniqueness."""
    table = Base.metadata.tables["iam.tenant_memberships"]

    assert table.schema == "iam"
    assert table.primary_key.columns.keys() == ["membership_id"]

    # Composite unique constraint on (tenant_id, user_id)
    uq_cols = [
        set(uq.columns.keys())
        for uq in table.constraints
        if isinstance(uq, UniqueConstraint) and not isinstance(uq, PrimaryKeyConstraint)
    ]
    assert {"tenant_id", "user_id"} in uq_cols

    # Foreign key constraints and ON DELETE RESTRICT policy
    fk_targets = {}
    for fk_constraint in table.constraints:
        if isinstance(fk_constraint, ForeignKeyConstraint):
            for fk in fk_constraint.elements:
                fk_targets[fk.parent.name] = (fk.target_fullname, fk.ondelete)

    assert "tenant_id" in fk_targets
    assert fk_targets["tenant_id"][0] == "iam.tenant_organizations.tenant_id"
    assert fk_targets["tenant_id"][1] == "RESTRICT"

    assert "user_id" in fk_targets
    assert fk_targets["user_id"][0] == "iam.user_profiles.user_id"
    assert fk_targets["user_id"][1] == "RESTRICT"

    assert "assigned_role" in fk_targets
    assert fk_targets["assigned_role"][0] == "iam.roles.role_id"
    assert fk_targets["assigned_role"][1] == "RESTRICT"

    # Check constraints
    ck_names = {ck.name for ck in table.constraints if isinstance(ck, CheckConstraint)}
    assert "ck_tenant_memberships_assigned_role" in ck_names
    assert "ck_tenant_memberships_membership_status" in ck_names

    # updated_at_utc column present
    assert "updated_at_utc" in table.columns


def test_active_user_sessions_table_contract():
    """Verify iam.active_user_sessions schema, primary key, foreign keys, and unique user constraint."""
    table = Base.metadata.tables["iam.active_user_sessions"]

    assert table.schema == "iam"
    assert table.primary_key.columns.keys() == ["session_id"]
    assert isinstance(table.columns["session_id"].type, PG_UUID)

    # Unique constraint on user_id (enforcing single active session invariant per AC-REQ-006 / DEC-20)
    uq_cols = [
        set(uq.columns.keys())
        for uq in table.constraints
        if isinstance(uq, UniqueConstraint) and not isinstance(uq, PrimaryKeyConstraint)
    ]
    assert {"user_id"} in uq_cols
    assert {"session_token_hash"} in uq_cols

    # Foreign keys
    fk_targets = {}
    for fk_constraint in table.constraints:
        if isinstance(fk_constraint, ForeignKeyConstraint):
            for fk in fk_constraint.elements:
                fk_targets[fk.parent.name] = (fk.target_fullname, fk.ondelete)

    assert "user_id" in fk_targets
    assert fk_targets["user_id"][0] == "iam.user_profiles.user_id"
    assert fk_targets["user_id"][1] == "CASCADE"

    assert "active_tenant_id" in fk_targets
    assert fk_targets["active_tenant_id"][0] == "iam.tenant_organizations.tenant_id"
    assert fk_targets["active_tenant_id"][1] == "RESTRICT"


def test_audit_event_records_table_contract():
    """Verify audit.audit_event_records schema, primary key, and correlation identifiers."""
    table = Base.metadata.tables["audit.audit_event_records"]

    assert table.schema == "audit"
    assert table.primary_key.columns.keys() == ["audit_event_id"]
    assert "action_type" in table.columns
    assert "correlation_id" in table.columns
    assert "event_timestamp_utc" in table.columns

    # Foreign keys with ON DELETE SET NULL
    fk_targets = {}
    for fk_constraint in table.constraints:
        if isinstance(fk_constraint, ForeignKeyConstraint):
            for fk in fk_constraint.elements:
                fk_targets[fk.parent.name] = (fk.target_fullname, fk.ondelete)

    assert "tenant_id" in fk_targets
    assert fk_targets["tenant_id"][0] == "iam.tenant_organizations.tenant_id"
    assert fk_targets["tenant_id"][1] == "SET NULL"

    assert "user_id" in fk_targets
    assert fk_targets["user_id"][0] == "iam.user_profiles.user_id"
    assert fk_targets["user_id"][1] == "SET NULL"


def test_billing_credit_models_contract():
    """Verify app.tenant_credit_balances and app.credit_deduction_ledgers constraints."""
    balance_table = Base.metadata.tables["app.tenant_credit_balances"]
    ledger_table = Base.metadata.tables["app.credit_deduction_ledgers"]

    assert balance_table.schema == "app"
    assert ledger_table.schema == "app"

    # Non-negative balance check constraints
    bal_ck_names = {ck.name for ck in balance_table.constraints if isinstance(ck, CheckConstraint)}
    assert "ck_credit_balance_allocated_nonneg" in bal_ck_names
    assert "ck_credit_balance_consumed_nonneg" in bal_ck_names
    assert "ck_credit_balance_remaining_nonneg" in bal_ck_names

    # Idempotency and status constraints on ledger
    ledger_uq_cols = [
        set(uq.columns.keys())
        for uq in ledger_table.constraints
        if isinstance(uq, UniqueConstraint) and not isinstance(uq, PrimaryKeyConstraint)
    ]
    assert {"tenant_id", "idempotency_key"} in ledger_uq_cols

    ledger_ck_names = {ck.name for ck in ledger_table.constraints if isinstance(ck, CheckConstraint)}
    assert "ck_credit_deductions_consumed_positive" in ledger_ck_names
    assert "ck_credit_deductions_balance_nonneg" in ledger_ck_names
    assert "ck_credit_deductions_status" in ledger_ck_names


def test_iam_orm_in_memory_instantiation():
    """Verify in-memory model instantiation and bidirectional relationship wiring."""
    tenant = TenantOrganization(
        tenant_id=uuid.uuid4(),
        organization_name="Cyber Threat Task Force",
        market_profile="LAW_ENFORCEMENT",
        account_status="ACTIVE",
    )

    role = Role(
        role_id="INVESTIGATOR_LEAD",
        role_name="Lead Investigator",
        description="Full investigative authority over tenant case dossiers",
        is_system_role=True,
    )

    user = UserProfile(
        user_id=uuid.uuid4(),
        email_address="lead.investigator@agency.gov",
        full_name="Detective John Miller",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$fake_salt$fake_hash",
        account_state="ACTIVE",
        mfa_enforced=True,
    )

    membership = TenantMembership(
        membership_id=uuid.uuid4(),
        tenant_id=tenant.tenant_id,
        user_id=user.user_id,
        assigned_role=role.role_id,
        membership_status="ACTIVE",
        organization=tenant,
        user=user,
        role_definition=role,
    )

    assert membership.organization == tenant
    assert membership.user == user
    assert membership.role_definition == role
    assert tenant.memberships == [membership]
    assert user.memberships == [membership]
    assert role.memberships == [membership]

    assert "<TenantOrganization" in repr(tenant)
    assert "<Role" in repr(role)
    assert "<UserProfile" in repr(user)
    assert "<TenantMembership" in repr(membership)
