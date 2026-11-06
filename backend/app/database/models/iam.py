"""Identity & Access Management (IAM) domain models for TTI Phase 1.

Defines:
- iam.tenant_organizations: Customer organizations (LEA, Corporate SOC, Managed Service)
- iam.roles: Operational roles catalog (TENANT_ADMIN, INVESTIGATOR_LEAD, INVESTIGATOR, READ_ONLY_ANALYST)
- iam.user_profiles: Investigator credentials, account state, and MFA telemetry
- iam.tenant_memberships: Scoped user-tenant-role binding with status lifecycle

DISCLAIMER & SECURITY BOUNDARY NOTICE:
---------------------------------------
ORM model definitions and relational constraints alone do NOT enforce runtime
multi-tenant isolation or authorization. Runtime security requires:
1. Cryptographic session verification (JWT signature and expiration).
2. Explicit membership validation matching user_id to target tenant_id.
3. Transaction-scoped session context (SET LOCAL app.current_tenant_id = :tenant_id).
4. Restrictive PostgreSQL Row-Level Security (RLS) policies on tenant workspace tables.

Canonical Traceability:
- FR-TEN-001: Tenant Data Isolation & Request Scope Verification
- FR-TEN-002: Granular Role-Based Access Control (RBAC) System
- ADR-004: Multi-Tenancy Scoping Model (Shared Threat Store + Isolated Case Workspaces)
- ADR-007: Sensitive Data Protection (Permanent Plaintext Password Rejection)
- Physical Schema Reference: docs/architecture/gate_4b_3a/physical_schema_design.md
"""

from datetime import datetime, timezone
from typing import Optional
import uuid
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class TenantOrganization(Base):
    """
    Represents a customer organization (e.g., Law Enforcement Agency or Corporate SOC).

    Canonical Reference:
    - Logical: TenantOrganization (docs/architecture/gate_4b_1/logical_data_model.md#21)
    - Physical: iam.tenant_organizations (docs/architecture/gate_4b_3a/physical_schema_design.md#21)
    """

    __tablename__ = "tenant_organizations"
    __table_args__ = (
        UniqueConstraint("organization_name", name="uq_tenant_organizations_name"),
        CheckConstraint(
            "market_profile IN ('LAW_ENFORCEMENT', 'CORPORATE_SOC', 'MANAGED_SERVICE')",
            name="ck_tenant_organizations_market_profile",
        ),
        CheckConstraint(
            "account_status IN ('PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONED')",
            name="ck_tenant_organizations_account_status",
        ),
        {"schema": "iam"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    market_profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    account_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="PENDING_APPROVAL",
        server_default="PENDING_APPROVAL",
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    memberships: Mapped[list["TenantMembership"]] = relationship(
        "TenantMembership",
        back_populates="organization",
        cascade="none",
    )

    def __repr__(self) -> str:
        return f"<TenantOrganization id={self.tenant_id} name='{self.organization_name}' status={self.account_status}>"


class Role(Base):
    """
    Catalog of operational roles and privilege templates assigned to tenant memberships.

    Canonical Reference:
    - Logical: RoleDefinition (docs/architecture/gate_4b_1/logical_data_model.md#24)
    - Migration Plan: iam.roles (docs/architecture/gate_4b_3a/migration_and_rollback_strategy.md#2)

    NOTE ON SYSTEM ROLE IMMUTABILITY:
    Enforcement of system-role immutability (is_system_role=True) is an open architectural
    requirement. Database-level trigger enforcement or column/table grant restrictions
    must be verified prior to exposing role administration endpoints.
    """

    __tablename__ = "roles"
    __table_args__ = (
        {"schema": "iam"},
    )

    role_id: Mapped[str] = mapped_column(
        String(50),
        primary_key=True,
        comment="Canonical role token: TENANT_ADMIN, INVESTIGATOR_LEAD, INVESTIGATOR, READ_ONLY_ANALYST",
    )
    role_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    is_system_role: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        comment="Immutable system role flag; cannot be deleted or altered by customer administrators",
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    memberships: Mapped[list["TenantMembership"]] = relationship(
        "TenantMembership",
        back_populates="role_definition",
        cascade="none",
    )

    def __repr__(self) -> str:
        return f"<Role id='{self.role_id}' is_system={self.is_system_role}>"


class UserProfile(Base):
    """
    Master investigator, analyst, and administrator user profile and credentials.

    Canonical Reference:
    - Logical: UserProfile (docs/architecture/gate_4b_1/logical_data_model.md#22)
    - Physical: iam.user_profiles (docs/architecture/gate_4b_3a/physical_schema_design.md#22)
    """

    __tablename__ = "user_profiles"
    __table_args__ = (
        UniqueConstraint("email_address", name="uq_user_profiles_email"),
        CheckConstraint(
            "account_state IN ('ACTIVE', 'LOCKED', 'INVITED')",
            name="ck_user_profiles_account_state",
        ),
        {"schema": "iam"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_address: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        index=True,
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Argon2id cryptographic hash (zero plaintext stored or logged)",
    )
    account_state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="ACTIVE",
        server_default="ACTIVE",
    )
    mfa_enforced: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    mfa_secret_encrypted: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary,
        nullable=True,
        default=None,
        comment="Encrypted TOTP seed (AES-256-GCM); key management policy pending resolution",
    )
    last_login_utc: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    memberships: Mapped[list["TenantMembership"]] = relationship(
        "TenantMembership",
        back_populates="user",
        cascade="none",
    )

    def __repr__(self) -> str:
        return f"<UserProfile id={self.user_id} email='{self.email_address}' state={self.account_state}>"


class TenantMembership(Base):
    """
    Associates a UserProfile with a TenantOrganization, assigning an operational role.

    Canonical Reference:
    - Logical: TenantMembership (docs/architecture/gate_4b_1/logical_data_model.md#23)
    - Physical: iam.tenant_memberships (docs/architecture/gate_4b_3a/physical_schema_design.md#23)

    NOTE ON DELETION POLICY:
    Foreign keys enforce ON DELETE RESTRICT. Deletion cascades across memberships,
    tenants, and users are strictly barred to prevent orphaned case workspaces or audit loss.
    """

    __tablename__ = "tenant_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_memberships_tenant_user"),
        CheckConstraint(
            "assigned_role IN ('TENANT_ADMIN', 'INVESTIGATOR_LEAD', 'INVESTIGATOR', 'READ_ONLY_ANALYST')",
            name="ck_tenant_memberships_assigned_role",
        ),
        CheckConstraint(
            "membership_status IN ('PENDING_ACCEPTANCE', 'ACTIVE', 'REVOKED')",
            name="ck_tenant_memberships_membership_status",
        ),
        {"schema": "iam"},
    )

    membership_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    assigned_role: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("iam.roles.role_id", ondelete="RESTRICT"),
        nullable=False,
    )
    membership_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="PENDING_ACCEPTANCE",
        server_default="PENDING_ACCEPTANCE",
    )
    granted_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    organization: Mapped["TenantOrganization"] = relationship(
        "TenantOrganization",
        back_populates="memberships",
    )
    user: Mapped["UserProfile"] = relationship(
        "UserProfile",
        back_populates="memberships",
    )
    role_definition: Mapped["Role"] = relationship(
        "Role",
        back_populates="memberships",
    )

    def __repr__(self) -> str:
        return f"<TenantMembership id={self.membership_id} tenant={self.tenant_id} user={self.user_id} role={self.assigned_role} status={self.membership_status}>"


class ActiveUserSession(Base):
    """
    Enforces single active authenticated session per user account with interactive displacement.

    Canonical Reference:
    - Requirements: AC-REQ-006 (docs/product/product_baseline/functional_requirements.md#ac-req-006)
    - Decision: DEC-20 (docs/product/gate_3b/stakeholder_decision_register.md#dec-20)
    - Physical: iam.active_user_sessions (docs/architecture/gate_4b_3a/physical_schema_design.md#25)
    """

    __tablename__ = "active_user_sessions"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_active_user_sessions_user_id"),
        UniqueConstraint("session_token_hash", name="uq_active_user_sessions_token_hash"),
        {"schema": "iam"},
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    active_tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    session_token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of opaque bearer session token (zero plaintext tokens stored)",
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_activity_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    user: Mapped["UserProfile"] = relationship("UserProfile")
    active_tenant: Mapped["TenantOrganization"] = relationship("TenantOrganization")

    def __repr__(self) -> str:
        return f"<ActiveUserSession id={self.session_id} user={self.user_id} tenant={self.active_tenant_id}>"
