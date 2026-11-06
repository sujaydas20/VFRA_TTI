"""Pydantic schemas for Phase 2 IAM authentication, sessions, and organizations."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    """Credentials and parameters for password-based login."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., description="User's registered email address", min_length=3, max_length=320)
    password: str = Field(..., description="User's plaintext password for Argon2id verification", min_length=1)
    tenant_id: Optional[UUID] = Field(None, description="Optional target tenant organization to activate upon login")
    force_terminate_existing: bool = Field(
        False,
        description="If True, displaces any existing active session under DEC-20 policy",
    )


class UserProfileResponse(BaseModel):
    """Public user identity projection."""

    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    email_address: str
    full_name: str
    account_state: str


class LoginResponse(BaseModel):
    """Authentication token and active session context response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserProfileResponse
    active_tenant_id: UUID
    assigned_role: str
    permissions: List[str]


class MeResponse(BaseModel):
    """Authenticated investigator session telemetry and active tenant context."""

    user_id: UUID
    email_address: str
    full_name: str
    account_state: str
    active_tenant_id: UUID
    organization_name: str
    assigned_role: str
    permissions: List[str]


class OrganizationResponse(BaseModel):
    """Organization workspace details."""

    model_config = ConfigDict(from_attributes=True)

    tenant_id: UUID
    organization_name: str
    market_profile: str
    account_status: str
    created_at_utc: datetime


class MemberResponse(BaseModel):
    """Tenant organization member projection."""

    model_config = ConfigDict(from_attributes=True)

    membership_id: UUID
    tenant_id: UUID
    user_id: UUID
    email_address: str
    full_name: str
    assigned_role: str
    membership_status: str
    granted_at_utc: datetime


class UpdateMemberRoleRequest(BaseModel):
    """Payload to alter a member's operational role."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(..., description="Canonical role token: TENANT_ADMIN, INVESTIGATOR_LEAD, INVESTIGATOR, READ_ONLY_ANALYST")


class ReactivateMemberRequest(BaseModel):
    """Payload to reactivate a revoked or pending membership."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(..., description="Canonical role to assign upon reactivation")
