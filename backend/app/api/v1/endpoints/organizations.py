"""Organization workspace and membership management API endpoints for TTI Phase 2."""

from datetime import datetime, timezone
from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantSecurityContext,
    get_authorized_tenant_db,
    require_permission_dep,
)
from app.core.iam_lifecycle import reactivate_tenant_membership
from app.core.rbac import (
    PERM_ORG_READ,
    PERM_USER_MANAGE,
    PERM_USER_READ,
    validate_self_elevation_attempt,
)
from app.database.models.audit import AuditEventRecord
from app.database.models.iam import TenantMembership, UserProfile
from app.schemas.iam import (
    MemberResponse,
    OrganizationResponse,
    ReactivateMemberRequest,
    UpdateMemberRoleRequest,
)

router = APIRouter(prefix="/organizations", tags=["Organizations & Memberships"])


@router.get(
    "/current",
    response_model=OrganizationResponse,
    summary="Retrieve current active organization workspace",
)
async def get_current_organization(
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_ORG_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> OrganizationResponse:
    """Return the validated active tenant organization workspace details."""
    return OrganizationResponse(
        tenant_id=ctx.organization.tenant_id,
        organization_name=ctx.organization.organization_name,
        market_profile=ctx.organization.market_profile,
        account_status=ctx.organization.account_status,
        created_at_utc=ctx.organization.created_at_utc,
    )


@router.get(
    "/members",
    response_model=List[MemberResponse],
    summary="List members of current tenant organization",
)
async def list_organization_members(
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_USER_READ)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> List[MemberResponse]:
    """
    List investigator and analyst memberships within the current active tenant.

    Enforces:
    - PostgreSQL Row-Level Security (RLS) bound by transaction-local app.current_tenant_id.
    - RBAC: requires 'user:read' permission.
    """
    stmt = (
        select(TenantMembership, UserProfile)
        .join(UserProfile, TenantMembership.user_id == UserProfile.user_id)
        .where(TenantMembership.tenant_id == ctx.organization.tenant_id)
        .order_by(UserProfile.full_name)
    )
    results = (await db.execute(stmt)).all()

    members = [
        MemberResponse(
            membership_id=m.membership_id,
            tenant_id=m.tenant_id,
            user_id=u.user_id,
            email_address=u.email_address,
            full_name=u.full_name,
            assigned_role=m.assigned_role,
            membership_status=m.membership_status,
            granted_at_utc=m.granted_at_utc,
        )
        for m, u in results
    ]
    return members


@router.post(
    "/members/{target_user_id}/role",
    response_model=MemberResponse,
    summary="Update a member's operational role within the organization",
)
async def update_member_role(
    target_user_id: uuid.UUID,
    body: UpdateMemberRoleRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_USER_MANAGE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> MemberResponse:
    """
    Modify an investigator's role within the tenant organization.

    Invariants Enforced:
    - User cannot alter or elevate their own role (Scenario 6 / AC-REQ-003).
    - Caller must hold TENANT_ADMIN role (validated via validate_self_elevation_attempt).
    - Emits MEMBERSHIP_ROLE_UPDATED audit record.
    """
    if target_user_id == ctx.user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ROLE_SELF_MODIFICATION_FORBIDDEN: Users are strictly barred from modifying their own role.",
        )

    # Validate target role and elevation boundaries
    validate_self_elevation_attempt(ctx.membership.assigned_role, body.role)

    stmt = (
        select(TenantMembership, UserProfile)
        .join(UserProfile, TenantMembership.user_id == UserProfile.user_id)
        .where(
            TenantMembership.tenant_id == ctx.organization.tenant_id,
            TenantMembership.user_id == target_user_id,
        )
    )
    result = (await db.execute(stmt)).first()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user membership not found in this organization.",
        )

    membership, target_user = result
    old_role = membership.assigned_role
    now = datetime.now(timezone.utc)
    client_ip = request.client.host if request.client else None

    membership.assigned_role = body.role
    membership.updated_at_utc = now

    audit_event = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=ctx.organization.tenant_id,
        user_id=ctx.user.user_id,
        action_type="MEMBERSHIP_ROLE_UPDATED",
        client_ip_address=client_ip,
        correlation_id=uuid.uuid4(),
        details={
            "target_user_id": str(target_user_id),
            "old_role": old_role,
            "new_role": body.role,
        },
        event_timestamp_utc=now,
    )
    db.add(audit_event)
    await db.commit()

    return MemberResponse(
        membership_id=membership.membership_id,
        tenant_id=membership.tenant_id,
        user_id=target_user.user_id,
        email_address=target_user.email_address,
        full_name=target_user.full_name,
        assigned_role=membership.assigned_role,
        membership_status=membership.membership_status,
        granted_at_utc=membership.granted_at_utc,
    )


@router.post(
    "/members/{target_user_id}/reactivate",
    response_model=MemberResponse,
    summary="Reactivate a revoked membership in-place under UNIQUE (tenant_id, user_id)",
)
async def reactivate_member(
    target_user_id: uuid.UUID,
    body: ReactivateMemberRequest,
    request: Request,
    ctx: TenantSecurityContext = Depends(require_permission_dep(PERM_USER_MANAGE)),
    db: AsyncSession = Depends(get_authorized_tenant_db),
) -> MemberResponse:
    """
    Reactivate a revoked membership in-place (DEC-15).

    Invariants:
    - User cannot reactivate their own membership.
    - Updates membership_status to ACTIVE without creating duplicate rows.
    - Emits MEMBERSHIP_REACTIVATE audit event.
    """
    if target_user_id == ctx.user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ROLE_SELF_MODIFICATION_FORBIDDEN: Users cannot alter their own membership.",
        )

    validate_self_elevation_attempt(ctx.membership.assigned_role, body.role)

    stmt = (
        select(TenantMembership, UserProfile)
        .join(UserProfile, TenantMembership.user_id == UserProfile.user_id)
        .where(
            TenantMembership.tenant_id == ctx.organization.tenant_id,
            TenantMembership.user_id == target_user_id,
        )
    )
    result = (await db.execute(stmt)).first()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user membership not found in this organization.",
        )

    membership, target_user = result
    client_ip = request.client.host if request.client else None

    # Call canonical DEC-15 reactivation helper
    audit_event = reactivate_tenant_membership(
        membership=membership,
        new_role=body.role,
        actor_user_id=ctx.user.user_id,
        client_ip=client_ip,
    )
    db.add(audit_event)
    await db.commit()

    return MemberResponse(
        membership_id=membership.membership_id,
        tenant_id=membership.tenant_id,
        user_id=target_user.user_id,
        email_address=target_user.email_address,
        full_name=target_user.full_name,
        assigned_role=membership.assigned_role,
        membership_status=membership.membership_status,
        granted_at_utc=membership.granted_at_utc,
    )
