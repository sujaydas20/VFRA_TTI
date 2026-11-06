"""FastAPI dependency injection providers for Phase 2 IAM, tenant security, and database scoping."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable, Optional
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.iam_lifecycle import (
    hash_session_token,
    validate_membership_scope,
    validate_organization_status,
)
from app.core.rbac import require_permission
from app.core.security import (
    TenantContext,
    decode_access_token,
    get_current_tenant_context,
)
from app.database.models.iam import (
    ActiveUserSession,
    TenantMembership,
    TenantOrganization,
    UserProfile,
)
from app.database.session import get_db, set_transaction_tenant_context


@dataclass
class UserSessionContext:
    """Validated user identity and server-side active session state."""

    user: UserProfile
    session: ActiveUserSession
    raw_token: str


@dataclass
class TenantSecurityContext:
    """
    Complete verified tenant security boundary.

    Contains:
    - user: Authenticated active user profile
    - session: Active server-side session
    - membership: Active tenant membership binding
    - organization: Active customer organization
    """

    user: UserProfile
    session: ActiveUserSession
    membership: TenantMembership
    organization: TenantOrganization


async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> UserSessionContext:
    """
    Authenticate investigator identity via Bearer JWT token.

    Validates:
    1. Authorization header format (Bearer <token>).
    2. Cryptographic signature and expiration of JWT.
    3. Server-side session record in iam.active_user_sessions (single active session invariant, DEC-20).
    4. Session token hash match (rejects displaced/revoked sessions).
    5. User account state in iam.user_profiles (rejects LOCKED or INACTIVE users).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MISSING_AUTHENTICATION_TOKEN: Bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split("Bearer ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MISSING_AUTHENTICATION_TOKEN: Bearer token is empty.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Decode and cryptographically verify signature + claims
    payload = decode_access_token(token)
    try:
        user_id = UUID(payload["sub"])
        session_id = UUID(payload["sid"])
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOKEN_MALFORMED: Token claims are invalid or missing required identifiers.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Verify User Profile and Account State
    stmt_user = select(UserProfile).where(UserProfile.user_id == user_id)
    user = await db.scalar(stmt_user)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="USER_NOT_FOUND: Authenticated user account does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.account_state == "LOCKED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ACCOUNT_LOCKED: User account is locked. Please contact your administrator.",
        )

    if user.account_state != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"ACCOUNT_INACTIVE: User account is currently {user.account_state}.",
        )

    # 2. Verify Server-Side Active Session Record
    stmt_session = select(ActiveUserSession).where(
        ActiveUserSession.user_id == user_id,
        ActiveUserSession.session_id == session_id,
    )
    session_rec = await db.scalar(stmt_session)
    if session_rec is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SESSION_REVOKED_OR_DISPLACED: Active session not found or displaced by another login.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify session token hash
    expected_hash = hash_session_token(token)
    if session_rec.session_token_hash != expected_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SESSION_REVOKED_OR_DISPLACED: Session token has been revoked or displaced.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)
    if session_rec.expires_at_utc < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SESSION_EXPIRED: Active session has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Keep session activity fresh
    session_rec.last_activity_utc = now

    return UserSessionContext(user=user, session=session_rec, raw_token=token)


async def get_tenant_security_context(
    current_user: UserSessionContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> TenantSecurityContext:
    """
    Verify tenant membership and organization lifecycle for the requested tenant.

    Rules:
    - X-Tenant-ID is a selector ONLY, never proof of authorization.
    - If X-Tenant-ID is omitted, defaults to the session's active_tenant_id.
    - User MUST possess an ACTIVE membership in the target tenant (rejects REVOKED / PENDING).
    - Target organization MUST be in ACTIVE status (rejects PENDING_APPROVAL / SUSPENDED / DEPROVISIONED).
    """
    if x_tenant_id:
        try:
            target_tenant_id = UUID(x_tenant_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid X-Tenant-ID header format. Must be a valid UUIDv4.",
            )
    else:
        target_tenant_id = current_user.session.active_tenant_id

    # 1. Verify Active Tenant Membership
    stmt_membership = select(TenantMembership).where(
        TenantMembership.tenant_id == target_tenant_id,
        TenantMembership.user_id == current_user.user.user_id,
    )
    membership = await db.scalar(stmt_membership)
    validate_membership_scope(membership, target_tenant_id, current_user.user.user_id)

    # 2. Verify Target Organization Status
    stmt_org = select(TenantOrganization).where(
        TenantOrganization.tenant_id == target_tenant_id,
    )
    organization = await db.scalar(stmt_org)
    validate_organization_status(organization)

    return TenantSecurityContext(
        user=current_user.user,
        session=current_user.session,
        membership=membership,  # type: ignore[arg-type]
        organization=organization,  # type: ignore[arg-type]
    )


async def get_authorized_tenant_db(
    ctx: TenantSecurityContext = Depends(get_tenant_security_context),
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an AsyncSession with transaction-local PostgreSQL tenant context bound.

    Enforces:
    - SET LOCAL app.current_tenant_id = :tenant_id
    - Binds within the exact transaction used for tenant queries.
    - Guarantees PostgreSQL RLS restricts queries to ctx.organization.tenant_id.
    """
    await set_transaction_tenant_context(db, ctx.organization.tenant_id)
    yield db


def require_permission_dep(permission: str) -> Callable[..., TenantSecurityContext]:
    """FastAPI dependency factory enforcing static RBAC permissions on protected routes."""

    def dependency(
        ctx: TenantSecurityContext = Depends(get_tenant_security_context),
    ) -> TenantSecurityContext:
        require_permission(ctx.membership.assigned_role, permission)
        return ctx

    return dependency


__all__ = [
    "get_db",
    "get_settings",
    "get_current_tenant_context",
    "get_current_user",
    "get_tenant_security_context",
    "get_authorized_tenant_db",
    "require_permission_dep",
    "TenantContext",
    "UserSessionContext",
    "TenantSecurityContext",
    "Settings",
    "AsyncSession",
]
