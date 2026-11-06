"""Authentication and session lifecycle API endpoints for TTI Phase 2."""

from datetime import datetime, timedelta, timezone
import secrets
from typing import List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantSecurityContext,
    UserSessionContext,
    get_current_user,
    get_db,
    get_tenant_security_context,
)
from app.core.config import get_settings
from app.core.rate_limit import enforce_login_rate_limits, get_rate_limiter
from app.services.protocols import RateLimiter
from app.core.iam_lifecycle import (
    hash_session_token,
    validate_membership_scope,
    validate_organization_status,
)
from app.core.rbac import get_role_permissions
from app.core.security import (
    create_access_token,
    verify_password,
)
from app.database.models.audit import AuditEventRecord
from app.database.models.iam import (
    ActiveUserSession,
    TenantMembership,
    TenantOrganization,
    UserProfile,
)
from app.schemas.iam import (
    LoginRequest,
    LoginResponse,
    MeResponse,
    UserProfileResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication & Sessions"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate investigator with Argon2id and establish single active session",
)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> LoginResponse:
    """
    Authenticate investigator credentials and enforce Phase 2 security invariants:

    - Argon2id password verification (constant-time protection against timing attacks).
    - User account state enforcement (rejects LOCKED or INACTIVE users).
    - Multi-tenant membership verification (ensures active membership in target organization).
    - Organization lifecycle verification (rejects PENDING_APPROVAL / SUSPENDED / DEPROVISIONED).
    - Single active session invariant (DEC-20):
      - If active session exists: returns HTTP 409 Conflict unless force_terminate_existing=True.
      - If force_terminate_existing=True: displaces previous session and emits SESSION_DISPLACED audit event.
    - Emits auditable lifecycle event in audit.audit_event_records.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent")
    await enforce_login_rate_limits(limiter=limiter, client_ip=client_ip, email=body.email)

    # 1. User Profile Lookup
    stmt_user = select(UserProfile).where(UserProfile.email_address == body.email.strip().lower())
    user = await db.scalar(stmt_user)

    if user is None:
        # Dummy verification to equalize timing
        verify_password("dummy_constant_time", "$argon2id$v=19$m=65536,t=2,p=1$dummy_hash_for_timing")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="INVALID_CREDENTIALS: Invalid email address or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Verify Password with Argon2id
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="INVALID_CREDENTIALS: Invalid email address or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Verify Account State
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

    # 4. Target Tenant Resolution & Membership Verification
    if body.tenant_id:
        target_tenant_id = body.tenant_id
        stmt_m = select(TenantMembership).where(
            TenantMembership.tenant_id == target_tenant_id,
            TenantMembership.user_id == user.user_id,
        )
        membership = await db.scalar(stmt_m)
        validate_membership_scope(membership, target_tenant_id, user.user_id)
    else:
        # Auto-select user's first active membership
        stmt_memberships = select(TenantMembership).where(
            TenantMembership.user_id == user.user_id,
            TenantMembership.membership_status == "ACTIVE",
        )
        active_memberships = (await db.scalars(stmt_memberships)).all()
        if not active_memberships:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="NO_ACTIVE_TENANT_MEMBERSHIP: User does not belong to any active tenant organization.",
            )
        membership = active_memberships[0]
        target_tenant_id = membership.tenant_id

    # 5. Organization Lifecycle Verification (DEC-22)
    stmt_org = select(TenantOrganization).where(
        TenantOrganization.tenant_id == target_tenant_id,
    )
    organization = await db.scalar(stmt_org)
    validate_organization_status(organization)

    # 6. Session Governance (DEC-20 Single Active Session Invariant)
    stmt_session = select(ActiveUserSession).where(ActiveUserSession.user_id == user.user_id)
    existing_session = await db.scalar(stmt_session)
    ttl_minutes = settings.TTI_ACCESS_TOKEN_EXPIRE_MINUTES

    if existing_session is not None and existing_session.expires_at_utc > now:
        if not body.force_terminate_existing:
            # Emit audit log for rejected concurrent login
            rejected_audit = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=target_tenant_id,
                user_id=user.user_id,
                action_type="SESSION_CONCURRENT_LOGIN_REJECTED",
                client_ip_address=client_ip,
                correlation_id=uuid.uuid4(),
                details={
                    "existing_session_id": str(existing_session.session_id),
                    "reason": "ACTIVE_SESSION_EXISTS",
                },
                event_timestamp_utc=now,
            )
            db.add(rejected_audit)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="ACTIVE_SESSION_EXISTS: An active authenticated session already exists for this account. Set force_terminate_existing=true to displace previous session.",
            )

        # Displace existing session
        displaced_id = existing_session.session_id
        session_id = uuid.uuid4()
        existing_session.session_id = session_id
        token_jwt = create_access_token(
            subject=str(user.user_id),
            active_tenant_id=str(target_tenant_id),
            session_id=str(session_id),
        )
        existing_session.active_tenant_id = target_tenant_id
        existing_session.session_token_hash = hash_session_token(token_jwt)
        existing_session.ip_address = client_ip
        existing_session.user_agent = user_agent
        existing_session.last_activity_utc = now
        existing_session.expires_at_utc = now + timedelta(minutes=ttl_minutes)

        displaced_audit = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=target_tenant_id,
            user_id=user.user_id,
            action_type="SESSION_DISPLACED",
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "displaced_session_id": str(displaced_id),
                "new_session_id": str(session_id),
                "override_flag": True,
            },
            event_timestamp_utc=now,
        )
        db.add(displaced_audit)
    else:
        # Re-use or create fresh session record
        if existing_session is not None:
            session_id = uuid.uuid4()
            existing_session.session_id = session_id
            token_jwt = create_access_token(
                subject=str(user.user_id),
                active_tenant_id=str(target_tenant_id),
                session_id=str(session_id),
            )
            existing_session.active_tenant_id = target_tenant_id
            existing_session.session_token_hash = hash_session_token(token_jwt)
            existing_session.ip_address = client_ip
            existing_session.user_agent = user_agent
            existing_session.last_activity_utc = now
            existing_session.expires_at_utc = now + timedelta(minutes=ttl_minutes)
        else:
            session_id = uuid.uuid4()
            token_jwt = create_access_token(
                subject=str(user.user_id),
                active_tenant_id=str(target_tenant_id),
                session_id=str(session_id),
            )
            new_session = ActiveUserSession(
                session_id=session_id,
                user_id=user.user_id,
                active_tenant_id=target_tenant_id,
                session_token_hash=hash_session_token(token_jwt),
                ip_address=client_ip,
                user_agent=user_agent,
                created_at_utc=now,
                last_activity_utc=now,
                expires_at_utc=now + timedelta(minutes=ttl_minutes),
            )
            db.add(new_session)

        created_audit = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=target_tenant_id,
            user_id=user.user_id,
            action_type="SESSION_CREATED",
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={"session_id": str(session_id)},
            event_timestamp_utc=now,
        )
        db.add(created_audit)

    # 7. Update Last Login
    user.last_login_utc = now
    await db.commit()

    role = membership.assigned_role  # type: ignore[union-attr]
    permissions = sorted(list(get_role_permissions(role)))

    return LoginResponse(
        access_token=token_jwt,
        token_type="bearer",
        expires_in=ttl_minutes * 60,
        user=UserProfileResponse(
            user_id=user.user_id,
            email_address=user.email_address,
            full_name=user.full_name,
            account_state=user.account_state,
        ),
        active_tenant_id=target_tenant_id,
        assigned_role=role,
        permissions=permissions,
    )


@router.post(
    "/logout",
    summary="Revoke active user session and emit audit event",
)
async def logout(
    request: Request,
    user_ctx: UserSessionContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Terminate the active server-side session, invalidating the session token immediately."""
    client_ip = request.client.host if request.client else None
    now = datetime.now(timezone.utc)

    # Emit audit event prior to session deletion
    audit = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=user_ctx.session.active_tenant_id,
        user_id=user_ctx.user.user_id,
        action_type="SESSION_TERMINATED",
        client_ip_address=client_ip,
        correlation_id=uuid.uuid4(),
        details={"session_id": str(user_ctx.session.session_id)},
        event_timestamp_utc=now,
    )
    db.add(audit)

    # Delete active session record
    await db.delete(user_ctx.session)
    await db.commit()

    return {"message": "Session terminated successfully."}


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Get authenticated investigator profile and active tenant permissions",
)
async def get_me(
    ctx: TenantSecurityContext = Depends(get_tenant_security_context),
) -> MeResponse:
    """Return active investigator profile, tenant organization, and authorized permissions."""
    role = ctx.membership.assigned_role
    permissions = sorted(list(get_role_permissions(role)))

    return MeResponse(
        user_id=ctx.user.user_id,
        email_address=ctx.user.email_address,
        full_name=ctx.user.full_name,
        account_state=ctx.user.account_state,
        active_tenant_id=ctx.organization.tenant_id,
        organization_name=ctx.organization.organization_name,
        assigned_role=role,
        permissions=permissions,
    )
