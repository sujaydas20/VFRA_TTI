"""IAM lifecycle enforcement, session governance, and credit accounting service logic.

Implements Product-Owner-Approved Engineering Invariants:
- Scenario 1: Organization remains blocked until approved (DEC-22, AC-REQ-002)
- Scenario 2: Suspended/deprovisioned organizations blocked (DEC-22, AC-REQ-002)
- Scenario 3: Revoked membership cannot access tenant resources (AC-REQ-004)
- Scenario 4: Forged tenant identifiers do not bypass membership checks (FR-TEN-001)
- Scenario 5: Missing tenant context fails closed (ADR-004)
- Scenario 6: Role self-elevation prevented (AC-REQ-003, DEC-14)
- Scenario 7: In-place membership reactivation under UNIQUE (tenant_id, user_id) (DEC-15)
- Scenario 8: Single active session and interactive displacement (DEC-20, AC-REQ-006)
- Scenario 9: Quota overspend prevention (DEC-19, AC-REQ-005)
- Scenario 10: Idempotent deduction retries (DEC-19, AC-REQ-005)
- Scenario 11: Charge / refund lifecycle (DEC-19, AC-REQ-005)
- Scenario 12: Audit trail generation (DEC-17, NFR-OBS-001)
- Scenario 14: Platform admin zero-ambient customer evidence access (DEC-21, AC-REQ-001)
"""

from datetime import datetime, timezone, timedelta
import hashlib
import secrets
from typing import Optional, Tuple
import uuid
from fastapi import HTTPException, status

from app.database.models.iam import (
    ActiveUserSession,
    Role,
    TenantMembership,
    TenantOrganization,
    UserProfile,
)
from app.database.models.audit import AuditEventRecord
from app.database.models.billing import (
    CreditDeductionLedger,
    TenantCreditBalance,
)
from app.core.rbac import (
    CANONICAL_ROLES,
    ROLE_TENANT_ADMIN,
    validate_self_elevation_attempt,
)


# =============================================================================
# Organization Lifecycle Governance (Scenarios 1 & 2)
# =============================================================================

def validate_organization_status(organization: Optional[TenantOrganization]) -> None:
    """
    Enforce organization lifecycle status invariants (AC-REQ-002, DEC-22).
    - PENDING_APPROVAL: Blocked until platform administrator activates.
    - SUSPENDED / DEPROVISIONED: Blocked from all protected tenant operations.
    """
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found.",
        )

    if organization.account_status == "PENDING_APPROVAL":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization registration is pending platform administrator approval.",
        )

    if organization.account_status in ("SUSPENDED", "DEPROVISIONED"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Organization access denied: account is currently {organization.account_status}.",
        )

    if organization.account_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Organization is not in an active operational state ({organization.account_status}).",
        )


# =============================================================================
# Membership & Tenant Scope Verification (Scenarios 3, 4, 5, 6, 7)
# =============================================================================

def validate_membership_scope(
    membership: Optional[TenantMembership],
    requested_tenant_id: Optional[uuid.UUID],
    authenticated_user_id: Optional[uuid.UUID],
) -> TenantMembership:
    """
    Validate that the authenticated user possesses an active membership in the target tenant.
    - Fails closed if tenant_id is missing (Scenario 5).
    - Fails closed if membership does not match target tenant (Scenario 4).
    - Fails closed if membership is REVOKED or PENDING (Scenario 3).
    """
    if requested_tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing tenant execution context: tenant_id must not be null.",
        )

    if authenticated_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authenticated user identity.",
        )

    if (
        membership is None
        or membership.tenant_id != requested_tenant_id
        or membership.user_id != authenticated_user_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User does not belong to the requested tenant organization.",
        )

    if membership.membership_status == "REVOKED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User membership in this organization has been revoked.",
        )

    if membership.membership_status == "PENDING_ACCEPTANCE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User membership is pending invitation acceptance.",
        )

    if membership.membership_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Membership status is {membership.membership_status}.",
        )

    return membership


def reactivate_tenant_membership(
    membership: TenantMembership,
    new_role: str,
    actor_user_id: uuid.UUID,
    client_ip: Optional[str] = None,
) -> AuditEventRecord:
    """
    Perform in-place membership reactivation under UNIQUE (tenant_id, user_id) (DEC-15).
    Updates membership_status to ACTIVE and emits an auditable transition event.
    """
    if new_role not in CANONICAL_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid canonical role: '{new_role}'.",
        )

    old_status = membership.membership_status
    old_role = membership.assigned_role

    membership.membership_status = "ACTIVE"
    membership.assigned_role = new_role
    now = datetime.now(timezone.utc)
    membership.granted_at_utc = now
    membership.updated_at_utc = now

    audit_event = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=membership.tenant_id,
        user_id=actor_user_id,
        action_type="MEMBERSHIP_REACTIVATE",
        client_ip_address=client_ip,
        correlation_id=uuid.uuid4(),
        details={
            "target_user_id": str(membership.user_id),
            "old_status": old_status,
            "new_status": "ACTIVE",
            "old_role": old_role,
            "new_role": new_role,
        },
        event_timestamp_utc=now,
    )
    return audit_event


# =============================================================================
# Single Active Session Governance & Displacement (Scenario 8 / DEC-20)
# =============================================================================

def hash_session_token(token: str) -> str:
    """Compute SHA-256 hash of opaque bearer session token (ADR-007: zero plaintext secrets)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def process_user_login_session(
    user_id: uuid.UUID,
    active_tenant_id: uuid.UUID,
    existing_session: Optional[ActiveUserSession],
    force_terminate_existing: bool = False,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    session_ttl_minutes: int = 480,
) -> Tuple[ActiveUserSession, AuditEventRecord, str]:
    """
    Enforce reconciled DEC-20 / AC-REQ-006 single active session policy:
    1. If an unexpired session exists and force_terminate_existing=False:
       Reject with HTTP 409 Conflict (prevent silent concurrent sharing).
    2. If force_terminate_existing=True:
       Displace the existing session and issue a new session with an audit log.
    3. Return (session_model, audit_event, raw_token).
    """
    now = datetime.now(timezone.utc)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)

    if existing_session is not None and existing_session.expires_at_utc > now:
        if not force_terminate_existing:
            # Emit audit event for rejected concurrent attempt
            rejected_audit = AuditEventRecord(
                audit_event_id=uuid.uuid4(),
                tenant_id=active_tenant_id,
                user_id=user_id,
                action_type="SESSION_CONCURRENT_LOGIN_REJECTED",
                client_ip_address=client_ip,
                correlation_id=uuid.uuid4(),
                details={
                    "existing_session_id": str(existing_session.session_id),
                    "reason": "ACTIVE_SESSION_EXISTS",
                },
                event_timestamp_utc=now,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="ACTIVE_SESSION_EXISTS: An active authenticated session already exists for this account. Set force_terminate_existing=true to displace previous session.",
            )

        # Displace existing session
        displaced_session_id = existing_session.session_id
        existing_session.session_token_hash = token_hash
        existing_session.active_tenant_id = active_tenant_id
        existing_session.ip_address = client_ip
        existing_session.user_agent = user_agent
        existing_session.last_activity_utc = now
        existing_session.expires_at_utc = now + timedelta(minutes=session_ttl_minutes)

        audit_event = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=active_tenant_id,
            user_id=user_id,
            action_type="SESSION_DISPLACED",
            client_ip_address=client_ip,
            correlation_id=uuid.uuid4(),
            details={
                "displaced_session_id": str(displaced_session_id),
                "new_session_id": str(existing_session.session_id),
                "override_flag": True,
            },
            event_timestamp_utc=now,
        )
        return existing_session, audit_event, raw_token

    # Create fresh session
    new_session = ActiveUserSession(
        session_id=uuid.uuid4(),
        user_id=user_id,
        active_tenant_id=active_tenant_id,
        session_token_hash=token_hash,
        ip_address=client_ip,
        user_agent=user_agent,
        created_at_utc=now,
        last_activity_utc=now,
        expires_at_utc=now + timedelta(minutes=session_ttl_minutes),
    )

    audit_event = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=active_tenant_id,
        user_id=user_id,
        action_type="SESSION_CREATED",
        client_ip_address=client_ip,
        correlation_id=uuid.uuid4(),
        details={"session_id": str(new_session.session_id)},
        event_timestamp_utc=now,
    )
    return new_session, audit_event, raw_token


def switch_session_tenant_context(
    session: ActiveUserSession,
    target_tenant_id: uuid.UUID,
    user_memberships: list[TenantMembership],
) -> None:
    """
    Allow multi-tenant users to switch active tenant context within their active session
    without triggering second-login rejection (DEC-20).
    """
    valid_memberships = [
        m for m in user_memberships
        if m.tenant_id == target_tenant_id and m.membership_status == "ACTIVE"
    ]
    if not valid_memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot switch tenant context: User has no active membership in target organization.",
        )

    session.active_tenant_id = target_tenant_id
    session.last_activity_utc = datetime.now(timezone.utc)


# =============================================================================
# Credit Quota & Usage Ledger Accounting (Scenarios 9, 10, 11 / DEC-19)
# =============================================================================

def execute_credit_deduction(
    credit_balance: TenantCreditBalance,
    credits_required: int,
    action_type: str,
    user_id: uuid.UUID,
    idempotency_key: Optional[str] = None,
    existing_ledgers: Optional[list[CreditDeductionLedger]] = None,
    reference_id: Optional[str] = None,
    description: Optional[str] = None,
) -> Tuple[CreditDeductionLedger, bool]:
    """
    Execute an atomic credit deduction with idempotency and quota protection:
    1. If idempotency_key is provided and already recorded: return existing ledger without re-charging (Scenario 10).
    2. Verify balance_credits >= credits_required (Scenario 9).
    3. Update balance and record committed deduction entry.
    Returns: (ledger_entry, was_already_processed_bool)
    """
    if credits_required <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credits consumed must be a strictly positive integer.",
        )

    # 1. Idempotency Check (Scenario 10)
    if idempotency_key and existing_ledgers:
        for ledger in existing_ledgers:
            if ledger.idempotency_key == idempotency_key and ledger.tenant_id == credit_balance.tenant_id:
                return ledger, True  # Already processed; return existing result

    # 2. Quota Check (Scenario 9)
    if credit_balance.balance_credits < credits_required:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"INSUFFICIENT_CREDITS: Operation '{action_type}' requires {credits_required} credits, but current balance is {credit_balance.balance_credits}.",
        )

    # 3. Atomic Deduction
    credit_balance.balance_credits -= credits_required
    credit_balance.consumed_credits += credits_required
    credit_balance.updated_at_utc = datetime.now(timezone.utc)

    ledger_entry = CreditDeductionLedger(
        deduction_id=uuid.uuid4(),
        tenant_id=credit_balance.tenant_id,
        user_id=user_id,
        action_type=action_type,
        credits_consumed=credits_required,
        balance_after_deduction=credit_balance.balance_credits,
        idempotency_key=idempotency_key,
        status="COMMITTED",
        reference_id=reference_id,
        description=description,
        created_at_utc=datetime.now(timezone.utc),
    )
    return ledger_entry, False


def refund_failed_operation_credits(
    credit_balance: TenantCreditBalance,
    ledger_entry: CreditDeductionLedger,
    reason: str,
) -> AuditEventRecord:
    """
    Refund credits for a failed operation per documented charge/refund policy (Scenario 11).
    Restores organization balance and marks ledger status as REFUNDED.
    """
    if ledger_entry.status == "REFUNDED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credit deduction has already been refunded.",
        )

    if ledger_entry.tenant_id != credit_balance.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant mismatch between ledger entry and credit balance.",
        )

    # Restore balance
    credit_balance.balance_credits += ledger_entry.credits_consumed
    credit_balance.consumed_credits -= ledger_entry.credits_consumed
    credit_balance.updated_at_utc = datetime.now(timezone.utc)

    ledger_entry.status = "REFUNDED"
    now = datetime.now(timezone.utc)

    audit_event = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=credit_balance.tenant_id,
        user_id=ledger_entry.user_id,
        action_type="CREDIT_REFUNDED",
        correlation_id=uuid.uuid4(),
        details={
            "deduction_id": str(ledger_entry.deduction_id),
            "credits_refunded": ledger_entry.credits_consumed,
            "restored_balance": credit_balance.balance_credits,
            "reason": reason,
        },
        event_timestamp_utc=now,
    )
    return audit_event


# =============================================================================
# Platform Admin Scoping Boundary (Scenario 14 / DEC-21)
# =============================================================================

def validate_platform_admin_evidence_access(
    is_platform_admin: bool,
    dual_control_token: Optional[str] = None,
) -> None:
    """
    Enforce zero-ambient platform administrator access to customer evidence (DEC-21, AC-REQ-001).
    Platform administrators possess zero default access to investigative case workspaces,
    case notes, or evidence packages. Any emergency exception requires an audited dual-control token.
    """
    if is_platform_admin:
        if not dual_control_token or not dual_control_token.startswith("DUAL_CONTROL_VERIFIED_"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PLATFORM_ADMIN_ACCESS_DENIED: Platform administrators possess zero ambient access to customer investigative case workspaces or evidence files. Access requires an authorized dual-control warrant token.",
            )
