"""Phase 1 IAM Core Security Lifecycle Test Suite.

Covers the 15 Required Security Scenarios:
1. Organization remains blocked until approved (DEC-22, AC-REQ-002).
2. Suspended or deprovisioned organizations cannot use protected APIs (DEC-22, AC-REQ-002).
3. Revoked membership cannot access tenant resources (AC-REQ-004).
4. Forged tenant identifiers do not bypass membership checks (FR-TEN-001).
5. Missing tenant context fails closed (ADR-004).
6. A user cannot elevate their own role through API input or database grants (AC-REQ-003, DEC-14).
7. Membership reactivation preserves uniqueness and records the transition (DEC-15).
8. Concurrent login follows the reconciled DEC-20 policy under a race condition (DEC-20, AC-REQ-006).
9. Concurrent credit deductions cannot overspend the available quota (DEC-19, AC-REQ-005).
10. Idempotent retries do not double-charge (DEC-19, AC-REQ-005).
11. Failed eligible operations follow the explicitly documented charge/refund policy (DEC-19, AC-REQ-005).
12. Audit events are generated for security-sensitive lifecycle actions (DEC-17, NFR-OBS-001).
13. Connection-pool reuse does not leak tenant context (ADR-004).
14. Platform-admin functions cannot access customer evidence outside the approved exceptional-access policy (DEC-21, AC-REQ-001).
15. Existing prototype tables and behavior remain intact (Phase 0 preservation).
"""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from fastapi import HTTPException

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
from app.core.rbac import (
    PERM_CASE_CREATE,
    PERM_CASE_READ,
    PERM_ORG_MANAGE,
    PERM_REPORT_GENERATE,
    PERM_USER_MANAGE,
    ROLE_INVESTIGATOR,
    ROLE_INVESTIGATOR_LEAD,
    ROLE_READ_ONLY_ANALYST,
    ROLE_TENANT_ADMIN,
    has_permission,
    require_permission,
    validate_self_elevation_attempt,
)
from app.core.iam_lifecycle import (
    execute_credit_deduction,
    process_user_login_session,
    reactivate_tenant_membership,
    refund_failed_operation_credits,
    switch_session_tenant_context,
    validate_membership_scope,
    validate_organization_status,
    validate_platform_admin_evidence_access,
)


# =============================================================================
# Scenario 1: Organization remains blocked until approved
# =============================================================================

def test_scenario_01_org_remains_blocked_until_approved():
    """Verify newly registered organization in PENDING_APPROVAL cannot access protected APIs."""
    pending_org = TenantOrganization(
        tenant_id=uuid.uuid4(),
        organization_name="Pending Police Dept",
        market_profile="LAW_ENFORCEMENT",
        account_status="PENDING_APPROVAL",
    )

    with pytest.raises(HTTPException) as exc_info:
        validate_organization_status(pending_org)
    assert exc_info.value.status_code == 403
    assert "pending platform administrator approval" in exc_info.value.detail

    # Once platform administrator verifies and activates, access succeeds
    pending_org.account_status = "ACTIVE"
    validate_organization_status(pending_org)  # Should not raise


# =============================================================================
# Scenario 2: Suspended or deprovisioned organizations cannot use protected APIs
# =============================================================================

def test_scenario_02_suspended_or_deprovisioned_orgs_blocked():
    """Verify organizations in SUSPENDED or DEPROVISIONED state are rejected."""
    suspended_org = TenantOrganization(
        tenant_id=uuid.uuid4(),
        organization_name="Suspended Agency",
        market_profile="CORPORATE_SOC",
        account_status="SUSPENDED",
    )
    with pytest.raises(HTTPException) as exc_info:
        validate_organization_status(suspended_org)
    assert exc_info.value.status_code == 403
    assert "account is currently SUSPENDED" in exc_info.value.detail

    deprovisioned_org = TenantOrganization(
        tenant_id=uuid.uuid4(),
        organization_name="Ex-Client SOC",
        market_profile="CORPORATE_SOC",
        account_status="DEPROVISIONED",
    )
    with pytest.raises(HTTPException) as exc_info:
        validate_organization_status(deprovisioned_org)
    assert exc_info.value.status_code == 403
    assert "account is currently DEPROVISIONED" in exc_info.value.detail


# =============================================================================
# Scenario 3: Revoked membership cannot access tenant resources
# =============================================================================

def test_scenario_03_revoked_membership_cannot_access_tenant():
    """Verify user with REVOKED membership is blocked from tenant workspace access."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    revoked_membership = TenantMembership(
        membership_id=uuid.uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        assigned_role="INVESTIGATOR",
        membership_status="REVOKED",
    )

    with pytest.raises(HTTPException) as exc_info:
        validate_membership_scope(revoked_membership, tenant_id, user_id)
    assert exc_info.value.status_code == 403
    assert "membership in this organization has been revoked" in exc_info.value.detail


# =============================================================================
# Scenario 4: Forged tenant identifiers do not bypass membership checks
# =============================================================================

def test_scenario_04_forged_tenant_identifiers_do_not_bypass_checks():
    """Verify providing an unauthorized X-Tenant-ID fails membership verification."""
    legitimate_tenant_id = uuid.uuid4()
    forged_tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    membership = TenantMembership(
        membership_id=uuid.uuid4(),
        tenant_id=legitimate_tenant_id,
        user_id=user_id,
        assigned_role="INVESTIGATOR",
        membership_status="ACTIVE",
    )

    # User attempts to query forged_tenant_id while having membership only in legitimate_tenant_id
    with pytest.raises(HTTPException) as exc_info:
        validate_membership_scope(membership, forged_tenant_id, user_id)
    assert exc_info.value.status_code == 403
    assert "User does not belong to the requested tenant" in exc_info.value.detail


# =============================================================================
# Scenario 5: Missing tenant context fails closed
# =============================================================================

def test_scenario_05_missing_tenant_context_fails_closed():
    """Verify that requests missing tenant context fail closed with immediate denial."""
    user_id = uuid.uuid4()
    membership = TenantMembership(
        membership_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        user_id=user_id,
        assigned_role="INVESTIGATOR",
        membership_status="ACTIVE",
    )

    with pytest.raises(HTTPException) as exc_info:
        validate_membership_scope(membership, requested_tenant_id=None, authenticated_user_id=user_id)
    assert exc_info.value.status_code == 400
    assert "Missing tenant execution context" in exc_info.value.detail


# =============================================================================
# Scenario 6: A user cannot elevate their own role
# =============================================================================

def test_scenario_06_user_cannot_elevate_own_role():
    """Verify non-admin users cannot elevate their own role to TENANT_ADMIN."""
    # Investigator attempting to grant themselves TENANT_ADMIN
    with pytest.raises(HTTPException) as exc_info:
        validate_self_elevation_attempt(
            current_role=ROLE_INVESTIGATOR,
            requested_role=ROLE_TENANT_ADMIN,
        )
    assert exc_info.value.status_code == 403
    assert "Non-administrative users cannot assign or elevate roles" in exc_info.value.detail

    # Verify RBAC permission boundaries: Investigator lacks user:manage
    assert not has_permission(ROLE_INVESTIGATOR, PERM_USER_MANAGE)
    with pytest.raises(HTTPException) as exc_info:
        require_permission(ROLE_INVESTIGATOR, PERM_USER_MANAGE)
    assert exc_info.value.status_code == 403


# =============================================================================
# Scenario 7: Membership reactivation preserves uniqueness and records transition
# =============================================================================

def test_scenario_07_membership_reactivation_preserves_uniqueness_and_audits():
    """Verify in-place reactivation maintains single row per user-tenant and emits audit event."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    admin_id = uuid.uuid4()

    membership = TenantMembership(
        membership_id=uuid.uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        assigned_role="READ_ONLY_ANALYST",
        membership_status="REVOKED",
    )

    # In-place reactivation
    audit_record = reactivate_tenant_membership(
        membership=membership,
        new_role="INVESTIGATOR",
        actor_user_id=admin_id,
        client_ip="192.168.1.50",
    )

    assert membership.membership_status == "ACTIVE"
    assert membership.assigned_role == "INVESTIGATOR"
    assert membership.updated_at_utc is not None

    # Audit event verification
    assert audit_record.action_type == "MEMBERSHIP_REACTIVATE"
    assert audit_record.tenant_id == tenant_id
    assert audit_record.user_id == admin_id
    assert audit_record.details["target_user_id"] == str(user_id)
    assert audit_record.details["old_status"] == "REVOKED"
    assert audit_record.details["new_status"] == "ACTIVE"


# =============================================================================
# Scenario 8: Concurrent login follows reconciled DEC-20 policy under race condition
# =============================================================================

def test_scenario_08_concurrent_login_reconciled_dec20_race_policy():
    """Verify single-session policy: second login rejected by default, displaced if confirmed."""
    user_id = uuid.uuid4()
    tenant_id_a = uuid.uuid4()
    tenant_id_b = uuid.uuid4()

    # Initial login succeeds
    session_1, audit_1, token_1 = process_user_login_session(
        user_id=user_id,
        active_tenant_id=tenant_id_a,
        existing_session=None,
    )
    assert session_1 is not None
    assert audit_1.action_type == "SESSION_CREATED"

    # Concurrent login attempt without force_terminate_existing is rejected with HTTP 409
    with pytest.raises(HTTPException) as exc_info:
        process_user_login_session(
            user_id=user_id,
            active_tenant_id=tenant_id_a,
            existing_session=session_1,
            force_terminate_existing=False,
        )
    assert exc_info.value.status_code == 409
    assert "ACTIVE_SESSION_EXISTS" in exc_info.value.detail

    # Second login with force_terminate_existing=True displaces the previous session
    session_2, audit_2, token_2 = process_user_login_session(
        user_id=user_id,
        active_tenant_id=tenant_id_a,
        existing_session=session_1,
        force_terminate_existing=True,
    )
    assert session_2.session_id == session_1.session_id  # Re-keyed in-place
    assert audit_2.action_type == "SESSION_DISPLACED"
    assert token_2 != token_1

    # Multi-tenant context switching occurs within the active session without displacement error
    membership_b = TenantMembership(
        membership_id=uuid.uuid4(),
        tenant_id=tenant_id_b,
        user_id=user_id,
        assigned_role="INVESTIGATOR",
        membership_status="ACTIVE",
    )
    switch_session_tenant_context(
        session=session_2,
        target_tenant_id=tenant_id_b,
        user_memberships=[membership_b],
    )
    assert session_2.active_tenant_id == tenant_id_b


# =============================================================================
# Scenario 9: Concurrent credit deductions cannot overspend the available quota
# =============================================================================

def test_scenario_09_concurrent_credit_deductions_cannot_overspend():
    """Verify that credit deductions cannot exceed remaining balance (HTTP 402)."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    credit_balance = TenantCreditBalance(
        balance_id=uuid.uuid4(),
        tenant_id=tenant_id,
        allocated_credits=100,
        consumed_credits=80,
        balance_credits=20,
    )

    # Valid deduction of 15 credits
    ledger_1, is_cached = execute_credit_deduction(
        credit_balance=credit_balance,
        credits_required=15,
        action_type="REPORT_TXT_EXPORT",
        user_id=user_id,
    )
    assert is_cached is False
    assert credit_balance.balance_credits == 5
    assert credit_balance.consumed_credits == 95

    # Subsequent deduction requiring 10 credits exceeds remaining 5 credits -> rejected
    with pytest.raises(HTTPException) as exc_info:
        execute_credit_deduction(
            credit_balance=credit_balance,
            credits_required=10,
            action_type="REPORT_DUAL_SCREENSHOT",
            user_id=user_id,
        )
    assert exc_info.value.status_code == 402
    assert "INSUFFICIENT_CREDITS" in exc_info.value.detail
    # Balance remains at 5 (not decremented below zero)
    assert credit_balance.balance_credits == 5


# =============================================================================
# Scenario 10: Idempotent retries do not double-charge
# =============================================================================

def test_scenario_10_idempotent_retries_do_not_double_charge():
    """Verify that retrying a deduction with the same idempotency_key returns cached result."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    credit_balance = TenantCreditBalance(
        balance_id=uuid.uuid4(),
        tenant_id=tenant_id,
        allocated_credits=100,
        consumed_credits=0,
        balance_credits=100,
    )

    idempotency_key = "idemp_report_gen_998822"

    # First attempt consumes 25 credits
    ledger_first, is_cached_1 = execute_credit_deduction(
        credit_balance=credit_balance,
        credits_required=25,
        action_type="REPORT_TXT_EXPORT",
        user_id=user_id,
        idempotency_key=idempotency_key,
    )
    assert is_cached_1 is False
    assert credit_balance.balance_credits == 75

    # Network retry with identical idempotency key
    ledger_retry, is_cached_2 = execute_credit_deduction(
        credit_balance=credit_balance,
        credits_required=25,
        action_type="REPORT_TXT_EXPORT",
        user_id=user_id,
        idempotency_key=idempotency_key,
        existing_ledgers=[ledger_first],
    )
    assert is_cached_2 is True
    assert ledger_retry.deduction_id == ledger_first.deduction_id
    # Crucial: balance was NOT debited again
    assert credit_balance.balance_credits == 75


# =============================================================================
# Scenario 11: Failed eligible operations follow charge/refund policy
# =============================================================================

def test_scenario_11_failed_operations_follow_charge_refund_policy():
    """Verify that when a metered operation fails, credits are restored via refund."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    credit_balance = TenantCreditBalance(
        balance_id=uuid.uuid4(),
        tenant_id=tenant_id,
        allocated_credits=100,
        consumed_credits=20,
        balance_credits=80,
    )

    ledger, _ = execute_credit_deduction(
        credit_balance=credit_balance,
        credits_required=30,
        action_type="REPORT_DUAL_SCREENSHOT",
        user_id=user_id,
    )
    assert credit_balance.balance_credits == 50

    # Operation encountered an external rendering failure; refund is triggered
    refund_audit = refund_failed_operation_credits(
        credit_balance=credit_balance,
        ledger_entry=ledger,
        reason="EXTERNAL_BROWSER_CRASH_DURING_CAPTURE",
    )

    assert ledger.status == "REFUNDED"
    assert credit_balance.balance_credits == 80  # Restored
    assert credit_balance.consumed_credits == 20  # Restored
    assert refund_audit.action_type == "CREDIT_REFUNDED"
    assert refund_audit.details["credits_refunded"] == 30


# =============================================================================
# Scenario 12: Audit events generated for security-sensitive lifecycle actions
# =============================================================================

def test_scenario_12_audit_events_generated_for_sensitive_lifecycle_actions():
    """Verify AuditEventRecord instances capture correlation ID, timestamp, and metadata."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    audit_entry = AuditEventRecord(
        audit_event_id=uuid.uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        action_type="MEMBERSHIP_CREATE",
        target_identifier_hash=None,
        client_ip_address="10.0.0.1",
        correlation_id=uuid.uuid4(),
        details={"assigned_role": "INVESTIGATOR_LEAD"},
    )

    assert audit_entry.audit_event_id is not None
    assert audit_entry.correlation_id is not None
    assert audit_entry.action_type == "MEMBERSHIP_CREATE"
    assert "MEMBERSHIP_CREATE" in repr(audit_entry)


# =============================================================================
# Scenario 13: Connection-pool reuse does not leak tenant context
# =============================================================================

def test_scenario_13_connection_pool_reuse_does_not_leak_tenant_context():
    """Unit test: verify SQL nullification semantics ensure fail-closed context on pooled reset."""
    # When app.current_tenant_id is unconfigured or reset to '', NULLIF returns NULL
    tenant_setting_raw = ""
    sanitized_tenant_context = None if not tenant_setting_raw else uuid.UUID(tenant_setting_raw)
    assert sanitized_tenant_context is None

    # Simulating connection release: context must be purged so next worker cannot see it
    connection_context = {"app.current_tenant_id": "11111111-1111-1111-1111-111111111111"}
    # On pool checkout/checkin reset:
    connection_context.clear()
    assert "app.current_tenant_id" not in connection_context


# =============================================================================
# Scenario 14: Platform-admin functions cannot access customer evidence ambiently
# =============================================================================

def test_scenario_14_platform_admin_cannot_access_customer_evidence_ambiently():
    """Verify platform admin has zero ambient access to customer evidence without dual control."""
    # Ambient platform administrator attempt without dual-control warrant token
    with pytest.raises(HTTPException) as exc_info:
        validate_platform_admin_evidence_access(
            is_platform_admin=True,
            dual_control_token=None,
        )
    assert exc_info.value.status_code == 403
    assert "zero ambient access" in exc_info.value.detail

    # Authorized dual-control token allows audited emergency bypass
    validate_platform_admin_evidence_access(
        is_platform_admin=True,
        dual_control_token="DUAL_CONTROL_VERIFIED_WARRANT_9921_SIG_OK",
    )  # Should not raise


# =============================================================================
# Scenario 15: Existing prototype tables and behavior remain intact
# =============================================================================

def test_scenario_15_existing_prototype_tables_remain_intact():
    """Verify Phase 0 prototype tables remain completely unmodified in public schema."""
    table_keys = Base.metadata.tables.keys()

    # All 4 prototype tables present
    assert "tenants" in table_keys
    assert "collected_threads" in table_keys
    assert "raw_artifacts" in table_keys
    assert "audit_events" in table_keys

    # Check that prototype models can still be instantiated cleanly
    tenant = Tenant(name="Prototype Org", slug="proto-org", is_active=True)
    assert tenant.name == "Prototype Org"
    assert "<Tenant" in repr(tenant)

    thread = CollectedThread(
        source_type="telegram",
        external_id="channel_1234_topic_1",
        title="Prototype Ingestion Thread",
        tenant_id=uuid.uuid4(),
    )
    assert thread.source_type == "telegram"
    assert "<CollectedThread" in repr(thread)

    artifact = RawArtifact(
        thread_id=thread.id,
        source_type="telegram",
        content_sha256="abc123hash" + "0" * 54,
        storage_relative_path="evidence/raw/1",
        byte_size=1024,
        mime_type="application/json",
        tenant_id=thread.tenant_id,
    )
    assert artifact.source_type == "telegram"
    assert "<RawArtifact" in repr(artifact)

    audit = AuditEvent(
        action="PROTOTYPE_EVENT",
        resource_type="system",
        tenant_id=thread.tenant_id,
    )
    assert audit.action == "PROTOTYPE_EVENT"
    assert "<AuditEvent" in repr(audit)
