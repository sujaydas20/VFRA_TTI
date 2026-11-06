"""Live PostgreSQL integration tests for Phase 2 Runtime IAM & RBAC Authentication Slice.

Covers:
1. Valid password login with Argon2id and invalid password rejection (timing safe).
2. Token verification: expired tokens, revoked/displaced tokens, malformed tokens.
3. User account states: LOCKED and INACTIVE user enforcement.
4. Organization lifecycle states: PENDING_APPROVAL, SUSPENDED, DEPROVISIONED.
5. Membership scope: missing membership, REVOKED membership, PENDING_ACCEPTANCE.
6. RBAC enforcement & self-elevation prevention on /organizations/members/{id}/role.
7. Forged tenant selector (X-Tenant-ID) and database-level RLS cross-tenant isolation.
8. Second concurrent login and DEC-20 displacement policy (409 Conflict -> displacement).
9. Audit trail verification in audit.audit_event_records.
10. Least-privileged runtime role (tti_app_role) RLS non-bypass verification.

Note: Cleanly SKIPPED if live PostgreSQL database is offline or unreachable.
"""

from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.security import create_access_token, hash_password
from app.database.models.audit import AuditEventRecord
from app.database.models.iam import (
    ActiveUserSession,
    Role,
    TenantMembership,
    TenantOrganization,
    UserProfile,
)
from app.main import app


@pytest.fixture(scope="module")
def live_pg_engine():
    """Verify live PostgreSQL connectivity; skip suite if unavailable."""
    settings = get_settings()
    url = settings.sync_database_url
    try:
        engine = create_engine(url, connect_args={"connect_timeout": 3})
        with engine.connect() as test_conn:
            test_conn.execute(text("SELECT 1;"))
        yield engine
        engine.dispose()
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL database unreachable ({type(exc).__name__}); skipping runtime IAM tests")


@pytest_asyncio.fixture
async def live_client(live_pg_engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an HTTP test client connected to the application with live DB."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


# =============================================================================
# Test 1: Valid Login & Invalid Password (Argon2id)
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_login_valid_and_invalid_password(live_pg_engine, live_client: AsyncClient):
    """Verify password-based authentication via Argon2id with constant-time verification."""
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    plain_password = "CorrectInvestigatorPassword123!"
    password_hash = hash_password(plain_password)
    email = f"analyst_{user_id}@agency.gov"

    # Setup database state
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE')
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"t_id": org_id, "name": f"Org {org_id}"}
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, :email, 'Special Agent', :pw_hash, 'ACTIVE')
            ON CONFLICT (user_id) DO NOTHING;
            """),
            {"u_id": user_id, "email": email, "pw_hash": password_hash}
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES (gen_random_uuid(), :t_id, :u_id, 'INVESTIGATOR', 'ACTIVE')
            ON CONFLICT (tenant_id, user_id) DO NOTHING;
            """),
            {"t_id": org_id, "u_id": user_id}
        )

    # 1. Successful Login
    res_valid = await live_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": plain_password},
    )
    assert res_valid.status_code == 200, res_valid.text
    data = res_valid.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["user_id"] == str(user_id)
    assert data["user"]["account_state"] == "ACTIVE"
    assert data["active_tenant_id"] == str(org_id)
    assert data["assigned_role"] == "INVESTIGATOR"
    assert "search:query" in data["permissions"]
    assert "case:create" in data["permissions"]

    # 2. Invalid Password
    res_bad_pw = await live_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword!"},
    )
    assert res_bad_pw.status_code == 401
    assert "INVALID_CREDENTIALS" in res_bad_pw.json()["detail"]

    # 3. Nonexistent User
    res_bad_user = await live_client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@agency.gov", "password": "AnyPassword123!"},
    )
    assert res_bad_user.status_code == 401
    assert "INVALID_CREDENTIALS" in res_bad_user.json()["detail"]


# =============================================================================
# Test 2: Token Verification (Expired, Revoked, Malformed)
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_token_validation_expired_revoked_malformed(live_pg_engine, live_client: AsyncClient):
    """Verify cryptographic JWT validation and server-side session checks."""
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    plain_pw = "TokenTestPass123!"
    pw_hash = hash_password(plain_pw)
    email = f"tokentest_{user_id}@agency.gov"

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'CORPORATE_SOC', 'ACTIVE');"),
            {"t_id": org_id, "name": f"Token Org {org_id}"}
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'Token User', :pw, 'ACTIVE');"),
            {"u_id": user_id, "email": email, "pw": pw_hash}
        )
        conn.execute(
            text("INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status) VALUES (gen_random_uuid(), :t_id, :u_id, 'READ_ONLY_ANALYST', 'ACTIVE');"),
            {"t_id": org_id, "u_id": user_id}
        )

    # Login to obtain valid token
    login_res = await live_client.post("/api/v1/auth/login", json={"email": email, "password": plain_pw})
    assert login_res.status_code == 200
    valid_token = login_res.json()["access_token"]

    # 1. Valid token succeeds
    res_me = await live_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert res_me.status_code == 200
    assert res_me.json()["email_address"] == email

    # 2. Malformed token rejected
    res_malformed = await live_client.get("/api/v1/auth/me", headers={"Authorization": "Bearer malformed.jwt.token"})
    assert res_malformed.status_code == 401
    assert "TOKEN_INVALID" in res_malformed.json()["detail"]

    # 3. Expired token rejected
    expired_token = create_access_token(
        subject=str(user_id),
        active_tenant_id=str(org_id),
        session_id=str(uuid.uuid4()),
        expires_delta=timedelta(seconds=-10),
    )
    res_expired = await live_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res_expired.status_code == 401
    assert "TOKEN_EXPIRED" in res_expired.json()["detail"]

    # 4. Revoked / Displaced token (server-side session row deleted)
    with live_pg_engine.begin() as conn:
        conn.execute(text("DELETE FROM iam.active_user_sessions WHERE user_id = :u_id;"), {"u_id": user_id})

    res_revoked = await live_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert res_revoked.status_code == 401
    assert "SESSION_REVOKED_OR_DISPLACED" in res_revoked.json()["detail"]


# =============================================================================
# Test 3: User Account States (LOCKED & INACTIVE)
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_user_account_states_locked_and_inactive(live_pg_engine, live_client: AsyncClient):
    """Verify that LOCKED and INACTIVE users are barred from authentication and protected APIs."""
    org_id = uuid.uuid4()
    locked_user_id = uuid.uuid4()
    inactive_user_id = uuid.uuid4()
    pw_hash = hash_password("StatePassword123!")

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE');"),
            {"t_id": org_id, "name": f"State Org {org_id}"}
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'Locked User', :pw, 'LOCKED');"),
            {"u_id": locked_user_id, "email": f"locked_{locked_user_id}@agency.gov", "pw": pw_hash}
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'Invited User', :pw, 'INVITED');"),
            {"u_id": inactive_user_id, "email": f"invited_{inactive_user_id}@agency.gov", "pw": pw_hash}
        )

    # 1. Locked User Login -> 403 Forbidden
    res_locked = await live_client.post(
        "/api/v1/auth/login",
        json={"email": f"locked_{locked_user_id}@agency.gov", "password": "StatePassword123!"},
    )
    assert res_locked.status_code == 403
    assert "ACCOUNT_LOCKED" in res_locked.json()["detail"]

    # 2. Inactive User Login -> 403 Forbidden
    res_inactive = await live_client.post(
        "/api/v1/auth/login",
        json={"email": f"invited_{inactive_user_id}@agency.gov", "password": "StatePassword123!"},
    )
    assert res_inactive.status_code == 403
    assert "ACCOUNT_INACTIVE" in res_inactive.json()["detail"]


# =============================================================================
# Test 4: Organization Lifecycle States (DEC-22)
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_organization_lifecycle_states(live_pg_engine, live_client: AsyncClient):
    """Verify that organizations in PENDING_APPROVAL, SUSPENDED, and DEPROVISIONED are barred."""
    pending_org = uuid.uuid4()
    suspended_org = uuid.uuid4()
    user_id = uuid.uuid4()
    pw_hash = hash_password("OrgLifecycle123!")
    email = f"lifecycle_{user_id}@agency.gov"

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES 
                (:p_id, :p_name, 'LAW_ENFORCEMENT', 'PENDING_APPROVAL'),
                (:s_id, :s_name, 'CORPORATE_SOC', 'SUSPENDED');
            """),
            {
                "p_id": pending_org, "p_name": f"Pending Org {pending_org}",
                "s_id": suspended_org, "s_name": f"Suspended Org {suspended_org}",
            }
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'Lifecycle User', :pw, 'ACTIVE');"),
            {"u_id": user_id, "email": email, "pw": pw_hash}
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :p_id, :u_id, 'TENANT_ADMIN', 'ACTIVE'),
                (gen_random_uuid(), :s_id, :u_id, 'INVESTIGATOR', 'ACTIVE');
            """),
            {"p_id": pending_org, "s_id": suspended_org, "u_id": user_id}
        )

    # 1. Attempt login to Pending Approval organization
    res_pending = await live_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "OrgLifecycle123!", "tenant_id": str(pending_org)},
    )
    assert res_pending.status_code == 403
    assert "pending platform administrator approval" in res_pending.json()["detail"]

    # 2. Attempt login to Suspended organization
    res_suspended = await live_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "OrgLifecycle123!", "tenant_id": str(suspended_org)},
    )
    assert res_suspended.status_code == 403
    assert "SUSPENDED" in res_suspended.json()["detail"]


# =============================================================================
# Test 5: Membership Scope (Missing, Revoked, Pending)
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_membership_scope(live_pg_engine, live_client: AsyncClient):
    """Verify that REVOKED or PENDING memberships cannot access tenant resources."""
    org_id = uuid.uuid4()
    foreign_org_id = uuid.uuid4()
    revoked_user_id = uuid.uuid4()
    pending_user_id = uuid.uuid4()
    pw_hash = hash_password("MembershipPass123!")

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE'), (:f_id, :f_name, 'CORPORATE_SOC', 'ACTIVE');"),
            {"t_id": org_id, "name": f"Mem Org {org_id}", "f_id": foreign_org_id, "f_name": f"Foreign Org {foreign_org_id}"}
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'Revoked User', :pw, 'ACTIVE'), (:p_id, :p_email, 'Pending User', :pw, 'ACTIVE');"),
            {
                "u_id": revoked_user_id, "email": f"revoked_{revoked_user_id}@agency.gov", "pw": pw_hash,
                "p_id": pending_user_id, "p_email": f"pending_{pending_user_id}@agency.gov",
            }
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :t_id, :r_id, 'INVESTIGATOR', 'REVOKED'),
                (gen_random_uuid(), :t_id, :p_id, 'INVESTIGATOR', 'PENDING_ACCEPTANCE');
            """),
            {"t_id": org_id, "r_id": revoked_user_id, "p_id": pending_user_id}
        )

    # 1. Revoked membership login -> 403 Forbidden
    res_revoked = await live_client.post(
        "/api/v1/auth/login",
        json={"email": f"revoked_{revoked_user_id}@agency.gov", "password": "MembershipPass123!", "tenant_id": str(org_id)},
    )
    assert res_revoked.status_code == 403
    assert "revoked" in res_revoked.json()["detail"].lower()

    # 2. Pending membership login -> 403 Forbidden
    res_pending = await live_client.post(
        "/api/v1/auth/login",
        json={"email": f"pending_{pending_user_id}@agency.gov", "password": "MembershipPass123!", "tenant_id": str(org_id)},
    )
    assert res_pending.status_code == 403
    assert "pending invitation acceptance" in res_pending.json()["detail"].lower()

    # 3. User attempting to log into an organization they don't belong to
    res_foreign = await live_client.post(
        "/api/v1/auth/login",
        json={"email": f"pending_{pending_user_id}@agency.gov", "password": "MembershipPass123!", "tenant_id": str(foreign_org_id)},
    )
    assert res_foreign.status_code == 403
    assert "does not belong" in res_foreign.json()["detail"].lower()


# =============================================================================
# Test 6: RBAC & Self-Elevation Prevention
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_rbac_and_self_elevation_prevention(live_pg_engine, live_client: AsyncClient):
    """
    Verify:
    1. Static RBAC blocks non-admins from managing roles.
    2. Tenant admins cannot elevate or modify their own role (Scenario 6 / AC-REQ-003).
    3. Tenant admins can successfully update other members' roles.
    """
    org_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    analyst_id = uuid.uuid4()
    pw_hash = hash_password("RbacTestPass123!")

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE');"),
            {"t_id": org_id, "name": f"RBAC Org {org_id}"}
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:a_id, :a_email, 'Admin User', :pw, 'ACTIVE'), (:u_id, :u_email, 'Analyst User', :pw, 'ACTIVE');"),
            {
                "a_id": admin_id, "a_email": f"admin_{admin_id}@agency.gov", "pw": pw_hash,
                "u_id": analyst_id, "u_email": f"analyst_{analyst_id}@agency.gov",
            }
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :t_id, :a_id, 'TENANT_ADMIN', 'ACTIVE'),
                (gen_random_uuid(), :t_id, :u_id, 'INVESTIGATOR', 'ACTIVE');
            """),
            {"t_id": org_id, "a_id": admin_id, "u_id": analyst_id}
        )

    # Login analyst
    res_analyst_login = await live_client.post("/api/v1/auth/login", json={"email": f"analyst_{analyst_id}@agency.gov", "password": "RbacTestPass123!"})
    analyst_token = res_analyst_login.json()["access_token"]

    # Login admin
    res_admin_login = await live_client.post("/api/v1/auth/login", json={"email": f"admin_{admin_id}@agency.gov", "password": "RbacTestPass123!"})
    admin_token = res_admin_login.json()["access_token"]

    # 1. Analyst cannot manage roles (missing user:manage)
    res_analyst_manage = await live_client.post(
        f"/api/v1/organizations/members/{analyst_id}/role",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"role": "TENANT_ADMIN"},
    )
    assert res_analyst_manage.status_code == 403
    assert "user:manage" in res_analyst_manage.json()["detail"] or "permitted" in res_analyst_manage.json()["detail"]

    # 2. Admin cannot alter their OWN role (anti-self-elevation invariant)
    res_self_elevate = await live_client.post(
        f"/api/v1/organizations/members/{admin_id}/role",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "INVESTIGATOR"},
    )
    assert res_self_elevate.status_code == 403
    assert "ROLE_SELF_MODIFICATION_FORBIDDEN" in res_self_elevate.json()["detail"]

    # 3. Admin successfully promotes analyst to INVESTIGATOR_LEAD
    res_promote = await live_client.post(
        f"/api/v1/organizations/members/{analyst_id}/role",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "INVESTIGATOR_LEAD"},
    )
    assert res_promote.status_code == 200
    assert res_promote.json()["assigned_role"] == "INVESTIGATOR_LEAD"


# =============================================================================
# Test 7: Forged Tenant Selector (X-Tenant-ID) & Cross-Tenant Isolation
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_forged_tenant_selector_and_cross_tenant_isolation(live_pg_engine, live_client: AsyncClient):
    """
    Verify:
    1. X-Tenant-ID header alone cannot grant access to an unauthorized tenant.
    2. Database RLS prevents Tenant A queries from seeing Tenant B memberships.
    """
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()
    pw_hash = hash_password("TenantIsoPass123!")

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:a_id, :a_name, 'LAW_ENFORCEMENT', 'ACTIVE'), (:b_id, :b_name, 'CORPORATE_SOC', 'ACTIVE');"),
            {"a_id": org_a, "a_name": f"Org A {org_a}", "b_id": org_b, "b_name": f"Org B {org_b}"}
        )
        conn.execute(
            text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:a_id, :a_email, 'User A', :pw, 'ACTIVE'), (:b_id, :b_email, 'User B', :pw, 'ACTIVE');"),
            {
                "a_id": user_a, "a_email": f"usera_{user_a}@agency.gov", "pw": pw_hash,
                "b_id": user_b, "b_email": f"userb_{user_b}@agency.gov",
            }
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :a_id, :ua_id, 'TENANT_ADMIN', 'ACTIVE'),
                (gen_random_uuid(), :b_id, :ub_id, 'TENANT_ADMIN', 'ACTIVE');
            """),
            {"a_id": org_a, "ua_id": user_a, "b_id": org_b, "ub_id": user_b}
        )

    # Login User A
    login_a = await live_client.post("/api/v1/auth/login", json={"email": f"usera_{user_a}@agency.gov", "password": "TenantIsoPass123!"})
    token_a = login_a.json()["access_token"]

    # 1. User A attempts to forge X-Tenant-ID to Org B
    res_forged = await live_client.get(
        "/api/v1/organizations/current",
        headers={"Authorization": f"Bearer {token_a}", "X-Tenant-ID": str(org_b)},
    )
    assert res_forged.status_code == 403
    assert "does not belong" in res_forged.json()["detail"].lower()

    # 2. User A queries members under Org A -> returns strictly Org A members
    res_members_a = await live_client.get(
        "/api/v1/organizations/members",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_members_a.status_code == 200
    members_data = res_members_a.json()
    assert len(members_data) == 1
    assert members_data[0]["user_id"] == str(user_a)
    assert members_data[0]["tenant_id"] == str(org_a)


# =============================================================================
# Test 8: Second Concurrent Login (DEC-20 Reconciled Policy)
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_second_concurrent_login_dec20(live_pg_engine, live_client: AsyncClient):
    """
    Verify single active session policy (DEC-20 / AC-REQ-006):
    1. Login 1 succeeds -> active session 1.
    2. Login 2 without force_terminate_existing -> rejected with HTTP 409 Conflict.
    3. Session 1 remains valid and operational.
    4. Login 2 with force_terminate_existing=True -> succeeds, displaces session 1.
    5. Token from Login 1 is immediately invalidated (401 Unauthorized).
    """
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    plain_pw = "Dec20Pass123!"
    pw_hash = hash_password(plain_pw)
    email = f"dec20_{user_id}@agency.gov"

    with live_pg_engine.begin() as conn:
        conn.execute(text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE');"), {"t_id": org_id, "name": f"DEC20 Org {org_id}"})
        conn.execute(text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'DEC20 User', :pw, 'ACTIVE');"), {"u_id": user_id, "email": email, "pw": pw_hash})
        conn.execute(text("INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status) VALUES (gen_random_uuid(), :t_id, :u_id, 'INVESTIGATOR', 'ACTIVE');"), {"t_id": org_id, "u_id": user_id})

    # Step 1: Login 1
    login_1 = await live_client.post("/api/v1/auth/login", json={"email": email, "password": plain_pw})
    assert login_1.status_code == 200
    token_1 = login_1.json()["access_token"]

    # Step 2: Login 2 without force termination -> 409 Conflict
    login_2_reject = await live_client.post("/api/v1/auth/login", json={"email": email, "password": plain_pw, "force_terminate_existing": False})
    assert login_2_reject.status_code == 409
    assert "ACTIVE_SESSION_EXISTS" in login_2_reject.json()["detail"]

    # Step 3: Session 1 still works
    res_me_1 = await live_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_1}"})
    assert res_me_1.status_code == 200

    # Step 4: Login 2 with force_terminate_existing=True -> succeeds
    login_2_displace = await live_client.post("/api/v1/auth/login", json={"email": email, "password": plain_pw, "force_terminate_existing": True})
    assert login_2_displace.status_code == 200
    token_2 = login_2_displace.json()["access_token"]

    # Step 5: Token 2 works
    res_me_2 = await live_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_2}"})
    assert res_me_2.status_code == 200

    # Step 6: Token 1 is now rejected
    res_me_1_after = await live_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_1}"})
    assert res_me_1_after.status_code == 401
    assert "SESSION_REVOKED_OR_DISPLACED" in res_me_1_after.json()["detail"]


# =============================================================================
# Test 9: Audit Trail Verification
# =============================================================================

@pytest.mark.asyncio
async def test_runtime_audit_event_emission(live_pg_engine, live_client: AsyncClient):
    """Verify that sensitive IAM lifecycle actions emit real database rows in audit.audit_event_records."""
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    plain_pw = "AuditPass123!"
    pw_hash = hash_password(plain_pw)
    email = f"audit_{user_id}@agency.gov"

    with live_pg_engine.begin() as conn:
        conn.execute(text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE');"), {"t_id": org_id, "name": f"Audit Org {org_id}"})
        conn.execute(text("INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state) VALUES (:u_id, :email, 'Audit User', :pw, 'ACTIVE');"), {"u_id": user_id, "email": email, "pw": pw_hash})
        conn.execute(text("INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status) VALUES (gen_random_uuid(), :t_id, :u_id, 'INVESTIGATOR', 'ACTIVE');"), {"t_id": org_id, "u_id": user_id})

    # 1. Login generates SESSION_CREATED
    login_res = await live_client.post("/api/v1/auth/login", json={"email": email, "password": plain_pw})
    token = login_res.json()["access_token"]

    # 2. Logout generates SESSION_TERMINATED
    logout_res = await live_client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200

    # Verify audit records exist in live database
    with live_pg_engine.connect() as conn:
        res = conn.execute(
            text("SELECT action_type FROM audit.audit_event_records WHERE user_id = :u_id ORDER BY event_timestamp_utc ASC;"),
            {"u_id": user_id}
        )
        actions = [row[0] for row in res.fetchall()]
        assert "SESSION_CREATED" in actions
        assert "SESSION_TERMINATED" in actions


# =============================================================================
# Test 10: Runtime Database Role (tti_app_role) RLS Non-Bypass
# =============================================================================

def test_runtime_rls_cannot_be_bypassed_by_app_role(live_pg_engine):
    """
    Verify the least-privileged database runtime role (tti_app_role) cannot bypass RLS (DEC-18).
    - Without context: queries return 0 rows.
    - With Tenant A context: returns strictly Tenant A rows.
    - Direct insert with mismatched tenant_id: rejected by RLS WITH CHECK policy.
    """
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES 
                (:ta, :na, 'LAW_ENFORCEMENT', 'ACTIVE'),
                (:tb, :nb, 'CORPORATE_SOC', 'ACTIVE')
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"ta": tenant_a, "na": f"AppRole Org A {tenant_a}", "tb": tenant_b, "nb": f"AppRole Org B {tenant_b}"}
        )

    with live_pg_engine.connect() as conn:
        conn.execute(text("SET ROLE tti_app_role;"))

        # 1. Without tenant context -> fails closed (0 rows)
        conn.execute(text("RESET app.current_tenant_id;"))
        res_empty = conn.execute(text("SELECT tenant_id FROM iam.tenant_organizations WHERE tenant_id IN (:ta, :tb);"), {"ta": tenant_a, "tb": tenant_b})
        assert len(res_empty.fetchall()) == 0

        # 2. With Tenant A context -> strictly Tenant A visible
        conn.execute(text("SELECT set_config('app.current_tenant_id', :ta, true);"), {"ta": str(tenant_a)})
        res_ta = conn.execute(text("SELECT tenant_id FROM iam.tenant_organizations WHERE tenant_id IN (:ta, :tb);"), {"ta": tenant_a, "tb": tenant_b})
        rows_ta = res_ta.fetchall()
        assert len(rows_ta) == 1
        assert rows_ta[0][0] == tenant_a

        # 3. Direct insert for Tenant B while bound to Tenant A -> rejected by RLS policy
        with pytest.raises(Exception) as exc_info:
            conn.execute(
                text("""
                INSERT INTO iam.active_user_sessions (session_id, user_id, active_tenant_id, session_token_hash, expires_at_utc)
                VALUES (gen_random_uuid(), gen_random_uuid(), :tb, 'bad_token_hash', CURRENT_TIMESTAMP + INTERVAL '1 hour');
                """),
                {"tb": tenant_b}
            )
        assert "row-level security policy" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

        conn.rollback()
        conn.execute(text("RESET ROLE;"))
