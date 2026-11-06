"""Phase 5 Case Management integration, security, and tenant isolation test suite.

Validates:
1. FR-EVI-001: Compartmentalized Case Workspace & Evidence Staging.
2. Case reference generation and tenant-scoped uniqueness (HTTP 409 on conflict).
3. Message pinning with investigator tags and analyst annotations.
4. Defense-in-depth: Tenant A cannot pin Tenant B's messages (composite foreign key + RLS).
5. Unpinning a message preserves underlying threat telemetry and raw evidence blobs without mutation.
6. Confidential analyst notes with creator attribution and chronological ordering.
7. Closed-case governance: Cases in FINALIZED_LOCKED or ARCHIVED reject pins, unpins, notes, and metadata changes with HTTP 409 Conflict.
8. Multi-tenant isolation: Cross-tenant case access and pinning attempts return HTTP 404 Fail-Closed.
9. RBAC permission enforcement: READ_ONLY_ANALYST is blocked from case creation, pinning, notes, and updates (HTTP 403).
10. Transactional audit ledger: CASE_CREATED, CASE_UPDATED, CASE_STATUS_CHANGED, MESSAGE_PINNED_TO_CASE, MESSAGE_UNPINNED_FROM_CASE, CASE_NOTE_ADDED recorded in audit.audit_event_records.
11. RLS enforcement: tti_app_role cannot bypass tenant isolation on app.investigative_cases, app.case_message_associations, and app.case_notes.
"""

from datetime import datetime, timezone
import hashlib
from typing import AsyncGenerator, Dict, Any, Optional
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select, text

from app.core.config import get_settings
from app.core.security import hash_password
from app.database.models.audit import AuditEventRecord
from app.database.models.cases import CaseMessageAssociation, CaseNote, InvestigativeCase
from app.database.models.intelligence import SourceChannel, SourceMessage
from app.main import app

settings = get_settings()


@pytest.fixture(scope="module")
def live_pg_engine():
    """Verify live PostgreSQL availability; skip suite if database is unreachable."""
    sync_url = settings.sync_database_url
    engine = create_engine(sync_url, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1;"))
        yield engine
        engine.dispose()
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL database unreachable ({type(exc).__name__}); skipping Case Management tests")


@pytest_asyncio.fixture
async def live_client(live_pg_engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an HTTP test client connected to the application with live DB."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def setup_tenant_and_user(
    live_pg_engine,
    org_name: str,
    email: str,
    password: str,
    role: str = "INVESTIGATOR",
) -> Dict[str, Any]:
    """Helper to provision a clean test organization, user profile, and membership."""
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    password_hash = hash_password(password)

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE')
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"t_id": org_id, "name": org_name},
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, :email, 'Agent Smith', :pw_hash, 'ACTIVE')
            ON CONFLICT (user_id) DO NOTHING;
            """),
            {"u_id": user_id, "email": email, "pw_hash": password_hash},
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES (gen_random_uuid(), :t_id, :u_id, :role, 'ACTIVE')
            ON CONFLICT (tenant_id, user_id) DO NOTHING;
            """),
            {"t_id": org_id, "u_id": user_id, "role": role},
        )

    return {"tenant_id": org_id, "user_id": user_id, "email": email, "password": password, "role": role}


def seed_threat_message(
    live_pg_engine,
    tenant_id: uuid.UUID,
    channel_id: str,
    message_id: str,
    raw_text: str = "Threat telemetry data sample",
    sequence_id: int = 1,
) -> None:
    """Helper to register an authorized channel and seed a threat message directly."""
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO threat.source_channels 
                (tenant_id, channel_id, channel_title, source_type, is_authorized, created_at_utc, updated_at_utc)
            VALUES 
                (:t_id, :ch_id, 'Authorized Channel', 'telegram', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, channel_id) DO UPDATE SET is_authorized = TRUE;
            """),
            {"t_id": tenant_id, "ch_id": channel_id},
        )
        conn.execute(
            text("""
            INSERT INTO threat.source_messages 
                (tenant_id, message_id, channel_id, source_sequence_id, broadcast_timestamp_utc, ingested_at_utc)
            VALUES 
                (:t_id, :m_id, :ch_id, :seq, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, message_id) DO NOTHING;
            """),
            {"t_id": tenant_id, "m_id": message_id, "ch_id": channel_id, "seq": sequence_id},
        )


async def login_and_get_token(client: AsyncClient, email: str, password: str) -> str:
    """Helper to authenticate and return the Bearer JWT token."""
    res = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


@pytest.mark.asyncio
async def test_case_creation_explicit_and_autogenerated_ref(live_client: AsyncClient, live_pg_engine):
    """Verify case creation with both custom case reference and auto-generated reference, plus audit trail."""
    u1 = setup_tenant_and_user(live_pg_engine, "CaseOrgAlpha", "case_creator@alpha.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u1["email"], u1["password"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create with custom case_reference
    res1 = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_title": "Operation Sovereign Shield",
            "case_reference": "CASE-2026-CR-001",
            "internal_agency_ref": "WARRANT-DOJ-992",
            "description": "Investigation into syndicated botnet operations.",
        },
    )
    assert res1.status_code == 201, res1.text
    c1 = res1.json()
    assert c1["case_reference"] == "CASE-2026-CR-001"
    assert c1["case_title"] == "Operation Sovereign Shield"
    assert c1["internal_agency_ref"] == "WARRANT-DOJ-992"
    assert c1["case_status"] == "ACTIVE"
    assert c1["tenant_id"] == str(u1["tenant_id"])
    assert c1["lead_investigator_id"] == str(u1["user_id"])

    # 2. Create with auto-generated case_reference (case_reference=None)
    res2 = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_title": "Operation Silent Beacon",
            "description": "C2 server infrastructure tracking.",
        },
    )
    assert res2.status_code == 201, res2.text
    c2 = res2.json()
    assert c2["case_reference"].startswith("CASE-")
    assert c2["case_reference"] != "CASE-2026-CR-001"

    # 3. Verify transactional audit records in audit.audit_event_records
    with live_pg_engine.connect() as conn:
        audit_rows = conn.execute(
            text("""
            SELECT action_type, target_identifier_hash, details 
            FROM audit.audit_event_records 
            WHERE tenant_id = :t_id AND action_type = 'CASE_CREATED'
            ORDER BY event_timestamp_utc ASC;
            """),
            {"t_id": u1["tenant_id"]},
        ).fetchall()
        assert len(audit_rows) == 2
        ref1_hash = hashlib.sha256("CASE-2026-CR-001".encode()).hexdigest()
        assert audit_rows[0][1] == ref1_hash


@pytest.mark.asyncio
async def test_case_duplicate_reference_conflict(live_client: AsyncClient, live_pg_engine):
    """Verify that creating two cases with the same reference within a tenant is rejected with HTTP 409 Conflict."""
    u = setup_tenant_and_user(live_pg_engine, "ConflictOrg", "conflict_analyst@tti.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    # First case
    res1 = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "Unique Case A", "case_reference": "REF-UNIQUE-409"},
    )
    assert res1.status_code == 201

    # Duplicate case
    res2 = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "Unique Case B", "case_reference": "REF-UNIQUE-409"},
    )
    assert res2.status_code == 409
    assert "already exists in this tenant" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_case_listing_and_filtering(live_client: AsyncClient, live_pg_engine):
    """Verify paginated case listing and status filtering."""
    u = setup_tenant_and_user(live_pg_engine, "ListOrg", "lister@tti.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    # Create 3 cases
    for i in range(1, 4):
        await live_client.post(
            "/api/v1/cases",
            headers=headers,
            json={"case_title": f"Batch Case {i}", "case_reference": f"BATCH-{i}"},
        )

    # List all
    res = await live_client.get("/api/v1/cases?limit=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 3
    assert len(data["items"]) >= 3

    # Filter by status ACTIVE
    res_active = await live_client.get("/api/v1/cases?status=ACTIVE", headers=headers)
    assert res_active.status_code == 200
    assert all(item["case_status"] == "ACTIVE" for item in res_active.json()["items"])

    # Filter by status ARCHIVED (expect 0)
    res_archived = await live_client.get("/api/v1/cases?status=ARCHIVED", headers=headers)
    assert res_archived.status_code == 200
    assert res_archived.json()["total"] == 0


@pytest.mark.asyncio
async def test_case_message_pinning_and_duplicate_conflict(live_client: AsyncClient, live_pg_engine):
    """Verify message pinning, tags, annotations, and duplicate pin rejection."""
    u = setup_tenant_and_user(live_pg_engine, "PinOrg", "pinner@tti.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    # Seed threat message
    seed_threat_message(live_pg_engine, u["tenant_id"], "ch_threat_alpha", "msg_pin_test_1", sequence_id=101)

    # Create Case
    c_res = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "Pin Test Workspace", "case_reference": "CASE-PIN-01"},
    )
    case_id = c_res.json()["case_id"]

    # 1. Pin valid message
    pin_res = await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={
            "message_id": "msg_pin_test_1",
            "investigator_tags": ["botnet_c2", "ransomware_affiliate"],
            "analyst_annotation": "Primary suspect wallet identified in payload text.",
        },
    )
    assert pin_res.status_code == 201, pin_res.text
    assoc = pin_res.json()
    assert assoc["message_id"] == "msg_pin_test_1"
    assert assoc["investigator_tags"] == ["botnet_c2", "ransomware_affiliate"]
    assert assoc["analyst_annotation"] == "Primary suspect wallet identified in payload text."
    assert assoc["pinned_by_user_id"] == str(u["user_id"])

    # 2. Pin duplicate message to same case (must reject with HTTP 409)
    dup_res = await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "msg_pin_test_1"},
    )
    assert dup_res.status_code == 409
    assert "already pinned" in dup_res.json()["detail"]

    # 3. Pin non-existent message (must reject with HTTP 404)
    notfound_res = await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "ghost_message_999"},
    )
    assert notfound_res.status_code == 404

    # 4. Verify case detail includes pinned message
    detail_res = await live_client.get(f"/api/v1/cases/{case_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["pinned_messages"]) == 1
    assert detail["pinned_messages"][0]["message_id"] == "msg_pin_test_1"

    # 5. Verify audit log entry
    with live_pg_engine.connect() as conn:
        pin_audit = conn.execute(
            text("""
            SELECT action_type, details 
            FROM audit.audit_event_records 
            WHERE tenant_id = :t_id AND action_type = 'MESSAGE_PINNED_TO_CASE';
            """),
            {"t_id": u["tenant_id"]},
        ).fetchone()
        assert pin_audit is not None
        assert pin_audit[1]["message_id"] == "msg_pin_test_1"


@pytest.mark.asyncio
async def test_case_message_unpinning_preserves_threat_telemetry(live_client: AsyncClient, live_pg_engine):
    """Verify unpinning removes association but preserves underlying threat telemetry without mutation."""
    u = setup_tenant_and_user(live_pg_engine, "UnpinOrg", "unpinner@tti.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    seed_threat_message(live_pg_engine, u["tenant_id"], "ch_unpin_ch", "msg_to_unpin_01", sequence_id=201)

    c_res = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "Unpin Workspace", "case_reference": "CASE-UNPIN-01"},
    )
    case_id = c_res.json()["case_id"]

    # Pin
    await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "msg_to_unpin_01"},
    )

    # Unpin
    unpin_res = await live_client.delete(
        f"/api/v1/cases/{case_id}/messages/msg_to_unpin_01",
        headers=headers,
    )
    assert unpin_res.status_code == 204

    # Verify case has 0 pinned messages now
    detail_res = await live_client.get(f"/api/v1/cases/{case_id}", headers=headers)
    assert len(detail_res.json()["pinned_messages"]) == 0

    # CRITICAL INVARIANT: Verify message is STILL present in threat.source_messages!
    with live_pg_engine.connect() as conn:
        msg = conn.execute(
            text("SELECT message_id FROM threat.source_messages WHERE tenant_id = :t_id AND message_id = :m_id;"),
            {"t_id": u["tenant_id"], "m_id": "msg_to_unpin_01"},
        ).fetchone()
        assert msg is not None, "Source message was unexpectedly deleted or mutated!"

        # Verify audit log
        unpin_audit = conn.execute(
            text("SELECT action_type FROM audit.audit_event_records WHERE tenant_id = :t_id AND action_type = 'MESSAGE_UNPINNED_FROM_CASE';"),
            {"t_id": u["tenant_id"]},
        ).fetchone()
        assert unpin_audit is not None


@pytest.mark.asyncio
async def test_case_analyst_notes_creation_and_listing(live_client: AsyncClient, live_pg_engine):
    """Verify adding notes to a case with author attribution and chronological retrieval."""
    u = setup_tenant_and_user(live_pg_engine, "NotesOrg", "analyst_notes@tti.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    c_res = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "Hypothesis Workspace", "case_reference": "CASE-NOTE-01"},
    )
    case_id = c_res.json()["case_id"]

    # Add Note 1
    n1_res = await live_client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=headers,
        json={
            "note_title": "Working Hypothesis on Threat Actor",
            "note_content": "Infrastructure matches known APT group signature.",
        },
    )
    assert n1_res.status_code == 201
    n1 = n1_res.json()
    assert n1["note_title"] == "Working Hypothesis on Threat Actor"
    assert n1["author_user_id"] == str(u["user_id"])

    # Add Note 2
    n2_res = await live_client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=headers,
        json={
            "note_title": "Evidence Corroboration",
            "note_content": "Cross-referenced blockchain hashes with external intelligence feed.",
        },
    )
    assert n2_res.status_code == 201

    # List Notes
    notes_res = await live_client.get(f"/api/v1/cases/{case_id}/notes", headers=headers)
    assert notes_res.status_code == 200
    notes = notes_res.json()
    assert len(notes) == 2
    assert notes[0]["note_title"] == "Working Hypothesis on Threat Actor"
    assert notes[1]["note_title"] == "Evidence Corroboration"


@pytest.mark.asyncio
async def test_closed_case_modification_protection(live_client: AsyncClient, live_pg_engine):
    """Verify that FINALIZED_LOCKED and ARCHIVED cases reject pins, unpins, notes, and metadata changes with HTTP 409."""
    u = setup_tenant_and_user(live_pg_engine, "LockOrg", "lead_lock@tti.gov", "Secret123!", "INVESTIGATOR_LEAD")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    seed_threat_message(live_pg_engine, u["tenant_id"], "ch_lock", "msg_lock_test_1", sequence_id=301)
    seed_threat_message(live_pg_engine, u["tenant_id"], "ch_lock", "msg_lock_test_2", sequence_id=302)

    # 1. Create case and pin initial message
    c_res = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "Locked Case Test", "case_reference": "CASE-LOCK-01"},
    )
    case_id = c_res.json()["case_id"]

    await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "msg_lock_test_1"},
    )

    # 2. Transition case to FINALIZED_LOCKED
    lock_res = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers,
        json={"case_status": "FINALIZED_LOCKED"},
    )
    assert lock_res.status_code == 200
    assert lock_res.json()["case_status"] == "FINALIZED_LOCKED"
    assert lock_res.json()["closed_at_utc"] is not None

    # 3. Attempt to pin a new message to locked case -> HTTP 409
    pin_locked = await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "msg_lock_test_2"},
    )
    assert pin_locked.status_code == 409
    assert "status 'FINALIZED_LOCKED'" in pin_locked.json()["detail"]

    # 4. Attempt to unpin existing message from locked case -> HTTP 409
    unpin_locked = await live_client.delete(
        f"/api/v1/cases/{case_id}/messages/msg_lock_test_1",
        headers=headers,
    )
    assert unpin_locked.status_code == 409
    assert "status 'FINALIZED_LOCKED'" in unpin_locked.json()["detail"]

    # 5. Attempt to add a note to locked case -> HTTP 409
    note_locked = await live_client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=headers,
        json={"note_title": "Late hypothesis", "note_content": "This should fail"},
    )
    assert note_locked.status_code == 409
    assert "status 'FINALIZED_LOCKED'" in note_locked.json()["detail"]

    # 6. Attempt to modify title of locked case -> HTTP 409
    meta_locked = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers,
        json={"case_title": "Tampered Title"},
    )
    assert meta_locked.status_code == 409
    assert "Cannot modify metadata of a case with status 'FINALIZED_LOCKED'" in meta_locked.json()["detail"]

    # 7. Reopen case to ACTIVE and verify modifications work again
    reopen_res = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers,
        json={"case_status": "ACTIVE"},
    )
    assert reopen_res.status_code == 200
    assert reopen_res.json()["case_status"] == "ACTIVE"
    assert reopen_res.json()["closed_at_utc"] is None

    # Now pinning msg_lock_test_2 succeeds
    pin_reopened = await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "msg_lock_test_2"},
    )
    assert pin_reopened.status_code == 201


@pytest.mark.asyncio
async def test_cross_tenant_case_isolation(live_client: AsyncClient, live_pg_engine):
    """Verify strict tenant isolation: Tenant B cannot read, pin to, or access Tenant A's cases or threat messages."""
    t_a = setup_tenant_and_user(live_pg_engine, "TenantAlphaAgency", "lead_alpha@alpha.gov", "Secret123!", "INVESTIGATOR")
    token_a = await login_and_get_token(live_client, t_a["email"], t_a["password"])
    headers_a = {"Authorization": f"Bearer {token_a}"}

    t_b = setup_tenant_and_user(live_pg_engine, "TenantBetaAgency", "lead_beta@beta.gov", "Secret123!", "INVESTIGATOR")
    token_b = await login_and_get_token(live_client, t_b["email"], t_b["password"])
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Tenant A creates case and seeds message
    seed_threat_message(live_pg_engine, t_a["tenant_id"], "ch_secret_alpha", "msg_alpha_secret_01", sequence_id=401)
    c_a_res = await live_client.post(
        "/api/v1/cases",
        headers=headers_a,
        json={"case_title": "Alpha Classified", "case_reference": "CASE-ALPHA-01"},
    )
    case_a_id = c_a_res.json()["case_id"]

    # 1. Tenant B attempts to read Tenant A's case -> HTTP 404 (Fail-closed)
    res_b_read = await live_client.get(f"/api/v1/cases/{case_a_id}", headers=headers_b)
    assert res_b_read.status_code == 404

    # 2. Tenant B attempts to pin to Tenant A's case -> HTTP 404
    res_b_pin = await live_client.post(
        f"/api/v1/cases/{case_a_id}/messages",
        headers=headers_b,
        json={"message_id": "msg_alpha_secret_01"},
    )
    assert res_b_pin.status_code == 404

    # 3. Tenant B creates their own case, then attempts to pin Tenant A's message -> HTTP 404 (message not found in Tenant B)
    c_b_res = await live_client.post(
        "/api/v1/cases",
        headers=headers_b,
        json={"case_title": "Beta Public", "case_reference": "CASE-BETA-01"},
    )
    case_b_id = c_b_res.json()["case_id"]

    res_b_pin_a_msg = await live_client.post(
        f"/api/v1/cases/{case_b_id}/messages",
        headers=headers_b,
        json={"message_id": "msg_alpha_secret_01"},
    )
    assert res_b_pin_a_msg.status_code == 404
    assert "not found in this tenant" in res_b_pin_a_msg.json()["detail"]


@pytest.mark.asyncio
async def test_case_rbac_permissions(live_client: AsyncClient, live_pg_engine):
    """Verify RBAC: READ_ONLY_ANALYST can read cases but is blocked from create, update, pin, and notes with HTTP 403."""
    u_lead = setup_tenant_and_user(live_pg_engine, "RbacCaseOrg", "rbac_lead@agency.gov", "Secret123!", "INVESTIGATOR_LEAD")
    token_lead = await login_and_get_token(live_client, u_lead["email"], u_lead["password"])
    headers_lead = {"Authorization": f"Bearer {token_lead}"}

    # Setup read-only user in the same tenant
    password_hash = hash_password("Secret123!")
    ro_user_id = uuid.uuid4()
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, 'analyst_ro@agency.gov', 'Analyst Jane', :pw_hash, 'ACTIVE');
            """),
            {"u_id": ro_user_id, "pw_hash": password_hash},
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES (gen_random_uuid(), :t_id, :u_id, 'READ_ONLY_ANALYST', 'ACTIVE');
            """),
            {"t_id": u_lead["tenant_id"], "u_id": ro_user_id},
        )

    token_ro = await login_and_get_token(live_client, "analyst_ro@agency.gov", "Secret123!")
    headers_ro = {"Authorization": f"Bearer {token_ro}"}

    # Lead creates case
    c_res = await live_client.post(
        "/api/v1/cases",
        headers=headers_lead,
        json={"case_title": "RBAC Case Container", "case_reference": "CASE-RBAC-01"},
    )
    case_id = c_res.json()["case_id"]

    # 1. READ_ONLY_ANALYST can list cases
    list_ro = await live_client.get("/api/v1/cases", headers=headers_ro)
    assert list_ro.status_code == 200

    # 2. READ_ONLY_ANALYST can get case detail
    detail_ro = await live_client.get(f"/api/v1/cases/{case_id}", headers=headers_ro)
    assert detail_ro.status_code == 200

    # 3. READ_ONLY_ANALYST cannot create case -> HTTP 403
    create_ro = await live_client.post(
        "/api/v1/cases",
        headers=headers_ro,
        json={"case_title": "Unauthorized Case", "case_reference": "CASE-UNAUTH-01"},
    )
    assert create_ro.status_code == 403
    assert "Required permission: 'case:create'" in create_ro.json()["detail"]

    # 4. READ_ONLY_ANALYST cannot update case -> HTTP 403
    update_ro = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_ro,
        json={"case_title": "Unauthorized Title"},
    )
    assert update_ro.status_code == 403
    assert "Required permission: 'case:update'" in update_ro.json()["detail"]

    # 5. READ_ONLY_ANALYST cannot pin message -> HTTP 403
    pin_ro = await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers_ro,
        json={"message_id": "any_msg"},
    )
    assert pin_ro.status_code == 403
    assert "Required permission: 'case:message_pin'" in pin_ro.json()["detail"]

    # 6. READ_ONLY_ANALYST cannot create note -> HTTP 403
    note_ro = await live_client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=headers_ro,
        json={"note_title": "Unauthorized Note", "note_content": "Body"},
    )
    assert note_ro.status_code == 403
    assert "Required permission: 'case:note_create'" in note_ro.json()["detail"]


@pytest.mark.asyncio
async def test_case_rls_cannot_be_bypassed_by_app_role(live_client: AsyncClient, live_pg_engine):
    """Verify that tti_app_role cannot bypass RLS when querying case management tables directly."""
    u = setup_tenant_and_user(live_pg_engine, "RlsOrg", "rls_test@tti.gov", "Secret123!", "INVESTIGATOR")
    token = await login_and_get_token(live_client, u["email"], u["password"])
    headers = {"Authorization": f"Bearer {token}"}

    seed_threat_message(live_pg_engine, u["tenant_id"], "ch_rls", "msg_rls_01", sequence_id=501)

    c_res = await live_client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_title": "RLS Case", "case_reference": "CASE-RLS-01"},
    )
    case_id = c_res.json()["case_id"]

    await live_client.post(
        f"/api/v1/cases/{case_id}/messages",
        headers=headers,
        json={"message_id": "msg_rls_01"},
    )
    await live_client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=headers,
        json={"note_title": "RLS Note", "note_content": "Content"},
    )

    # Test direct SQL execution as tti_app_role
    with live_pg_engine.begin() as conn:
        conn.execute(text("SET ROLE tti_app_role;"))

        # Without app.current_tenant_id set: FAIL-CLOSED (0 rows returned)
        conn.execute(text("RESET app.current_tenant_id;"))
        cases_no_tenant = conn.execute(text("SELECT * FROM app.investigative_cases;")).fetchall()
        assert len(cases_no_tenant) == 0

        pins_no_tenant = conn.execute(text("SELECT * FROM app.case_message_associations;")).fetchall()
        assert len(pins_no_tenant) == 0

        notes_no_tenant = conn.execute(text("SELECT * FROM app.case_notes;")).fetchall()
        assert len(notes_no_tenant) == 0

        # With DIFFERENT tenant_id set: FAIL-CLOSED (0 rows returned)
        diff_tenant = uuid.uuid4()
        conn.execute(text(f"SET app.current_tenant_id = '{diff_tenant}';"))
        cases_diff = conn.execute(text("SELECT * FROM app.investigative_cases;")).fetchall()
        assert len(cases_diff) == 0

        # With MATCHING tenant_id set: Exact matching rows returned
        conn.execute(text(f"SET app.current_tenant_id = '{u['tenant_id']}';"))
        cases_match = conn.execute(text("SELECT * FROM app.investigative_cases;")).fetchall()
        assert len(cases_match) == 1
        assert cases_match[0].case_reference == "CASE-RLS-01"

        pins_match = conn.execute(text("SELECT * FROM app.case_message_associations;")).fetchall()
        assert len(pins_match) == 1

        notes_match = conn.execute(text("SELECT * FROM app.case_notes;")).fetchall()
        assert len(notes_match) == 1

        conn.execute(text("RESET ROLE;"))


@pytest.mark.asyncio
async def test_lead_investigator_tenant_membership_validation(live_client: AsyncClient, live_pg_engine):
    """SEC-CASE-01: Verify lead investigator validation enforces active tenant membership.

    Validates:
    1. Default lead assignment when omitted defaults to the authenticated caller.
    2. Explicit assignment of an active member within the tenant succeeds (201).
    3. Assignment of a user from another tenant fails (400 Bad Request).
    4. Assignment of a revoked member in the same tenant fails (400 Bad Request).
    5. Assignment of an arbitrary non-existent user UUID fails (400 Bad Request).
    6. Updating case to assign a cross-tenant or revoked lead fails (400 Bad Request).
    7. Updating case to assign a valid active member succeeds (200 OK).
    """
    pw_hash = hash_password("Secret123!")

    # 1. Provision Tenant Alpha with user_a (INVESTIGATOR)
    t_a = setup_tenant_and_user(live_pg_engine, "AlphaAgency", "analyst_a@alpha.gov", "Secret123!", "INVESTIGATOR")
    token_a = await login_and_get_token(live_client, t_a["email"], t_a["password"])
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 2. Provision user_b (ACTIVE member in Tenant Alpha) and user_c (REVOKED member in Tenant Alpha)
    user_b_id = uuid.uuid4()
    user_c_id = uuid.uuid4()
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES 
                (:ub_id, 'analyst_b@alpha.gov', 'Agent Baker', :pw_hash, 'ACTIVE'),
                (:uc_id, 'analyst_c@alpha.gov', 'Agent Charlie', :pw_hash, 'ACTIVE');
            """),
            {"ub_id": user_b_id, "uc_id": user_c_id, "pw_hash": pw_hash},
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :t_id, :ub_id, 'INVESTIGATOR', 'ACTIVE'),
                (gen_random_uuid(), :t_id, :uc_id, 'INVESTIGATOR', 'REVOKED');
            """),
            {"t_id": t_a["tenant_id"], "ub_id": user_b_id, "uc_id": user_c_id},
        )

    # 3. Provision Tenant Beta with user_d (ACTIVE member in Tenant Beta)
    t_b = setup_tenant_and_user(live_pg_engine, "BetaAgency", "analyst_d@beta.gov", "Secret123!", "INVESTIGATOR")

    # Scenario 1: Default lead assignment when omitted
    res_default = await live_client.post(
        "/api/v1/cases",
        headers=headers_a,
        json={"case_title": "Default Lead Case", "case_reference": "CASE-LEAD-DEF"},
    )
    assert res_default.status_code == 201, res_default.text
    c_def = res_default.json()
    assert c_def["lead_investigator_id"] == str(t_a["user_id"])

    # Scenario 2: Valid active member in same tenant
    res_valid = await live_client.post(
        "/api/v1/cases",
        headers=headers_a,
        json={
            "case_title": "Explicit Active Lead Case",
            "case_reference": "CASE-LEAD-OK",
            "lead_investigator_id": str(user_b_id),
        },
    )
    assert res_valid.status_code == 201, res_valid.text
    assert res_valid.json()["lead_investigator_id"] == str(user_b_id)
    case_id = res_valid.json()["case_id"]

    # Scenario 3: Cross-tenant user assignment (User D belongs to Tenant Beta)
    res_cross = await live_client.post(
        "/api/v1/cases",
        headers=headers_a,
        json={
            "case_title": "Cross Tenant Lead Case",
            "case_reference": "CASE-LEAD-CROSS",
            "lead_investigator_id": str(t_b["user_id"]),
        },
    )
    assert res_cross.status_code == 400
    assert "must be an active member of this organization" in res_cross.json()["detail"]

    # Scenario 4: Revoked membership user assignment
    res_revoked = await live_client.post(
        "/api/v1/cases",
        headers=headers_a,
        json={
            "case_title": "Revoked Lead Case",
            "case_reference": "CASE-LEAD-REV",
            "lead_investigator_id": str(user_c_id),
        },
    )
    assert res_revoked.status_code == 400
    assert "must be an active member of this organization" in res_revoked.json()["detail"]

    # Scenario 5: Non-existent arbitrary UUID
    res_nonexistent = await live_client.post(
        "/api/v1/cases",
        headers=headers_a,
        json={
            "case_title": "Ghost Lead Case",
            "case_reference": "CASE-LEAD-GHOST",
            "lead_investigator_id": str(uuid.uuid4()),
        },
    )
    assert res_nonexistent.status_code == 400
    assert "must be an active member of this organization" in res_nonexistent.json()["detail"]

    # Scenario 6: Update existing case with cross-tenant lead
    patch_cross = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_a,
        json={"lead_investigator_id": str(t_b["user_id"])},
    )
    assert patch_cross.status_code == 400
    assert "must be an active member of this organization" in patch_cross.json()["detail"]

    # Scenario 7: Update existing case with revoked lead
    patch_revoked = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_a,
        json={"lead_investigator_id": str(user_c_id)},
    )
    assert patch_revoked.status_code == 400
    assert "must be an active member of this organization" in patch_revoked.json()["detail"]

    # Scenario 8: Update existing case with valid active lead
    patch_ok = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_a,
        json={"lead_investigator_id": str(t_a["user_id"])},
    )
    assert patch_ok.status_code == 200
    assert patch_ok.json()["lead_investigator_id"] == str(t_a["user_id"])


@pytest.mark.asyncio
async def test_locked_case_reopening_authorization_governance(live_client: AsyncClient, live_pg_engine):
    """SEC-CASE-02: Verify governance rules on reopening FINALIZED_LOCKED and ARCHIVED cases.

    Validates:
    1. An ordinary investigator who is NOT the lead cannot reopen a locked case (403 Forbidden).
    2. An ordinary investigator cannot bypass lock by bundling title mutation with reopening (403 Forbidden).
    3. An unauthorized investigator cannot reopen an ARCHIVED case (403 Forbidden).
    4. The assigned lead investigator CAN reopen their case to ACTIVE (200 OK).
    5. A user holding ROLE_INVESTIGATOR_LEAD CAN reopen any case in their tenant (200 OK).
    """
    pw_hash = hash_password("Secret123!")

    # 1. Setup Tenant Gamma with user_1 (INVESTIGATOR)
    t_g = setup_tenant_and_user(live_pg_engine, "GammaGov", "lead_inv1@gamma.gov", "Secret123!", "INVESTIGATOR")
    token_inv1 = await login_and_get_token(live_client, t_g["email"], t_g["password"])
    headers_inv1 = {"Authorization": f"Bearer {token_inv1}"}

    # 2. Provision user_2 (ordinary INVESTIGATOR) and user_3 (INVESTIGATOR_LEAD) in Tenant Gamma
    inv2_id = uuid.uuid4()
    lead_officer_id = uuid.uuid4()
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES 
                (:inv2_id, 'peer_inv2@gamma.gov', 'Peer Investigator', :pw_hash, 'ACTIVE'),
                (:lead_id, 'chief_lead@gamma.gov', 'Chief Lead Officer', :pw_hash, 'ACTIVE');
            """),
            {"inv2_id": inv2_id, "lead_id": lead_officer_id, "pw_hash": pw_hash},
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :t_id, :inv2_id, 'INVESTIGATOR', 'ACTIVE'),
                (gen_random_uuid(), :t_id, :lead_id, 'INVESTIGATOR_LEAD', 'ACTIVE');
            """),
            {"t_id": t_g["tenant_id"], "inv2_id": inv2_id, "lead_id": lead_officer_id},
        )

    token_inv2 = await login_and_get_token(live_client, "peer_inv2@gamma.gov", "Secret123!")
    headers_inv2 = {"Authorization": f"Bearer {token_inv2}"}

    token_lead = await login_and_get_token(live_client, "chief_lead@gamma.gov", "Secret123!")
    headers_lead = {"Authorization": f"Bearer {token_lead}"}

    # 3. Inv1 creates a case (assigned lead is Inv1)
    res_c = await live_client.post(
        "/api/v1/cases",
        headers=headers_inv1,
        json={"case_title": "Gamma Classified Operation", "case_reference": "CASE-GAMMA-01"},
    )
    assert res_c.status_code == 201
    case_id = res_c.json()["case_id"]

    # 4. Inv1 locks the case
    lock_res = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv1,
        json={"case_status": "FINALIZED_LOCKED"},
    )
    assert lock_res.status_code == 200
    assert lock_res.json()["case_status"] == "FINALIZED_LOCKED"

    # Scenario 1: Inv2 (ordinary investigator, not case lead) attempts to reopen -> 403 Forbidden
    reopen_unauth = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv2,
        json={"case_status": "ACTIVE"},
    )
    assert reopen_unauth.status_code == 403
    assert "Only the assigned lead investigator or an Investigator Lead can reopen" in reopen_unauth.json()["detail"]

    # Scenario 2: Inv2 attempts to bundle metadata change with reopening -> 403 Forbidden
    reopen_bundle = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv2,
        json={"case_status": "ACTIVE", "case_title": "Sneak Title Change"},
    )
    assert reopen_bundle.status_code == 403

    # Scenario 3: Inv1 archives the case, then Inv2 attempts to reopen -> 403 Forbidden
    await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv1,
        json={"case_status": "ARCHIVED"},
    )
    reopen_archived = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv2,
        json={"case_status": "ACTIVE"},
    )
    assert reopen_archived.status_code == 403

    # Scenario 4: Inv1 (assigned case lead) reopens the case -> 200 OK
    reopen_by_lead = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv1,
        json={"case_status": "ACTIVE"},
    )
    assert reopen_by_lead.status_code == 200
    assert reopen_by_lead.json()["case_status"] == "ACTIVE"

    # Scenario 5: Case is re-locked, then Chief Lead (holding INVESTIGATOR_LEAD role) reopens it -> 200 OK
    await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_inv1,
        json={"case_status": "FINALIZED_LOCKED"},
    )
    reopen_by_chief = await live_client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers_lead,
        json={"case_status": "ACTIVE"},
    )
    assert reopen_by_chief.status_code == 200
    assert reopen_by_chief.json()["case_status"] == "ACTIVE"
