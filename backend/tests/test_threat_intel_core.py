"""Phase 3 Threat Intelligence Core integration and security test suite.

Validates:
1. SEC-THREAT-01: Server-side source authorization enforcement (rejects unregistered/disabled sources with HTTP 403).
2. SEC-THREAT-02: Atomic batch staging with transaction savepoints and filesystem cleanup on tamper failure.
3. SEC-THREAT-03: In-batch duplicate validation (rejects conflicting duplicates with HTTP 422, collapses identical duplicates).
4. Tenant isolation across channels, messages, search, and thread views under Row-Level Security (RLS).
5. Zero raw evidence leakage in presentation and search responses.
6. Chronological thread reconstruction.
7. Role-Based Access Control (RBAC) enforcement (INVESTIGATOR vs READ_ONLY_ANALYST).
8. Append-only audit logging across all threat lifecycle operations.
9. SEC-THREAT-06: Deferred channel metadata update ensuring channel attributes/timestamps roll back on tamper conflict.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import AsyncGenerator, Dict, Any, Optional
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select, text

from app.core.config import get_settings
from app.core.security import hash_password
from app.database.models.audit import AuditEventRecord
from app.database.models.intelligence import (
    DerivedContentRepresentation,
    IngestionJob,
    RawEvidenceBlob,
    SourceChannel,
    SourceMessage,
)
from app.evidence.storage import LocalEvidenceStore
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
        pytest.skip(f"Live PostgreSQL database unreachable ({type(exc).__name__}); skipping Threat Intel Core tests")


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


def register_source_channel(
    live_pg_engine,
    tenant_id: uuid.UUID,
    channel_id: str,
    channel_title: str = "Authorized Channel",
    channel_handle: Optional[str] = None,
    source_type: str = "telegram",
    is_authorized: bool = True,
) -> None:
    """Helper to simulate trusted server-side administrative registration of a channel."""
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO threat.source_channels 
                (tenant_id, channel_id, channel_title, channel_handle, source_type, is_authorized, created_at_utc, updated_at_utc)
            VALUES 
                (:t_id, :ch_id, :title, :handle, :s_type, :authz, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, channel_id) DO UPDATE SET is_authorized = :authz;
            """),
            {
                "t_id": tenant_id,
                "ch_id": channel_id,
                "title": channel_title,
                "handle": channel_handle,
                "s_type": source_type,
                "authz": is_authorized,
            },
        )


async def login_and_get_token(client: AsyncClient, email: str, password: str) -> str:
    """Helper to authenticate and return the Bearer JWT token."""
    res = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


# =============================================================================
# Test 1: Ingestion Pipeline, Normalization, Sanitization & Raw Evidence
# =============================================================================

@pytest.mark.asyncio
async def test_threat_ingest_normalization_and_sanitization(live_pg_engine, live_client: AsyncClient):
    """
    Verify complete ingestion vertical slice:
    - Pre-registers authorized channel.
    - Normalizes messages and thread references.
    - Sanitizes script tags, ANSI escapes, null bytes, defangs URIs.
    - Persists immutable verbatim raw payload into LocalEvidenceStore and raw_evidence_blobs.
    - Tracks ingestion job status as COMPLETED.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Ingest Test Org {uuid.uuid4()}",
        email=f"ingest_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    # Load synthetic fixture
    fixture_path = Path(__file__).parent / "fixtures" / "synthetic_threat_intel.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    # SEC-THREAT-01: Explicitly register and authorize the source server-side
    register_source_channel(
        live_pg_engine,
        tenant_id=tenant_id,
        channel_id=payload["source_reference"],
        channel_title=payload.get("channel_title", "Threat Actors Lounge"),
        channel_handle=payload.get("channel_handle"),
        is_authorized=True,
    )

    # 1. Submit Ingestion
    res = await live_client.post("/api/v1/threat/ingest", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    job_data = res.json()
    assert job_data["status"] == "COMPLETED"
    assert job_data["records_processed"] == 4
    assert job_data["source_reference"] == payload["source_reference"]
    job_id = job_data["job_id"]

    # 2. Verify Job Query Status Endpoint
    res_job = await live_client.get(f"/api/v1/threat/ingest/jobs/{job_id}", headers=headers)
    assert res_job.status_code == 200
    assert res_job.json()["status"] == "COMPLETED"
    assert res_job.json()["records_processed"] == 4

    # 3. Direct DB Invariants Check
    with live_pg_engine.begin() as conn:
        msg_count = conn.execute(
            text("SELECT COUNT(*) FROM threat.source_messages WHERE tenant_id = :t_id"),
            {"t_id": tenant_id},
        ).scalar()
        assert msg_count == 4

        # Sanitization assertions
        derived_9002 = conn.execute(
            text("SELECT sanitized_message_text FROM threat.derived_content_representations WHERE tenant_id = :t_id AND source_message_id = 'msg_9002'"),
            {"t_id": tenant_id},
        ).scalar()
        assert "<script>" not in derived_9002
        assert "[REDACTED_SCRIPT_BLOCK]" in derived_9002
        assert "[REDACTED_EMBED_BLOCK]" in derived_9002

        derived_9001 = conn.execute(
            text("SELECT sanitized_message_text FROM threat.derived_content_representations WHERE tenant_id = :t_id AND source_message_id = 'msg_9001'"),
            {"t_id": tenant_id},
        ).scalar()
        assert "defanged-javascript-blocked:" in derived_9001

        derived_9003 = conn.execute(
            text("SELECT sanitized_message_text FROM threat.derived_content_representations WHERE tenant_id = :t_id AND source_message_id = 'msg_9003'"),
            {"t_id": tenant_id},
        ).scalar()
        assert "\u001b" not in derived_9003
        assert "\u0000" not in derived_9003

        # Evidence storage assertions
        blob_9001 = conn.execute(
            text("SELECT payload_sha256_hash, payload_storage_locator, byte_size FROM evidence.raw_evidence_blobs WHERE tenant_id = :t_id AND source_message_id = 'msg_9001'"),
            {"t_id": tenant_id},
        ).fetchone()
        assert blob_9001 is not None
        sha_9001, locator_9001, size_9001 = blob_9001[0], blob_9001[1], blob_9001[2]

        evidence_store = LocalEvidenceStore()
        raw_bytes = evidence_store.retrieve_raw_evidence(str(tenant_id), locator_9001)
        assert len(raw_bytes) == size_9001
        assert hashlib.sha256(raw_bytes).hexdigest() == sha_9001
        assert b"javascript:alert('xss')" in raw_bytes


# =============================================================================
# Test 2: SEC-THREAT-01 Server-Side Source Authorization Tests
# =============================================================================

@pytest.mark.asyncio
async def test_unknown_source_rejected_even_if_client_claims_authorized(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-01: An incoming request must never authorize its own source using a client-controlled flag.
    Unknown / unregistered channels must be rejected with HTTP 403 SOURCE_NOT_REGISTERED.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Authz Test Org {uuid.uuid4()}",
        email=f"authz_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(user_info["tenant_id"])}

    # Submitting an unregistered channel (even if client attempts to send is_authorized_source=True)
    payload = {
        "source_reference": "unregistered_external_channel",
        "source_type": "telegram",
        "is_authorized_source": True,  # Must be ignored; server-side state is required!
        "messages": [
            {
                "message_id": "unregistered_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Unregistered channel chatter.",
            }
        ],
    }

    res = await live_client.post("/api/v1/threat/ingest", json=payload, headers=headers)
    assert res.status_code == 403
    assert "SOURCE_NOT_REGISTERED" in res.json()["detail"]

    # Verify channel was NOT auto-created in database
    with live_pg_engine.begin() as conn:
        ch_exists = conn.execute(
            text("SELECT 1 FROM threat.source_channels WHERE tenant_id = :t_id AND channel_id = 'unregistered_external_channel'"),
            {"t_id": user_info["tenant_id"]},
        ).scalar()
        assert ch_exists is None


@pytest.mark.asyncio
async def test_registered_but_disabled_source_rejected(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-01: Channels registered with is_authorized=False must be rejected with HTTP 403 SOURCE_UNAUTHORIZED.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Disabled Channel Org {uuid.uuid4()}",
        email=f"disabled_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    # Pre-register channel with is_authorized=False
    register_source_channel(
        live_pg_engine,
        tenant_id=tenant_id,
        channel_id="revoked_intel_feed",
        is_authorized=False,
    )

    payload = {
        "source_reference": "revoked_intel_feed",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "revoked_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Chatter from disabled feed.",
            }
        ],
    }

    res = await live_client.post("/api/v1/threat/ingest", json=payload, headers=headers)
    assert res.status_code == 403
    assert "SOURCE_UNAUTHORIZED" in res.json()["detail"]

    # Check job is marked REJECTED and audit event recorded
    with live_pg_engine.begin() as conn:
        job = conn.execute(
            text("SELECT status, error_message FROM app.ingestion_jobs WHERE tenant_id = :t_id AND source_reference = 'revoked_intel_feed'"),
            {"t_id": tenant_id},
        ).fetchone()
        assert job[0] == "REJECTED"

        audit = conn.execute(
            text("SELECT action_type FROM audit.audit_event_records WHERE tenant_id = :t_id AND action_type = 'INGESTION_SOURCE_UNAUTHORIZED'"),
            {"t_id": tenant_id},
        ).scalar()
        assert audit == "INGESTION_SOURCE_UNAUTHORIZED"


@pytest.mark.asyncio
async def test_tenant_a_cannot_use_tenant_b_registered_source(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-01: Tenant A cannot ingest records for a source registered only by Tenant B.
    """
    user_a = setup_tenant_and_user(live_pg_engine, f"Tenant A {uuid.uuid4()}", f"user_a_{uuid.uuid4()}@agency.gov", "Pass123!")
    user_b = setup_tenant_and_user(live_pg_engine, f"Tenant B {uuid.uuid4()}", f"user_b_{uuid.uuid4()}@agency.gov", "Pass123!")

    # Register source strictly for Tenant B
    register_source_channel(live_pg_engine, tenant_id=user_b["tenant_id"], channel_id="bravo_private_channel", is_authorized=True)

    token_a = await login_and_get_token(live_client, user_a["email"], user_a["password"])
    headers_a = {"Authorization": f"Bearer {token_a}", "X-Tenant-ID": str(user_a["tenant_id"])}

    payload_a = {
        "source_reference": "bravo_private_channel",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "attempt_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Tenant A trying to ingest into Tenant B feed.",
            }
        ],
    }

    res = await live_client.post("/api/v1/threat/ingest", json=payload_a, headers=headers_a)
    assert res.status_code == 403
    assert "SOURCE_NOT_REGISTERED" in res.json()["detail"]


# =============================================================================
# Test 3: SEC-THREAT-02 Atomic Batch Staging & Tamper Rollback Tests
# =============================================================================

@pytest.mark.asyncio
async def test_tamper_conflict_leaves_no_partial_batch_records(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-02: A tamper conflict on a later message must not commit previously staged
    messages or derived representations from the rejected batch.
    Files written during the failed batch must be cleaned up from disk.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Atomic Tamper Org {uuid.uuid4()}",
        email=f"atomic_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    register_source_channel(live_pg_engine, tenant_id=tenant_id, channel_id="atomic_channel", is_authorized=True)

    # 1. Ingest initial authentic message
    initial_payload = {
        "source_reference": "atomic_channel",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "msg_authentic_prior",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "Authentic original message content.",
            }
        ],
    }
    res_init = await live_client.post("/api/v1/threat/ingest", json=initial_payload, headers=headers)
    assert res_init.status_code == 201

    # 2. Ingest batch of 3 messages where:
    # - msg_new_1: valid new message
    # - msg_new_2: valid new message
    # - msg_authentic_prior: CONFLICTING tampered payload!
    tamper_batch = {
        "source_reference": "atomic_channel",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "msg_new_1",
                "source_sequence_id": 2,
                "broadcast_timestamp_utc": "2026-10-29T10:05:00Z",
                "raw_text": "New message one.",
            },
            {
                "message_id": "msg_new_2",
                "source_sequence_id": 3,
                "broadcast_timestamp_utc": "2026-10-29T10:10:00Z",
                "raw_text": "New message two.",
            },
            {
                "message_id": "msg_authentic_prior",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "TAMPERED ALTERED CONTENT FORGERY ATTEMPT",
            },
        ],
    }

    res_tamper = await live_client.post("/api/v1/threat/ingest", json=tamper_batch, headers=headers)
    assert res_tamper.status_code == 409
    assert "TAMPER_CONFLICT" in res_tamper.json()["detail"]

    # 3. CRITICAL ATOMICITY INVARIANT CHECK:
    # Neither msg_new_1 nor msg_new_2 must exist in the database!
    with live_pg_engine.begin() as conn:
        partial_messages = conn.execute(
            text("SELECT COUNT(*) FROM threat.source_messages WHERE tenant_id = :t_id AND message_id IN ('msg_new_1', 'msg_new_2')"),
            {"t_id": tenant_id},
        ).scalar()
        assert partial_messages == 0, "Partial batch messages were committed despite batch failure!"

        partial_derived = conn.execute(
            text("SELECT COUNT(*) FROM threat.derived_content_representations WHERE tenant_id = :t_id AND source_message_id IN ('msg_new_1', 'msg_new_2')"),
            {"t_id": tenant_id},
        ).scalar()
        assert partial_derived == 0, "Partial derived representations were committed despite batch failure!"

        partial_blobs = conn.execute(
            text("SELECT COUNT(*) FROM evidence.raw_evidence_blobs WHERE tenant_id = :t_id AND source_message_id IN ('msg_new_1', 'msg_new_2')"),
            {"t_id": tenant_id},
        ).scalar()
        assert partial_blobs == 0, "Partial raw evidence blobs were committed despite batch failure!"

        # Original message must remain 100% authentic and un-tampered
        original_blob = conn.execute(
            text("SELECT payload_sha256_hash FROM evidence.raw_evidence_blobs WHERE tenant_id = :t_id AND source_message_id = 'msg_authentic_prior'"),
            {"t_id": tenant_id},
        ).scalar()
        expected_sha = hashlib.sha256("Authentic original message content.".encode("utf-8")).hexdigest()
        assert original_blob == expected_sha

        # Job record must be marked FAILED with records_processed = 0
        failed_job = conn.execute(
            text("SELECT status, records_processed FROM app.ingestion_jobs WHERE tenant_id = :t_id AND status = 'FAILED'"),
            {"t_id": tenant_id},
        ).fetchone()
        assert failed_job[0] == "FAILED"
        assert failed_job[1] == 0


# =============================================================================
# Test 3b: SEC-THREAT-06 Channel Metadata Rollback & Update Regression Tests
# =============================================================================

@pytest.mark.asyncio
async def test_successful_ingestion_updates_channel_metadata(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-06: Verifies that a successful ingestion batch updates channel metadata
    (channel_title, channel_handle, updated_at_utc) in threat.source_channels.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Channel Metadata Success Org {uuid.uuid4()}",
        email=f"meta_ok_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    channel_id = f"meta_chan_{uuid.uuid4()}"
    register_source_channel(
        live_pg_engine,
        tenant_id=tenant_id,
        channel_id=channel_id,
        channel_title="Initial Channel Title",
        channel_handle="@initial_handle",
        is_authorized=True,
    )

    with live_pg_engine.begin() as conn:
        initial_ch = conn.execute(
            text("SELECT channel_title, channel_handle, updated_at_utc FROM threat.source_channels WHERE tenant_id = :t_id AND channel_id = :ch_id"),
            {"t_id": tenant_id, "ch_id": channel_id},
        ).fetchone()
        assert initial_ch[0] == "Initial Channel Title"
        assert initial_ch[1] == "@initial_handle"
        initial_updated_at = initial_ch[2]

    # Ingest a valid message and provide updated metadata
    update_payload = {
        "source_reference": channel_id,
        "source_type": "telegram",
        "channel_title": "Updated Intelligence Feed Title",
        "channel_handle": "@updated_feed_handle",
        "messages": [
            {
                "message_id": f"msg_meta_{uuid.uuid4()}",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T14:00:00Z",
                "raw_text": "Sample intelligence payload for metadata verification.",
            }
        ],
    }

    res = await live_client.post("/api/v1/threat/ingest", json=update_payload, headers=headers)
    assert res.status_code == 201
    job_data = res.json()
    assert job_data["status"] == "COMPLETED"
    assert job_data["records_processed"] == 1

    with live_pg_engine.begin() as conn:
        updated_ch = conn.execute(
            text("SELECT channel_title, channel_handle, updated_at_utc FROM threat.source_channels WHERE tenant_id = :t_id AND channel_id = :ch_id"),
            {"t_id": tenant_id, "ch_id": channel_id},
        ).fetchone()
        assert updated_ch[0] == "Updated Intelligence Feed Title"
        assert updated_ch[1] == "@updated_feed_handle"
        assert updated_ch[2] >= initial_updated_at


@pytest.mark.asyncio
async def test_tamper_conflict_preserves_original_channel_metadata(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-06: Verifies that when a tamper conflict occurs:
    1. Channel metadata attributes (channel_title, channel_handle, updated_at_utc) are strictly preserved (unmutated).
    2. Staged messages before the tamper conflict are rolled back from DB and filesystem.
    3. Job status is recorded as FAILED with records_processed = 0.
    4. INGESTION_TAMPER_CONFLICT audit event is committed in the outer transaction.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Tamper Metadata Rollback Org {uuid.uuid4()}",
        email=f"tamper_rollback_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    channel_id = f"chan_tamper_{uuid.uuid4()}"
    register_source_channel(
        live_pg_engine,
        tenant_id=tenant_id,
        channel_id=channel_id,
        channel_title="Original Trusted Title",
        channel_handle="@trusted_handle",
        is_authorized=True,
    )

    # 1. Ingest initial authentic message
    seed_msg_id = f"msg_seed_{uuid.uuid4()}"
    seed_payload = {
        "source_reference": channel_id,
        "source_type": "telegram",
        "messages": [
            {
                "message_id": seed_msg_id,
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "Authentic baseline content.",
            }
        ],
    }
    res_seed = await live_client.post("/api/v1/threat/ingest", json=seed_payload, headers=headers)
    assert res_seed.status_code == 201

    # Capture baseline channel state and timestamp
    with live_pg_engine.begin() as conn:
        baseline_ch = conn.execute(
            text("SELECT channel_title, channel_handle, updated_at_utc FROM threat.source_channels WHERE tenant_id = :t_id AND channel_id = :ch_id"),
            {"t_id": tenant_id, "ch_id": channel_id},
        ).fetchone()
        initial_title = baseline_ch[0]
        initial_handle = baseline_ch[1]
        initial_updated_at = baseline_ch[2]

    # 2. Ingest batch with new message followed by TAMPER CONFLICT message,
    # attempting to overwrite channel_title and channel_handle
    intermediate_msg_id = f"msg_interm_{uuid.uuid4()}"
    intermediate_raw_text = "Valid intermediate message staged before tamper conflict."
    tamper_batch_payload = {
        "source_reference": channel_id,
        "source_type": "telegram",
        "channel_title": "MALICIOUS FORGED CHANNEL TITLE OVERWRITE",
        "channel_handle": "@forged_malicious_handle",
        "messages": [
            {
                "message_id": intermediate_msg_id,
                "source_sequence_id": 2,
                "broadcast_timestamp_utc": "2026-10-29T10:05:00Z",
                "raw_text": intermediate_raw_text,
            },
            {
                "message_id": seed_msg_id,
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "TAMPERED CONFLICTING FORGERY CONTENT!",
            },
        ],
    }

    res_tamper = await live_client.post("/api/v1/threat/ingest", json=tamper_batch_payload, headers=headers)
    assert res_tamper.status_code == 409
    assert "TAMPER_CONFLICT" in res_tamper.json()["detail"]

    # 3. VERIFY METADATA IMMUTABILITY (SEC-THREAT-06):
    # Channel metadata must be strictly identical to baseline!
    with live_pg_engine.begin() as conn:
        current_ch = conn.execute(
            text("SELECT channel_title, channel_handle, updated_at_utc FROM threat.source_channels WHERE tenant_id = :t_id AND channel_id = :ch_id"),
            {"t_id": tenant_id, "ch_id": channel_id},
        ).fetchone()
        assert current_ch[0] == initial_title, f"Channel title was mutated! Expected '{initial_title}', got '{current_ch[0]}'"
        assert current_ch[1] == initial_handle, f"Channel handle was mutated! Expected '{initial_handle}', got '{current_ch[1]}'"
        assert current_ch[2] == initial_updated_at, f"Channel updated_at_utc was advanced! Expected '{initial_updated_at}', got '{current_ch[2]}'"

        # Verify staged intermediate message was rolled back from DB
        msg_exists = conn.execute(
            text("SELECT COUNT(*) FROM threat.source_messages WHERE tenant_id = :t_id AND message_id = :m_id"),
            {"t_id": tenant_id, "m_id": intermediate_msg_id},
        ).scalar()
        assert msg_exists == 0, "Staged message was committed despite tamper conflict!"

        repr_exists = conn.execute(
            text("SELECT COUNT(*) FROM threat.derived_content_representations WHERE tenant_id = :t_id AND source_message_id = :m_id"),
            {"t_id": tenant_id, "m_id": intermediate_msg_id},
        ).scalar()
        assert repr_exists == 0, "Staged derived representation was committed despite tamper conflict!"

        blob_exists = conn.execute(
            text("SELECT COUNT(*) FROM evidence.raw_evidence_blobs WHERE tenant_id = :t_id AND source_message_id = :m_id"),
            {"t_id": tenant_id, "m_id": intermediate_msg_id},
        ).scalar()
        assert blob_exists == 0, "Staged raw evidence blob was committed despite tamper conflict!"

        # Verify job record marked FAILED with records_processed = 0
        failed_job = conn.execute(
            text("SELECT job_id, status, records_processed, error_message FROM app.ingestion_jobs WHERE tenant_id = :t_id AND status = 'FAILED' ORDER BY created_at_utc DESC LIMIT 1"),
            {"t_id": tenant_id},
        ).fetchone()
        assert failed_job is not None
        assert failed_job[1] == "FAILED"
        assert failed_job[2] == 0
        assert "TAMPER_CONFLICT" in failed_job[3]
        failed_job_id = failed_job[0]

        # Verify INGESTION_TAMPER_CONFLICT audit event exists
        audit_event = conn.execute(
            text("SELECT action_type, correlation_id FROM audit.audit_event_records WHERE tenant_id = :t_id AND action_type = 'INGESTION_TAMPER_CONFLICT' AND correlation_id = :corr_id"),
            {"t_id": tenant_id, "corr_id": failed_job_id},
        ).fetchone()
        assert audit_event is not None
        assert audit_event[0] == "INGESTION_TAMPER_CONFLICT"

    # 4. Verify filesystem cleanup: staged file for intermediate_msg_id was unlinked
    evidence_store = LocalEvidenceStore()
    interm_sha = hashlib.sha256(intermediate_raw_text.encode("utf-8")).hexdigest()
    expected_staged_file = Path(evidence_store.base_dir) / str(tenant_id) / f"{intermediate_msg_id}_{interm_sha[:16]}.raw"
    assert not expected_staged_file.exists(), f"Staged evidence file was not unlinked from disk: {expected_staged_file}"


# =============================================================================
# Test 4: SEC-THREAT-03 In-Batch Duplicate ID Validation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_duplicate_conflicting_ids_within_request_rejected(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-03: In-batch duplicate message IDs with conflicting payloads must be
    rejected with HTTP 422 DUPLICATE_MESSAGE_ID_CONFLICT.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Duplicate Conflict Org {uuid.uuid4()}",
        email=f"dup_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    register_source_channel(live_pg_engine, tenant_id=tenant_id, channel_id="dup_test_channel", is_authorized=True)

    conflicting_batch = {
        "source_reference": "dup_test_channel",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "dup_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Payload version Alpha",
            },
            {
                "message_id": "dup_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Payload version Beta - CONFLICTING DUPLICATE",
            },
        ],
    }

    res = await live_client.post("/api/v1/threat/ingest", json=conflicting_batch, headers=headers)
    assert res.status_code == 422
    assert "DUPLICATE_MESSAGE_ID_CONFLICT" in res.json()["detail"]


@pytest.mark.asyncio
async def test_duplicate_identical_ids_within_request_handled_cleanly(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-03: In-batch duplicate message IDs with identical payloads must be
    safely collapsed in-memory without causing a PostgreSQL UniqueViolation or HTTP 500.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Duplicate Identical Org {uuid.uuid4()}",
        email=f"dup_ident_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    register_source_channel(live_pg_engine, tenant_id=tenant_id, channel_id="ident_test_channel", is_authorized=True)

    identical_dup_batch = {
        "source_reference": "ident_test_channel",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "ident_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Identical duplicate payload.",
            },
            {
                "message_id": "ident_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Identical duplicate payload.",
            },
        ],
    }

    res = await live_client.post("/api/v1/threat/ingest", json=identical_dup_batch, headers=headers)
    assert res.status_code == 201
    assert res.json()["status"] == "COMPLETED"
    assert res.json()["records_processed"] == 1


@pytest.mark.asyncio
async def test_cross_request_identical_retry_idempotency(live_pg_engine, live_client: AsyncClient):
    """
    Cross-request retry of an already-ingested identical batch must succeed idempotently.
    """
    user_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Retry Org {uuid.uuid4()}",
        email=f"retry_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
    )
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    register_source_channel(live_pg_engine, tenant_id=tenant_id, channel_id="retry_channel", is_authorized=True)

    batch = {
        "source_reference": "retry_channel",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "retry_msg_1",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T12:00:00Z",
                "raw_text": "Message to be retried.",
            }
        ],
    }

    res1 = await live_client.post("/api/v1/threat/ingest", json=batch, headers=headers)
    assert res1.status_code == 201

    res2 = await live_client.post("/api/v1/threat/ingest", json=batch, headers=headers)
    assert res2.status_code == 201
    assert res2.json()["status"] == "COMPLETED"
    assert res2.json()["records_processed"] == 1


# =============================================================================
# Test 5: Cross-Tenant Threat Search & Thread Isolation (Multi-Tenancy)
# =============================================================================

@pytest.mark.asyncio
async def test_cross_tenant_search_and_thread_isolation(live_pg_engine, live_client: AsyncClient):
    """
    Verify:
    1. Tenant A cannot see Tenant B's threat records in search queries.
    2. Tenant A requesting Tenant B's thread detail receives HTTP 404.
    """
    user_alpha = setup_tenant_and_user(live_pg_engine, "Tenant Alpha", f"alpha_{uuid.uuid4()}@agency.gov", "AlphaPass123!")
    user_bravo = setup_tenant_and_user(live_pg_engine, "Tenant Bravo", f"bravo_{uuid.uuid4()}@agency.gov", "BravoPass123!")

    register_source_channel(live_pg_engine, user_alpha["tenant_id"], "alpha_intel_feed", is_authorized=True)
    register_source_channel(live_pg_engine, user_bravo["tenant_id"], "bravo_intel_feed", is_authorized=True)

    token_alpha = await login_and_get_token(live_client, user_alpha["email"], user_alpha["password"])
    headers_alpha = {"Authorization": f"Bearer {token_alpha}", "X-Tenant-ID": str(user_alpha["tenant_id"])}

    token_bravo = await login_and_get_token(live_client, user_bravo["email"], user_bravo["password"])
    headers_bravo = {"Authorization": f"Bearer {token_bravo}", "X-Tenant-ID": str(user_bravo["tenant_id"])}

    alpha_payload = {
        "source_reference": "alpha_intel_feed",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "alpha_msg_100",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "ALPHA CONFIDENTIAL: Cobalt Strike beacon discovered on internal subnet 10.20.30.0/24",
                "message_thread_id": "thread_alpha_c2",
            }
        ],
    }
    res_a = await live_client.post("/api/v1/threat/ingest", json=alpha_payload, headers=headers_alpha)
    assert res_a.status_code == 201

    bravo_payload = {
        "source_reference": "bravo_intel_feed",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "bravo_msg_200",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T11:00:00Z",
                "raw_text": "BRAVO SECRET: LockBit 3.0 ransomware affiliate negotiations in progress.",
                "message_thread_id": "thread_bravo_ransom",
            }
        ],
    }
    res_b = await live_client.post("/api/v1/threat/ingest", json=bravo_payload, headers=headers_bravo)
    assert res_b.status_code == 201

    # Search Isolation
    res_a_search1 = await live_client.get("/api/v1/threat/search?q=Cobalt", headers=headers_alpha)
    assert res_a_search1.status_code == 200
    assert res_a_search1.json()["total_results"] == 1

    res_a_search2 = await live_client.get("/api/v1/threat/search?q=LockBit", headers=headers_alpha)
    assert res_a_search2.status_code == 200
    assert res_a_search2.json()["total_results"] == 0

    res_b_search1 = await live_client.get("/api/v1/threat/search?q=LockBit", headers=headers_bravo)
    assert res_b_search1.status_code == 200
    assert res_b_search1.json()["total_results"] == 1

    res_b_search2 = await live_client.get("/api/v1/threat/search?q=Cobalt", headers=headers_bravo)
    assert res_b_search2.status_code == 200
    assert res_b_search2.json()["total_results"] == 0

    # Thread Access Isolation
    res_cross = await live_client.get("/api/v1/threat/threads/bravo_intel_feed/thread_bravo_ransom", headers=headers_alpha)
    assert res_cross.status_code == 404


# =============================================================================
# Test 6: Zero Raw Evidence Leakage in Presentation & Search
# =============================================================================

@pytest.mark.asyncio
async def test_threat_search_zero_raw_evidence_leakage(live_pg_engine, live_client: AsyncClient):
    """
    Search and thread responses must strictly exclude raw evidence filesystem paths,
    locators, and raw binary bytes.
    """
    user_info = setup_tenant_and_user(live_pg_engine, "Leakage Org", f"leak_{uuid.uuid4()}@agency.gov", "Pass123!")
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    register_source_channel(live_pg_engine, tenant_id=tenant_id, channel_id="leak_feed", is_authorized=True)

    payload = {
        "source_reference": "leak_feed",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "probe_msg_01",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "Investigation observable: darkweb onion portal http://classified.onion/repo",
            }
        ],
    }
    await live_client.post("/api/v1/threat/ingest", json=payload, headers=headers)

    res_search = await live_client.get("/api/v1/threat/search?q=classified", headers=headers)
    assert res_search.status_code == 200
    item = res_search.json()["items"][0]

    assert item["message_id"] == "probe_msg_01"
    assert "sanitized_text" in item
    assert "sanitization_flags" in item
    assert "content_sha256" in item

    # STRICT INVARIANT: Prohibit raw evidence paths / bytes
    assert "payload_storage_locator" not in item
    assert "storage_relative_path" not in item
    assert "raw_bytes" not in item
    assert "raw_payload" not in item
    assert "file_path" not in item


# =============================================================================
# Test 7: Thread Detail Chronological Sequence
# =============================================================================

@pytest.mark.asyncio
async def test_threat_thread_detail_chronology(live_pg_engine, live_client: AsyncClient):
    """
    Verify chronological sorting of conversation threads and reply-tree references.
    """
    user_info = setup_tenant_and_user(live_pg_engine, "Chrono Org", f"chrono_{uuid.uuid4()}@agency.gov", "Pass123!")
    tenant_id = user_info["tenant_id"]
    token = await login_and_get_token(live_client, user_info["email"], user_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    register_source_channel(live_pg_engine, tenant_id=tenant_id, channel_id="chrono_channel", is_authorized=True)

    thread_payload = {
        "source_reference": "chrono_channel",
        "source_type": "telegram",
        "channel_title": "Thread Chronology Channel",
        "messages": [
            {
                "message_id": "thread_msg_01",
                "source_sequence_id": 10,
                "broadcast_timestamp_utc": "2026-10-29T08:00:00Z",
                "message_thread_id": "target_thread_999",
                "raw_text": "Step 1: Reconnaissance executed on target network.",
            },
            {
                "message_id": "thread_msg_02",
                "source_sequence_id": 20,
                "broadcast_timestamp_utc": "2026-10-29T08:15:00Z",
                "message_thread_id": "target_thread_999",
                "reply_to_message_id": "thread_msg_01",
                "raw_text": "Step 2: Initial access granted via phishing hook.",
            },
            {
                "message_id": "thread_msg_03",
                "source_sequence_id": 30,
                "broadcast_timestamp_utc": "2026-10-29T08:30:00Z",
                "message_thread_id": "target_thread_999",
                "reply_to_message_id": "thread_msg_02",
                "raw_text": "Step 3: Exfiltration stage completed.",
            },
        ],
    }
    await live_client.post("/api/v1/threat/ingest", json=thread_payload, headers=headers)

    res_thread = await live_client.get("/api/v1/threat/threads/chrono_channel/target_thread_999", headers=headers)
    assert res_thread.status_code == 200
    data = res_thread.json()
    assert data["total_messages"] == 3
    assert [m["source_sequence_id"] for m in data["messages"]] == [10, 20, 30]
    assert data["messages"][1]["reply_to_message_id"] == "thread_msg_01"


# =============================================================================
# Test 8: Role-Based Access Control (RBAC) Permissions
# =============================================================================

@pytest.mark.asyncio
async def test_threat_rbac_permissions(live_pg_engine, live_client: AsyncClient):
    """
    Verify:
    1. READ_ONLY_ANALYST cannot ingest records (missing ingest:submit -> HTTP 403).
    2. READ_ONLY_ANALYST CAN execute searches (search:query permitted -> HTTP 200).
    3. READ_ONLY_ANALYST CAN read thread details (thread:read permitted -> HTTP 200).
    """
    org_id = uuid.uuid4()
    inv_user_id = uuid.uuid4()
    ro_user_id = uuid.uuid4()
    password = "CommonPassword123!"
    pw_hash = hash_password(password)

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status) VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE')"),
            {"t_id": org_id, "name": f"RBAC Org {org_id}"},
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES 
                (:inv_id, :inv_email, 'Lead Investigator', :pw_hash, 'ACTIVE'),
                (:ro_id, :ro_email, 'Read Only Analyst', :pw_hash, 'ACTIVE')
            """),
            {
                "inv_id": inv_user_id,
                "inv_email": f"inv_{org_id}@agency.gov",
                "ro_id": ro_user_id,
                "ro_email": f"ro_{org_id}@agency.gov",
                "pw_hash": pw_hash,
            },
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES 
                (gen_random_uuid(), :t_id, :inv_id, 'INVESTIGATOR', 'ACTIVE'),
                (gen_random_uuid(), :t_id, :ro_id, 'READ_ONLY_ANALYST', 'ACTIVE')
            """),
            {"t_id": org_id, "inv_id": inv_user_id, "ro_id": ro_user_id},
        )

    register_source_channel(live_pg_engine, tenant_id=org_id, channel_id="rbac_feed", is_authorized=True)

    token_inv = await login_and_get_token(live_client, f"inv_{org_id}@agency.gov", password)
    headers_inv = {"Authorization": f"Bearer {token_inv}", "X-Tenant-ID": str(org_id)}

    seed_payload = {
        "source_reference": "rbac_feed",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "rbac_seed_01",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "message_thread_id": "thread_rbac_1",
                "raw_text": "Sample intelligence observable for RBAC validation.",
            }
        ],
    }
    res_inv = await live_client.post("/api/v1/threat/ingest", json=seed_payload, headers=headers_inv)
    assert res_inv.status_code == 201

    token_ro = await login_and_get_token(live_client, f"ro_{org_id}@agency.gov", password)
    headers_ro = {"Authorization": f"Bearer {token_ro}", "X-Tenant-ID": str(org_id)}

    ro_payload = {
        "source_reference": "rbac_feed",
        "source_type": "telegram",
        "messages": [
            {
                "message_id": "ro_unauthorized_02",
                "source_sequence_id": 2,
                "broadcast_timestamp_utc": "2026-10-29T10:05:00Z",
                "raw_text": "Unauthorized submission attempt.",
            }
        ],
    }
    res_ro = await live_client.post("/api/v1/threat/ingest", json=ro_payload, headers=headers_ro)
    assert res_ro.status_code == 403
    assert "ingest:submit" in res_ro.json()["detail"]

    res_ro_search = await live_client.get("/api/v1/threat/search?q=observable", headers=headers_ro)
    assert res_ro_search.status_code == 200

    res_ro_thread = await live_client.get("/api/v1/threat/threads/rbac_feed/thread_rbac_1", headers=headers_ro)
    assert res_ro_thread.status_code == 200


# =============================================================================
# Test 9: RLS Enforcement on Threat Tables Under tti_app_role
# =============================================================================

@pytest.mark.asyncio
async def test_threat_rls_cannot_be_bypassed_by_app_role(live_pg_engine):
    """
    Assert that threat tables enforce fail-closed behavior under tti_app_role.
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
            {"ta": tenant_a, "na": f"RLS Org A {tenant_a}", "tb": tenant_b, "nb": f"RLS Org B {tenant_b}"},
        )
        conn.execute(
            text("""
            INSERT INTO threat.source_channels (tenant_id, channel_id, channel_title, source_type, is_authorized)
            VALUES 
                (:ta, 'ch_a', 'Channel A', 'telegram', true),
                (:tb, 'ch_b', 'Channel B', 'telegram', true)
            ON CONFLICT (tenant_id, channel_id) DO NOTHING;
            """),
            {"ta": tenant_a, "tb": tenant_b},
        )

    with live_pg_engine.connect() as conn:
        conn.execute(text("SET ROLE tti_app_role;"))

        # 1. Missing tenant context -> 0 rows returned
        conn.execute(text("RESET app.current_tenant_id;"))
        rows_empty = conn.execute(text("SELECT channel_id FROM threat.source_channels WHERE channel_id IN ('ch_a', 'ch_b');")).fetchall()
        assert len(rows_empty) == 0

        # 2. Bound to Tenant A -> strictly Tenant A visible
        conn.execute(text("SELECT set_config('app.current_tenant_id', :ta, true);"), {"ta": str(tenant_a)})
        rows_ta = conn.execute(text("SELECT channel_id FROM threat.source_channels WHERE channel_id IN ('ch_a', 'ch_b');")).fetchall()
        assert len(rows_ta) == 1
        assert rows_ta[0][0] == "ch_a"

        # 3. Direct insert for Tenant B while bound to Tenant A -> rejected by RLS WITH CHECK
        with pytest.raises(Exception) as exc_info:
            conn.execute(
                text("""
                INSERT INTO threat.source_channels (tenant_id, channel_id, channel_title, source_type, is_authorized)
                VALUES (:tb, 'ch_b_forged', 'Forged Channel', 'telegram', true);
                """),
                {"tb": tenant_b},
            )
        assert "row-level security policy" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

        conn.rollback()
        conn.execute(text("RESET ROLE;"))


# =============================================================================
# Test 10: Phase 4 Source Channel Administration Tests (SEC-THREAT-05)
# =============================================================================

@pytest.mark.asyncio
async def test_channel_admin_registration_defaults_to_unauthorized(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-05: Admin can register a new source channel.
    Invariant: is_authorized defaults to False.
    Emits CHANNEL_REGISTERED audit event.
    """
    admin_info = setup_tenant_and_user(
        live_pg_engine,
        org_name=f"Channel Admin Org {uuid.uuid4()}",
        email=f"admin_{uuid.uuid4()}@agency.gov",
        password="ValidPassword123!",
        role="TENANT_ADMIN",
    )
    tenant_id = admin_info["tenant_id"]
    token = await login_and_get_token(live_client, admin_info["email"], admin_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    channel_id = f"chan_{str(uuid.uuid4())[:8]}"
    register_payload = {
        "channel_id": channel_id,
        "channel_title": "Dark Market Monitor",
        "channel_handle": "@dark_market",
        "source_type": "telegram",
    }

    res = await live_client.post("/api/v1/threat/channels", json=register_payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["channel_id"] == channel_id
    assert data["channel_title"] == "Dark Market Monitor"
    assert data["channel_handle"] == "@dark_market"
    assert data["source_type"] == "telegram"
    assert data["is_authorized"] is False
    assert data["tenant_id"] == str(tenant_id)

    # Verify database state
    with live_pg_engine.begin() as conn:
        db_ch = conn.execute(
            text("SELECT is_authorized, channel_title FROM threat.source_channels WHERE tenant_id = :t_id AND channel_id = :ch_id"),
            {"t_id": tenant_id, "ch_id": channel_id},
        ).fetchone()
        assert db_ch is not None
        assert db_ch[0] is False
        assert db_ch[1] == "Dark Market Monitor"

        # Verify CHANNEL_REGISTERED audit event
        ch_hash = hashlib.sha256(channel_id.encode("utf-8")).hexdigest()
        audit = conn.execute(
            text("SELECT action_type, details FROM audit.audit_event_records WHERE tenant_id = :t_id AND target_identifier_hash = :h AND action_type = 'CHANNEL_REGISTERED'"),
            {"t_id": tenant_id, "h": ch_hash},
        ).fetchone()
        assert audit is not None
        assert audit[0] == "CHANNEL_REGISTERED"
        assert audit[1]["is_authorized"] is False


@pytest.mark.asyncio
async def test_channel_admin_duplicate_registration_rejected(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-05: Duplicate channel registration within the same tenant must return HTTP 409 Conflict.
    Same channel_id registered under a different tenant must succeed independently.
    """
    tenant_a = setup_tenant_and_user(live_pg_engine, f"Tenant A {uuid.uuid4()}", f"admin_a_{uuid.uuid4()}@a.gov", "Pass123!", role="TENANT_ADMIN")
    tenant_b = setup_tenant_and_user(live_pg_engine, f"Tenant B {uuid.uuid4()}", f"admin_b_{uuid.uuid4()}@b.gov", "Pass123!", role="TENANT_ADMIN")

    token_a = await login_and_get_token(live_client, tenant_a["email"], tenant_a["password"])
    token_b = await login_and_get_token(live_client, tenant_b["email"], tenant_b["password"])

    headers_a = {"Authorization": f"Bearer {token_a}", "X-Tenant-ID": str(tenant_a["tenant_id"])}
    headers_b = {"Authorization": f"Bearer {token_b}", "X-Tenant-ID": str(tenant_b["tenant_id"])}

    shared_channel_id = f"shared_{str(uuid.uuid4())[:8]}"
    payload = {
        "channel_id": shared_channel_id,
        "channel_title": "Shared Observable Channel",
        "source_type": "telegram",
    }

    # 1. First registration in Tenant A -> 201 Created
    res1 = await live_client.post("/api/v1/threat/channels", json=payload, headers=headers_a)
    assert res1.status_code == 201

    # 2. Duplicate registration in Tenant A -> 409 Conflict
    res2 = await live_client.post("/api/v1/threat/channels", json=payload, headers=headers_a)
    assert res2.status_code == 409
    assert "CHANNEL_ALREADY_EXISTS" in res2.json()["detail"]

    # 3. Same channel_id in Tenant B -> 201 Created (tenant siloed isolation)
    res3 = await live_client.post("/api/v1/threat/channels", json=payload, headers=headers_b)
    assert res3.status_code == 201
    assert res3.json()["tenant_id"] == str(tenant_b["tenant_id"])


@pytest.mark.asyncio
async def test_non_admin_cannot_register_or_update_channels(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-05: Users lacking PERM_ORG_MANAGE (e.g. INVESTIGATOR, READ_ONLY_ANALYST)
    must receive HTTP 403 Forbidden on POST and PATCH.
    """
    user_inv = setup_tenant_and_user(live_pg_engine, f"Inv Org {uuid.uuid4()}", f"inv_{uuid.uuid4()}@agency.gov", "Pass123!", role="INVESTIGATOR")
    tenant_id = user_inv["tenant_id"]
    token_inv = await login_and_get_token(live_client, user_inv["email"], user_inv["password"])
    headers_inv = {"Authorization": f"Bearer {token_inv}", "X-Tenant-ID": str(tenant_id)}

    # POST rejected
    res_post = await live_client.post(
        "/api/v1/threat/channels",
        json={"channel_id": "inv_chan", "channel_title": "Unauthorized attempt"},
        headers=headers_inv,
    )
    assert res_post.status_code == 403
    assert "org:manage" in res_post.json()["detail"]

    # PATCH rejected
    res_patch = await live_client.patch(
        "/api/v1/threat/channels/some_chan",
        json={"is_authorized": True},
        headers=headers_inv,
    )
    assert res_patch.status_code == 403
    assert "org:manage" in res_patch.json()["detail"]


@pytest.mark.asyncio
async def test_patch_channel_metadata_and_authorization_transitions(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-05:
    1. Updating is_authorized: False -> True emits CHANNEL_AUTHORIZATION_GRANTED.
    2. Updating is_authorized: True -> False emits CHANNEL_AUTHORIZATION_REVOKED.
    3. Updating metadata emits CHANNEL_METADATA_UPDATED.
    4. Empty update returns HTTP 400.
    5. Unknown channel returns HTTP 404.
    """
    admin_info = setup_tenant_and_user(live_pg_engine, f"Authz Transition Org {uuid.uuid4()}", f"admin_tz_{uuid.uuid4()}@agency.gov", "Pass123!", role="TENANT_ADMIN")
    tenant_id = admin_info["tenant_id"]
    token = await login_and_get_token(live_client, admin_info["email"], admin_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    channel_id = f"chan_tz_{str(uuid.uuid4())[:8]}"
    # Register channel (defaults to is_authorized=False)
    reg_res = await live_client.post(
        "/api/v1/threat/channels",
        json={"channel_id": channel_id, "channel_title": "Initial Title", "channel_handle": "@initial"},
        headers=headers,
    )
    assert reg_res.status_code == 201
    assert reg_res.json()["is_authorized"] is False

    # 1. Update metadata only
    patch_meta = await live_client.patch(
        f"/api/v1/threat/channels/{channel_id}",
        json={"channel_title": "Updated Title Alpha", "channel_handle": "@updated_alpha"},
        headers=headers,
    )
    assert patch_meta.status_code == 200
    assert patch_meta.json()["channel_title"] == "Updated Title Alpha"
    assert patch_meta.json()["channel_handle"] == "@updated_alpha"
    assert patch_meta.json()["is_authorized"] is False

    # 2. Grant authorization (False -> True)
    patch_grant = await live_client.patch(
        f"/api/v1/threat/channels/{channel_id}",
        json={"is_authorized": True},
        headers=headers,
    )
    assert patch_grant.status_code == 200
    assert patch_grant.json()["is_authorized"] is True

    # 3. Revoke authorization (True -> False)
    patch_revoke = await live_client.patch(
        f"/api/v1/threat/channels/{channel_id}",
        json={"is_authorized": False},
        headers=headers,
    )
    assert patch_revoke.status_code == 200
    assert patch_revoke.json()["is_authorized"] is False

    # 4. Empty update returns HTTP 400
    patch_empty = await live_client.patch(
        f"/api/v1/threat/channels/{channel_id}",
        json={},
        headers=headers,
    )
    assert patch_empty.status_code == 400
    assert "NO_UPDATES_PROVIDED" in patch_empty.json()["detail"]

    # 5. Non-existent channel returns HTTP 404
    patch_404 = await live_client.patch(
        "/api/v1/threat/channels/nonexistent_channel_id",
        json={"channel_title": "Nope"},
        headers=headers,
    )
    assert patch_404.status_code == 404
    assert "CHANNEL_NOT_FOUND" in patch_404.json()["detail"]

    # Verify audit events
    with live_pg_engine.begin() as conn:
        ch_hash = hashlib.sha256(channel_id.encode("utf-8")).hexdigest()
        audit_types = conn.execute(
            text("SELECT action_type FROM audit.audit_event_records WHERE tenant_id = :t_id AND target_identifier_hash = :h ORDER BY event_timestamp_utc ASC"),
            {"t_id": tenant_id, "h": ch_hash},
        ).fetchall()
        actions = [a[0] for a in audit_types]
        assert "CHANNEL_REGISTERED" in actions
        assert "CHANNEL_METADATA_UPDATED" in actions
        assert "CHANNEL_AUTHORIZATION_GRANTED" in actions
        assert "CHANNEL_AUTHORIZATION_REVOKED" in actions


@pytest.mark.asyncio
async def test_cross_tenant_channel_isolation_and_listing(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-05:
    1. GET /api/v1/threat/channels returns ONLY caller's tenant channels.
    2. Read-only analysts can list channels (PERM_INGEST_READ).
    3. Cross-tenant PATCH returns 404.
    """
    user_a = setup_tenant_and_user(live_pg_engine, f"Tenant A {uuid.uuid4()}", f"admin_a_{uuid.uuid4()}@a.gov", "Pass123!", role="TENANT_ADMIN")
    user_b = setup_tenant_and_user(live_pg_engine, f"Tenant B {uuid.uuid4()}", f"analyst_b_{uuid.uuid4()}@b.gov", "Pass123!", role="READ_ONLY_ANALYST")

    token_a = await login_and_get_token(live_client, user_a["email"], user_a["password"])
    token_b = await login_and_get_token(live_client, user_b["email"], user_b["password"])

    headers_a = {"Authorization": f"Bearer {token_a}", "X-Tenant-ID": str(user_a["tenant_id"])}
    headers_b = {"Authorization": f"Bearer {token_b}", "X-Tenant-ID": str(user_b["tenant_id"])}

    # Register 2 channels in Tenant A
    chan_a1 = f"chan_a1_{str(uuid.uuid4())[:8]}"
    chan_a2 = f"chan_a2_{str(uuid.uuid4())[:8]}"
    await live_client.post("/api/v1/threat/channels", json={"channel_id": chan_a1, "channel_title": "Channel A1"}, headers=headers_a)
    await live_client.post("/api/v1/threat/channels", json={"channel_id": chan_a2, "channel_title": "Channel A2"}, headers=headers_a)

    # List channels as Tenant B (READ_ONLY_ANALYST) -> must see 0 channels
    res_b_list = await live_client.get("/api/v1/threat/channels", headers=headers_b)
    assert res_b_list.status_code == 200
    assert res_b_list.json()["total_channels"] == 0
    assert len(res_b_list.json()["channels"]) == 0

    # Cross-tenant PATCH: Tenant B admin cannot update Tenant A channel
    user_b_admin = setup_tenant_and_user(live_pg_engine, f"Tenant B Admin {uuid.uuid4()}", f"admin_b_{uuid.uuid4()}@b.gov", "Pass123!", role="TENANT_ADMIN")
    token_b_admin = await login_and_get_token(live_client, user_b_admin["email"], user_b_admin["password"])
    headers_b_admin = {"Authorization": f"Bearer {token_b_admin}", "X-Tenant-ID": str(user_b_admin["tenant_id"])}

    cross_patch = await live_client.patch(
        f"/api/v1/threat/channels/{chan_a1}",
        json={"is_authorized": True},
        headers=headers_b_admin,
    )
    assert cross_patch.status_code == 404
    assert "CHANNEL_NOT_FOUND" in cross_patch.json()["detail"]


@pytest.mark.asyncio
async def test_ingestion_fails_when_unauthorized_and_succeeds_after_admin_enables(live_pg_engine, live_client: AsyncClient):
    """
    SEC-THREAT-05 & SEC-THREAT-01 integration:
    1. Admin registers channel -> is_authorized=False.
    2. Ingestion attempt returns HTTP 403 SOURCE_UNAUTHORIZED.
    3. Admin patches channel to is_authorized=True.
    4. Ingestion attempt succeeds with HTTP 201 COMPLETED.
    """
    admin_info = setup_tenant_and_user(live_pg_engine, f"Ingest Lifecycle Org {uuid.uuid4()}", f"admin_ing_{uuid.uuid4()}@agency.gov", "Pass123!", role="TENANT_ADMIN")
    tenant_id = admin_info["tenant_id"]
    token = await login_and_get_token(live_client, admin_info["email"], admin_info["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    channel_id = f"chan_ing_{str(uuid.uuid4())[:8]}"
    # 1. Register channel
    res_reg = await live_client.post(
        "/api/v1/threat/channels",
        json={"channel_id": channel_id, "channel_title": "Onboarding Feed"},
        headers=headers,
    )
    assert res_reg.status_code == 201
    assert res_reg.json()["is_authorized"] is False

    # 2. Ingestion while unauthorized fails
    ingest_payload = {
        "source_reference": channel_id,
        "source_type": "telegram",
        "messages": [
            {
                "message_id": f"msg_{str(uuid.uuid4())[:8]}",
                "source_sequence_id": 1,
                "broadcast_timestamp_utc": "2026-10-29T10:00:00Z",
                "raw_text": "Sample intelligence payload before authorization.",
            }
        ],
    }
    res_ing_blocked = await live_client.post("/api/v1/threat/ingest", json=ingest_payload, headers=headers)
    assert res_ing_blocked.status_code == 403
    assert "SOURCE_UNAUTHORIZED" in res_ing_blocked.json()["detail"]

    # 3. Explicit authorization via PATCH
    res_patch = await live_client.patch(
        f"/api/v1/threat/channels/{channel_id}",
        json={"is_authorized": True},
        headers=headers,
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["is_authorized"] is True

    # 4. Ingestion after authorization succeeds
    res_ing_ok = await live_client.post("/api/v1/threat/ingest", json=ingest_payload, headers=headers)
    assert res_ing_ok.status_code == 201
    assert res_ing_ok.json()["status"] == "COMPLETED"
    assert res_ing_ok.json()["records_processed"] == 1

