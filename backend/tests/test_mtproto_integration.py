"""Telegram MTProto integration test suite.

Telegram transport is MOCKED (no live network, no auth); the ingestion,
sanitization, evidence, AI detection, and dashboard layers are the REAL
production pipeline exercised against live PostgreSQL.

Validates:
1. Configuration loading and credential validation.
2. Connector health states and authorization guards.
3. Telethon message mapping (no media download).
4. Full collection cycle: MTProto -> ingest -> AI analysis -> database.
5. Idempotent re-collection (no duplicate records) + incremental checkpoints.
6. Edit detection with immutable raw evidence.
7. Dashboard endpoint returns real database statistics (RBAC enforced).
8. Bot API compatibility is preserved.
"""

import hashlib
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text

from app.core.config import get_settings
from app.core.errors import ConnectorNotConfiguredError
from app.core.security import hash_password
from app.main import app
from app.connectors.telegram.models import TelegramMessagePayload
from app.services.mtproto_collector import (
    MTProtoCollectorService,
    compare_edits,
    composite_message_id,
    get_mtproto_collector,
)

settings = get_settings()

TEST_FRAUD_TEXT = "Your KYC is expired, click hxxps://bank-verify[.]example/login to update now"


def _make_photo_media():
    """Build a genuine Telethon MessageMediaPhoto with a lightweight FakePhoto."""
    from app.connectors.telegram.mtproto import MessageMediaPhoto

    if MessageMediaPhoto is None:  # telethon unavailable
        return None
    fake_photo = type("FakePhoto", (), {"id": 777, "sizes": [type("S", (), {"size": 12345})()]})()
    return MessageMediaPhoto(photo=fake_photo)


class FakeTelethonMessage:
    """Minimal stand-in for a Telethon Message."""

    def __init__(
        self,
        message_id: int,
        text: str,
        sender_username: Optional[str] = "threat_actor",
        sender_id: int = 987654321,
        has_photo: bool = False,
    ) -> None:
        self.id = message_id
        self.message = text
        self.date = datetime.now(timezone.utc)
        self.edit_date = None
        self.sender = type("Sender", (), {"id": sender_id, "username": sender_username})()
        self.views = 42
        self.media = (
            _make_photo_media()
            if has_photo
            else None
        )
        self.reply_to_msg_id = None
        self.forward = None
        self.action = None
        self.chat_id = 123456789
        self.chat = type("Chat", (), {"title": "Fake Threat Channel"})()


class FakeMTProtoConnector:
    """In-memory MTProto connector emulating authorized collection."""

    def __init__(self, messages: Optional[List[FakeTelethonMessage]] = None) -> None:
        self._messages = messages or []
        self._connected = True
        self.disconnect_called = False

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self.disconnect_called = True
        self._connected = False

    async def health_check(self):
        """Mimic the real connector contract for the status endpoint."""
        from app.connectors.base import ConnectorHealth, ConnectorStatus

        return ConnectorHealth(
            connector_id="telegram-mtproto-fake",
            status=ConnectorStatus.HEALTHY if self._connected else ConnectorStatus.DISCONNECTED,
            message="Fake MTProto connector (test double).",
            is_live_collection_active=False,
            last_checked_utc=datetime.now(timezone.utc).isoformat(),
            metadata={
                "authenticated": self._connected,
                "telethon_installed": True,
                "account_username": "fake_collector",
                "last_connected_utc": None,
                "last_sync_utc": None,
            },
        )

    async def collect_channel_messages(
        self,
        tenant_id: str,
        channel_identifier: str,
        limit: int = 50,
        offset_id: int = 0,
    ) -> List[TelegramMessagePayload]:
        """Delegate mapping to the REAL connector to exercise production code."""
        from app.connectors.telegram.mtproto import MTProtoTelegramConnector

        mapper = MTProtoTelegramConnector()
        selected = [m for m in self._messages if m.id > offset_id][:limit]
        return [mapper._map_message(m, channel_id=m.chat_id, channel_title=m.chat.title) for m in selected]


def _run(coro):
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

# ============================================================================
# Fixtures & helpers (live PostgreSQL, mocked Telegram transport)
# ============================================================================


@pytest.fixture(scope="module")
def live_pg_engine():
    """Verify live PostgreSQL availability; skip suite if unreachable."""
    engine = create_engine(settings.sync_database_url, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1;"))
        yield engine
        engine.dispose()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Live PostgreSQL unreachable ({type(exc).__name__}); skipping MTProto tests")


@pytest_asyncio.fixture
async def live_client(live_pg_engine) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def setup_tenant_and_user(live_pg_engine, role: str = "INVESTIGATOR") -> Dict[str, Any]:
    """Provision a clean test tenant, user, and membership."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    email = f"mtproto_{uuid.uuid4()}@agency.gov"
    password = "ValidPassword123!"
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE')
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"t_id": tenant_id, "name": f"MTProto Test Org {uuid.uuid4()}"},
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, :email, 'MTProto Agent', :pw_hash, 'ACTIVE')
            """),
            {"u_id": user_id, "email": email, "pw_hash": hash_password(password)},
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES (gen_random_uuid(), :t_id, :u_id, :role, 'ACTIVE')
            """),
            {"t_id": tenant_id, "u_id": user_id, "role": role},
        )
    return {"tenant_id": tenant_id, "user_id": user_id, "email": email, "password": password}


def register_source_channel(
    live_pg_engine, tenant_id, channel_id: str, handle: Optional[str], authorized: bool = True
) -> None:
    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO threat.source_channels
                (tenant_id, channel_id, channel_title, channel_handle, source_type, is_authorized, created_at_utc, updated_at_utc)
            VALUES
                (:t_id, :ch_id, :title, :handle, 'telegram', :authz, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, channel_id) DO UPDATE SET is_authorized = :authz;
            """),
            {
                "t_id": tenant_id,
                "ch_id": channel_id,
                "title": f"MTProto Channel {channel_id}",
                "handle": handle,
                "authz": authorized,
            },
        )


async def login_and_get_token(client: AsyncClient, email: str, password: str) -> str:
    res = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]



# ============================================================================
# Test 1: Configuration, credential validation, message mapping
# ============================================================================


def test_mtproto_configuration_loading():
    """api_id/api_hash load from environment; no credentials hardcoded in source."""
    api_id = os.environ.get("TTI_TELEGRAM_API_ID") or settings.TTI_TELEGRAM_API_ID
    api_hash = os.environ.get("TTI_TELEGRAM_API_HASH") or settings.TTI_TELEGRAM_API_HASH
    assert settings.mtproto_credentials_configured == bool(api_id and api_hash)

    connector_src = (Path(__file__).resolve().parent.parent / "app" / "connectors" / "telegram" / "mtproto.py").read_text(encoding="utf-8")
    assert "51a76b8435bc44e52729c629ed3a8923" not in connector_src
    assert "34891529" not in connector_src


def test_connector_health_without_session():
    """No session configured -> connector reports DISABLED without connecting."""
    from app.connectors.telegram.mtproto import MTProtoTelegramConnector

    health = _run(MTProtoTelegramConnector().health_check())
    assert health.status.value in ("disabled", "unconfigured")
    assert health.is_live_collection_active is False


def test_connector_collect_requires_authorization():
    """Collection without an authorized session raises a domain error (no network)."""
    from app.connectors.telegram.mtproto import MTProtoTelegramConnector

    with pytest.raises(ConnectorNotConfiguredError):
        _run(MTProtoTelegramConnector().collect_channel_messages("t", "@x"))


def test_message_mapping_no_media_download():
    """Telethon message maps to normalized payload; media is metadata-only."""
    from app.connectors.telegram.mtproto import MTProtoTelegramConnector

    connector = MTProtoTelegramConnector()
    msg = FakeTelethonMessage(101, TEST_FRAUD_TEXT, has_photo=True)
    payload = connector._map_message(msg, channel_id=123456789, channel_title="Fake Threat Channel")

    assert payload.message_id == 101
    assert payload.raw_text == TEST_FRAUD_TEXT
    assert payload.sender_username == "threat_actor"
    assert payload.media is not None
    assert payload.media.file_type == "photo"
    assert payload.media.mime_type == "image/jpeg"
    assert not hasattr(connector, "download_media")  # metadata-only contract


def test_composite_message_id_stability():
    assert composite_message_id("@chan", 42) == "@chan:42"
    assert composite_message_id("@chan", 42) == composite_message_id("@chan", 42)


# ============================================================================
# Test 2: Collection cycle -> ingest -> AI analysis -> database
# ============================================================================


@pytest.mark.asyncio
async def test_collection_cycle_ingests_and_analyzes(live_pg_engine):
    """Mocked MTProto cycle drives the REAL ingest + AI pipeline into PostgreSQL."""
    user = setup_tenant_and_user(live_pg_engine)
    tenant_id = user["tenant_id"]
    channel_ref = f"@mtproto_cycle_{uuid.uuid4().hex[:8]}"
    register_source_channel(live_pg_engine, tenant_id, channel_id=channel_ref, handle=channel_ref)

    messages = [
        FakeTelethonMessage(501, TEST_FRAUD_TEXT),
        FakeTelethonMessage(502, "Send crypto to bc1qxy2kgdygjrsqtzq2n0yrf249 before midnight"),
        FakeTelethonMessage(503, "Innocent weather update, nothing suspicious here"),
    ]
    collector = MTProtoCollectorService(connector=FakeMTProtoConnector(messages))
    totals = await collector.run_collection_cycle(tenant_id=tenant_id)

    assert totals["collected"] == 3, totals
    assert totals["failed"] == 0, totals
    assert totals["analyzed"] == 3, totals

    with live_pg_engine.begin() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM threat.source_messages WHERE tenant_id = :t AND channel_id = :c"),
            {"t": tenant_id, "c": channel_ref},
        ).scalar()
        assert count == 3
        det = conn.execute(
            text("SELECT COUNT(*) FROM app.detections WHERE tenant_id = :t"),
            {"t": tenant_id},
        ).scalar()
        assert det >= 1
        blobs = conn.execute(
            text("SELECT COUNT(*) FROM evidence.raw_evidence_blobs WHERE tenant_id = :t"),
            {"t": tenant_id},
        ).scalar()
        assert blobs == 3


@pytest.mark.asyncio
async def test_recollection_is_idempotent(live_pg_engine):
    """Second cycle with identical messages ingests zero new records."""
    user = setup_tenant_and_user(live_pg_engine)
    tenant_id = user["tenant_id"]
    channel_ref = f"@mtproto_dup_{uuid.uuid4().hex[:8]}"
    register_source_channel(live_pg_engine, tenant_id, channel_id=channel_ref, handle=channel_ref)

    messages = [FakeTelethonMessage(601, TEST_FRAUD_TEXT), FakeTelethonMessage(602, "Second message body")]
    collector = MTProtoCollectorService(connector=FakeMTProtoConnector(messages))

    first = await collector.run_collection_cycle(tenant_id=tenant_id)
    second = await collector.run_collection_cycle(tenant_id=tenant_id)

    assert first["collected"] == 2
    assert second["collected"] == 0, second
    assert second["duplicates"] == 2, second

    with live_pg_engine.begin() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM threat.source_messages WHERE tenant_id = :t"),
            {"t": tenant_id},
        ).scalar()
        assert count == 2


@pytest.mark.asyncio
async def test_incremental_collection_uses_checkpoint(live_pg_engine):
    """Only messages past the checkpoint are collected on subsequent cycles."""
    user = setup_tenant_and_user(live_pg_engine)
    tenant_id = user["tenant_id"]
    channel_ref = f"@mtproto_inc_{uuid.uuid4().hex[:8]}"
    register_source_channel(live_pg_engine, tenant_id, channel_id=channel_ref, handle=channel_ref)

    collector = MTProtoCollectorService(connector=FakeMTProtoConnector([FakeTelethonMessage(701, "First")]))
    await collector.run_collection_cycle(tenant_id=tenant_id)

    collector.connector._messages.append(FakeTelethonMessage(702, "Second"))
    totals = await collector.run_collection_cycle(tenant_id=tenant_id)
    assert totals["collected"] == 1, totals


# ============================================================================
# Test 3: Edit detection & evidence immutability
# ============================================================================


@pytest.mark.asyncio
async def test_edit_detection_preserves_immutable_evidence(live_pg_engine):
    """An edited message is detected, audit-logged, and NOT overwritten."""
    user = setup_tenant_and_user(live_pg_engine)
    tenant_id = user["tenant_id"]
    channel_ref = f"@mtproto_edit_{uuid.uuid4().hex[:8]}"
    register_source_channel(live_pg_engine, tenant_id, channel_id=channel_ref, handle=channel_ref)

    original = FakeTelethonMessage(801, "Original benign content")
    collector = MTProtoCollectorService(connector=FakeMTProtoConnector([original]))
    await collector.run_collection_cycle(tenant_id=tenant_id)

    original_digest = hashlib.sha256(b"Original benign content").hexdigest()

    # Actor edits the message upstream; compare against stored evidence
    from app.connectors.telegram.mtproto import MTProtoTelegramConnector
    from app.database.session import async_session_factory, set_transaction_tenant_context

    edited = FakeTelethonMessage(801, "EDITED malicious payload: hxxps://evil[.]example")
    async with async_session_factory() as session:
        await set_transaction_tenant_context(session, tenant_id)
        mapper = MTProtoTelegramConnector()
        live = [mapper._map_message(edited, channel_id=edited.chat_id, channel_title=edited.chat.title)]
        edits = await compare_edits(session, tenant_id, channel_ref, live, checkpoint=801)
        await session.commit()

    assert edits == 1

    with live_pg_engine.begin() as conn:
        stored = conn.execute(
            text(
                "SELECT payload_sha256_hash FROM evidence.raw_evidence_blobs "
                "WHERE tenant_id = :t AND source_message_id = :m"
            ),
            {"t": tenant_id, "m": composite_message_id(channel_ref, 801)},
        ).scalar()
        assert stored == original_digest
        audit = conn.execute(
            text(
                "SELECT COUNT(*) FROM audit.audit_event_records "
                "WHERE tenant_id = :t AND action_type = 'MTPROTO_MESSAGE_EDIT_DETECTED'"
            ),
            {"t": tenant_id},
        ).scalar()
        assert audit == 1


# ============================================================================
# Test 4: Dashboard API returns real statistics (RBAC enforced)
# ============================================================================


@pytest.mark.asyncio
async def test_mtproto_status_endpoint_real_stats(live_client: AsyncClient, live_pg_engine):
    """GET /mtproto/status returns live DB-backed statistics for the tenant."""
    user = setup_tenant_and_user(live_pg_engine)
    tenant_id = user["tenant_id"]
    channel_ref = f"@mtproto_dash_{uuid.uuid4().hex[:8]}"
    register_source_channel(live_pg_engine, tenant_id, channel_id=channel_ref, handle=channel_ref)

    collector = get_mtproto_collector()
    collector.connector = FakeMTProtoConnector([FakeTelethonMessage(901, TEST_FRAUD_TEXT)])
    await collector.run_collection_cycle(tenant_id=tenant_id)

    token = await login_and_get_token(live_client, user["email"], user["password"])
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

    res = await live_client.get("/api/v1/mtproto/status", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["total_messages_collected"] == 1
    assert data["channels_monitored"] >= 1
    assert data["messages_collected_today"] >= 1
    assert data["pending_analysis"] == 0  # analysis completed in-cycle
    assert data["threats_detected"] >= 1
    assert data["connection"]["telethon_installed"] is True
    assert data["collector"]["cycles_completed"] >= 1

    # Unauthenticated access rejected
    res_anon = await live_client.get("/api/v1/mtproto/status")
    assert res_anon.status_code == 401


# ============================================================================
# Test 5: Bot API compatibility & default-off collector
# ============================================================================


def test_bot_api_still_functional():
    """Existing aiogram Bot API integration remains intact."""
    from app.adapters.telegram.bot import create_bot, create_dispatcher

    bot = create_bot(token="123456:AAEBogusTestTokenForLocalHarness000")
    assert bot is not None
    dispatcher = create_dispatcher()
    assert dispatcher is not None


def test_collector_disabled_by_default():
    """Collector stays idle unless TTI_MTPROTO_ENABLED is true."""
    collector = MTProtoCollectorService()
    _run(collector.start())
    assert collector.stats["status"] == "DISABLED"
    assert collector.is_running is False
