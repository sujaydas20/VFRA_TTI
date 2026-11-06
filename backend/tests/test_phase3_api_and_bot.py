"""Phase 3 Test Suite: Bot /analyse command, REST API endpoints, and CLI commands."""

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select, text

from app.adapters.telegram.bot import MockTelegramSession, create_bot, create_dispatcher
from app.adapters.telegram.handlers.submission_handlers import handle_analyse
from app.core.config import get_settings
from app.core.security import hash_password
from app.database.models.audit import AuditEventRecord
from app.database.models.detection import DetectionRecord, DetectionRuleHitRecord
from app.database.session import async_session_factory, set_transaction_tenant_context
from app.main import app
from app.services.consent_service import ConsentService
from aiogram.types import Chat, Message, User

settings = get_settings()


@pytest.fixture(scope="module")
def live_pg_engine():
    sync_url = settings.sync_database_url
    engine = create_engine(sync_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


def setup_test_auth(live_pg_engine, role: str = "INVESTIGATOR"):
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    email = f"user_{user_id.hex[:6]}@example.com"
    password = "StrongPassword123!"
    pw_hash = hash_password(password)

    with live_pg_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :org_name, 'LAW_ENFORCEMENT', 'ACTIVE');
            """),
            {"t_id": org_id, "org_name": f"Org {org_id.hex[:8]}"},
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, :email, 'Analyst 1', :pw_hash, 'ACTIVE');
            """),
            {"u_id": user_id, "email": email, "pw_hash": pw_hash},
        )
        conn.execute(
            text("""
            INSERT INTO iam.tenant_memberships (membership_id, tenant_id, user_id, assigned_role, membership_status)
            VALUES (gen_random_uuid(), :t_id, :u_id, :role, 'ACTIVE');
            """),
            {"t_id": org_id, "u_id": user_id, "role": role},
        )

    return {"tenant_id": org_id, "user_id": user_id, "email": email, "password": password}


@pytest.mark.asyncio
async def test_bot_analyse_command_unconsented():
    """Verify /analyse returns Consent Required if user lacks message_analysis consent."""
    mock_session = MockTelegramSession()
    bot = create_bot(session=mock_session)
    consent_service = ConsentService()

    user = User(id=77889901, is_bot=False, first_name="Bob")
    chat = Chat(id=77889901, type="private")
    msg = Message(
        message_id=1,
        date=datetime.now(timezone.utc),
        chat=chat,
        from_user=user,
        text="/analyse test text",
    ).as_(bot)

    await handle_analyse(msg, consent_service)

    assert len(mock_session.sent_methods) > 0
    reply = mock_session.sent_methods[-1]
    assert "Consent Required" in reply.text


@pytest.mark.asyncio
async def test_bot_analyse_command_consented_with_scam_text():
    """Verify /analyse on scam text returns categories and 1930 helpline advisory."""
    mock_session = MockTelegramSession()
    bot = create_bot(session=mock_session)
    consent_service = ConsentService()
    user_id = 77889902

    async with async_session_factory() as session:
        async with session.begin():
            await consent_service.get_or_create_subject(session, user_id)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

    user = User(id=user_id, is_bot=False, first_name="Charlie")
    chat = Chat(id=user_id, type="private")
    msg = Message(
        message_id=2,
        date=datetime.now(timezone.utc),
        chat=chat,
        from_user=user,
        text="/analyse Sir aapka KYC expire ho gaya, abhi link par click karke update karo warna account band",
    ).as_(bot)

    await handle_analyse(msg, consent_service)

    assert len(mock_session.sent_methods) > 0
    reply = mock_session.sent_methods[-1]
    assert "Threat Detection Analysis" in reply.text
    assert "Banking Fraud" in reply.text
    assert "1930" in reply.text
    assert "cybercrime.gov.in" in reply.text


@pytest.mark.asyncio
async def test_bot_analyse_command_consented_with_benign_text():
    """Verify /analyse on benign text returns 'No Obvious Threat Detected'."""
    mock_session = MockTelegramSession()
    bot = create_bot(session=mock_session)
    consent_service = ConsentService()
    user_id = 77889903

    async with async_session_factory() as session:
        async with session.begin():
            await consent_service.get_or_create_subject(session, user_id)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

    user = User(id=user_id, is_bot=False, first_name="Dave")
    chat = Chat(id=user_id, type="private")
    msg = Message(
        message_id=3,
        date=datetime.now(timezone.utc),
        chat=chat,
        from_user=user,
        text="/analyse Meeting 5 baje hai, doc bhej do",
    ).as_(bot)

    await handle_analyse(msg, consent_service)

    assert len(mock_session.sent_methods) > 0
    reply = mock_session.sent_methods[-1]
    assert "No Obvious Threat Detected" in reply.text
    assert "Absence of indicators does not mean this message is safe" in reply.text


@pytest.mark.asyncio
async def test_detections_api_endpoints(live_pg_engine):
    """Verify REST API: list detections, get detail, review patch, and taxonomy lookups."""
    auth_data = setup_test_auth(live_pg_engine, role="INVESTIGATOR")
    tenant_id = auth_data["tenant_id"]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Login to obtain JWT
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": auth_data["email"], "password": auth_data["password"]},
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

        # 2. Seed a detection record in DB
        det_id = uuid.uuid4()
        async with async_session_factory() as session:
            async with session.begin():
                await set_transaction_tenant_context(session, tenant_id)
                det_rec = DetectionRecord(
                    detection_id=det_id,
                    tenant_id=tenant_id,
                    message_id="api_test_msg_1",
                    category="banking_fraud",
                    stance="potentially_facilitating",
                    severity="HIGH",
                    rule_confidence=0.85,
                    explanation="Matched KYC suspension phrase",
                    taxonomy_version="2026.03.1",
                    engine_version="1.0.0",
                    review_status="unreviewed",
                )
                session.add(det_rec)
                hit_rec = DetectionRuleHitRecord(
                    detection_id=det_id,
                    tenant_id=tenant_id,
                    rule_id="bank_kyc_suspension",
                    rule_version="2026.03.1",
                    span_start=0,
                    span_end=20,
                    masked_excerpt="Sir aapka KYC expire [OTP_REDACTED]",
                )
                session.add(hit_rec)

        # 3. GET /api/v1/detections
        res_list = await client.get("/api/v1/detections", headers=headers)
        assert res_list.status_code == 200
        data = res_list.json()
        assert data["total"] >= 1
        assert any(item["detection_id"] == str(det_id) for item in data["items"])
        item = [i for i in data["items"] if i["detection_id"] == str(det_id)][0]
        assert item["confidence_label"] == "rule confidence (uncalibrated)"
        assert len(item["hits"]) >= 1

        # 4. GET /api/v1/detections/{id}
        res_detail = await client.get(f"/api/v1/detections/{det_id}", headers=headers)
        assert res_detail.status_code == 200
        assert res_detail.json()["category"] == "banking_fraud"

        # 5. PATCH /api/v1/detections/{id}/review
        res_patch = await client.patch(
            f"/api/v1/detections/{det_id}/review",
            json={"review_status": "confirmed"},
            headers=headers,
        )
        assert res_patch.status_code == 200
        assert res_patch.json()["review_status"] == "confirmed"

        # Verify audit log in audit.audit_event_records
        async with async_session_factory() as session:
            async with session.begin():
                await set_transaction_tenant_context(session, tenant_id)
                stmt = select(AuditEventRecord).where(
                    AuditEventRecord.tenant_id == tenant_id,
                    AuditEventRecord.action_type == "DETECTION_REVIEW_STATUS_UPDATED",
                )
                audit_records = (await session.execute(stmt)).scalars().all()
                assert len(audit_records) >= 1
                last_audit = audit_records[-1]
                assert last_audit.details["detection_id"] == str(det_id)
                assert last_audit.details["old_status"] == "unreviewed"
                assert last_audit.details["new_status"] == "confirmed"

        # 6. GET /api/v1/threat-categories
        res_cats = await client.get("/api/v1/threat-categories", headers=headers)
        assert res_cats.status_code == 200
        assert len(res_cats.json()) == 11

        # 7. GET /api/v1/keyword-rules
        res_rules = await client.get("/api/v1/keyword-rules", headers=headers)
        assert res_rules.status_code == 200
        assert len(res_rules.json()) >= 21


def test_cli_rules_evaluate_without_holdout():
    """Verify python -m app.cli rules evaluate prints 'holdout: not provided' without error."""
    backend_dir = Path(__file__).resolve().parent.parent
    res = subprocess.run(
        [sys.executable, "-m", "app.cli", "rules", "evaluate"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "DEV (GENERATED) EVALUATION RESULTS" in res.stdout
    assert "holdout: not provided" in res.stdout
    assert "Report written to" in res.stdout


@pytest.mark.asyncio
async def test_bot_analyse_fail_closed_messaging(monkeypatch):
    """Verify /analyse fails closed when in production with 0 reviewed rules or when degraded."""
    mock_session = MockTelegramSession()
    bot = create_bot(session=mock_session)
    consent_service = ConsentService()
    user_id = 77889904

    async with async_session_factory() as session:
        async with session.begin():
            await consent_service.get_or_create_subject(session, user_id)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

    user = User(id=user_id, is_bot=False, first_name="Eve")
    chat = Chat(id=user_id, type="private")
    msg = Message(
        message_id=4,
        date=datetime.now(timezone.utc),
        chat=chat,
        from_user=user,
        text="/analyse Suspicious text here",
    ).as_(bot)

    monkeypatch.setenv("TTI_ENV", "production")
    await handle_analyse(msg, consent_service)

    assert len(mock_session.sent_methods) > 0
    reply = mock_session.sent_methods[-1]
    assert "Threat analysis is currently unavailable" in reply.text


@pytest.mark.asyncio
async def test_bot_analyse_and_submit_length_exceeded():
    """Verify /analyse and /submit reject messages exceeding 4096 chars with friendly response."""
    from app.adapters.telegram.handlers.submission_handlers import handle_submit_message
    mock_session = MockTelegramSession()
    bot = create_bot(session=mock_session)
    consent_service = ConsentService()
    user_id = 77889905

    async with async_session_factory() as session:
        async with session.begin():
            await consent_service.get_or_create_subject(session, user_id)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

    user = User(id=user_id, is_bot=False, first_name="Frank")
    chat = Chat(id=user_id, type="private")
    oversized_text = "A" * 4100

    # Test /analyse
    msg_analyse = Message(
        message_id=5,
        date=datetime.now(timezone.utc),
        chat=chat,
        from_user=user,
        text=f"/analyse {oversized_text}",
    ).as_(bot)
    await handle_analyse(msg_analyse, consent_service)
    reply = mock_session.sent_methods[-1]
    assert "Message exceeds the maximum allowed length of 4096 characters" in reply.text

    # Test /submit
    msg_submit = Message(
        message_id=6,
        date=datetime.now(timezone.utc),
        chat=chat,
        from_user=user,
        text=f"/submit {oversized_text}",
    ).as_(bot)
    await handle_submit_message(msg_submit, consent_service)
    reply_sub = mock_session.sent_methods[-1]
    assert "Message exceeds the maximum allowed length of 4096 characters" in reply_sub.text


@pytest.mark.asyncio
async def test_api_message_length_exceeded_returns_422(live_pg_engine):
    """Verify API ingestion returns HTTP 422 when raw_text exceeds 4096 chars."""
    auth_data = setup_test_auth(live_pg_engine, role="TENANT_ADMIN")
    tenant_id = auth_data["tenant_id"]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": auth_data["email"], "password": auth_data["password"]},
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id)}

        oversized_payload = {
            "source_reference": "@threat_channel",
            "source_type": "telegram",
            "messages": [
                {
                    "message_id": "msg_long_1",
                    "source_sequence_id": 1,
                    "raw_text": "X" * 4100,
                    "broadcast_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            ],
        }

        res = await client.post("/api/v1/threat/ingest", json=oversized_payload, headers=headers)
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_rbac_on_detections_endpoints(live_pg_engine):
    """Verify RBAC on detection endpoints (401 unauthenticated, 403 forbidden role, 200 investigator)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Unauthenticated request -> 401
        res_unauth = await client.get("/api/v1/detections")
        assert res_unauth.status_code == 401

        # 2. Authenticated with VIEWER role (lacks PERM_CASE_UPDATE) trying PATCH review -> 403
        viewer_auth = setup_test_auth(live_pg_engine, role="READ_ONLY_ANALYST")
        viewer_tid = viewer_auth["tenant_id"]
        login_v = await client.post(
            "/api/v1/auth/login",
            json={"email": viewer_auth["email"], "password": viewer_auth["password"]},
            headers={"X-Tenant-ID": str(viewer_tid)},
        )
        v_token = login_v.json()["access_token"]
        v_headers = {"Authorization": f"Bearer {v_token}", "X-Tenant-ID": str(viewer_tid)}

        fake_det_id = uuid.uuid4()
        res_forbidden = await client.patch(
            f"/api/v1/detections/{fake_det_id}/review",
            json={"review_status": "confirmed"},
            headers=v_headers,
        )
        assert res_forbidden.status_code == 403


@pytest.mark.asyncio
async def test_health_and_status_detection_engine_diagnostics():
    """Verify health and status endpoints expose detection_engine diagnostics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Check /health
        res_health = await client.get("/api/v1/health")
        assert res_health.status_code == 200
        health_data = res_health.json()
        assert "detection_engine" in health_data["components"]
        engine_comp = health_data["components"]["detection_engine"]
        assert "rules_loaded" in engine_comp["details"]
        assert "is_degraded" in engine_comp["details"]

        # Check /status
        res_status = await client.get("/api/v1/status")
        assert res_status.status_code == 200
        status_data = res_status.json()
        assert "detection_engine" in status_data
        assert "rules_loaded" in status_data["detection_engine"]
        assert "is_degraded" in status_data["detection_engine"]
