"""Phase 4 Test Suite: Alert generation, duplicate suppression, triage, and RLS isolation."""

import uuid

import pytest
from sqlalchemy import func, select, text

from app.core.rbac import (
    PERM_ALERT_ASSIGN,
    PERM_ALERT_READ,
    PERM_ALERT_TRIAGE,
    ROLE_INVESTIGATOR,
    ROLE_INVESTIGATOR_LEAD,
    ROLE_READ_ONLY_ANALYST,
    get_role_permissions,
)
from app.database.models.alerts import (
    ALERT_STATUS_ASSIGNED,
    ALERT_STATUS_OPEN,
    ALERT_STATUS_TRIAGED,
    SEVERITY_PRIORITY,
    AlertRecord,
    AnalystFeedbackRecord,
)
from app.database.models.audit import AuditEventRecord
from app.database.models.detection import DetectionRecord
from app.database.models.iam import TenantOrganization, UserProfile
from app.database.session import async_session_factory, set_transaction_tenant_context
from app.services.alert_service import AlertService
from app.services.detection_service import ThreatDetectionService


async def _seed_detection(session, tenant_id, category, severity, message_id=None):
    """Persist a tenant-scoped DetectionRecord and return it."""
    rec = DetectionRecord(
        detection_id=uuid.uuid4(),
        tenant_id=tenant_id,
        message_id=message_id or f"msg_{uuid.uuid4().hex[:8]}",
        category=category,
        stance="potentially_facilitating",
        severity=severity,
        rule_confidence=0.6,
        explanation="KYC expiry lure matched",
        taxonomy_version="2026.03.1",
        engine_version="1.0.0",
    )
    session.add(rec)
    await session.flush()
    return rec


def _org(tenant_id):
    return TenantOrganization(
        tenant_id=tenant_id,
        organization_name=f"Org {tenant_id.hex[:6]}",
        market_profile="LAW_ENFORCEMENT",
        account_status="ACTIVE",
    )


@pytest.mark.asyncio
async def test_alert_generation_for_high_severity_detection():
    """A MEDIUM+ detection raises an OPEN alert with correct priority."""
    service = AlertService()
    tenant_id = uuid.uuid4()

    async with async_session_factory() as session:
        async with session.begin():
            session.add(_org(tenant_id))
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            alert, outcome = await service.create_alert_for_detection(
                session=session,
                tenant_id=tenant_id,
                detection=await _seed_detection(session, tenant_id, "phishing", "HIGH"),
            )
            assert outcome == "created"
            assert alert is not None
            assert alert.alert_status == ALERT_STATUS_OPEN
            assert alert.priority == SEVERITY_PRIORITY["HIGH"]
            assert alert.hit_count == 1


@pytest.mark.asyncio
async def test_below_threshold_detection_raises_no_alert():
    """LOW/INFO detections never raise alerts (alert-fatigue guard)."""
    service = AlertService()
    tenant_id = uuid.uuid4()

    async with async_session_factory() as session:
        async with session.begin():
            session.add(_org(tenant_id))
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            alert, outcome = await service.create_alert_for_detection(
                session=session,
                tenant_id=tenant_id,
                detection=await _seed_detection(session, tenant_id, "phishing", "LOW"),
            )
            assert alert is None
            assert outcome == "below_threshold"


@pytest.mark.asyncio
async def test_duplicate_suppression_increments_hit_count():
    """Repeated hits of the same category inside the window collapse into one alert."""
    service = AlertService()
    tenant_id = uuid.uuid4()

    async with async_session_factory() as session:
        async with session.begin():
            session.add(_org(tenant_id))
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            first, o1 = await service.create_alert_for_detection(
                session=session, tenant_id=tenant_id,
                detection=await _seed_detection(session, tenant_id, "upi_fraud", "HIGH"),
            )
            second, o2 = await service.create_alert_for_detection(
                session=session, tenant_id=tenant_id,
                detection=await _seed_detection(session, tenant_id, "upi_fraud", "HIGH"),
            )
            third, o3 = await service.create_alert_for_detection(
                session=session, tenant_id=tenant_id,
                detection=await _seed_detection(session, tenant_id, "upi_fraud", "MEDIUM"),
            )

            assert (o1, o2, o3) == ("created", "suppressed", "suppressed")
            assert first.alert_id == second.alert_id == third.alert_id
            assert third.hit_count == 3

            count_stmt = select(func.count()).select_from(AlertRecord).where(
                AlertRecord.tenant_id == tenant_id
            )
            assert (await session.execute(count_stmt)).scalar() == 1


@pytest.mark.asyncio
async def test_alert_rls_isolation_between_tenants():
    """Tenant A cannot read Tenant B alerts under RLS."""
    service = AlertService()
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    async with async_session_factory() as session:
        async with session.begin():
            session.add(_org(tenant_a))
            session.add(_org(tenant_b))
            await session.flush()

            await set_transaction_tenant_context(session, tenant_a)
            await service.create_alert_for_detection(
                session=session, tenant_id=tenant_a,
                detection=await _seed_detection(session, tenant_a, "banking_fraud", "CRITICAL"),
            )
            await session.flush()

        # In a separate transaction, query as Tenant B using tti_app_role
        async with session.begin():
            await session.execute(text("SET ROLE tti_app_role;"))
            await set_transaction_tenant_context(session, tenant_b)
            assert (await session.execute(select(func.count()).select_from(AlertRecord))).scalar() == 0

            records, total = await service.list_alerts(session, tenant_b)
            assert total == 0
            assert records == []
            await session.execute(text("RESET ROLE;"))


@pytest.mark.asyncio
async def test_alert_triage_records_feedback_and_audit():
    """Triage records analyst decision, emits feedback row, and an audit event."""
    service = AlertService()
    tenant_id = uuid.uuid4()
    analyst_id = uuid.uuid4()

    async with async_session_factory() as session:
        async with session.begin():
            session.add(_org(tenant_id))
            session.add(
                UserProfile(
                    user_id=analyst_id,
                    email_address=f"analyst_{analyst_id.hex[:6]}@tti.local",
                    full_name="Triage Analyst",
                    password_hash="x",
                    account_state="ACTIVE",
                )
            )
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            alert, _ = await service.create_alert_for_detection(
                session=session, tenant_id=tenant_id,
                detection=await _seed_detection(session, tenant_id, "fake_job_scams", "HIGH"),
            )

            triaged = await service.triage_alert(
                session=session, tenant_id=tenant_id, actor_user_id=analyst_id,
                alert_id=alert.alert_id,
                analyst_decision="FALSE_POSITIVE", analyst_notes="Benign recruiter post",
            )
            assert triaged.alert_status == ALERT_STATUS_TRIAGED
            assert triaged.analyst_decision == "FALSE_POSITIVE"
            fb_stmt = select(func.count()).select_from(AnalystFeedbackRecord).where(
                AnalystFeedbackRecord.alert_id == alert.alert_id
            )
            assert (await session.execute(fb_stmt)).scalar() == 1

            audit_stmt = select(func.count()).select_from(AuditEventRecord).where(
                AuditEventRecord.tenant_id == tenant_id
            )
            assert (await session.execute(audit_stmt)).scalar() == 1


def test_alert_rbac_permission_matrix():
    """Static RBAC: analysts triage, read-only analysts only read."""
    assert PERM_ALERT_READ in get_role_permissions(ROLE_READ_ONLY_ANALYST)
    assert PERM_ALERT_TRIAGE not in get_role_permissions(ROLE_READ_ONLY_ANALYST)
    assert PERM_ALERT_ASSIGN not in get_role_permissions(ROLE_INVESTIGATOR)
    assert PERM_ALERT_TRIAGE in get_role_permissions(ROLE_INVESTIGATOR)
    assert PERM_ALERT_ASSIGN in get_role_permissions(ROLE_INVESTIGATOR_LEAD)


@pytest.mark.asyncio
async def test_detection_pipeline_raises_alert_end_to_end():
    """ThreatDetectionService persists detections AND raises alerts in one pass."""
    service = ThreatDetectionService()
    tenant_id = uuid.uuid4()
    message_id = f"msg_{uuid.uuid4().hex[:8]}"

    async with async_session_factory() as session:
        async with session.begin():
            session.add(_org(tenant_id))
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            raw_text = (
                "Sir aapka KYC expire ho gaya, click hxxp://sbi-rewards-claim[.]xyz/update "
                "to verify OTP and pay the processing fee via UPI @paytm now"
            )
            results = await service.analyze_and_record(
                session=session, tenant_id=tenant_id,
                message_id=message_id, raw_text=raw_text,
            )
            assert len(results) > 0

            alerts, total = await AlertService().list_alerts(session, tenant_id)
            assert total >= 1
            for a in alerts:
                # No message content is ever persisted on the alert.
                assert "KYC" not in a.alert_title
                assert a.priority >= SEVERITY_PRIORITY["MEDIUM"]
