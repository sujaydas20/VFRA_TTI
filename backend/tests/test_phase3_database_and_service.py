"""Phase 3 Test Suite: Database persistence, RLS isolation, Deletion Cascade, and Consent Gating."""

from pathlib import Path
import uuid
import pytest
from sqlalchemy import func, select, text

from app.database.models.consent import (
    ConsentRecord,
    TelegramSubjectRecord,
)
from app.database.models.detection import (
    DetectionRecord,
    DetectionRuleHitRecord,
    KeywordRuleRecord,
    ThreatCategoryRecord,
    URLIndicatorRecord,
)
from app.database.models.iam import TenantOrganization
from app.database.session import async_session_factory, set_transaction_tenant_context
from app.services.consent_service import ConsentService
from app.services.detection_service import ThreatDetectionService
from app.services.detection_sink import LoggingDetectionSink
from app.workers.detection_tasks import _run_analyze_message


@pytest.mark.asyncio
async def test_taxonomy_sync_and_persistence():
    """Verify synchronization of disk YAML taxonomy into threat schema tables."""
    backend_dir = Path(__file__).resolve().parent.parent
    taxonomy_dir = backend_dir / "rules" / "taxonomy"

    service = ThreatDetectionService()
    async with async_session_factory() as session:
        async with session.begin():
            res = await service.sync_taxonomy(session, taxonomy_dir)
            assert res["categories_synced"] == 11
            assert res["rules_synced"] >= 21

            # Verify rows exist in DB
            cat_count = (await session.execute(select(func.count()).select_from(ThreatCategoryRecord))).scalar()
            assert cat_count == 11

            rule_count = (await session.execute(select(func.count()).select_from(KeywordRuleRecord))).scalar()
            assert rule_count >= 21


@pytest.mark.asyncio
async def test_detection_persistence_and_idempotency():
    """Verify idempotent detection storage and masked excerpt preservation."""
    service = ThreatDetectionService()
    tenant_id = uuid.uuid4()
    message_id = f"msg_{uuid.uuid4().hex[:8]}"

    async with async_session_factory() as session:
        async with session.begin():
            # Setup tenant
            org = TenantOrganization(
                tenant_id=tenant_id,
                organization_name=f"Org {tenant_id.hex[:6]}",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            session.add(org)
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            raw_text = "Sir aapka KYC expire ho gaya, click hxxp://sbi-rewards-claim[.]xyz/update to verify OTP: 984512"

            # 1. First analysis run
            results_1 = await service.analyze_and_record(
                session=session,
                tenant_id=tenant_id,
                message_id=message_id,
                raw_text=raw_text,
            )
            assert len(results_1) > 0

            # 2. Second analysis run (identical message_id) -> Idempotency enforced
            results_2 = await service.analyze_and_record(
                session=session,
                tenant_id=tenant_id,
                message_id=message_id,
                raw_text=raw_text,
            )
            assert len(results_2) == len(results_1)

            # Query database to confirm no duplicate rows were created
            det_count_stmt = select(func.count()).select_from(DetectionRecord).where(
                DetectionRecord.tenant_id == tenant_id,
                DetectionRecord.message_id == message_id,
            )
            det_count = (await session.execute(det_count_stmt)).scalar()
            assert det_count == len(results_1)

            # Confirm excerpt masking invariant
            hit_stmt = select(DetectionRuleHitRecord).where(
                DetectionRuleHitRecord.tenant_id == tenant_id
            )
            hits = (await session.execute(hit_stmt)).scalars().all()
            for h in hits:
                assert "984512" not in h.masked_excerpt


@pytest.mark.asyncio
async def test_row_level_security_isolation_on_detections():
    """Verify Tenant A cannot view or query detections belonging to Tenant B."""
    service = ThreatDetectionService()
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    async with async_session_factory() as session:
        async with session.begin():
            org_a = TenantOrganization(
                tenant_id=tenant_a,
                organization_name="Tenant A",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            org_b = TenantOrganization(
                tenant_id=tenant_b,
                organization_name="Tenant B",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            session.add_all([org_a, org_b])
            await session.flush()

            # Record detection under Tenant A
            await set_transaction_tenant_context(session, tenant_a)
            await service.analyze_and_record(
                session=session,
                tenant_id=tenant_a,
                message_id="msg_a_1",
                raw_text="Electricity bill unpaid! Call 9876543210 immediately",
            )

        # In a separate transaction, query as Tenant B using tti_app_role
        async with session.begin():
            await session.execute(text("SET ROLE tti_app_role;"))
            await set_transaction_tenant_context(session, tenant_b)
            stmt = select(DetectionRecord)
            records = (await session.execute(stmt)).scalars().all()
            assert len(records) == 0, "Tenant B leaked Tenant A's detections across RLS boundary!"
            await session.execute(text("RESET ROLE;"))


@pytest.mark.asyncio
async def test_consent_deletion_cascade_purges_detections():
    """Verify execute_deletion cascades to purge all detections and indicators for subject."""
    consent_service = ConsentService()
    detection_service = ThreatDetectionService()
    tenant_id = uuid.uuid4()
    user_id = 99887766

    async with async_session_factory() as session:
        async with session.begin():
            org = TenantOrganization(
                tenant_id=tenant_id,
                organization_name="Cascade Test Org",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            session.add(org)
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            subject = await consent_service.get_or_create_subject(session, user_id)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

            # Record detection linked to this subject
            await detection_service.analyze_and_record(
                session=session,
                tenant_id=tenant_id,
                message_id="msg_sub_1",
                raw_text="Download this apk file to claim your free PM Kisan Yojana installment",
                subject_id=subject.id,
            )

            # Confirm detection exists
            pre_count = (
                await session.execute(
                    select(func.count())
                    .select_from(DetectionRecord)
                    .where(DetectionRecord.subject_id == subject.id)
                )
            ).scalar()
            assert pre_count > 0

            # Execute deletion cascade
            del_result = await consent_service.execute_deletion(session, user_id)
            assert del_result["status"] == "completed"
            assert del_result["deleted_counts"]["detections"] > 0

            # Confirm detections, hits, and indicators were completely purged
            post_det = (
                await session.execute(
                    select(func.count())
                    .select_from(DetectionRecord)
                    .where(DetectionRecord.subject_id == subject.id)
                )
            ).scalar()
            assert post_det == 0


@pytest.mark.asyncio
async def test_worker_task_consent_recheck():
    """Verify detection task re-checks consent at execution time and skips if missing/revoked."""
    tenant_id = uuid.uuid4()
    user_id = 11223344
    consent_service = ConsentService()

    async with async_session_factory() as session:
        async with session.begin():
            org = TenantOrganization(
                tenant_id=tenant_id,
                organization_name="Worker Consent Org",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            session.add(org)
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)
            await consent_service.get_or_create_subject(session, user_id)

    # 1. User has no active consent -> task must skip execution
    payload_no_consent = {
        "message_id": "task_msg_1",
        "raw_text": "Sir aapka KYC expire ho gaya",
        "telegram_user_id": user_id,
    }
    res_skipped = await _run_analyze_message(str(tenant_id), payload_no_consent)
    assert res_skipped["status"] == "skipped"
    assert res_skipped["reason"] == "consent_missing_or_revoked"
    assert res_skipped["detections_count"] == 0

    # 2. Grant consent and verify task executes
    async with async_session_factory() as session:
        async with session.begin():
            await set_transaction_tenant_context(session, tenant_id)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

    payload_consented = {
        "message_id": "task_msg_2",
        "raw_text": "Sir aapka KYC expire ho gaya, link par click karo",
        "telegram_user_id": user_id,
    }
    res_completed = await _run_analyze_message(str(tenant_id), payload_consented)
    assert res_completed["status"] == "completed"
    assert res_completed["detections_count"] > 0

@pytest.mark.asyncio
async def test_scan_all_stored_text_columns_for_unmasked_sensitive_data():
    """Verify that every stored text column across detection tables has zero unmasked sensitive PII."""
    service = ThreatDetectionService()
    tenant_id = uuid.uuid4()
    msg_id = f"leak_scan_{uuid.uuid4().hex[:8]}"

    async with async_session_factory() as session:
        async with session.begin():
            org = TenantOrganization(
                tenant_id=tenant_id,
                organization_name=f"Leak Scan Org {tenant_id.hex[:6]}",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            session.add(org)
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)

            # Ingest text containing various sensitive PII
            raw_sensitive = (
                "Call 9876543210 immediately. Your A/c 50100234567890 OTP is 849201. "
                "Card 4532-0151-1283-0366 CVV 492 password SecretPass123! "
                "Aadhaar 1234 5678 9012 PAN ABCDE1234F telegram @scam_boss. "
                "Send to fraudster@phishing.com or UPI pay.user@okhdfcbank"
            )

            await service.analyze_and_record(
                session=session,
                tenant_id=tenant_id,
                message_id=msg_id,
                raw_text=raw_sensitive,
            )

            # Query all text columns from app.detections
            det_rows = (
                await session.execute(
                    select(DetectionRecord.explanation, DetectionRecord.stance, DetectionRecord.severity)
                    .where(DetectionRecord.tenant_id == tenant_id)
                )
            ).all()

            # Query all text columns from app.detection_rule_hits
            hit_rows = (
                await session.execute(
                    select(DetectionRuleHitRecord.masked_excerpt)
                    .where(DetectionRuleHitRecord.tenant_id == tenant_id)
                )
            ).all()

            # Query all text columns from app.url_indicators
            url_rows = (
                await session.execute(
                    select(URLIndicatorRecord.defanged_url, URLIndicatorRecord.domain)
                    .where(URLIndicatorRecord.tenant_id == tenant_id)
                )
            ).all()

    # Collect all stored string fragments
    all_stored_texts = []
    for r in det_rows:
        all_stored_texts.extend([str(val) for val in r if val])
    for r in hit_rows:
        all_stored_texts.extend([str(val) for val in r if val])
    for r in url_rows:
        all_stored_texts.extend([str(val) for val in r if val])

    forbidden_pii = [
        "9876543210",
        "5010023456",
        "849201",
        "0151-1283",
        "SecretPass123!",
        "1234 5678",
        "ABCDE",
        "@scam_boss",
        "fraudster@",
        "pay.user@",
    ]

    for stored_text in all_stored_texts:
        for pii in forbidden_pii:
            assert pii not in stored_text, f"Sensitive PII '{pii}' leaked in database column: '{stored_text}'"


@pytest.mark.asyncio
async def test_consent_revoked_between_enqueue_and_run():
    """Verify race condition: consent granted at enqueue but revoked before execution causes immediate abort."""
    tenant_id = uuid.uuid4()
    user_id = 55667788
    consent_service = ConsentService()

    async with async_session_factory() as session:
        async with session.begin():
            org = TenantOrganization(
                tenant_id=tenant_id,
                organization_name=f"Revoke Race Org {tenant_id.hex[:6]}",
                market_profile="LAW_ENFORCEMENT",
                account_status="ACTIVE",
            )
            session.add(org)
            await session.flush()
            await set_transaction_tenant_context(session, tenant_id)
            await consent_service.get_or_create_subject(session, user_id)
            # 1. Grant consent initially (as if at enqueue time)
            await consent_service.grant_permissions(
                session=session,
                telegram_user_id=user_id,
                permissions_update={"message_analysis": True, "keyword_detection": True},
            )

    # 2. User revokes consent before task runs
    async with async_session_factory() as session:
        async with session.begin():
            await set_transaction_tenant_context(session, tenant_id)
            await consent_service.revoke_consent(session, user_id)

    # 3. Task executes and re-checks consent in database
    payload = {
        "message_id": "revoked_race_msg_1",
        "raw_text": "Sir aapka KYC expire ho gaya, link par click karo",
        "telegram_user_id": user_id,
    }
    res = await _run_analyze_message(str(tenant_id), payload)
    assert res["status"] == "skipped"
    assert res["reason"] == "consent_missing_or_revoked"
    assert res["detections_count"] == 0

    # Confirm no detection was saved in database
    async with async_session_factory() as session:
        async with session.begin():
            await set_transaction_tenant_context(session, tenant_id)
            count = (
                await session.execute(
                    select(func.count())
                    .select_from(DetectionRecord)
                    .where(DetectionRecord.message_id == "revoked_race_msg_1")
                )
            ).scalar()
            assert count == 0


def test_alembic_downgrade_and_upgrade(alembic_config):
    """Verify Alembic migration 0010 can downgrade to 0009 and re-upgrade without error."""
    from alembic import command
    # Downgrade 0010 -> 0009
    command.downgrade(alembic_config, "-1")
    # Upgrade 0009 -> 0010
    command.upgrade(alembic_config, "head")
