"""Tests for /delete_me erasure workflows and /export data portability."""

import pytest
from sqlalchemy import select
from app.core.identity_crypto import hash_telegram_user_id
from app.database.models.consent import (
    TelegramSubjectRecord,
    ConsentRecord,
    DeletionRequestRecord,
    ConsentedSubmissionRecord,
)
from app.database.session import async_session_factory
from app.services.consent_service import ConsentService


@pytest.mark.asyncio
async def test_delete_me_removes_subject_and_writes_minimal_audit():
    """Executing deletion purges subject identity and data, leaving only irreversible audit entry."""
    service = ConsentService()
    test_user_id = 888111222

    async with async_session_factory() as session:
        # Create subject and grant permission
        await service.grant_permissions(
            session=session,
            telegram_user_id=test_user_id,
            permissions_update={"message_analysis": True},
        )
        subject = await service.get_or_create_subject(session, test_user_id)
        subject_id = subject.id

        # Insert a consented submission
        sub = ConsentedSubmissionRecord(
            tenant_id=subject.tenant_id,
            subject_id=subject_id,
            submission_hash="sha256_mock_hash_delete_me",
            sanitized_text="Sensitive user submission to be purged",
        )
        session.add(sub)
        await session.commit()

        # Execute irreversible deletion
        result = await service.execute_deletion(session, test_user_id)
        await session.commit()

        assert result["status"] == "completed"
        assert result["deleted_counts"]["submissions"] == 1
        assert result["deleted_counts"]["consent_records"] >= 1

        # Verify subject is gone
        subj_res = await session.execute(
            select(TelegramSubjectRecord).where(TelegramSubjectRecord.id == subject_id)
        )
        assert subj_res.scalar_one_or_none() is None

        # Verify submissions are gone
        sub_res = await session.execute(
            select(ConsentedSubmissionRecord).where(ConsentedSubmissionRecord.subject_id == subject_id)
        )
        assert sub_res.scalars().all() == []

        # Verify audit ledger entry exists with blind hash
        expected_hash = hash_telegram_user_id(test_user_id, pepper=service.settings.TTI_ID_PEPPER)
        audit_res = await session.execute(
            select(DeletionRequestRecord)
            .where(DeletionRequestRecord.subject_hash == expected_hash)
            .order_by(DeletionRequestRecord.requested_at.desc())
        )
        audit_entry = audit_res.scalars().first()
        assert audit_entry is not None
        assert audit_entry.status == "completed"
        assert audit_entry.deleted_counts["submissions"] == 1


@pytest.mark.asyncio
async def test_export_returns_only_subject_data():
    """Export returns formatted JSON containing only that subject's consented telemetry."""
    service = ConsentService()
    user_a = 999111001
    user_b = 999111002

    async with async_session_factory() as session:
        # User A data
        await service.grant_permissions(session, user_a, {"message_analysis": True})
        subj_a = await service.get_or_create_subject(session, user_a)
        session.add(
            ConsentedSubmissionRecord(
                tenant_id=subj_a.tenant_id,
                subject_id=subj_a.id,
                submission_hash="hash_a",
                sanitized_text="Message from User A",
            )
        )

        # User B data
        await service.grant_permissions(session, user_b, {"keyword_detection": True})
        subj_b = await service.get_or_create_subject(session, user_b)
        session.add(
            ConsentedSubmissionRecord(
                tenant_id=subj_b.tenant_id,
                subject_id=subj_b.id,
                submission_hash="hash_b",
                sanitized_text="Message from User B",
            )
        )
        await session.commit()

        # Export User A
        export_a = await service.export_user_data(session, user_a)
        assert export_a["subject_found"] is True
        assert export_a["subject_id"] == str(subj_a.id)

        # Confirm export contains User A's data and strictly none of User B's
        texts = [s["sanitized_text"] for s in export_a["submissions"]]
        assert "Message from User A" in texts
        assert "Message from User B" not in texts
