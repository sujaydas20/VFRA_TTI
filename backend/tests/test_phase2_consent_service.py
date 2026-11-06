"""Tests for ConsentService: granular permissions, versioning, revocation, and enforcement."""

import pytest
from sqlalchemy import select
from app.core.errors import ConsentRequiredError
from app.database.models.consent import ConsentedSubmissionRecord
from app.database.session import async_session_factory
from app.services.consent_service import (
    ALL_PERMITTED_CATEGORIES,
    ConsentService,
    get_active_consent_policy,
)


@pytest.mark.asyncio
async def test_subject_created_with_all_permissions_off():
    """Newly onboarded subject has all 7 granular permissions set strictly to False."""
    service = ConsentService()
    test_user_id = 111222333

    async with async_session_factory() as session:
        subject = await service.get_or_create_subject(session, test_user_id)
        assert subject is not None
        assert subject.is_active is True

        consent = await service.get_active_consent(session, test_user_id)
        assert consent is not None
        assert consent.status == "pending"
        for cat in ALL_PERMITTED_CATEGORIES:
            assert consent.permitted_categories[cat] is False, f"Category {cat} must default to False"


@pytest.mark.asyncio
async def test_grant_consent_records_version_and_timestamp():
    """Granting consent stores active status, version, purpose, and granted_at timestamp."""
    service = ConsentService()
    test_user_id = 111222444

    async with async_session_factory() as session:
        # Enable message_analysis
        record = await service.grant_permissions(
            session=session,
            telegram_user_id=test_user_id,
            permissions_update={"message_analysis": True, "keyword_detection": True},
        )
        await session.commit()

        assert record.status == "active"
        assert record.consent_version == get_active_consent_policy()["version"]
        assert record.granted_at is not None
        assert record.permitted_categories["message_analysis"] is True
        assert record.permitted_categories["keyword_detection"] is True
        assert record.permitted_categories["nlp_analysis"] is False

        # Verify check_permission evaluates to True for granted, False for ungranted
        has_msg = await service.check_permission(session, test_user_id, "message_analysis")
        assert has_msg is True
        has_nlp = await service.check_permission(session, test_user_id, "nlp_analysis")
        assert has_nlp is False


@pytest.mark.asyncio
async def test_consent_version_bump_supersedes_active_consent():
    """If the active policy version is bumped, older consent is treated as superseded/inactive."""
    service = ConsentService()
    test_user_id = 111222555

    async with async_session_factory() as session:
        record = await service.grant_permissions(
            session=session,
            telegram_user_id=test_user_id,
            permissions_update={"message_analysis": True},
        )
        # Manually alter version to simulate an older consent version
        record.consent_version = "0.9.0"
        await session.commit()

        # check_permission must return False because version 0.9.0 does not match active 1.0.0
        allowed = await service.check_permission(session, test_user_id, "message_analysis")
        assert allowed is False


@pytest.mark.asyncio
async def test_unauthorised_processing_raises_consent_required_error():
    """Invoking enforce_permission without active consent raises ConsentRequiredError."""
    service = ConsentService()
    test_user_id = 111222666

    async with async_session_factory() as session:
        # Create unconsented subject
        await service.get_or_create_subject(session, test_user_id)

        with pytest.raises(ConsentRequiredError) as exc_info:
            await service.enforce_permission(session, test_user_id, "message_analysis")

        assert "Operation requires explicit active consent" in str(exc_info.value)
        assert exc_info.value.details["permission"] == "message_analysis"


@pytest.mark.asyncio
async def test_revoke_blocks_future_analysis_and_purges_submissions():
    """Revoking consent immediately halts processing and executes retention purge."""
    service = ConsentService()
    test_user_id = 111222777

    async with async_session_factory() as session:
        # Grant message_analysis
        await service.grant_permissions(
            session=session,
            telegram_user_id=test_user_id,
            permissions_update={"message_analysis": True},
        )
        subject = await service.get_or_create_subject(session, test_user_id)

        # Add a sample submission
        sub = ConsentedSubmissionRecord(
            tenant_id=subject.tenant_id,
            subject_id=subject.id,
            submission_hash="mock_hash_12345",
            sanitized_text="Sample raw message",
        )
        session.add(sub)
        await session.commit()

        # Confirm permission is initially active
        assert await service.check_permission(session, test_user_id, "message_analysis") is True

        # Execute revocation
        rev_record = await service.revoke_consent(session, test_user_id)
        await session.commit()

        assert rev_record.status == "revoked"
        assert rev_record.revoked_at is not None
        assert rev_record.permitted_categories["message_analysis"] is False

        # Future permission check returns False
        assert await service.check_permission(session, test_user_id, "message_analysis") is False

        # Verify raw submissions were purged under immediate retention mode
        res = await session.execute(
            select(ConsentedSubmissionRecord).where(ConsentedSubmissionRecord.subject_id == subject.id)
        )
        rows = res.scalars().all()
        assert len(rows) == 0
