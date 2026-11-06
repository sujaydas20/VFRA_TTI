"""Consent service implementing strict, informed, purpose-specific, and revocable consent.

Architecture:
- Framework-free business logic.
- Implements ConsentCheckerProtocol.
- Raises ConsentRequiredError when unconsented analysis is attempted.
- Enforces data minimization and retention workflows.
"""

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ConsentRequiredError, ConsentVersionMismatchError
from app.core.identity_crypto import (
    hash_telegram_user_id,
    encrypt_telegram_user_id,
    decrypt_telegram_user_id,
)
from app.database.models.consent import (
    TelegramSubjectRecord,
    ConsentRecord,
    DeletionRequestRecord,
    ConsentedSubmissionRecord,
)

ALL_PERMITTED_CATEGORIES = [
    "message_analysis",
    "keyword_detection",
    "nlp_analysis",
    "activity_analytics",
    "timeline",
    "reports",
    "approved_group_context",
]


def get_default_permissions() -> Dict[str, bool]:
    """All 7 granular permissions default strictly to OFF."""
    return {cat: False for cat in ALL_PERMITTED_CATEGORIES}


def get_active_consent_policy() -> Dict[str, str]:
    """Read the active consent version and policy text from version-controlled file."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    rule_path = os.path.join(base_dir, "rules", "consent_v1.0.0.txt")

    version = "1.0.0"
    purpose = "Threat intelligence, fraud prevention, and behavioral analytics"
    content = ""

    if os.path.exists(rule_path):
        with open(rule_path, "r", encoding="utf-8") as f:
            content = f.read()
            v_match = re.search(r"^VERSION=(.+)$", content, re.MULTILINE)
            if v_match:
                version = v_match.group(1).strip()
            p_match = re.search(r"^PURPOSE=(.+)$", content, re.MULTILINE)
            if p_match:
                purpose = p_match.group(1).strip()

    return {
        "version": version,
        "purpose": purpose,
        "content": content,
    }


class ConsentService:
    """Service managing subject onboarding, granular consent, revocations, and data erasures."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()

    async def get_or_create_subject(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        tenant_id: Optional[uuid.UUID] = None,
        chat_context: Optional[Dict[str, Any]] = None,
    ) -> TelegramSubjectRecord:
        """Retrieve existing subject by blind hash or create a new pseudonymized subject."""
        user_hash = hash_telegram_user_id(telegram_user_id, pepper=self.settings.TTI_ID_PEPPER)
        active_tenant_id = tenant_id or uuid.UUID(self.settings.TTI_DEFAULT_TENANT_ID)

        stmt = select(TelegramSubjectRecord).where(
            TelegramSubjectRecord.telegram_user_id_hash == user_hash
        )
        res = await session.execute(stmt)
        subject = res.scalar_one_or_none()

        if subject is None:
            encrypted_id = encrypt_telegram_user_id(
                telegram_user_id, key=self.settings.effective_encryption_key
            )
            subject = TelegramSubjectRecord(
                tenant_id=active_tenant_id,
                telegram_user_id_hash=user_hash,
                encrypted_telegram_user_id=encrypted_id,
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            session.add(subject)
            await session.flush()

            # Create default pending consent record (all False)
            policy = get_active_consent_policy()
            default_consent = ConsentRecord(
                tenant_id=active_tenant_id,
                subject_id=subject.id,
                consent_version=policy["version"],
                purpose=policy["purpose"],
                permitted_categories=get_default_permissions(),
                status="pending",
                chat_context=chat_context or {},
                created_at=datetime.now(timezone.utc),
            )
            session.add(default_consent)
            await session.flush()

        return subject

    async def get_active_consent(
        self,
        session: AsyncSession,
        telegram_user_id: int,
    ) -> Optional[ConsentRecord]:
        """Fetch active consent record for a subject."""
        user_hash = hash_telegram_user_id(telegram_user_id, pepper=self.settings.TTI_ID_PEPPER)
        stmt = (
            select(ConsentRecord)
            .join(TelegramSubjectRecord, ConsentRecord.subject_id == TelegramSubjectRecord.id)
            .where(
                TelegramSubjectRecord.telegram_user_id_hash == user_hash,
                TelegramSubjectRecord.is_active.is_(True),
                ConsentRecord.status != "superseded",
            )
            .order_by(ConsentRecord.created_at.desc(), ConsentRecord.id.desc())
        )
        res = await session.execute(stmt)
        return res.scalars().first()

    async def check_permission(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permission: str,
        chat_type: str = "private",
    ) -> bool:
        """Check if subject has active, non-superseded consent for a specific permission."""
        consent = await self.get_active_consent(session, telegram_user_id)
        if not consent:
            return False

        # In groups, approved_group_context is an absolute prerequisite
        if chat_type in ("group", "supergroup"):
            if not consent.permitted_categories.get("approved_group_context", False):
                return False

        # Verify active version
        active_version = get_active_consent_policy()["version"]
        if consent.consent_version != active_version:
            # Superseded: require re-consent
            return False

        if consent.status != "active":
            return False

        return bool(consent.permitted_categories.get(permission, False))

    async def enforce_permission(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permission: str,
        chat_type: str = "private",
    ) -> None:
        """Raise ConsentRequiredError if permission is not granted and active."""
        allowed = await self.check_permission(session, telegram_user_id, permission, chat_type)
        if not allowed:
            raise ConsentRequiredError(
                f"Operation requires explicit active consent for '{permission}'.",
                details={
                    "permission": permission,
                    "chat_type": chat_type,
                    "action_required": "Please use /consent in private chat to review and grant permission.",
                },
            )

    async def grant_permissions(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permissions_update: Dict[str, bool],
        chat_context: Optional[Dict[str, Any]] = None,
    ) -> ConsentRecord:
        """Record explicit consent update with version and timestamp."""
        subject = await self.get_or_create_subject(session, telegram_user_id, chat_context=chat_context)
        active_policy = get_active_consent_policy()

        existing = await self.get_active_consent(session, telegram_user_id)
        base_perms = existing.permitted_categories.copy() if existing else get_default_permissions()

        for k, v in permissions_update.items():
            if k in ALL_PERMITTED_CATEGORIES:
                base_perms[k] = bool(v)

        # Supersede prior active or pending records
        prior_stmt = select(ConsentRecord).where(
            ConsentRecord.subject_id == subject.id,
            ConsentRecord.status.in_(["active", "pending"]),
        )
        prior_records = (await session.execute(prior_stmt)).scalars().all()
        for r in prior_records:
            r.status = "superseded"

        # Create new versioned consent record
        new_consent = ConsentRecord(
            tenant_id=subject.tenant_id,
            subject_id=subject.id,
            consent_version=active_policy["version"],
            purpose=active_policy["purpose"],
            permitted_categories=base_perms,
            status="active" if any(base_perms.values()) else "pending",
            chat_context=chat_context or (existing.chat_context if existing else {}),
            granted_at=datetime.now(timezone.utc) if any(base_perms.values()) else None,
            created_at=datetime.now(timezone.utc),
        )
        session.add(new_consent)
        await session.flush()
        return new_consent

    async def revoke_consent(
        self,
        session: AsyncSession,
        telegram_user_id: int,
        permissions_to_revoke: Optional[List[str]] = None,
    ) -> ConsentRecord:
        """Revoke all or selected permissions and trigger retention policy."""
        subject = await self.get_or_create_subject(session, telegram_user_id)
        existing = await self.get_active_consent(session, telegram_user_id)
        active_policy = get_active_consent_policy()

        current_perms = existing.permitted_categories.copy() if existing else get_default_permissions()

        if permissions_to_revoke is None:
            # Revoke ALL permissions
            current_perms = {k: False for k in current_perms}
            status = "revoked"
        else:
            for p in permissions_to_revoke:
                if p in current_perms:
                    current_perms[p] = False
            status = "active" if any(current_perms.values()) else "revoked"

        # Supersede prior records
        prior_stmt = select(ConsentRecord).where(
            ConsentRecord.subject_id == subject.id,
            ConsentRecord.status.in_(["active", "pending"]),
        )
        prior_records = (await session.execute(prior_stmt)).scalars().all()
        for r in prior_records:
            r.status = "superseded"

        revocation_record = ConsentRecord(
            tenant_id=subject.tenant_id,
            subject_id=subject.id,
            consent_version=active_policy["version"],
            purpose=active_policy["purpose"],
            permitted_categories=current_perms,
            status=status,
            chat_context=existing.chat_context if existing else {},
            granted_at=existing.granted_at if existing and status == "active" else None,
            revoked_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        session.add(revocation_record)
        await session.flush()

        # Retention enforcement: immediate purge of raw submissions if message_analysis was revoked
        if not current_perms.get("message_analysis", False) and self.settings.TTI_CONSENT_RETENTION_MODE == "immediate":
            await session.execute(
                delete(ConsentedSubmissionRecord).where(
                    ConsentedSubmissionRecord.subject_id == subject.id
                )
            )

        return revocation_record

    async def execute_deletion(
        self,
        session: AsyncSession,
        telegram_user_id: int,
    ) -> Dict[str, Any]:
        """Erase all subject records and record minimal non-reversible audit proof."""
        user_hash = hash_telegram_user_id(telegram_user_id, pepper=self.settings.TTI_ID_PEPPER)
        stmt = select(TelegramSubjectRecord).where(
            TelegramSubjectRecord.telegram_user_id_hash == user_hash
        )
        res = await session.execute(stmt)
        subject = res.scalar_one_or_none()

        if not subject:
            return {"status": "not_found", "deleted_counts": {}}

        tenant_id = subject.tenant_id
        subject_id = subject.id

        # Count submissions
        sub_count_stmt = select(func.count()).select_from(ConsentedSubmissionRecord).where(
            ConsentedSubmissionRecord.subject_id == subject_id
        )
        sub_count = (await session.execute(sub_count_stmt)).scalar() or 0

        # Count consents
        consent_count_stmt = select(func.count()).select_from(ConsentRecord).where(
            ConsentRecord.subject_id == subject_id
        )
        consent_count = (await session.execute(consent_count_stmt)).scalar() or 0

        # Purge detections and indicators associated with subject
        from app.database.models.detection import DetectionRecord
        det_count_stmt = select(func.count()).select_from(DetectionRecord).where(
            DetectionRecord.subject_id == subject_id
        )
        det_count = (await session.execute(det_count_stmt)).scalar() or 0
        await session.execute(
            delete(DetectionRecord).where(DetectionRecord.subject_id == subject_id)
        )

        # Purge subject (cascades to consent_records and consented_submissions)
        await session.execute(
            delete(TelegramSubjectRecord).where(TelegramSubjectRecord.id == subject_id)
        )

        deleted_counts = {
            "submissions": sub_count,
            "consent_records": consent_count,
            "detections": det_count,
            "subject_identity": 1,
        }

        # Create minimal audit ledger record (only blind hash, never reversible)
        audit_entry = DeletionRequestRecord(
            tenant_id=tenant_id,
            subject_hash=user_hash,
            requested_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            status="completed",
            deleted_counts=deleted_counts,
        )
        session.add(audit_entry)
        await session.flush()

        return {
            "status": "completed",
            "subject_hash": user_hash,
            "deleted_counts": deleted_counts,
        }

    async def export_user_data(
        self,
        session: AsyncSession,
        telegram_user_id: int,
    ) -> Dict[str, Any]:
        """Export all data stored about the subject as formatted JSON."""
        user_hash = hash_telegram_user_id(telegram_user_id, pepper=self.settings.TTI_ID_PEPPER)
        stmt = select(TelegramSubjectRecord).where(
            TelegramSubjectRecord.telegram_user_id_hash == user_hash
        )
        res = await session.execute(stmt)
        subject = res.scalar_one_or_none()

        if not subject:
            return {
                "subject_found": False,
                "message": "No active subject records found.",
            }

        # Query consent records
        consent_stmt = (
            select(ConsentRecord)
            .where(ConsentRecord.subject_id == subject.id)
            .order_by(ConsentRecord.created_at.desc())
        )
        consents = (await session.execute(consent_stmt)).scalars().all()

        # Query submissions
        sub_stmt = (
            select(ConsentedSubmissionRecord)
            .where(ConsentedSubmissionRecord.subject_id == subject.id)
            .order_by(ConsentedSubmissionRecord.created_at.desc())
        )
        submissions = (await session.execute(sub_stmt)).scalars().all()

        return {
            "subject_found": True,
            "subject_id": str(subject.id),
            "is_active": subject.is_active,
            "created_at": subject.created_at.isoformat(),
            "consent_history": [
                {
                    "consent_version": c.consent_version,
                    "purpose": c.purpose,
                    "status": c.status,
                    "permitted_categories": c.permitted_categories,
                    "granted_at": c.granted_at.isoformat() if c.granted_at else None,
                    "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
                    "created_at": c.created_at.isoformat(),
                }
                for c in consents
            ],
            "submissions": [
                {
                    "submission_hash": s.submission_hash,
                    "sanitized_text": s.sanitized_text,
                    "detected_language": s.detected_language,
                    "created_at": s.created_at.isoformat(),
                }
                for s in submissions
            ],
        }
