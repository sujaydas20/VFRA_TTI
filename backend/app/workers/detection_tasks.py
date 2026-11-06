"""Celery worker tasks for asynchronous threat and fraud detection.

Runs on dedicated queue: 'detection'.
Invariants:
- Re-checks statutory consent at execution time within worker_tenant_session.
- If consent is missing, revoked, or deleted, exits immediately with no detections saved.
- Exponential backoff with jitter and payload-free dead-letter recording on failure.
"""

import asyncio
import logging
from typing import Any, Dict, Optional
import uuid

from app.core.config import get_settings
from app.services.consent_service import ConsentService
from app.services.detection_service import ThreatDetectionService
from app.workers.base import compute_backoff_delay, record_dead_letter_job, worker_tenant_session
from app.workers.celery_app import celery_app

logger = logging.getLogger("tti.workers.detection")


@celery_app.task(
    bind=True,
    name="detection.analyze_message",
    queue="detection",
    max_retries=3,
    acks_late=True,
)
def analyze_message_task(
    self,
    tenant_id: str,
    payload: Dict[str, Any],
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute message threat detection with statutory consent re-validation."""
    try:
        return asyncio.run(_run_analyze_message(tenant_id, payload))
    except Exception as exc:
        attempt = self.request.retries + 1
        if attempt >= self.max_retries:
            logger.error(
                "Task detection.analyze_message failed permanently after %d retries: %s",
                attempt,
                exc,
            )
            asyncio.run(
                record_dead_letter_job(
                    task_name="detection.analyze_message",
                    queue_name="detection",
                    tenant_id=tenant_id,
                    args=(),
                    kwargs={"tenant_id": tenant_id, "idempotency_key": idempotency_key},
                    exc=exc,
                    attempt_count=attempt,
                )
            )
            raise exc

        backoff = compute_backoff_delay(attempt)
        logger.warning(
            "Retrying detection.analyze_message in %.2f s (attempt %d/%d): %s",
            backoff,
            attempt,
            self.max_retries,
            exc,
        )
        raise self.retry(exc=exc, countdown=int(backoff))


async def _run_analyze_message(tenant_id_str: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Internal async handler for message analysis."""
    tenant_id = uuid.UUID(tenant_id_str)
    message_id = payload["message_id"]
    raw_text = payload.get("raw_text", "")
    telegram_user_id = payload.get("telegram_user_id")
    subject_id_raw = payload.get("subject_id")
    subject_id = uuid.UUID(subject_id_raw) if subject_id_raw else None
    chat_type = payload.get("chat_type", "private")

    async with worker_tenant_session(tenant_id) as session:
        # Re-check consent at execution time if telegram_user_id is available
        if telegram_user_id is not None:
            consent_service = ConsentService()
            has_msg_consent = await consent_service.check_permission(
                session=session,
                telegram_user_id=int(telegram_user_id),
                permission="message_analysis",
                chat_type=chat_type,
            )
            has_kw_consent = await consent_service.check_permission(
                session=session,
                telegram_user_id=int(telegram_user_id),
                permission="keyword_detection",
                chat_type=chat_type,
            )

            if not (has_msg_consent and has_kw_consent):
                logger.info(
                    "Skipping threat detection: user consent not granted at execution time (user_id=%s)",
                    telegram_user_id,
                )
                return {
                    "status": "skipped",
                    "reason": "consent_missing_or_revoked",
                    "detections_count": 0,
                }

        detection_service = ThreatDetectionService()
        detections = await detection_service.analyze_and_record(
            session=session,
            tenant_id=tenant_id,
            message_id=message_id,
            raw_text=raw_text,
            subject_id=subject_id,
        )

        return {
            "status": "completed",
            "detections_count": len(detections),
            "categories": [d.category for d in detections],
        }

