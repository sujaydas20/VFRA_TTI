"""Celery Asynchronous Tasks for Telegram Monitoring (Module 14).

Executes background collection jobs, batch message processing, and evidentiary media retrieval.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.connectors.telegram.historical_collector import HistoricalCollector
from app.connectors.telegram.media_processor import MediaProcessor
from app.connectors.telegram.message_processor import MessageProcessor
from app.connectors.telegram.models import TelegramMessagePayload
from app.core.config import get_settings
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_async_session_maker():
    settings = get_settings()
    engine = create_async_engine(settings.async_database_url, echo=False)
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@celery_app.task(
    bind=True,
    name="app.workers.tasks.dispatch_historical_collection",
    max_retries=3,
    default_retry_delay=10,
)
def dispatch_historical_collection(
    self,
    tenant_id: str,
    channel_id: str,
    account_id: Optional[str] = None,
    job_id: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Asynchronous Celery worker task executing historical message collection.
    """
    logger.info("Executing Celery historical collection for channel %s (job %s)", channel_id, job_id)

    async def _run():
        session_maker = _get_async_session_maker()
        async with session_maker() as db:
            collector = HistoricalCollector()
            processor = MessageProcessor()

            async def _on_batch(batch: List[TelegramMessagePayload]):
                for msg in batch:
                    try:
                        await processor.process_single_message(
                            db=db,
                            tenant_id=UUID(tenant_id),
                            payload=msg,
                        )
                    except Exception as e:
                        logger.error("Failed to process message %s: %s", msg.message_id, e)
                await db.commit()

            count = await collector.collect_channel_history(
                db=db,
                tenant_id=UUID(tenant_id),
                channel_id=channel_id,
                account_id=UUID(account_id) if account_id else None,
                job_id=UUID(job_id) if job_id else None,
                limit=limit,
                on_batch_collected=_on_batch,
            )
            return {"channel_id": channel_id, "messages_collected": count, "status": "COMPLETED"}

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Celery task dispatch_historical_collection failed: %s", exc)
        raise self.retry(exc=exc)


@celery_app.task(
    name="app.workers.tasks.process_telegram_message_batch",
    max_retries=3,
)
def process_telegram_message_batch(
    tenant_id: str,
    channel_id: str,
    messages_payloads: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Process and ingest a batch of pre-fetched Telegram messages.
    """
    async def _run():
        session_maker = _get_async_session_maker()
        async with session_maker() as db:
            processor = MessageProcessor()
            processed_count = 0
            for item in messages_payloads:
                payload = TelegramMessagePayload.model_validate(item)
                res = await processor.process_single_message(
                    db=db,
                    tenant_id=UUID(tenant_id),
                    payload=payload,
                )
                if res is not None:
                    processed_count += 1
            await db.commit()
            return {"processed_count": processed_count, "total": len(messages_payloads)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    name="app.workers.tasks.analyze_telegram_message_ai",
    max_retries=3,
    default_retry_delay=5,
)
def analyze_telegram_message_ai(
    self,
    tenant_id: str,
    message_id: str,
    channel_id: str,
    raw_text: str,
    channel_title: Optional[str] = None,
    sender_username: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Asynchronously analyze a Telegram message with Gemini AI and local NLP pipeline.
    Ensures message collection is NEVER blocked by external LLM analysis.
    """
    logger.info("Executing AI analysis for message %s (channel %s)", message_id, channel_id)

    async def _run():
        from app.ai.threat_classifier import ThreatClassificationOrchestrator
        session_maker = _get_async_session_maker()
        async with session_maker() as db:
            orchestrator = ThreatClassificationOrchestrator()
            analysis = await orchestrator.analyze_message(
                db=db,
                tenant_id=UUID(tenant_id),
                message_id=message_id,
                channel_id=channel_id,
                raw_text=raw_text,
                channel_title=channel_title,
                sender_username=sender_username,
            )
            return {
                "analysis_id": str(analysis.analysis_id),
                "threat_detected": analysis.threat_detected,
                "category": analysis.threat_category,
                "severity": analysis.severity,
                "calibrated_score": analysis.calibrated_score,
            }

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Celery task analyze_telegram_message_ai failed: %s", exc)
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="app.workers.tasks.run_channel_anomaly_check",
    max_retries=2,
)
def run_channel_anomaly_check(
    self,
    tenant_id: str,
    channel_id: str,
) -> Dict[str, Any]:
    """
    Evaluate message posting velocity and detect statistical bursts on channel.
    """
    logger.info("Evaluating statistical anomalies for channel %s", channel_id)

    async def _run():
        from app.ai.anomaly_detector import AnomalyDetectionEngine
        session_maker = _get_async_session_maker()
        async with session_maker() as db:
            detector = AnomalyDetectionEngine()
            anomalies = await detector.evaluate_channel_anomalies(
                db=db,
                tenant_id=UUID(tenant_id),
                channel_id=channel_id,
            )
            await db.commit()
            return {"anomalies_detected": len(anomalies)}

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error("Celery task run_channel_anomaly_check failed: %s", exc)
        raise self.retry(exc=exc)


