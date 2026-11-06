"""Celery worker mesh and task broker configuration for TTI.

Configures:
- 8 dedicated operational queues.
- Dynamic concurrency from environment variables.
- task_acks_late and reject_on_worker_lost for high-reliability message delivery.
- Timeouts and prefetch limits to prevent memory exhaustion and unbounded execution.
"""

import os
from celery import Celery
from kombu import Exchange, Queue

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "tti_workers",
    broker=settings.effective_celery_broker_url,
    backend=settings.effective_celery_result_backend,
)

# -----------------------------------------------------------------------------
# Queues and Routing Definitions
# -----------------------------------------------------------------------------
default_exchange = Exchange("tti_tasks", type="direct")

QUEUES = (
    Queue("ingestion", default_exchange, routing_key="ingestion"),
    Queue("processing", default_exchange, routing_key="processing"),
    Queue("detection", default_exchange, routing_key="detection"),
    Queue("nlp", default_exchange, routing_key="nlp"),
    Queue("alerts", default_exchange, routing_key="alerts"),
    Queue("behaviour", default_exchange, routing_key="behaviour"),
    Queue("reports", default_exchange, routing_key="reports"),
    Queue("cleanup", default_exchange, routing_key="cleanup"),
    Queue("telegram_ai", default_exchange, routing_key="telegram_ai"),
)

celery_app.conf.update(
    task_queues=QUEUES,
    task_default_queue="processing",
    task_default_exchange="tti_tasks",
    task_default_routing_key="processing",
    task_routes={
        "app.workers.tasks.analyze_telegram_message_ai": {"queue": "telegram_ai"},
        "app.workers.tasks.run_channel_anomaly_check": {"queue": "telegram_ai"},
    },
    # Reliability & Delivery Invariants
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # Execution Time Limits
    task_time_limit=300,        # 5 minutes hard limit (SIGKILL)
    task_soft_time_limit=240,   # 4 minutes soft limit (SoftTimeLimitExceeded)
    # Testing & Eager Execution
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=True,
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


def get_queue_concurrency(queue_name: str) -> int:
    """Return configured worker concurrency limit for a specific queue from environment."""
    mapping = {
        "ingestion": settings.CELERY_INGESTION_CONCURRENCY,
        "processing": settings.CELERY_PROCESSING_CONCURRENCY,
        "detection": settings.CELERY_DETECTION_CONCURRENCY,
        "nlp": settings.CELERY_NLP_CONCURRENCY,
        "fraud": settings.CELERY_FRAUD_CONCURRENCY,
        "url_intelligence": settings.CELERY_URL_INTELLIGENCE_CONCURRENCY,
        "behaviour": settings.CELERY_BEHAVIOUR_CONCURRENCY,
        "alerts": settings.CELERY_ALERTS_CONCURRENCY,
        "reports": settings.CELERY_REPORTS_CONCURRENCY,
        "cleanup": settings.CELERY_CLEANUP_CONCURRENCY,
    }
    return mapping.get(queue_name, 2)


@celery_app.task(name="tti.health_check_task", queue="processing")
def health_check_task(payload: str = "ping") -> str:
    """Diagnostic Celery task for end-to-end background execution testing."""
    return f"pong:{payload}"
