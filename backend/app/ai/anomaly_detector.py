"""AI Module 5: Statistical Anomaly Detection & Behavioral Monitoring.

Capabilities:
- Rolling window velocity tracking (message volume, URL frequency, IOC frequency)
- Z-score deviation calculation against established historical baselines
- Configurable sensitivity thresholds (default z >= 2.5)
- Gemini-powered contextual anomaly explanation
- Anomaly persistence to threat.threat_anomalies
"""

from datetime import datetime, timedelta, timezone
import logging
import math
from typing import Dict, List, Optional
from uuid import UUID
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.gemini_client import GeminiClientWrapper
from app.ai.schemas import AnomalyTypeEnum, ThreatSeverityEnum
from app.core.config import get_settings
from app.database.models.ai import ThreatAnomalyRecord
from app.database.models.intelligence import SourceMessage

logger = logging.getLogger(__name__)


class AnomalyDetectionEngine:
    """Detects statistical posting bursts and behavioral deviations in monitored channels."""

    def __init__(self, gemini_client: Optional[GeminiClientWrapper] = None):
        self.settings = get_settings()
        self.gemini_client = gemini_client or GeminiClientWrapper.get_instance()
        self.z_threshold = self.settings.AI_ANOMALY_ZSCORE_THRESHOLD

    async def evaluate_channel_anomalies(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        channel_id: str,
        sample_messages: Optional[List[str]] = None,
    ) -> List[ThreatAnomalyRecord]:
        """
        Assess message volume velocity over the past hour compared to 24-hour baseline.
        """
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)
        one_day_ago = now - timedelta(days=1)

        # 1. Count messages in last 1 hour
        stmt_1h = select(func.count(SourceMessage.message_id)).where(
            SourceMessage.tenant_id == tenant_id,
            SourceMessage.channel_id == channel_id,
            SourceMessage.broadcast_timestamp_utc >= one_hour_ago,
        )
        current_1h_count = (await db.scalar(stmt_1h)) or 0

        # 2. Count messages in last 24 hours
        stmt_24h = select(func.count(SourceMessage.message_id)).where(
            SourceMessage.tenant_id == tenant_id,
            SourceMessage.channel_id == channel_id,
            SourceMessage.broadcast_timestamp_utc >= one_day_ago,
        )
        total_24h_count = (await db.scalar(stmt_24h)) or 0

        # Compute hourly baseline mean and standard deviation
        hourly_mean = max(1.0, total_24h_count / 24.0)
        # Poisson-like standard deviation estimate for event counts: sqrt(mean) with floor of 1.5
        hourly_std = max(1.5, math.sqrt(hourly_mean))

        z_score = (current_1h_count - hourly_mean) / hourly_std
        detected_records: List[ThreatAnomalyRecord] = []

        if z_score >= self.z_threshold and current_1h_count >= 10:
            logger.warning(
                "Anomaly detected in channel %s: volume=%d, mean=%.1f, z=%.2f",
                channel_id, current_1h_count, hourly_mean, z_score,
            )

            # Generate Gemini explanation
            sample_list = sample_messages or [f"Recent high velocity activity on channel {channel_id}"]
            explanation = await self.gemini_client.interpret_anomaly(
                channel_id=channel_id,
                anomaly_type=AnomalyTypeEnum.VOLUME_SPIKE.value,
                metric_value=float(current_1h_count),
                baseline_mean=hourly_mean,
                z_score=z_score,
                sample_recent_messages=sample_list,
            )

            severity = ThreatSeverityEnum.HIGH.value if z_score >= 4.0 else ThreatSeverityEnum.MEDIUM.value

            anomaly = ThreatAnomalyRecord(
                anomaly_id=uuid.uuid4(),
                tenant_id=tenant_id,
                channel_id=channel_id,
                anomaly_type=AnomalyTypeEnum.VOLUME_SPIKE.value,
                metric_value=float(current_1h_count),
                baseline_mean=hourly_mean,
                baseline_std=hourly_std,
                z_score=round(z_score, 2),
                gemini_explanation=explanation,
                severity=severity,
                detected_at_utc=now,
            )
            db.add(anomaly)
            detected_records.append(anomaly)

        return detected_records
