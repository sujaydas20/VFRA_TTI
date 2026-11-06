"""AI Alert Generation and Deduplication Engine.

Dispatches actionable threat alerts to threat.ai_alerts and audit logs
when high-confidence or critical severity threats are detected.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.schemas import ThreatSeverityEnum
from app.database.models.ai import AIAlertRecord, AIMessageAnalysis
from app.database.models.audit import AuditEventRecord

logger = logging.getLogger(__name__)


class AIAlertEngine:
    """Manages high-priority alert generation with deduplication."""

    async def evaluate_and_create_alert(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        analysis: AIMessageAnalysis,
        client_ip: Optional[str] = None,
    ) -> Optional[AIAlertRecord]:
        """
        Evaluate analysis and create alert if severity meets threshold (HIGH or CRITICAL).
        Computes SHA-256 fingerprint to suppress duplicate alert flooding.
        """
        if analysis.severity not in (ThreatSeverityEnum.HIGH.value, ThreatSeverityEnum.CRITICAL.value):
            return None

        # Compute deterministic alert hash based on tenant, category, and message
        raw_key = f"{tenant_id}:{analysis.threat_category}:{analysis.message_id}"
        alert_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        # Check for existing alert with same hash
        stmt = select(AIAlertRecord).where(
            AIAlertRecord.tenant_id == tenant_id,
            AIAlertRecord.alert_hash == alert_hash,
        )
        existing = await db.scalar(stmt)
        if existing:
            logger.debug("Suppressing duplicate alert with hash %s", alert_hash[:12])
            return existing

        now = datetime.now(timezone.utc)
        title = f"[{analysis.severity}] {analysis.threat_category.replace('_', ' ').title()} Alert"
        summary = (
            f"High-priority threat detected on channel '{analysis.channel_id}' with calibrated score "
            f"{analysis.calibrated_score:.1f}/100. {analysis.threat_description}"
        )

        alert = AIAlertRecord(
            alert_id=uuid.uuid4(),
            tenant_id=tenant_id,
            analysis_id=analysis.analysis_id,
            message_id=analysis.message_id,
            channel_id=analysis.channel_id,
            alert_title=title,
            alert_category=analysis.threat_category,
            severity=analysis.severity,
            confidence=analysis.calibrated_score,
            alert_hash=alert_hash,
            summary=summary,
            evidence_pointers=analysis.supporting_evidence,
            status="NEW",
            created_at_utc=now,
        )
        db.add(alert)

        # Audit event
        audit = AuditEventRecord(
            audit_event_id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=None,
            action_type="AI_THREAT_ALERT_GENERATED",
            target_identifier_hash=alert_hash,
            client_ip_address=client_ip,
            correlation_id=alert.alert_id,
            details={
                "message_id": analysis.message_id,
                "category": analysis.threat_category,
                "severity": analysis.severity,
                "confidence": analysis.calibrated_score,
            },
            event_timestamp_utc=now,
        )
        db.add(audit)

        logger.info("Generated %s alert for message %s in channel %s", analysis.severity, analysis.message_id, analysis.channel_id)
        return alert
