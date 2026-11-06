"""AI Module 6: Cross-Source Intelligence Correlation & Threat Graph Linking.

Identifies:
- Shared IOCs (same crypto address, UPI ID, domain, IP across different messages/channels)
- Threat actor overlap (same username or forward source across distinct monitoring feeds)
- Campaign propagation (clustered multi-channel solicitations)
"""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from uuid import UUID
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.schemas import CorrelationTypeEnum
from app.database.models.ai import ExtractedIOCRecord, IntelligenceCorrelation

logger = logging.getLogger(__name__)


class IntelligenceCorrelationEngine:
    """Discovers relationships and campaigns across disparate intelligence sources."""

    async def correlate_message_iocs(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        message_id: str,
        channel_id: str,
        new_iocs: List[ExtractedIOCRecord],
    ) -> List[IntelligenceCorrelation]:
        """
        Search historical IOC ledger for matches on normalized values across different channels.
        Creates non-duplicate IntelligenceCorrelation records.
        """
        if not new_iocs:
            return []

        correlations: List[IntelligenceCorrelation] = []
        now = datetime.now(timezone.utc)

        for ioc in new_iocs:
            # Query existing IOCs matching this normalized value in other messages
            stmt = select(ExtractedIOCRecord).where(
                ExtractedIOCRecord.tenant_id == tenant_id,
                ExtractedIOCRecord.normalized_value == ioc.normalized_value,
                ExtractedIOCRecord.message_id != message_id,
            ).limit(10)

            matches = (await db.scalars(stmt)).all()
            for match in matches:
                # Check if correlation already exists
                exist_stmt = select(IntelligenceCorrelation).where(
                    IntelligenceCorrelation.tenant_id == tenant_id,
                    IntelligenceCorrelation.source_message_id == message_id,
                    IntelligenceCorrelation.target_message_id == match.message_id,
                    IntelligenceCorrelation.correlation_type == CorrelationTypeEnum.SHARED_IOC.value,
                )
                existing = await db.scalar(exist_stmt)
                if existing:
                    continue

                corr = IntelligenceCorrelation(
                    correlation_id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    source_message_id=message_id,
                    target_message_id=match.message_id,
                    source_channel_id=channel_id,
                    target_channel_id=match.channel_id,
                    correlation_type=CorrelationTypeEnum.SHARED_IOC.value,
                    matched_entity_type=ioc.ioc_type,
                    matched_entity_value=ioc.defanged_value,
                    confidence=0.95,
                    explanation=(
                        f"Cross-channel correlation identified: shared {ioc.ioc_type} "
                        f"'{ioc.defanged_value}' observed across channels {channel_id} and {match.channel_id}."
                    ),
                    created_at_utc=now,
                )
                db.add(corr)
                correlations.append(corr)

        return correlations
