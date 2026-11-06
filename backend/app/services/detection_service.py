"""Threat detection service layer coordinating database persistence, engine, and sinks."""

from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models.detection import (
    DetectionRecord,
    DetectionRuleHitRecord,
    KeywordRuleRecord,
    ThreatCategoryRecord,
    URLIndicatorRecord,
)
from app.detection.engine import CompiledDetectionResult, ThreatDetectionEngine
from app.detection.taxonomy_loader import load_taxonomy_from_directory
from app.services.alert_service import AlertService
from app.services.detection_sink import LoggingDetectionSink
from app.services.protocols import DetectionSink


class ThreatDetectionService:
    """Service providing threat taxonomy management and message analysis workflows."""

    def __init__(self, detection_sink: Optional[DetectionSink] = None):
        self.sink = detection_sink or LoggingDetectionSink()

    async def sync_taxonomy(
        self,
        session: AsyncSession,
        taxonomy_dir: Path,
    ) -> Dict[str, int]:
        """Synchronize disk YAML taxonomy definitions into threat schema tables."""
        categories, rules = load_taxonomy_from_directory(taxonomy_dir)

        # 1. Upsert Categories
        for cat in categories:
            stmt = (
                insert(ThreatCategoryRecord)
                .values(
                    category_id=cat["category"],
                    display_name=cat["display_name"],
                    description=cat["description"],
                    default_severity=cat["default_severity"],
                    is_active=cat["is_active"],
                )
                .on_conflict_do_update(
                    index_elements=[ThreatCategoryRecord.category_id],
                    set_={
                        "display_name": cat["display_name"],
                        "description": cat["description"],
                        "default_severity": cat["default_severity"],
                        "is_active": cat["is_active"],
                    },
                )
            )
            await session.execute(stmt)

        # 2. Upsert Rules
        for r in rules:
            stmt = (
                insert(KeywordRuleRecord)
                .values(
                    rule_id=r["rule_id"],
                    category=r["category"],
                    rule_type=r["rule_type"],
                    languages=r["languages"],
                    pattern_payload=r["pattern_payload"],
                    weight=r["weight"],
                    default_severity=r["default_severity"],
                    explanation_template=r["explanation_template"],
                    is_enabled=r["is_enabled"],
                    is_reviewed=r["is_reviewed"],
                    taxonomy_version=r["taxonomy_version"],
                )
                .on_conflict_do_update(
                    index_elements=[KeywordRuleRecord.rule_id],
                    set_={
                        "category": r["category"],
                        "rule_type": r["rule_type"],
                        "languages": r["languages"],
                        "pattern_payload": r["pattern_payload"],
                        "weight": r["weight"],
                        "default_severity": r["default_severity"],
                        "explanation_template": r["explanation_template"],
                        "is_enabled": r["is_enabled"],
                        "is_reviewed": r["is_reviewed"],
                        "taxonomy_version": r["taxonomy_version"],
                    },
                )
            )
            await session.execute(stmt)

        await session.flush()
        return {"categories_synced": len(categories), "rules_synced": len(rules)}

    async def get_active_engine(
        self,
        session: Optional[AsyncSession] = None,
        taxonomy_dir: Optional[Path] = None,
    ) -> ThreatDetectionEngine:
        """Construct an initialized ThreatDetectionEngine instance."""
        rules: List[Dict[str, Any]] = []

        if session is not None:
            # Query rules from database
            stmt = select(KeywordRuleRecord).where(KeywordRuleRecord.is_enabled == True)
            db_rules = (await session.execute(stmt)).scalars().all()
            for r in db_rules:
                rules.append({
                    "rule_id": r.rule_id,
                    "category": r.category,
                    "rule_type": r.rule_type,
                    "languages": r.languages,
                    "pattern_payload": r.pattern_payload,
                    "weight": r.weight,
                    "default_severity": r.default_severity,
                    "explanation_template": r.explanation_template,
                    "is_enabled": r.is_enabled,
                    "is_reviewed": r.is_reviewed,
                    "taxonomy_version": r.taxonomy_version,
                })

        # If database has no rules, fall back to disk YAML
        if not rules:
            target_dir = taxonomy_dir or (Path(__file__).resolve().parent.parent.parent / "rules" / "taxonomy")
            _, rules = load_taxonomy_from_directory(target_dir)

        return ThreatDetectionEngine(rules)

    async def analyze_and_record(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        message_id: str,
        raw_text: str,
        subject_id: Optional[uuid.UUID] = None,
        taxonomy_dir: Optional[Path] = None,
    ) -> List[CompiledDetectionResult]:
        """Analyze message, persist detections with idempotency, and emit to sink."""
        engine = await self.get_active_engine(session=session, taxonomy_dir=taxonomy_dir)
        detections = engine.analyze_message(
            raw_text=raw_text,
            tenant_id=tenant_id,
            message_id=message_id,
            subject_id=subject_id,
        )

        persisted: List[CompiledDetectionResult] = []

        for d in detections:
            # Check for existing detection to guarantee idempotency
            existing_stmt = select(DetectionRecord).where(
                DetectionRecord.tenant_id == tenant_id,
                DetectionRecord.message_id == message_id,
                DetectionRecord.category == d.category,
                DetectionRecord.taxonomy_version == d.taxonomy_version,
            )
            existing = (await session.execute(existing_stmt)).scalar_one_or_none()
            if existing:
                persisted.append(d)
                continue

            detection_rec = DetectionRecord(
                detection_id=d.detection_id,
                tenant_id=tenant_id,
                subject_id=subject_id,
                message_id=message_id,
                category=d.category,
                stance=d.stance,
                severity=d.severity,
                rule_confidence=d.rule_confidence,
                explanation=d.explanation,
                taxonomy_version=d.taxonomy_version,
                engine_version=d.engine_version,
            )
            session.add(detection_rec)
            await session.flush()

            # Record rule hits (masked excerpts only)
            for h in d.hits:
                hit_rec = DetectionRuleHitRecord(
                    detection_id=detection_rec.detection_id,
                    tenant_id=tenant_id,
                    rule_id=h.rule_id,
                    rule_version=h.taxonomy_version,
                    span_start=h.span_start,
                    span_end=h.span_end,
                    masked_excerpt=h.masked_excerpt,
                )
                session.add(hit_rec)

            # Record URL indicators (defanged only)
            for ind in d.url_indicators:
                url_rec = URLIndicatorRecord(
                    detection_id=detection_rec.detection_id,
                    tenant_id=tenant_id,
                    defanged_url=ind["defanged_url"],
                    domain=ind["domain"],
                    indicator_flags=ind["indicator_flags"],
                )
                session.add(url_rec)

            await session.flush()

            # Emit to downstream sink
            await self.sink.emit(d)

            # Phase 4: raise alert with duplicate suppression (no message content)
            await AlertService().create_alert_for_detection(
                session=session,
                tenant_id=tenant_id,
                detection=detection_rec,
            )

            persisted.append(d)

        return persisted

