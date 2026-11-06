"""AI Module 2: Automated Threat Intelligence & Classification Orchestrator.

Orchestrates the complete 6-stage AI threat intelligence pipeline:
Stage 1: Rule Engine & Heuristic Pre-scan
Stage 2: Local NLP, Text Normalization, Slang & Relevance Triage
Stage 3: Gemini API Contextual Analysis & Structured JSON Output
Stage 4: IOC Extraction, Validation, Defanging & Association
Stage 5: Deterministic Calibrated Scoring & Severity Assignment
Stage 6: Persistence, Cross-Source Correlation, and Alert Dispatch
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.alert_engine import AIAlertEngine
from app.ai.correlation_engine import IntelligenceCorrelationEngine
from app.ai.gemini_client import GeminiClientWrapper
from app.ai.ioc_extractor import IOCExtractor
from app.ai.message_understanding import MessageUnderstandingEngine
from app.ai.schemas import (
    GeminiStructuredThreatOutput,
    ThreatCategoryEnum,
    ThreatSeverityEnum,
)
from app.ai.scoring_engine import ThreatScoringEngine
from app.database.models.ai import (
    AIMessageAnalysis,
    AITokenUsageRecord,
    ExtractedIOCRecord,
)

logger = logging.getLogger(__name__)


class ThreatClassificationOrchestrator:
    """Master orchestrator for AI threat intelligence analysis."""

    def __init__(
        self,
        understanding_engine: Optional[MessageUnderstandingEngine] = None,
        ioc_extractor: Optional[IOCExtractor] = None,
        gemini_client: Optional[GeminiClientWrapper] = None,
        scoring_engine: Optional[ThreatScoringEngine] = None,
        correlation_engine: Optional[IntelligenceCorrelationEngine] = None,
        alert_engine: Optional[AIAlertEngine] = None,
    ):
        self.understanding = understanding_engine or MessageUnderstandingEngine()
        self.ioc_extractor = ioc_extractor or IOCExtractor()
        self.gemini = gemini_client or GeminiClientWrapper.get_instance()
        self.scoring = scoring_engine or ThreatScoringEngine()
        self.correlation = correlation_engine or IntelligenceCorrelationEngine()
        self.alert_engine = alert_engine or AIAlertEngine()

    async def analyze_message(
        self,
        db: AsyncSession,
        tenant_id: UUID,
        message_id: str,
        channel_id: str,
        raw_text: str,
        channel_title: Optional[str] = None,
        sender_username: Optional[str] = None,
        recent_context: Optional[List[str]] = None,
        client_ip: Optional[str] = None,
    ) -> AIMessageAnalysis:
        """
        Execute full end-to-end threat intelligence pipeline for a single message.
        """
        now = datetime.now(timezone.utc)

        # ---------------------------------------------------------------------
        # Stage 1 & 2: Local Preprocessing & Relevance Triage
        # ---------------------------------------------------------------------
        prep = self.understanding.process(raw_text)

        # Extract deterministic IOCs
        extracted_iocs = self.ioc_extractor.extract_all(prep.normalized_text)

        # Check if already analyzed to ensure idempotency
        stmt_exist = select(AIMessageAnalysis).where(
            AIMessageAnalysis.tenant_id == tenant_id,
            AIMessageAnalysis.message_id == message_id,
        )
        existing = await db.scalar(stmt_exist)
        if existing:
            logger.debug("Message %s already analyzed in tenant %s. Returning existing record.", message_id, tenant_id)
            return existing

        # ---------------------------------------------------------------------
        # Stage 3: Gemini Analysis or Low-Relevance Bypass
        # ---------------------------------------------------------------------
        if not prep.is_relevant_for_ai and not extracted_iocs:
            # Low-relevance message (trivial greeting or pure noise): bypass LLM to save tokens
            analysis = AIMessageAnalysis(
                analysis_id=uuid.uuid4(),
                tenant_id=tenant_id,
                message_id=message_id,
                channel_id=channel_id,
                threat_detected=False,
                threat_category=ThreatCategoryEnum.BENIGN.value,
                secondary_categories=[],
                threat_description="Trivial conversational chatter; no threat detected.",
                severity=ThreatSeverityEnum.INFO.value,
                confidence_score=5.0,
                calibrated_score=5.0,
                slang_interpretations=[],
                coded_language_detected=False,
                supporting_evidence=[],
                explanation=prep.relevance_reason,
                recommended_action="DISCARD_OR_ARCHIVE",
                model_used="local-relevance-filter",
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=0.5,
                analyzed_at_utc=now,
            )
            db.add(analysis)
            await db.commit()
            await db.refresh(analysis)
            return analysis

        # Deep analysis with Gemini API (or heuristic fallback)
        gemini_result, usage_meta = await self.gemini.analyze_message_content(
            sanitized_text=prep.normalized_text,
            channel_title=channel_title,
            sender_username=sender_username,
            recent_context=recent_context,
        )

        # ---------------------------------------------------------------------
        # Stage 4: Merge Slang and Metadata
        # ---------------------------------------------------------------------
        slang_list = [s.model_dump() for s in gemini_result.slang_interpretations]
        for term, meaning in prep.detected_slang.items():
            if not any(s["term"].lower() == term.lower() for s in slang_list):
                slang_list.append({"term": term, "meaning": meaning})

        # ---------------------------------------------------------------------
        # Stage 5: Calibrated Threat Scoring
        # ---------------------------------------------------------------------
        calibrated_score = self.scoring.calculate_calibrated_score(
            llm_confidence=gemini_result.confidence_score,
            threat_category=gemini_result.primary_category.value,
            extracted_iocs=extracted_iocs,
            detected_slang=prep.detected_slang,
            threat_detected=gemini_result.threat_detected,
        )

        has_critical_ioc = any(i.ioc_type.startswith("crypto_") for i in extracted_iocs)
        final_severity = self.scoring.determine_severity(
            calibrated_score=calibrated_score,
            threat_category=gemini_result.primary_category.value,
            has_critical_ioc=has_critical_ioc,
        )

        # ---------------------------------------------------------------------
        # Stage 6: Database Persistence & IOC Association
        # ---------------------------------------------------------------------
        analysis_id = uuid.uuid4()
        analysis = AIMessageAnalysis(
            analysis_id=analysis_id,
            tenant_id=tenant_id,
            message_id=message_id,
            channel_id=channel_id,
            threat_detected=gemini_result.threat_detected,
            threat_category=gemini_result.primary_category.value,
            secondary_categories=gemini_result.secondary_categories,
            threat_description=gemini_result.threat_description,
            severity=final_severity.value,
            confidence_score=gemini_result.confidence_score,
            calibrated_score=calibrated_score,
            slang_interpretations=slang_list,
            coded_language_detected=gemini_result.coded_language_detected or prep.obfuscation_detected,
            supporting_evidence=gemini_result.supporting_evidence,
            explanation=gemini_result.explanation,
            recommended_action=gemini_result.recommended_action,
            model_used=usage_meta.get("model", "gemini-2.5-flash"),
            prompt_tokens=usage_meta.get("prompt_tokens", 0),
            completion_tokens=usage_meta.get("completion_tokens", 0),
            latency_ms=usage_meta.get("latency_ms", 0.0),
            analyzed_at_utc=now,
        )
        db.add(analysis)

        # Persist extracted IOC records
        db_iocs: List[ExtractedIOCRecord] = []
        for ioc in extracted_iocs:
            ioc_rec = ExtractedIOCRecord(
                ioc_id=uuid.uuid4(),
                tenant_id=tenant_id,
                analysis_id=analysis_id,
                message_id=message_id,
                channel_id=channel_id,
                ioc_type=ioc.ioc_type,
                raw_value=ioc.raw_value,
                normalized_value=ioc.normalized_value,
                defanged_value=ioc.defanged_value,
                is_validated=ioc.is_validated,
                is_malicious=ioc.is_malicious,
                confidence=ioc.confidence,
                extracted_at_utc=now,
            )
            db.add(ioc_rec)
            db_iocs.append(ioc_rec)

        # Record Token Usage
        if usage_meta.get("total_tokens", 0) > 0:
            token_rec = AITokenUsageRecord(
                usage_id=uuid.uuid4(),
                tenant_id=tenant_id,
                model_name=usage_meta.get("model", "gemini-2.5-flash"),
                operation_type="MESSAGE_ANALYSIS",
                prompt_tokens=usage_meta.get("prompt_tokens", 0),
                completion_tokens=usage_meta.get("completion_tokens", 0),
                total_tokens=usage_meta.get("total_tokens", 0),
                estimated_cost_usd=usage_meta.get("estimated_cost_usd", 0.0),
                latency_ms=usage_meta.get("latency_ms", 0.0),
                recorded_at_utc=now,
            )
            db.add(token_rec)

        # Cross-Source Intelligence Correlation
        try:
            await self.correlation.correlate_message_iocs(
                db=db,
                tenant_id=tenant_id,
                message_id=message_id,
                channel_id=channel_id,
                new_iocs=db_iocs,
            )
        except Exception as e:
            logger.warning("Correlation processing failed for message %s: %s", message_id, e)

        # Alert Generation
        try:
            await self.alert_engine.evaluate_and_create_alert(
                db=db,
                tenant_id=tenant_id,
                analysis=analysis,
                client_ip=client_ip,
            )
        except Exception as e:
            logger.warning("Alert dispatch failed for message %s: %s", message_id, e)

        await db.commit()
        await db.refresh(analysis)
        return analysis
