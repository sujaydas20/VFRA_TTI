"""Threat Detection Engine orchestrator.

Loads taxonomy rules, coordinates detectors, stance classifier, and URL indicators,
and compiles explainable detection records.
"""

from collections import defaultdict
from dataclasses import dataclass, field
import logging
import os
import time
from typing import Any, Dict, List, Optional
import uuid

from app.detection.detectors import (
    EntityDetector,
    KeywordDetector,
    PhraseDetector,
    RegexDetector,
    RuleExecutionTimeoutError,
    RuleMatch,
)
from app.detection.normalizer import TextNormalizer
from app.detection.scoring import (
    calculate_rule_confidence,
    resolve_severity,
)
from app.detection.stance import StanceClassifier
from app.detection.url_indicators import URLIndicatorDetector

logger = logging.getLogger(__name__)

ENGINE_VERSION = "1.0.0"
MAX_MESSAGE_LENGTH = 4096
OVERALL_MESSAGE_BUDGET_MS = 200.0  # 200ms per-message time budget


@dataclass
class CompiledDetectionResult:
    """Detection result structured for persistence and downstream sinks."""

    detection_id: uuid.UUID
    tenant_id: uuid.UUID
    message_id: str
    category: str
    stance: str
    severity: str
    rule_confidence: float
    explanation: str
    taxonomy_version: str
    engine_version: str
    hits: List[RuleMatch] = field(default_factory=list)
    url_indicators: List[Dict[str, Any]] = field(default_factory=list)
    subject_id: Optional[uuid.UUID] = None
    is_degraded: bool = False


class ThreatDetectionEngine:
    """Core rule execution engine for threat and fraud identification."""

    def __init__(self, rules: List[Dict[str, Any]], taxonomy_version: str = "2026.03.1"):
        self.taxonomy_version = taxonomy_version
        self.detectors: List[Any] = []
        self.rules_loaded: int = 0
        self.reviewed_rules_loaded: int = 0
        self.is_degraded: bool = False
        self.rule_timeout_counts: Dict[str, int] = defaultdict(int)
        self._load_detectors(rules)

    def _load_detectors(self, rules: List[Dict[str, Any]]) -> None:
        """Compile detector objects from rule definitions."""
        is_prod = os.getenv("TTI_ENV", "development").lower() == "production"

        for r in rules:
            if not r.get("is_enabled", True):
                continue
            is_reviewed = r.get("is_reviewed", False)
            if is_reviewed:
                self.reviewed_rules_loaded += 1

            # Production guard: unreviewed rules are excluded in production
            if is_prod and not is_reviewed:
                continue

            rule_type = r.get("rule_type")
            try:
                if rule_type == "keyword":
                    self.detectors.append(KeywordDetector(r))
                elif rule_type == "phrase":
                    self.detectors.append(PhraseDetector(r))
                elif rule_type == "regex":
                    self.detectors.append(RegexDetector(r))
                elif rule_type == "entity":
                    self.detectors.append(EntityDetector(r))
            except Exception:
                # Log or skip invalid rule
                continue

        self.rules_loaded = len(self.detectors)

    def analyze_message(
        self,
        raw_text: str,
        tenant_id: uuid.UUID,
        message_id: str,
        subject_id: Optional[uuid.UUID] = None,
    ) -> List[CompiledDetectionResult]:
        """Analyze message text against all active detectors and produce detection results."""
        if not raw_text or not raw_text.strip():
            return []

        # Enforce hard length cap
        if len(raw_text) > MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"Message length ({len(raw_text)}) exceeds maximum allowed limit of {MAX_MESSAGE_LENGTH} characters"
            )

        start_time = time.perf_counter()
        degraded = False

        # Multilingual text normalization
        norm_text = TextNormalizer.normalize(raw_text)

        # Rule matching with per-rule timeout and overall message budget
        raw_hits: List[RuleMatch] = []
        for detector in self.detectors:
            # Check overall per-message budget
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if elapsed_ms > OVERALL_MESSAGE_BUDGET_MS:
                logger.warning(
                    "Overall message analysis budget exceeded (%.2f ms > %.2f ms)",
                    elapsed_ms,
                    OVERALL_MESSAGE_BUDGET_MS,
                )
                degraded = True
                break

            try:
                hits = detector.match(norm_text)
                if hits:
                    raw_hits.extend(hits)
            except RuleExecutionTimeoutError as e:
                self.rule_timeout_counts[e.rule_id] += 1
                logger.warning(
                    "Rule execution timeout: rule_id=%s, count=%d (content omitted)",
                    e.rule_id,
                    self.rule_timeout_counts[e.rule_id],
                )
                degraded = True
                self.is_degraded = True
                continue
            except Exception:
                continue

        # Offline URL indicators
        indicators = URLIndicatorDetector.analyze_text(raw_text)

        # If indicators found (e.g. suspicious link, apk, brand lookalike), inject indicator category
        has_url_indicators = len(indicators) > 0
        if has_url_indicators and not any(h.category == "suspicious_urls" for h in raw_hits):
            from app.detection.masking import extract_masked_excerpt
            _, _, excerpt = extract_masked_excerpt(norm_text.raw_text, 0, min(len(raw_text), 30))
            raw_hits.append(
                RuleMatch(
                    rule_id="url_heuristic_suspicious",
                    category="suspicious_urls",
                    weight=1.5,
                    severity="HIGH",
                    explanation="Suspicious URL indicator flags detected",
                    span_start=0,
                    span_end=min(len(raw_text), 30),
                    masked_excerpt=excerpt,
                    taxonomy_version=self.taxonomy_version,
                )
            )

        has_detections = len(raw_hits) > 0

        # Stance classification
        if degraded:
            # Degraded execution routes to human review with unclear stance
            stance = "unclear"
        else:
            stance = StanceClassifier.classify(raw_text, has_detections=has_detections)
            if has_detections and stance == "none":
                stance = "unclear"

        # Group hits by category
        grouped: Dict[str, List[RuleMatch]] = {}
        for h in raw_hits:
            grouped.setdefault(h.category, []).append(h)

        results: List[CompiledDetectionResult] = []
        for cat, hits in grouped.items():
            weights = [h.weight for h in hits]
            severities = [h.severity for h in hits]
            confidence = calculate_rule_confidence(weights)
            severity = resolve_severity(severities, stance, indicator_count=len(indicators))
            
            explanations = list({h.explanation for h in hits})
            summary_explanation = "; ".join(explanations)
            if degraded:
                summary_explanation += " [DEGRADED_EXECUTION_TIMEOUT: Routed to human review]"

            cat_indicators = indicators if cat in ("phishing", "suspicious_urls", "banking_fraud", "malware_indicators") else []

            results.append(
                CompiledDetectionResult(
                    detection_id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    subject_id=subject_id,
                    message_id=message_id,
                    category=cat,
                    stance=stance,
                    severity=severity,
                    rule_confidence=confidence,
                    explanation=summary_explanation,
                    taxonomy_version=self.taxonomy_version,
                    engine_version=ENGINE_VERSION,
                    hits=hits,
                    url_indicators=cat_indicators,
                    is_degraded=degraded,
                )
            )

        return results
