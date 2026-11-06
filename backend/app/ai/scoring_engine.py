"""AI Module 7: Calibrated Threat Scoring and Severity Determination.

Combines deterministic heuristic weights with Gemini semantic confidence scores
to produce balanced, auditable, and reproducible threat severity ratings.
"""

from typing import Dict, List
from app.ai.schemas import ExtractedIOCItem, ThreatCategoryEnum, ThreatSeverityEnum


class ThreatScoringEngine:
    """Calibrates AI confidence with deterministic indicator weights."""

    @staticmethod
    def calculate_calibrated_score(
        llm_confidence: float,
        threat_category: str,
        extracted_iocs: List[ExtractedIOCItem],
        detected_slang: Dict[str, str],
        threat_detected: bool,
    ) -> float:
        """
        Compute deterministic calibrated score (0.0 to 100.0).
        Prevents LLM hallucinated scores by tying final rating to verifiable evidence.
        """
        if not threat_detected:
            return min(llm_confidence, 20.0)

        # Baseline is 50% LLM weight
        base = llm_confidence * 0.50

        # Heuristic bonuses
        evidence_points = 0.0

        # Crypto indicators (BTC, ETH, TRON)
        crypto_count = sum(1 for i in extracted_iocs if i.ioc_type.startswith("crypto_"))
        evidence_points += min(crypto_count * 15.0, 30.0)

        # Malicious URLs / Domains
        url_count = sum(1 for i in extracted_iocs if i.ioc_type in ("url", "domain"))
        evidence_points += min(url_count * 10.0, 20.0)

        # Financial UPI IDs
        upi_count = sum(1 for i in extracted_iocs if i.ioc_type == "upi_id")
        evidence_points += min(upi_count * 15.0, 20.0)

        # Confirmed fraud slang terms
        slang_count = len(detected_slang)
        evidence_points += min(slang_count * 5.0, 15.0)

        # High-risk category weight
        if threat_category in (
            ThreatCategoryEnum.MALWARE.value,
            ThreatCategoryEnum.DATA_LEAKS.value,
            ThreatCategoryEnum.EXTORTION.value,
            ThreatCategoryEnum.BANKING_FRAUD.value,
        ):
            evidence_points += 10.0

        # If zero verifiable IOCs and zero slang, cap confidence at 60.0
        calibrated = base + evidence_points
        if not extracted_iocs and not detected_slang:
            calibrated = min(calibrated, 55.0)

        return round(min(max(calibrated, 5.0), 99.0), 2)

    @staticmethod
    def determine_severity(
        calibrated_score: float,
        threat_category: str,
        has_critical_ioc: bool = False,
    ) -> ThreatSeverityEnum:
        """Determine standardized severity level from calibrated score and category."""
        if calibrated_score < 25.0:
            return ThreatSeverityEnum.INFO
        if calibrated_score < 50.0:
            return ThreatSeverityEnum.LOW
        if calibrated_score < 75.0:
            return ThreatSeverityEnum.MEDIUM

        # Score >= 75
        if calibrated_score >= 85.0 or has_critical_ioc or threat_category in (
            ThreatCategoryEnum.MALWARE.value,
            ThreatCategoryEnum.EXTORTION.value,
            ThreatCategoryEnum.DATA_LEAKS.value,
        ):
            return ThreatSeverityEnum.CRITICAL

        return ThreatSeverityEnum.HIGH
