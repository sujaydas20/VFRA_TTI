"""Concrete detector implementations for keyword, phrase, regex, and structured entity matching.

Includes ReDoS static analysis, execution timeout guards, and sensitive excerpt extraction.
"""

from dataclasses import dataclass
import logging
import re
from typing import Any, Dict, List, Optional, Pattern
import regex

from app.detection.masking import extract_masked_excerpt, passes_luhn
from app.detection.normalizer import NormalizedText

logger = logging.getLogger(__name__)


class RuleExecutionTimeoutError(Exception):
    """Raised when an individual rule exceeds its runtime execution budget."""

    def __init__(self, rule_id: str, timeout_seconds: float = 0.05):
        super().__init__(f"Rule '{rule_id}' exceeded runtime budget of {timeout_seconds}s")
        self.rule_id = rule_id
        self.timeout_seconds = timeout_seconds


@dataclass
class RuleMatch:
    """Represents a single rule hit on an input message."""

    rule_id: str
    category: str
    weight: float
    severity: str
    explanation: str
    span_start: int
    span_end: int
    masked_excerpt: str
    taxonomy_version: str = "2026.03.1"


class ReDoSChecker:
    """Static analysis to detect vulnerable regex patterns with nested quantifiers."""

    SUSPICIOUS_NESTED_QUANTIFIERS = re.compile(
        r"(\([^\)]*[\+\*][^\)]*\)[\+\*])"  # Group with quantifier followed by another quantifier: (a+)+ or (a*)*
    )

    @classmethod
    def is_safe(cls, pattern: str) -> bool:
        """Validate whether regex contains dangerous nested quantifiers causing catastrophic backtracking."""
        if not pattern:
            return True
        if cls.SUSPICIOUS_NESTED_QUANTIFIERS.search(pattern):
            return False
        return True


class KeywordDetector:
    """Detector for exact keyword and token occurrences across multiple scripts."""

    def __init__(self, rule: Dict[str, Any]):
        self.rule_id = rule["rule_id"]
        self.category = rule["category"]
        self.weight = float(rule.get("weight", 1.0))
        self.severity = rule.get("default_severity", "MEDIUM")
        self.explanation = rule.get("explanation_template", f"Matched keyword rule {self.rule_id}")
        self.taxonomy_version = rule.get("taxonomy_version", "2026.03.1")

        keywords = rule.get("pattern_payload", {}).get("keywords", [])
        self.compiled_patterns: List[Pattern] = []

        for kw in keywords:
            kw_clean = kw.strip()
            if not kw_clean:
                continue
            is_latin = all(ord(c) < 128 for c in kw_clean)
            if is_latin:
                p = re.compile(rf"\b{re.escape(kw_clean)}\b", re.IGNORECASE)
            else:
                p = re.compile(rf"(?:^|[^\w\u0900-\u097f]){re.escape(kw_clean)}(?:$|[^\w\u0900-\u097f])", re.IGNORECASE)
            self.compiled_patterns.append(p)

    def match(self, norm_text: NormalizedText) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for p in self.compiled_patterns:
            for m in p.finditer(norm_text.text):
                norm_start, norm_end = m.start(), m.end()
                raw_start, raw_end = norm_text.get_raw_span(norm_start, norm_end)
                _, _, masked_excerpt = extract_masked_excerpt(
                    norm_text.raw_text, raw_start, raw_end
                )
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        category=self.category,
                        weight=self.weight,
                        severity=self.severity,
                        explanation=self.explanation,
                        span_start=raw_start,
                        span_end=raw_end,
                        masked_excerpt=masked_excerpt,
                        taxonomy_version=self.taxonomy_version,
                    )
                )
        return matches


class PhraseDetector:
    """Detector for multi-word phrases and proximity patterns."""

    def __init__(self, rule: Dict[str, Any]):
        self.rule_id = rule["rule_id"]
        self.category = rule["category"]
        self.weight = float(rule.get("weight", 1.0))
        self.severity = rule.get("default_severity", "MEDIUM")
        self.explanation = rule.get("explanation_template", f"Matched phrase rule {self.rule_id}")
        self.taxonomy_version = rule.get("taxonomy_version", "2026.03.1")

        phrases = rule.get("pattern_payload", {}).get("phrases", [])
        proximity_pairs = rule.get("pattern_payload", {}).get("proximity", [])
        self.compiled_patterns: List[Any] = []

        for phrase in phrases:
            clean = phrase.strip()
            if not clean:
                continue
            is_latin = all(ord(c) < 128 for c in clean)
            if is_latin:
                p = regex.compile(rf"\b{regex.escape(clean)}\b", regex.IGNORECASE)
            else:
                p = regex.compile(regex.escape(clean), regex.IGNORECASE)
            self.compiled_patterns.append(p)

        # Proximity patterns: [word1, word2, max_distance]
        for pair in proximity_pairs:
            w1, w2, dist = pair[0], pair[1], pair[2]
            p = regex.compile(
                rf"(?i)\b{regex.escape(w1)}\b(?:\W+\w+){{0,{dist}}}\W+\b{regex.escape(w2)}\b|"
                rf"(?i)\b{regex.escape(w2)}\b(?:\W+\w+){{0,{dist}}}\W+\b{regex.escape(w1)}\b"
            )
            self.compiled_patterns.append(p)

    def match(self, norm_text: NormalizedText) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for p in self.compiled_patterns:
            try:
                for m in p.finditer(norm_text.text, timeout=0.05):
                    norm_start, norm_end = m.start(), m.end()
                    raw_start, raw_end = norm_text.get_raw_span(norm_start, norm_end)
                    _, _, masked_excerpt = extract_masked_excerpt(
                        norm_text.raw_text, raw_start, raw_end
                    )
                    matches.append(
                        RuleMatch(
                            rule_id=self.rule_id,
                            category=self.category,
                            weight=self.weight,
                            severity=self.severity,
                            explanation=self.explanation,
                            span_start=raw_start,
                            span_end=raw_end,
                            masked_excerpt=masked_excerpt,
                            taxonomy_version=self.taxonomy_version,
                        )
                    )
            except (regex.error, TimeoutError) as e:
                raise RuleExecutionTimeoutError(self.rule_id, timeout_seconds=0.05) from e
        return matches


class RegexDetector:
    """Safe regular expression detector with ReDoS static analysis and runtime timeout."""

    def __init__(self, rule: Dict[str, Any]):
        self.rule_id = rule["rule_id"]
        self.category = rule["category"]
        self.weight = float(rule.get("weight", 1.0))
        self.severity = rule.get("default_severity", "MEDIUM")
        self.explanation = rule.get("explanation_template", f"Matched regex rule {self.rule_id}")
        self.taxonomy_version = rule.get("taxonomy_version", "2026.03.1")

        raw_pattern = rule.get("pattern_payload", {}).get("regex", "")
        if not ReDoSChecker.is_safe(raw_pattern):
            raise ValueError(f"Pattern for rule {self.rule_id} failed ReDoS static validation")

        self.compiled_pattern = regex.compile(raw_pattern, regex.IGNORECASE)

    def match(self, norm_text: NormalizedText) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        try:
            for m in self.compiled_pattern.finditer(norm_text.text, timeout=0.05):
                norm_start, norm_end = m.start(), m.end()
                raw_start, raw_end = norm_text.get_raw_span(norm_start, norm_end)
                _, _, masked_excerpt = extract_masked_excerpt(
                    norm_text.raw_text, raw_start, raw_end
                )
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        category=self.category,
                        weight=self.weight,
                        severity=self.severity,
                        explanation=self.explanation,
                        span_start=raw_start,
                        span_end=raw_end,
                        masked_excerpt=masked_excerpt,
                        taxonomy_version=self.taxonomy_version,
                    )
                )
        except (regex.error, TimeoutError) as e:
            raise RuleExecutionTimeoutError(self.rule_id, timeout_seconds=0.05) from e
        return matches


class EntityDetector:
    """Detects structured Indian entities (UPI VPA, IFSC, mobile numbers, payment cards)."""

    UPI_PATTERN = re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,256}@(okhdfcbank|okaxis|okicici|oksbi|paytm|ybl|axl|ibl|upi|idfcbank|postbank)\b",
        re.IGNORECASE,
    )
    IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
    MOBILE_PATTERN = re.compile(r"\b(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}\b")
    CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def __init__(self, rule: Dict[str, Any]):
        self.rule_id = rule["rule_id"]
        self.category = rule["category"]
        self.weight = float(rule.get("weight", 1.0))
        self.severity = rule.get("default_severity", "MEDIUM")
        self.explanation = rule.get("explanation_template", f"Matched entity rule {self.rule_id}")
        self.entity_type = rule.get("pattern_payload", {}).get("entity_type", "all")
        self.taxonomy_version = rule.get("taxonomy_version", "2026.03.1")

    def match(self, norm_text: NormalizedText) -> List[RuleMatch]:
        matches: List[RuleMatch] = []

        patterns_to_check = []
        if self.entity_type in ("upi", "all"):
            patterns_to_check.append(("upi", self.UPI_PATTERN, None))
        if self.entity_type in ("ifsc", "all"):
            patterns_to_check.append(("ifsc", self.IFSC_PATTERN, None))
        if self.entity_type in ("mobile", "all"):
            patterns_to_check.append(("mobile", self.MOBILE_PATTERN, None))
        if self.entity_type in ("card", "all"):
            patterns_to_check.append(("card", self.CARD_PATTERN, passes_luhn))

        for name, pattern, validator in patterns_to_check:
            for m in pattern.finditer(norm_text.text):
                val_text = m.group(0)
                if validator and not validator(re.sub(r"\D", "", val_text)):
                    continue
                norm_start, norm_end = m.start(), m.end()
                raw_start, raw_end = norm_text.get_raw_span(norm_start, norm_end)
                _, _, masked_excerpt = extract_masked_excerpt(
                    norm_text.raw_text, raw_start, raw_end
                )
                matches.append(
                    RuleMatch(
                        rule_id=f"{self.rule_id}_{name}",
                        category=self.category,
                        weight=self.weight,
                        severity=self.severity,
                        explanation=f"{self.explanation} (detected {name})",
                        span_start=raw_start,
                        span_end=raw_end,
                        masked_excerpt=masked_excerpt,
                        taxonomy_version=self.taxonomy_version,
                    )
                )
        return matches
