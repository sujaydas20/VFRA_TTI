"""Severity and uncalibrated heuristic confidence scoring matrix.

INVARIANTS:
- Confidence score is strictly heuristic / rule-based and explicitly labeled as uncalibrated.
- Stance modulates severity to avoid alert fatigue (warnings and discussions downgrade to INFO/LOW).
"""

from typing import List

CONFIDENCE_LABEL = "rule confidence (uncalibrated)"

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

REVERSE_SEVERITY = {v: k for k, v in SEVERITY_ORDER.items()}


def calculate_rule_confidence(weights: List[float]) -> float:
    """Calculate uncalibrated confidence score bounded between 0.1 and 1.0."""
    if not weights:
        return 0.0
    # Base heuristic: logarithmic or bounded asymptotic combination of matched rule weights
    total_weight = sum(weights)
    raw_score = 0.5 + 0.1 * min(total_weight, 5.0)
    return round(min(max(raw_score, 0.1), 0.99), 2)


def resolve_severity(
    rule_severities: List[str],
    stance: str,
    indicator_count: int = 0,
) -> str:
    """Resolve final severity level considering matched rules, stance, and indicators."""
    if not rule_severities:
        return "INFO"

    max_rank = max(SEVERITY_ORDER.get(s.upper(), 1) for s in rule_severities)

    # If indicators found (e.g. phishing URL with suspicious TLD), boost
    if indicator_count > 0 and max_rank < 4:
        max_rank += 1

    # Apply stance modulations
    if stance == "warning":
        # Pure warnings or alerts should never trigger CRITICAL/HIGH
        max_rank = min(max_rank, SEVERITY_ORDER["LOW"])
    elif stance in ("discussing", "reporting"):
        max_rank = min(max_rank, SEVERITY_ORDER["INFO"])
    elif stance in ("potentially_facilitating", "facilitating"):
        # Facilitating messages maintain their high urgency
        max_rank = max(max_rank, SEVERITY_ORDER["MEDIUM"])

    return REVERSE_SEVERITY.get(max_rank, "INFO")

