"""Human-in-the-loop decision engine interface.

GOVERNANCE & NON-NEGOTIABLE RULE:
Decisions affecting client assets or triggering high-priority external workflows
require human-in-the-loop verification. No autonomous external escalations occur in Phase 1.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pydantic import BaseModel


class PrioritizedThreatDecision(BaseModel):
    """Decision output detailing threat prioritization and suggested analyst actions."""
    tenant_id: str
    thread_id: str
    severity_level: str  # info, low, medium, high, critical
    recommended_action: str
    confidence_score: float
    analyst_review_status: str = "pending_analyst_review"


class DecisionEngineInterface(ABC):
    """Contract for deterministic threat assessment and prioritization logic."""

    @abstractmethod
    def evaluate_priority(
        self,
        tenant_id: str,
        thread_id: str,
        analysis_metadata: Dict[str, Any],
    ) -> PrioritizedThreatDecision:
        """Evaluate priority and determine recommended response playbook."""
        pass
