"""Analyst feedback collection and offline model evaluation interface.

GOVERNANCE & NON-NEGOTIABLE RULE:
Live reinforcement learning and unmonitored model self-modification are strictly
prohibited. The learning loop records analyst feedback (false positives, true positives)
exclusively for offline evaluation and benchmark validation.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class AnalystFeedbackEntry(BaseModel):
    """Analyst validation feedback on an AI classification or alert."""
    tenant_id: str
    thread_id: str
    analyst_id: str
    is_true_positive: bool
    corrected_severity: Optional[str] = None
    feedback_notes: Optional[str] = None
    submitted_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FeedbackCollectorInterface(ABC):
    """Interface for collecting analyst feedback for offline evaluation."""

    @abstractmethod
    async def record_feedback(self, feedback: AnalystFeedbackEntry) -> None:
        """Persist analyst feedback for offline model fine-tuning and evaluation."""
        pass
