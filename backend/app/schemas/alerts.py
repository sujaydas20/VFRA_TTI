"""Pydantic schemas for the Phase 4 alerting subsystem endpoints."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

CONFIDENCE_LABEL = "rule confidence (uncalibrated)"

ALERT_STATUSES = ("OPEN", "ASSIGNED", "TRIAGED", "DISMISSED")
ANALYST_DECISIONS = ("CONFIRMED", "FALSE_POSITIVE")


class AlertItem(BaseModel):
    alert_id: UUID
    tenant_id: UUID
    detection_id: Optional[UUID] = None
    category: str
    severity: str
    priority: int
    alert_title: str
    explanation: str
    confidence_label: str = CONFIDENCE_LABEL
    hit_count: int
    alert_status: str
    assigned_to_user_id: Optional[UUID] = None
    analyst_decision: Optional[str] = None
    analyst_notes: Optional[str] = None
    reviewed_by_user_id: Optional[UUID] = None
    first_seen_at: datetime
    last_seen_at: datetime
    reviewed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    items: List[AlertItem]
    total: int
    limit: int
    offset: int


class AlertAssignRequest(BaseModel):
    assigned_to_user_id: UUID


class AlertTriageRequest(BaseModel):
    analyst_decision: str = Field(pattern="^(CONFIRMED|FALSE_POSITIVE)$")
    analyst_notes: Optional[str] = None
    dismiss: bool = False


class AnalystFeedbackRequest(BaseModel):
    is_true_positive: bool
    corrected_severity: Optional[str] = Field(
        default=None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"
    )
    feedback_notes: Optional[str] = None


class AnalystFeedbackItem(BaseModel):
    feedback_id: UUID
    alert_id: UUID
    analyst_user_id: UUID
    is_true_positive: bool
    corrected_severity: Optional[str] = None
    feedback_notes: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertOverviewResponse(BaseModel):
    total_alerts: int
    open_alerts: int
    assigned_alerts: int
    triaged_alerts: int
    dismissed_alerts: int
    critical_open: int
    high_open: int
    medium_open: int
    low_open: int
    total_hits_suppressed: int
