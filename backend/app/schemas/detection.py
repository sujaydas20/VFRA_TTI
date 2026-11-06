"""Pydantic schemas for Threat Detection and Rules Engine endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class DetectionRuleHitItem(BaseModel):
    hit_id: UUID
    rule_id: str
    rule_version: str
    span_start: int
    span_end: int
    masked_excerpt: str

    model_config = {"from_attributes": True}


class URLIndicatorItem(BaseModel):
    indicator_id: UUID
    defanged_url: str
    domain: str
    indicator_flags: List[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class DetectionItem(BaseModel):
    detection_id: UUID
    tenant_id: UUID
    message_id: str
    category: str
    stance: str
    severity: str
    rule_confidence: float
    confidence_label: str = "rule confidence (uncalibrated)"
    explanation: str
    taxonomy_version: str
    engine_version: str
    review_status: str
    created_at: datetime
    hits: List[DetectionRuleHitItem] = []
    url_indicators: List[URLIndicatorItem] = []

    model_config = {"from_attributes": True}


class DetectionListResponse(BaseModel):
    items: List[DetectionItem]
    total: int
    limit: int
    offset: int


class DetectionReviewRequest(BaseModel):
    review_status: str = Field(pattern="^(unreviewed|confirmed|false_positive|dismissed)$")


class ThreatCategoryItem(BaseModel):
    category_id: str
    display_name: str
    description: str
    default_severity: str
    is_active: bool

    model_config = {"from_attributes": True}


class KeywordRuleItem(BaseModel):
    rule_id: str
    category: str
    rule_type: str
    languages: List[str]
    weight: float
    default_severity: str
    explanation_template: str
    is_enabled: bool
    is_reviewed: bool
    taxonomy_version: str

    model_config = {"from_attributes": True}

