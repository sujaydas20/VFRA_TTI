"""Pydantic schemas for the Gemini AI Threat Intelligence Engine."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
import uuid

from pydantic import BaseModel, ConfigDict, Field


class ThreatCategoryEnum(str, Enum):
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    BANKING_FRAUD = "BANKING_FRAUD"
    UPI_FRAUD = "UPI_FRAUD"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    CYBERCRIME = "CYBERCRIME"
    DATA_LEAKS = "DATA_LEAKS"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"
    IDENTITY_FRAUD = "IDENTITY_FRAUD"
    EXTORTION = "EXTORTION"
    SUSPICIOUS_FINANCIAL_ACTIVITY = "SUSPICIOUS_FINANCIAL_ACTIVITY"
    ONLINE_SCAMS = "ONLINE_SCAMS"
    OTHER_SUSPICIOUS = "OTHER_SUSPICIOUS"
    BENIGN = "BENIGN"


class ThreatSeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyTypeEnum(str, Enum):
    VOLUME_SPIKE = "VOLUME_SPIKE"
    URL_FLOOD = "URL_FLOOD"
    NEW_IOC_SURGE = "NEW_IOC_SURGE"
    CROSS_GROUP_PROPAGATION = "CROSS_GROUP_PROPAGATION"
    KEYWORD_BURST = "KEYWORD_BURST"


class CorrelationTypeEnum(str, Enum):
    SHARED_IOC = "SHARED_IOC"
    ACTOR_COLLUSION = "ACTOR_COLLUSION"
    CAMPAIGN_PROPAGATION = "CAMPAIGN_PROPAGATION"
    INFRASTRUCTURE_REUSE = "INFRASTRUCTURE_REUSE"
    THEMATIC_SIMILARITY = "THEMATIC_SIMILARITY"


# -----------------------------------------------------------------------------
# Structured Gemini Output Schema
# -----------------------------------------------------------------------------

class SlangInterpretation(BaseModel):
    term: str = Field(description="The slang, abbreviation, emoji, or coded term detected")
    meaning: str = Field(description="The contextual meaning or fraud implication of the term")


class GeminiStructuredThreatOutput(BaseModel):
    """Schema enforced for Gemini structured JSON response."""
    threat_detected: bool = Field(description="True if potential threat or suspicious activity is identified")
    primary_category: ThreatCategoryEnum = Field(default=ThreatCategoryEnum.BENIGN, description="Primary threat category")
    secondary_categories: List[str] = Field(default_factory=list, description="Additional applicable threat categories")
    severity: ThreatSeverityEnum = Field(default=ThreatSeverityEnum.INFO, description="Threat severity level")
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Confidence score between 0.0 and 100.0")
    threat_description: str = Field(default="", description="Concise executive description of the detected threat")
    explanation: str = Field(default="", description="Detailed contextual reasoning justifying the classification")
    supporting_evidence: List[str] = Field(default_factory=list, description="Specific snippets, phrases, or indicators from the text")
    slang_interpretations: List[SlangInterpretation] = Field(default_factory=list, description="List of slang, emojis, or coded words interpreted")
    coded_language_detected: bool = Field(default=False, description="Whether obfuscated, leetspeak, or evasive terminology was used")
    is_actionable: bool = Field(default=False, description="Whether this finding warrants immediate investigator triage")
    recommended_action: str = Field(default="MONITOR", description="Recommended next step for analysts")


# -----------------------------------------------------------------------------
# Extracted Indicator Schemas
# -----------------------------------------------------------------------------

class ExtractedIOCItem(BaseModel):
    ioc_type: str
    raw_value: str
    normalized_value: str
    defanged_value: str
    is_validated: bool = True
    is_malicious: bool = False
    confidence: float = 1.0
    context_snippet: Optional[str] = None


# -----------------------------------------------------------------------------
# API Request & Response Schemas
# -----------------------------------------------------------------------------

class AIAnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="Raw message text to analyze")
    channel_id: Optional[str] = Field(default="manual_submission", description="Associated channel identifier")
    message_id: Optional[str] = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}", description="Message reference")
    include_context: bool = Field(default=True, description="Whether to include slang and emoji interpretation")


class AIMessageAnalysisResponse(BaseModel):
    analysis_id: UUID
    tenant_id: UUID
    message_id: str
    channel_id: str
    threat_detected: bool
    threat_category: str
    secondary_categories: List[str]
    threat_description: str
    severity: str
    confidence_score: float
    calibrated_score: float
    slang_interpretations: List[Dict[str, str]]
    coded_language_detected: bool
    supporting_evidence: List[str]
    explanation: str
    recommended_action: str
    model_used: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    is_reviewed: bool
    review_decision: Optional[str] = None
    review_notes: Optional[str] = None
    analyzed_at_utc: datetime
    iocs: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class AIOverviewResponse(BaseModel):
    total_messages_analyzed: int
    threats_detected: int
    high_critical_count: int
    total_iocs_extracted: int
    total_anomalies_detected: int
    total_correlations_found: int
    active_alerts_count: int
    categories_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    model_name: str
    total_tokens_consumed: int
    estimated_total_cost_usd: float


class AIReviewFeedbackRequest(BaseModel):
    analysis_id: UUID
    decision: str = Field(..., pattern="^(TRUE_POSITIVE|FALSE_POSITIVE|BENIGN|CONFIRMED_THREAT)$")
    notes: Optional[str] = None


class AnomalyResponseItem(BaseModel):
    anomaly_id: UUID
    tenant_id: UUID
    channel_id: str
    anomaly_type: str
    metric_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    gemini_explanation: Optional[str]
    severity: str
    detected_at_utc: datetime

    model_config = ConfigDict(from_attributes=True)


class IntelligenceCorrelationItem(BaseModel):
    correlation_id: UUID
    tenant_id: UUID
    source_message_id: str
    target_message_id: str
    source_channel_id: str
    target_channel_id: str
    correlation_type: str
    matched_entity_type: Optional[str]
    matched_entity_value: Optional[str]
    confidence: float
    explanation: Optional[str]
    created_at_utc: datetime

    model_config = ConfigDict(from_attributes=True)


class AIAlertItem(BaseModel):
    alert_id: UUID
    tenant_id: UUID
    analysis_id: Optional[UUID]
    message_id: str
    channel_id: str
    alert_title: str
    alert_category: str
    severity: str
    confidence: float
    summary: str
    evidence_pointers: List[Any]
    status: str
    created_at_utc: datetime

    model_config = ConfigDict(from_attributes=True)


class AISystemHealthResponse(BaseModel):
    status: str
    gemini_configured: bool
    model_name: str
    pro_model_name: str
    daily_token_usage: int
    daily_token_budget: int
    estimated_daily_cost_usd: float
    average_latency_ms: float
    queue_name: str
    rate_limit_rpm: int
