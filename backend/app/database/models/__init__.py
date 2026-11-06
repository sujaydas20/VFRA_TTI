"""Database models export for Alembic and application queries."""

from app.database.models.tenant import Tenant
from app.database.models.intelligence import (
    CollectedThread,
    RawArtifact,
    SourceChannel,
    SourceMessage,
    DerivedContentRepresentation,
    RawEvidenceBlob,
    IngestionJob,
)
from app.database.models.audit import AuditEvent, AuditEventRecord
from app.database.models.iam import (
    TenantOrganization,
    Role,
    UserProfile,
    TenantMembership,
    ActiveUserSession,
)
from app.database.models.billing import (
    TenantCreditBalance,
    CreditDeductionLedger,
)
from app.database.models.cases import (
    InvestigativeCase,
    CaseMessageAssociation,
    CaseNote,
)
from app.database.models.jobs import SystemJobRecord
from app.database.models.consent import (
    WebhookUpdateRecord,
    TelegramSubjectRecord,
    ConsentRecord,
    DeletionRequestRecord,
    ConsentedSubmissionRecord,
)
from app.database.models.detection import (
    ThreatCategoryRecord,
    KeywordRuleRecord,
    DetectionRecord,
    DetectionRuleHitRecord,
    URLIndicatorRecord,
)
from app.database.models.alerts import AlertRecord, AnalystFeedbackRecord
from app.database.models.ai import (
    AIMessageAnalysis,
    AIAlertRecord,
    AITokenUsageRecord,
    ThreatAnomalyRecord,
    ExtractedIOCRecord,
    IntelligenceCorrelation,
)

__all__ = [
    "Tenant",
    "CollectedThread",
    "RawArtifact",
    "SourceChannel",
    "SourceMessage",
    "DerivedContentRepresentation",
    "RawEvidenceBlob",
    "IngestionJob",
    "AuditEvent",
    "AuditEventRecord",
    "TenantOrganization",
    "Role",
    "UserProfile",
    "TenantMembership",
    "ActiveUserSession",
    "TenantCreditBalance",
    "CreditDeductionLedger",
    "InvestigativeCase",
    "CaseMessageAssociation",
    "CaseNote",
    "SystemJobRecord",
    "WebhookUpdateRecord",
    "TelegramSubjectRecord",
    "ConsentRecord",
    "DeletionRequestRecord",
    "ConsentedSubmissionRecord",
    "ThreatCategoryRecord",
    "KeywordRuleRecord",
    "DetectionRecord",
    "DetectionRuleHitRecord",
    "URLIndicatorRecord",
    "AlertRecord",
    "AnalystFeedbackRecord",
    "AIMessageAnalysis",
    "AIAlertRecord",
    "AITokenUsageRecord",
    "ThreatAnomalyRecord",
    "ExtractedIOCRecord",
    "IntelligenceCorrelation",
]
