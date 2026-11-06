"""Organization credit quota and usage ledger models (Domain 3 / app schema).

Canonical Reference:
- Requirements: AC-REQ-005 (Org Credit Quota & Per-Action Consumption)
- Decisions: DEC-19 (Credit Quota Sizing, Free Search / Paid Heavy Operations)
- Anti-Meter Flaw Protection: Standard chat/thread browsing is free per FR-THR-001.
"""

from datetime import datetime, timezone
from typing import Optional
import uuid
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class TenantCreditBalance(Base):
    """
    Tracks an organization's allocated credit quota, total consumed credits, and remaining balance.

    Invariants:
    - Balance cannot be negative (enforced at DB check constraint level).
    - Thread search and message scrolling are strictly unmetered per FR-THR-001 / DEC-19.
    """

    __tablename__ = "tenant_credit_balances"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_tenant_credit_balances_tenant"),
        CheckConstraint("allocated_credits >= 0", name="ck_credit_balance_allocated_nonneg"),
        CheckConstraint("consumed_credits >= 0", name="ck_credit_balance_consumed_nonneg"),
        CheckConstraint("balance_credits >= 0", name="ck_credit_balance_remaining_nonneg"),
        {"schema": "app"},
    )

    balance_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    allocated_credits: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    consumed_credits: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    balance_credits: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    reset_frequency: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="MONTHLY",
        server_default="MONTHLY",
    )
    last_reset_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<TenantCreditBalance tenant={self.tenant_id} balance={self.balance_credits}/{self.allocated_credits}>"


class CreditDeductionLedger(Base):
    """
    Immutable ledger of credit deductions for heavy operations.

    Invariants:
    - Credits consumed must be positive (> 0).
    - Idempotency key per tenant ensures duplicate requests do not double-charge.
    - Status transitions between COMMITTED and REFUNDED.
    """

    __tablename__ = "credit_deduction_ledgers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_credit_deductions_tenant_idempotency"),
        CheckConstraint("credits_consumed > 0", name="ck_credit_deductions_consumed_positive"),
        CheckConstraint("balance_after_deduction >= 0", name="ck_credit_deductions_balance_nonneg"),
        CheckConstraint(
            "status IN ('COMMITTED', 'REFUNDED')",
            name="ck_credit_deductions_status",
        ),
        {"schema": "app"},
    )

    deduction_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.tenant_organizations.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("iam.user_profiles.user_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    action_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Designated metered action: REPORT_TXT_EXPORT, REPORT_DUAL_SCREENSHOT, BULK_EXPORT, etc.",
    )
    credits_consumed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    balance_after_deduction: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    idempotency_key: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Caller-supplied idempotency key preventing double deduction on retry",
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="COMMITTED",
        server_default="COMMITTED",
    )
    reference_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Associated case ID, report UID, or job ID",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    details: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<CreditDeductionLedger id={self.deduction_id} tenant={self.tenant_id} action={self.action_type} consumed={self.credits_consumed} status={self.status}>"
