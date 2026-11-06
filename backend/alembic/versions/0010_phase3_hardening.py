"""Phase 3 hardening: stance check constraint and value migration.

Revision ID: 0010_phase3_hardening
Revises: 0009_phase3_threat_engine
Create Date: 2026-11-02 01:50:00
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0010_phase3_hardening"
down_revision: Union[str, None] = "0009_phase3_threat_engine"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Migrate stored facilitating values to potentially_facilitating
    op.execute("""
        UPDATE app.detections
        SET stance = 'potentially_facilitating'
        WHERE stance = 'facilitating';
    """)

    # 2. Add strict CHECK constraint for validated stance values
    op.execute("""
        ALTER TABLE app.detections
        ADD CONSTRAINT ck_app_detections_stance
        CHECK (stance IN ('reporting', 'warning', 'discussing', 'potentially_facilitating', 'unclear'));
    """)


def downgrade() -> None:
    # 1. Drop CHECK constraint
    op.execute("""
        ALTER TABLE app.detections
        DROP CONSTRAINT IF EXISTS ck_app_detections_stance;
    """)

    # 2. Revert potentially_facilitating back to facilitating
    op.execute("""
        UPDATE app.detections
        SET stance = 'facilitating'
        WHERE stance = 'potentially_facilitating';
    """)

