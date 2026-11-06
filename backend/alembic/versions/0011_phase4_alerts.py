"""Phase 4: Alerting subsystem tables (app.alerts, app.analyst_feedback)

Revision ID: 0011_phase4_alerts
Revises: 0010_phase3_hardening
Create Date: 2026-11-05

Canonical Reference:
- Phase 4: Alert state machine (OPEN, ASSIGNED, TRIAGED, DISMISSED),
  duplicate suppression via hit_count, analyst triage + feedback.
- Invariants: Multi-tenant isolated via RLS, no message content persisted.
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0011_phase4_alerts"
down_revision: Union[str, None] = "0010_phase3_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.alerts (
            alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            detection_id UUID REFERENCES app.detections(detection_id) ON DELETE CASCADE,
            category VARCHAR(64) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            priority INTEGER NOT NULL,
            alert_title VARCHAR(255) NOT NULL,
            explanation TEXT NOT NULL,
            confidence_label VARCHAR(64) NOT NULL DEFAULT 'rule confidence (uncalibrated)',
            hit_count INTEGER NOT NULL DEFAULT 1,
            alert_status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
            assigned_to_user_id UUID REFERENCES iam.user_profiles(user_id) ON DELETE SET NULL,
            analyst_decision VARCHAR(32),
            analyst_notes TEXT,
            reviewed_by_user_id UUID REFERENCES iam.user_profiles(user_id) ON DELETE SET NULL,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT ck_alert_status CHECK (alert_status IN ('OPEN', 'ASSIGNED', 'TRIAGED', 'DISMISSED')),
            CONSTRAINT ck_alert_analyst_decision CHECK (analyst_decision IS NULL OR analyst_decision IN ('CONFIRMED', 'FALSE_POSITIVE')),
            CONSTRAINT ck_alert_hit_count_positive CHECK (hit_count >= 1)
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_alerts_tenant_status ON app.alerts(tenant_id, alert_status);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_alerts_tenant_created ON app.alerts(tenant_id, created_at);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_alerts_tenant_category ON app.alerts(tenant_id, category);")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.analyst_feedback (
            feedback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            alert_id UUID NOT NULL REFERENCES app.alerts(alert_id) ON DELETE CASCADE,
            analyst_user_id UUID NOT NULL REFERENCES iam.user_profiles(user_id) ON DELETE RESTRICT,
            is_true_positive BOOLEAN NOT NULL,
            corrected_severity VARCHAR(32),
            feedback_notes TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_analyst_feedback_tenant ON app.analyst_feedback(tenant_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_analyst_feedback_alert ON app.analyst_feedback(alert_id);")

    # 3. Row-Level Security (mirrors migration 0009 pattern)
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE 'ALTER TABLE app.alerts ENABLE ROW LEVEL SECURITY';
            EXECUTE 'ALTER TABLE app.alerts FORCE ROW LEVEL SECURITY';

            DROP POLICY IF EXISTS p_tenant_alerts ON app.alerts;
            CREATE POLICY p_tenant_alerts ON app.alerts
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            DROP POLICY IF EXISTS p_tenant_analyst_feedback ON app.analyst_feedback;
            CREATE POLICY p_tenant_analyst_feedback ON app.analyst_feedback
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                DROP POLICY IF EXISTS p_platform_admin_alerts ON app.alerts;
                CREATE POLICY p_platform_admin_alerts ON app.alerts
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_analyst_feedback ON app.analyst_feedback;
                CREATE POLICY p_platform_admin_analyst_feedback ON app.analyst_feedback
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);
            END IF;
        END $$;
        """
    )

    # 4. Grants
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.alerts TO tti_app_role;
                GRANT SELECT, INSERT ON app.analyst_feedback TO tti_app_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.alerts TO tti_platform_admin_role;
                GRANT SELECT, INSERT ON app.analyst_feedback TO tti_platform_admin_role;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS app.analyst_feedback CASCADE;")
    op.execute("DROP TABLE IF EXISTS app.alerts CASCADE;")

