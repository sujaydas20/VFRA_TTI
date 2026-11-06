"""Phase 3: Threat and Fraud Detection Rules Engine

Revision ID: 0009_phase3_threat_detection_engine
Revises: 0008_phase2_telegram_and_consent
Create Date: 2026-11-01

Canonical Reference:
- Physical Schema Design: threat.threat_categories, threat.keyword_rules,
  app.detections, app.detection_rule_hits, app.url_indicators.
- Invariants: Multi-tenant isolated via RLS, masked excerpts only, uncalibrated confidence label,
  idempotent detection storage, no network calls for indicators.
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0009_phase3_threat_engine"
down_revision: Union[str, None] = "0008_phase2_telegram_and_consent"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Global Taxonomy Schema
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS threat.threat_categories (
            category_id VARCHAR(64) PRIMARY KEY,
            display_name VARCHAR(128) NOT NULL,
            description TEXT NOT NULL,
            default_severity VARCHAR(32) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS threat.keyword_rules (
            rule_id VARCHAR(64) PRIMARY KEY,
            category VARCHAR(64) NOT NULL REFERENCES threat.threat_categories(category_id) ON DELETE CASCADE,
            rule_type VARCHAR(32) NOT NULL,
            languages JSONB NOT NULL,
            pattern_payload JSONB NOT NULL,
            weight FLOAT NOT NULL DEFAULT 1.0,
            default_severity VARCHAR(32) NOT NULL,
            explanation_template TEXT NOT NULL,
            is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            is_reviewed BOOLEAN NOT NULL DEFAULT FALSE,
            taxonomy_version VARCHAR(64) NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_threat_keyword_rules_category ON threat.keyword_rules(category);")

    # 2. Tenant-Scoped Detection Tables
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.detections (
            detection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            subject_id UUID REFERENCES app.telegram_subjects(id) ON DELETE SET NULL,
            message_id VARCHAR(128) NOT NULL,
            category VARCHAR(64) NOT NULL,
            stance VARCHAR(32) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            rule_confidence FLOAT NOT NULL,
            explanation TEXT NOT NULL,
            taxonomy_version VARCHAR(64) NOT NULL,
            engine_version VARCHAR(32) NOT NULL,
            review_status VARCHAR(32) NOT NULL DEFAULT 'unreviewed',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_tenant_message_category_taxonomy UNIQUE (tenant_id, message_id, category, taxonomy_version)
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_detections_tenant_created ON app.detections(tenant_id, created_at);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_detections_category ON app.detections(tenant_id, category);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_detections_severity ON app.detections(tenant_id, severity);")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.detection_rule_hits (
            hit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            detection_id UUID NOT NULL REFERENCES app.detections(detection_id) ON DELETE CASCADE,
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            rule_id VARCHAR(64) NOT NULL,
            rule_version VARCHAR(64) NOT NULL,
            span_start INTEGER NOT NULL,
            span_end INTEGER NOT NULL,
            masked_excerpt VARCHAR(256) NOT NULL
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_rule_hits_detection ON app.detection_rule_hits(detection_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_rule_hits_tenant ON app.detection_rule_hits(tenant_id);")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app.url_indicators (
            indicator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            detection_id UUID NOT NULL REFERENCES app.detections(detection_id) ON DELETE CASCADE,
            tenant_id UUID NOT NULL REFERENCES iam.tenant_organizations(tenant_id) ON DELETE CASCADE,
            defanged_url TEXT NOT NULL,
            domain VARCHAR(255) NOT NULL,
            indicator_flags JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_url_indicators_detection ON app.url_indicators(detection_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_url_indicators_tenant ON app.url_indicators(tenant_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_app_url_indicators_domain ON app.url_indicators(domain);")

    # 3. Enable RLS on Tenant-Scoped Tables
    op.execute("ALTER TABLE app.detections ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE app.detections FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE app.detection_rule_hits ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE app.detection_rule_hits FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE app.url_indicators ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE app.url_indicators FORCE ROW LEVEL SECURITY;")

    op.execute(
        """
        DO $$
        BEGIN
            DROP POLICY IF EXISTS p_tenant_detections ON app.detections;
            CREATE POLICY p_tenant_detections ON app.detections
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            DROP POLICY IF EXISTS p_tenant_detection_rule_hits ON app.detection_rule_hits;
            CREATE POLICY p_tenant_detection_rule_hits ON app.detection_rule_hits
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            DROP POLICY IF EXISTS p_tenant_url_indicators ON app.url_indicators;
            CREATE POLICY p_tenant_url_indicators ON app.url_indicators
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                DROP POLICY IF EXISTS p_platform_admin_detections ON app.detections;
                CREATE POLICY p_platform_admin_detections ON app.detections
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_detection_rule_hits ON app.detection_rule_hits;
                CREATE POLICY p_platform_admin_detection_rule_hits ON app.detection_rule_hits
                    FOR ALL TO tti_platform_admin_role
                    USING (true) WITH CHECK (true);

                DROP POLICY IF EXISTS p_platform_admin_url_indicators ON app.url_indicators;
                CREATE POLICY p_platform_admin_url_indicators ON app.url_indicators
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
                GRANT SELECT ON threat.threat_categories TO tti_app_role;
                GRANT SELECT ON threat.keyword_rules TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.detections TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.detection_rule_hits TO tti_app_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.url_indicators TO tti_app_role;
            END IF;

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_platform_admin_role') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON threat.threat_categories TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON threat.keyword_rules TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.detections TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.detection_rule_hits TO tti_platform_admin_role;
                GRANT SELECT, INSERT, UPDATE, DELETE ON app.url_indicators TO tti_platform_admin_role;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS app.url_indicators CASCADE;")
    op.execute("DROP TABLE IF EXISTS app.detection_rule_hits CASCADE;")
    op.execute("DROP TABLE IF EXISTS app.detections CASCADE;")
    op.execute("DROP TABLE IF EXISTS threat.keyword_rules CASCADE;")
    op.execute("DROP TABLE IF EXISTS threat.threat_categories CASCADE;")
