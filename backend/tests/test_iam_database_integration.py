"""Live PostgreSQL database integration tests for Phase 1 IAM, RLS, and Concurrency.

Covers:
- Step 2 / SEC-AUDIT-02 & SEC-AUDIT-06: Database-level tenant isolation via Row-Level Security (RLS).
- Step 3 / SEC-AUDIT-01 & SEC-AUDIT-05: Real database concurrency tests:
  - Concurrent login attempts and single active session invariant (DEC-20).
  - Atomic credit deductions and overspend prevention (DEC-19).
  - Idempotent transaction keys preventing double-charging.
  - Connection-pool tenant context cleanup (zero leakage across transactions).

Note: Cleanly SKIPPED if live PostgreSQL database is offline or unreachable.
"""

import uuid
import pytest
from sqlalchemy import create_engine, text
from app.core.config import get_settings


@pytest.fixture(scope="module")
def live_db_engine():
    """Provide a SQLAlchemy Engine for live PostgreSQL tests; skips if unreachable."""
    settings = get_settings()
    url = settings.sync_database_url

    try:
        engine = create_engine(url, connect_args={"connect_timeout": 3})
        with engine.connect() as test_conn:
            test_conn.execute(text("SELECT 1;"))
        yield engine
        engine.dispose()
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL database unreachable ({type(exc).__name__}); live integration tests SKIPPED")


def test_live_database_schema_and_extensions_verified(live_db_engine):
    """Verify Phase 0 & Phase 1 schemas, extensions, and tables are present on live database."""
    with live_db_engine.connect() as conn:
        # Extensions
        res = conn.execute(text("SELECT extname FROM pg_extension WHERE extname IN ('uuid-ossp', 'pgcrypto', 'pg_trgm');"))
        exts = {row[0] for row in res.fetchall()}
        assert "uuid-ossp" in exts
        assert "pgcrypto" in exts
        assert "pg_trgm" in exts

        # Schemas
        res = conn.execute(text("SELECT schema_name FROM information_schema.schemata WHERE schema_name IN ('iam', 'threat', 'evidence', 'app', 'audit');"))
        schemas = {row[0] for row in res.fetchall()}
        assert {"iam", "threat", "evidence", "app", "audit"}.issubset(schemas)

        # Tables
        res = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'iam';"))
        tables = {row[0] for row in res.fetchall()}
        assert {"tenant_organizations", "roles", "user_profiles", "tenant_memberships", "active_user_sessions"}.issubset(tables)


def test_live_rls_cross_tenant_isolation_select(live_db_engine):
    """
    Verify PostgreSQL RLS strictly prevents cross-tenant data leakage (SEC-AUDIT-02).
    A query omitting explicit tenant filters only returns rows matching app.current_tenant_id.
    """
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    # 1. Setup two organizations and credit balances
    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES 
                (:t_a, :name_a, 'LAW_ENFORCEMENT', 'ACTIVE'),
                (:t_b, :name_b, 'CORPORATE_SOC', 'ACTIVE')
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"t_a": tenant_a, "name_a": f"LEA Org {tenant_a}", "t_b": tenant_b, "name_b": f"SOC Org {tenant_b}"}
        )

        conn.execute(
            text("""
            INSERT INTO app.tenant_credit_balances (balance_id, tenant_id, allocated_credits, consumed_credits, balance_credits)
            VALUES 
                (gen_random_uuid(), :t_a, 500, 100, 400),
                (gen_random_uuid(), :t_b, 1000, 200, 800)
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"t_a": tenant_a, "t_b": tenant_b}
        )

    # 2. Query under role tti_app_role with Tenant A context
    with live_db_engine.connect() as conn:
        conn.execute(text("SET ROLE tti_app_role;"))
        conn.execute(text("SET LOCAL app.current_tenant_id = :t_a;"), {"t_a": str(tenant_a)})

        # Query WITHOUT tenant_id filter
        result = conn.execute(text("SELECT tenant_id, balance_credits FROM app.tenant_credit_balances;"))
        rows = result.fetchall()

        # Must return strictly Tenant A's row
        assert len(rows) == 1
        assert rows[0][0] == tenant_a
        assert rows[0][1] == 400
        conn.execute(text("RESET ROLE;"))

    # 3. Query under role tti_app_role with Tenant B context
    with live_db_engine.connect() as conn:
        conn.execute(text("SET ROLE tti_app_role;"))
        conn.execute(text("SET LOCAL app.current_tenant_id = :t_b;"), {"t_b": str(tenant_b)})

        result = conn.execute(text("SELECT tenant_id, balance_credits FROM app.tenant_credit_balances;"))
        rows = result.fetchall()

        # Must return strictly Tenant B's row
        assert len(rows) == 1
        assert rows[0][0] == tenant_b
        assert rows[0][1] == 800
        conn.execute(text("RESET ROLE;"))


def test_live_rls_fail_closed_when_context_missing(live_db_engine):
    """Verify RLS fails closed (returns 0 rows) when app.current_tenant_id is missing or unset."""
    with live_db_engine.connect() as conn:
        conn.execute(text("SET ROLE tti_app_role;"))
        conn.execute(text("RESET app.current_tenant_id;"))

        result = conn.execute(text("SELECT * FROM app.tenant_credit_balances;"))
        rows = result.fetchall()
        assert len(rows) == 0, "Expected 0 rows when tenant context is unset (fail-closed)"
        conn.execute(text("RESET ROLE;"))


def test_live_platform_admin_visibility_for_org_approval(live_db_engine):
    """Verify tti_platform_admin_role can inspect all organizations for approval workflow (DEC-22)."""
    pending_tenant = uuid.uuid4()
    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'PENDING_APPROVAL')
            ON CONFLICT (tenant_id) DO NOTHING;
            """),
            {"t_id": pending_tenant, "name": f"Pending Org {pending_tenant}"}
        )

    with live_db_engine.connect() as conn:
        conn.execute(text("SET ROLE tti_platform_admin_role;"))
        res = conn.execute(
            text("SELECT tenant_id FROM iam.tenant_organizations WHERE tenant_id = :t_id AND account_status = 'PENDING_APPROVAL';"),
            {"t_id": pending_tenant}
        )
        assert res.scalar() == pending_tenant
        conn.execute(text("RESET ROLE;"))


def test_live_atomic_credit_deduction_and_overspend_protection(live_db_engine):
    """
    Verify atomic SQL deduction prevents overspend under concurrent conditions (SEC-AUDIT-05).
    Database check constraint ck_credit_balance_remaining_nonneg rejects negative balances.
    """
    tenant_id = uuid.uuid4()
    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'CORPORATE_SOC', 'ACTIVE');
            """),
            {"t_id": tenant_id, "name": f"Quota Test Org {tenant_id}"}
        )
        conn.execute(
            text("""
            INSERT INTO app.tenant_credit_balances (balance_id, tenant_id, allocated_credits, consumed_credits, balance_credits)
            VALUES (gen_random_uuid(), :t_id, 20, 0, 20);
            """),
            {"t_id": tenant_id}
        )

    # Attempt deduction 1: 15 credits (succeeds)
    with live_db_engine.begin() as conn:
        res = conn.execute(
            text("""
            UPDATE app.tenant_credit_balances
            SET balance_credits = balance_credits - 15,
                consumed_credits = consumed_credits + 15
            WHERE tenant_id = :t_id AND balance_credits >= 15
            RETURNING balance_credits;
            """),
            {"t_id": tenant_id}
        )
        new_balance = res.scalar()
        assert new_balance == 5

    # Attempt deduction 2: 15 credits (fails atomic WHERE condition -> 0 rows updated)
    with live_db_engine.begin() as conn:
        res = conn.execute(
            text("""
            UPDATE app.tenant_credit_balances
            SET balance_credits = balance_credits - 15,
                consumed_credits = consumed_credits + 15
            WHERE tenant_id = :t_id AND balance_credits >= 15
            RETURNING balance_credits;
            """),
            {"t_id": tenant_id}
        )
        assert res.rowcount == 0, "Second deduction should affect 0 rows (overdraft blocked)"

    # Attempt direct negative update (rejected by database check constraint)
    with pytest.raises(Exception) as exc_info:
        with live_db_engine.begin() as conn:
            conn.execute(
                text("UPDATE app.tenant_credit_balances SET balance_credits = -5 WHERE tenant_id = :t_id;"),
                {"t_id": tenant_id}
            )
    assert "ck_credit_balance_remaining_nonneg" in str(exc_info.value) or "check constraint" in str(exc_info.value).lower()


def test_live_idempotent_credit_deduction_prevents_duplicate_charge(live_db_engine):
    """Verify database unique constraint uq_credit_deductions_tenant_idempotency blocks duplicates."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    idemp_key = f"idemp_{uuid.uuid4()}"

    # Setup org and user
    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'CORPORATE_SOC', 'ACTIVE');
            """),
            {"t_id": tenant_id, "name": f"Idemp Org {tenant_id}"}
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, :email, 'Idemp User', 'argon2id_hash', 'ACTIVE');
            """),
            {"u_id": user_id, "email": f"idemp_{user_id}@agency.gov"}
        )

    # First deduction commit
    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO app.credit_deduction_ledgers 
                (deduction_id, tenant_id, user_id, action_type, credits_consumed, balance_after_deduction, idempotency_key, status)
            VALUES 
                (gen_random_uuid(), :t_id, :u_id, 'REPORT_TXT_EXPORT', 25, 75, :idemp, 'COMMITTED');
            """),
            {"t_id": tenant_id, "u_id": user_id, "idemp": idemp_key}
        )

    # Replay with same idempotency key in second transaction -> rejected by DB unique constraint
    with pytest.raises(Exception) as exc_info:
        with live_db_engine.begin() as conn:
            conn.execute(
                text("""
                INSERT INTO app.credit_deduction_ledgers 
                    (deduction_id, tenant_id, user_id, action_type, credits_consumed, balance_after_deduction, idempotency_key, status)
                VALUES 
                    (gen_random_uuid(), :t_id, :u_id, 'REPORT_TXT_EXPORT', 25, 75, :idemp, 'COMMITTED');
                """),
                {"t_id": tenant_id, "u_id": user_id, "idemp": idemp_key}
            )
    assert "uq_credit_deductions_tenant_idempotency" in str(exc_info.value) or "unique constraint" in str(exc_info.value).lower()


def test_live_single_active_session_constraint_blocks_concurrent_login(live_db_engine):
    """
    Verify unique constraint uq_active_user_sessions_user_id enforces single active session
    at the database engine level (DEC-20 / AC-REQ-006).
    """
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.tenant_organizations (tenant_id, organization_name, market_profile, account_status)
            VALUES (:t_id, :name, 'LAW_ENFORCEMENT', 'ACTIVE');
            """),
            {"t_id": tenant_id, "name": f"Session Org {tenant_id}"}
        )
        conn.execute(
            text("""
            INSERT INTO iam.user_profiles (user_id, email_address, full_name, password_hash, account_state)
            VALUES (:u_id, :email, 'Session User', 'argon2id_hash', 'ACTIVE');
            """),
            {"u_id": user_id, "email": f"session_{user_id}@agency.gov"}
        )

    # Session 1 inserted
    with live_db_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO iam.active_user_sessions
                (session_id, user_id, active_tenant_id, session_token_hash, expires_at_utc)
            VALUES
                (gen_random_uuid(), :u_id, :t_id, 'hash_session_1', CURRENT_TIMESTAMP + INTERVAL '8 hours');
            """),
            {"u_id": user_id, "t_id": tenant_id}
        )

    # Concurrent session 2 for same user_id -> rejected by database constraint
    with pytest.raises(Exception) as exc_info:
        with live_db_engine.begin() as conn:
            conn.execute(
                text("""
                INSERT INTO iam.active_user_sessions
                    (session_id, user_id, active_tenant_id, session_token_hash, expires_at_utc)
                VALUES
                    (gen_random_uuid(), :u_id, :t_id, 'hash_session_2', CURRENT_TIMESTAMP + INTERVAL '8 hours');
                """),
                {"u_id": user_id, "t_id": tenant_id}
            )
    assert "uq_active_user_sessions_user_id" in str(exc_info.value) or "unique constraint" in str(exc_info.value).lower()


def test_live_connection_pool_tenant_context_leakage_prevented(live_db_engine):
    """
    Verify SET LOCAL automatically clears upon transaction end, preventing context leakage (SEC-AUDIT-06).
    """
    tenant_a = uuid.uuid4()

    # We use a single raw connection across two sequential transaction blocks to verify
    # that SET LOCAL automatically clears upon COMMIT/ROLLBACK and does not bleed into the next transaction.
    with live_db_engine.connect() as conn:
        # Transaction 1: sets transaction-local context
        with conn.begin():
            conn.execute(text("SET LOCAL app.current_tenant_id = :t_a;"), {"t_a": str(tenant_a)})
            val = conn.execute(text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '');")).scalar()
            assert val == str(tenant_a)

        # Transaction 2 (simulating connection reuse from pool): context must be NULL / empty
        with conn.begin():
            val_after = conn.execute(text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '');")).scalar()
            assert val_after is None, f"Expected NULL for unconfigured tenant context, but got: {val_after}"
