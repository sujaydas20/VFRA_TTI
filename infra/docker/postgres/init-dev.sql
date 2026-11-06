-- TTI Local Development Database Initialization
-- Ensures dev database and initial schemas/extensions exist

-- 1. PostgreSQL Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- 2. Schema Namespaces
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS threat;
CREATE SCHEMA IF NOT EXISTS evidence;
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS audit;

-- 3. Security Roles (Idempotent Definition)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_admin_role') THEN
        CREATE ROLE tti_admin_role WITH NOLOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tti_app_role') THEN
        CREATE ROLE tti_app_role WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
END $$;

-- 4. Schema Permissions
GRANT USAGE, CREATE ON SCHEMA iam, threat, evidence, app, audit TO tti_admin_role;
GRANT USAGE ON SCHEMA iam, threat, evidence, app, audit TO tti_app_role;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'TTI PostgreSQL initialization script executed successfully with pg_trgm, schemas, and security roles.';
END $$;
