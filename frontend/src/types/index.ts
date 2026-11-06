/*
 * TTI — TypeScript domain types.
 *
 * Canonical backend contracts (implemented by the FastAPI backend):
 *   HealthStatusResponse, ConnectorHealth, ProjectStatusResponse
 *
 * Everything below the "MOCK-ONLY TYPES" section describes presentation-layer
 * domain models for endpoints the backend has not yet implemented. These are
 * consumed exclusively by the isolated mock adapter (services/api.ts) and must
 * not be treated as canonical API contracts. Backend-owned routes/schemas are
 * tracked in the backend integration checklist (docs/frontend-integration.md).
 */

/* ------------------------------------------------------------------ */
/* Branded identifier types                                           */
/* ------------------------------------------------------------------ */

export type RoleId = string;
export type TenantId = string;
export type UserId = string;
export type CaseId = string;
export type ThreadId = string;
export type EvidenceId = string;
export type ReportId = string;

/* ------------------------------------------------------------------ */
/* Canonical backend contracts (existing endpoints)                   */
/* ------------------------------------------------------------------ */

export interface ComponentHealth {
  status: 'healthy' | 'degraded' | 'unavailable' | 'disabled';
  latency_ms?: number;
  message: string;
  details?: Record<string, unknown>;
}

export interface HealthStatusResponse {
  status: 'healthy' | 'degraded' | 'unavailable';
  environment: string;
  project_name: string;
  version: string;
  timestamp_utc: string;
  components: {
    database: ComponentHealth;
    redis: ComponentHealth;
    evidence_storage: ComponentHealth;
    connectors: ComponentHealth;
  };
}

export interface ConnectorHealth {
  connector_id: string;
  status: 'healthy' | 'degraded' | 'disconnected' | 'disabled' | 'unconfigured';
  message: string;
  is_live_collection_active: boolean;
  rate_limit_remaining?: number;
  last_checked_utc?: string;
  metadata?: Record<string, unknown>;
}

/* ------------------------------------------------------------------ */
/* API integration inventory (canonical backend contract)             */
/* ------------------------------------------------------------------ */

export interface ApiIntegration {
  provider: string;
  purpose: string;
  category: string;
  endpoint?: string | null;
  credential_env_vars: string[];
  credential_available: boolean;
  credential_fingerprint?: string | null;
  configured: boolean;
  enabled: boolean;
  backend_integration: boolean;
  dependent_modules: string[];
  expected_configuration: string;
  notes?: string | null;
  connected: boolean;
  authentication_status: string;
  test_status: 'passed' | 'failed' | 'not_tested';
  last_success_utc?: string | null;
  last_error?: string | null;
  connection_status: 'connected' | 'not_connected' | 'disabled';
  configuration_completeness: 'complete' | 'partial' | 'missing_credentials';
}

export interface ApiIntegrationsResponse {
  total: number;
  connected: number;
  missing_credentials: number;
  failed: number;
  integrations: ApiIntegration[];
}

export interface ProjectStatusResponse {
  project: string;
  phase: string;
  phase_status: string;
  environment: string;
  tenant_context: {
    active_tenant_id: string;
    authentication_ready: boolean;
    tenant_isolation_design: string;
  };
  connectors_summary: {
    telegram_collection: string;
    darkweb_collection: string;
    untrusted_input_sanitizer: string;
    evidence_store_isolated: boolean;
  };
  security_baseline_compliance: {
    real_credentials_in_repo: boolean;
    live_scraping_authorized: boolean;
    evidence_separated_from_frontend: boolean;
    unrestricted_autonomous_actions: boolean;
    live_reinforcement_learning: boolean;
  };
  next_phase: string;
}

/* ------------------------------------------------------------------ */
/* Auth & session (presentation-layer; backend contract pending)      */
/* ------------------------------------------------------------------ */

export type UserRole = 'platform_admin' | 'org_admin' | 'analyst' | 'viewer';

export interface AuthUser {
  id: UserId;
  email: string;
  name: string;
  avatar_url?: string;
  role: UserRole;
  tenant_id?: TenantId;
  tenant_name?: string;
  permissions: string[];
  mfa_enabled: boolean;
  last_login_at?: string;
}

export interface SessionState {
  isAuthenticated: boolean;
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginResponse {
  user: AuthUser;
  token: string;
}

/* ------------------------------------------------------------------ */
/* Organizations (presentation-layer; backend contract pending)       */
/* ------------------------------------------------------------------ */

export type OrgStatus = 'pending' | 'active' | 'suspended' | 'rejected';

export interface Organization {
  id: TenantId;
  name: string;
  slug: string;
  status: OrgStatus;
  plan: string;
  member_count: number;
  case_count: number;
  created_at: string;
  approved_at?: string;
  approved_by?: UserId;
  domain?: string;
}

export interface OrganizationInvite {
  id: string;
  organization_id: TenantId;
  email: string;
  role: UserRole;
  status: 'pending' | 'accepted' | 'revoked';
  created_at: string;
}

/* ------------------------------------------------------------------ */
/* Users & memberships (presentation-layer; backend contract pending) */
/* ------------------------------------------------------------------ */

export interface Membership {
  user_id: UserId;
  organization_id: TenantId;
  role: UserRole;
  joined_at: string;
  invited_by?: UserId;
}

export interface UserWithMembership extends AuthUser {
  memberships: Membership[];
}

/* ------------------------------------------------------------------ */
/* Roles & subsystem access (presentation-layer; backend contract pending) */
/* ------------------------------------------------------------------ */

export type Subsystem =
  | 'ingestion'
  | 'evidence'
  | 'search'
  | 'reports'
  | 'audit'
  | 'billing'
  | 'users'
  | 'settings';

export interface Role {
  id: RoleId;
  name: string;
  description: string;
  subsystem_access: Record<Subsystem, boolean>;
  is_system: boolean;
}

export interface RoleAssignment {
  user_id: UserId;
  role_id: RoleId;
  organization_id: TenantId;
}

/* ------------------------------------------------------------------ */
/* Threat intelligence (Canonical backend contracts - Phase 3 & 4)    */
/* ------------------------------------------------------------------ */

export interface SourceChannelItem {
  tenant_id: string;
  channel_id: string;
  channel_title: string;
  channel_handle?: string | null;
  source_type: 'telegram' | 'darkweb';
  is_authorized: boolean;
  created_at_utc: string;
  updated_at_utc: string;
}

export interface SourceChannelListResponse {
  total_channels: number;
  limit: number;
  offset: number;
  channels: SourceChannelItem[];
}

export interface ChannelRegisterRequest {
  channel_id: string;
  channel_title: string;
  channel_handle?: string;
  source_type?: 'telegram' | 'darkweb';
  is_authorized?: boolean;
}

export interface ChannelUpdateRequest {
  channel_title?: string;
  channel_handle?: string;
  is_authorized?: boolean;
}

export interface ThreatMessageItem {
  message_id: string;
  channel_id: string;
  source_sequence_id: number;
  message_thread_id?: string | null;
  sender_username?: string | null;
  sender_native_id?: string | null;
  broadcast_timestamp_utc: string;
  reply_to_message_id?: string | null;
  has_media: boolean;
  sanitized_text: string;
  sanitization_flags: string[];
  content_sha256: string;
}

export interface ThreatSearchResponse {
  query: string;
  total_results: number;
  limit: number;
  offset: number;
  items: ThreatMessageItem[];
}

export interface ThreatThreadResponse {
  channel_id: string;
  channel_title?: string | null;
  thread_id: string;
  total_messages: number;
  messages: ThreatMessageItem[];
}

export type ThreadStatus = 'new' | 'analyzing' | 'analyzed' | 'archived';

export interface Thread {
  id: ThreadId;
  case_id: CaseId;
  source: 'telegram';
  channel: string;
  title: string;
  status: ThreadStatus;
  message_count: number;
  last_message_at: string;
  risk_score: number;
  tenant_id: TenantId;
  created_at: string;
}

export interface ThreadMessage {
  id: string;
  thread_id: ThreadId;
  sender: string;
  body: string;
  timestamp: string;
  sanitized: boolean;
}

export interface Case {
  id: CaseId;
  tenant_id: TenantId;
  title: string;
  description: string;
  status: 'open' | 'in_progress' | 'closed';
  severity: 'low' | 'medium' | 'high' | 'critical';
  thread_count: number;
  created_at: string;
  updated_at: string;
  assigned_to?: UserId;
}

export interface SearchResult {
  id: string;
  type: 'thread' | 'message' | 'case';
  title: string;
  snippet: string;
  source: string;
  timestamp: string;
  relevance_score: number;
  thread_id?: ThreadId;
  case_id?: CaseId;
}

/* ------------------------------------------------------------------ */
/* Evidence & reports (presentation-layer; backend contract pending)  */
/* ------------------------------------------------------------------ */

export type EvidenceType =
  | 'text'
  | 'screenshot'
  | 'archive'
  | 'metadata';

export interface EvidenceItem {
  id: EvidenceId;
  case_id: CaseId;
  thread_id: ThreadId;
  type: EvidenceType;
  filename: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
  tenant_id: TenantId;
}

export interface Report {
  id: ReportId;
  case_id: CaseId;
  title: string;
  status: 'generating' | 'ready' | 'failed';
  format: 'pdf' | 'csv' | 'json';
  generated_at?: string;
  download_url?: string;
}

/* ------------------------------------------------------------------ */
/* Credits & usage (presentation-layer; backend contract pending)     */
/* ------------------------------------------------------------------ */

export interface CreditQuota {
  tenant_id: TenantId;
  plan: string;
  monthly_limit: number;
  used: number;
  reset_at: string;
  cost_per_query: number;
  currency: string;
}

export interface UsageEntry {
  date: string;
  queries: number;
  cost: number;
}

/* ------------------------------------------------------------------ */
/* Audit events (presentation-layer; backend contract pending)        */
/* ------------------------------------------------------------------ */

export interface AuditEvent {
  id: string;
  tenant_id: TenantId;
  user_id: UserId;
  user_name: string;
  action: string;
  resource: string;
  outcome: 'success' | 'failure';
  created_at: string;
  ip_address: string;
}

/* ------------------------------------------------------------------ */
/* API error                                                          */
/* ------------------------------------------------------------------ */

export interface ApiError {
  status: number;
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

/* ------------------------------------------------------------------ */
/* MOCK-ONLY TYPES                                                    */
/* ------------------------------------------------------------------ */

/**
 * DemoData is fabricated for demonstration/development only.
 * It does not represent real threat indicators, collection status,
 * or evidence, and must never be presented as production data.
 */
export interface DemoDataMarker {
  __MOCK__: true;
}

export interface MockDemoData extends DemoDataMarker {
  user: AuthUser;
  organizations: Organization[];
  memberships: Membership[];
  roles: Role[];
  cases: Case[];
  threads: Thread[];
  messages: ThreadMessage[];
  evidence: EvidenceItem[];
  reports: Report[];
  credits: CreditQuota;
  usage: UsageEntry[];
  audit: AuditEvent[];
}