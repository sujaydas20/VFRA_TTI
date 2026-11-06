/// <reference types="vite/client" />

import {
  type AuthUser,
  type AuditEvent,
  type Case,
  type CaseId,
  type ChannelRegisterRequest,
  type ChannelUpdateRequest,
  type ConnectorHealth,
  type CreditQuota,
  type EvidenceItem,
  type HealthStatusResponse,
  type LoginCredentials,
  type LoginResponse,
  type Membership,
  type Organization,
  type OrgStatus,
  type ProjectStatusResponse,
  type Report,
  type Role,
  type SessionState,
  type SourceChannelItem,
  type SourceChannelListResponse,
  type Thread,
  type ThreadId,
  type ThreadMessage,
  type TenantId,
  type ThreatMessageItem,
  type ThreatSearchResponse,
  type ThreatThreadResponse,
  type UsageEntry,
  type UserWithMembership,
} from '../types';

import { type ApiIntegrationsResponse } from '../types';

/* ------------------------------------------------------------------ */
/* Configuration                                                        */
/* ------------------------------------------------------------------ */

/**
 * API base path mounted by the FastAPI backend under TTI_API_V1_STR (/api/v1).
 * The Vite dev server proxies /api to http://127.0.0.1:8000 (see vite.config.ts).
 */
export const API_BASE_URL = '/api/v1';

/**
 * Default to mock mode. The backend currently implements only
 * GET /api/v1/health, GET /api/v1/status and GET /api/v1/connectors.
 * All other domain endpoints are served by the isolated MockAdapter below
 * and are clearly labelled as demo data throughout the UI.
 * Set VITE_TTI_API_MODE=live to attempt live backend calls.
 */
export const API_MODE: 'live' | 'mock' =
  import.meta.env.VITE_TTI_API_MODE === 'live' ? 'live' : 'mock';

/* ------------------------------------------------------------------ */
/* API error                                                            */
/* ------------------------------------------------------------------ */

export class TtiApiError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'TtiApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/* ------------------------------------------------------------------ */
/* Centralized API client                                               */
/* ------------------------------------------------------------------ */

type RequestOptions = {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  noAuth?: boolean;
};

export class ApiClient {
  private baseUrl: string;
  private token: string | null = null;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
    if (typeof window !== 'undefined' && window.sessionStorage) {
      this.token = sessionStorage.getItem('tti_access_token');
    }
  }

  /** Set the bearer token (called after login / on session restore). */
  setToken(token: string | null): void {
    this.token = token;
    if (typeof window !== 'undefined' && window.sessionStorage) {
      if (token) {
        sessionStorage.setItem('tti_access_token', token);
      } else {
        sessionStorage.removeItem('tti_access_token');
      }
    }
  }

  getToken(): string | null {
    return this.token;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    options: RequestOptions = {},
  ): Promise<T> {
    const { headers = {}, signal, noAuth = false } = options;
    const url = `${this.baseUrl}${path}`;

    const requestHeaders: Record<string, string> = {
      'Accept': 'application/json',
      ...headers,
    };

    if (!noAuth && this.token) {
      requestHeaders['Authorization'] = `Bearer ${this.token}`;
    }

    if (body && !requestHeaders['Content-Type']) {
      requestHeaders['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, {
      method,
      headers: requestHeaders,
      body: body ? JSON.stringify(body) : undefined,
      signal,
    });

    if (!response.ok) {
      let code = 'REQUEST_FAILED';
      let message = `HTTP error ${response.status}: ${response.statusText}`;
      let details: Record<string, unknown> | undefined;

      try {
        const payload = (await response.json()) as { code?: string; message?: string; details?: Record<string, unknown> };
        code = payload.code ?? code;
        message = payload.message ?? message;
        details = payload.details;
      } catch {
        // ignore malformed error bodies
      }

      throw new TtiApiError(response.status, code, message, details);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return response.json();
  }

  get<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, undefined, options);
  }

  post<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, body, options);
  }

  put<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('PUT', path, body, options);
  }

  patch<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('PATCH', path, body, options);
  }

  del<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, undefined, options);
  }
}



/* ------------------------------------------------------------------ */
/* Mock adapter (isolated, demo data only)                              */
/* ------------------------------------------------------------------ */

/**
 * MockAdapter stands in for backend endpoints that are not yet implemented.
 * All data here is fabricated for demonstration/development and is tagged
 * with __MOCK__ so it can never be mistaken for real threat intelligence.
 *
 * Do NOT add credentials, tokens or customer data here.
 */
export class MockAdapter {
  private delayMs: number;

  constructor(delayMs: number = 0) {
    this.delayMs = delayMs;
  }

  private async once<T>(value: T): Promise<T> {
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    return value;
  }

  /* Auth ----------------------------------------------------------- */

  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    if (credentials.email.toLowerCase() !== 'analyst@example.com' || credentials.password !== 'demo-pass') {
      throw new TtiApiError(401, 'INVALID_CREDENTIALS', 'Invalid email address or password.');
    }
    const demoUser: AuthUser = {
      id: 'user_00000000-0000-0000-0000-000000000001',
      email: credentials.email,
      name: 'Demo Analyst',
      role: 'analyst',
      tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
      tenant_name: 'Demo Organization',
      permissions: ['cases:read', 'threads:read', 'evidence:read', 'reports:read', 'threat:channels:read', 'threat:search'],
      mfa_enabled: false,
      last_login_at: new Date().toISOString(),
    };
    return this.once({ user: demoUser, token: 'mock_token_demo_analyst' });
  }

  async me(): Promise<AuthUser> {
    return this.once({
      id: 'user_00000000-0000-0000-0000-000000000001',
      email: 'analyst@demo.local',
      name: 'Demo Analyst',
      role: 'analyst',
      tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
      tenant_name: 'Demo Organization',
      permissions: ['cases:read', 'threads:read', 'evidence:read', 'reports:read'],
      mfa_enabled: false,
      last_login_at: new Date().toISOString(),
    });
  }

  /* Organizations -------------------------------------------------- */

  async listOrganizations(): Promise<Organization[]> {
    return this.once([...demoOrganizations]);
  }

  async getOrganization(id: TenantId): Promise<Organization> {
    const found = demoOrganizations.find((o) => o.id === id);
    if (!found) {
      throw new TtiApiError(404, 'ORG_NOT_FOUND', 'Organization not found');
    }
    return this.once(found);
  }

  async updateOrganizationStatus(id: TenantId, status: OrgStatus): Promise<Organization> {
    const found = demoOrganizations.find((o) => o.id === id);
    if (!found) {
      throw new TtiApiError(404, 'ORG_NOT_FOUND', 'Organization not found');
    }
    found.status = status;
    if (status === 'active') {
      found.approved_at = new Date().toISOString();
      found.approved_by = 'user_platform_admin';
    }
    return this.once(found);
  }

  /* Roles ---------------------------------------------------------- */

  async listRoles(): Promise<Role[]> {
    return this.once([...demoRoles]);
  }

  /* Cases & threads ------------------------------------------------ */

  async listCases(): Promise<Case[]> {
    return this.once([...demoCases]);
  }

  async getCase(id: CaseId): Promise<Case> {
    const found = demoCases.find((c) => c.id === id);
    if (!found) {
      throw new TtiApiError(404, 'CASE_NOT_FOUND', 'Case not found');
    }
    return this.once(found);
  }

  async listThreads(caseId?: CaseId): Promise<Thread[]> {
    return this.once([...demoThreads.filter((t) => !caseId || t.case_id === caseId)]);
  }

  async getThread(id: ThreadId): Promise<Thread> {
    const found = demoThreads.find((t) => t.id === id);
    if (!found) {
      throw new TtiApiError(404, 'THREAD_NOT_FOUND', 'Thread not found');
    }
    return this.once(found);
  }

  async listThreadMessages(threadId: ThreadId): Promise<ThreadMessage[]> {
    return this.once([...demoMessages.filter((m) => m.thread_id === threadId)]);
  }

  /* Evidence & reports --------------------------------------------- */

  async listEvidence(caseId?: CaseId): Promise<EvidenceItem[]> {
    return this.once([...demoEvidence.filter((e) => !caseId || e.case_id === caseId)]);
  }

  async listReports(caseId?: CaseId): Promise<Report[]> {
    return this.once([...demoReports.filter((r) => !caseId || r.case_id === caseId)]);
  }

  /* Credits & usage ------------------------------------------------ */

  async getCreditQuota(): Promise<CreditQuota> {
    return this.once({ ...demoCredits });
  }

  async listUsage(): Promise<UsageEntry[]> {
    return this.once([...demoUsage]);
  }

  /* Audit ---------------------------------------------------------- */

  async listAuditEvents(): Promise<AuditEvent[]> {
    return this.once([...demoAudit]);
  }

  /* Threat Intelligence & Channels (Phase 3 & 4) ------------------ */

  async listChannels(
    limit: number = 50,
    offset: number = 0,
    is_authorized?: boolean,
    source_type?: string,
  ): Promise<SourceChannelListResponse> {
    let filtered = [...demoChannels];
    if (is_authorized !== undefined) {
      filtered = filtered.filter((c) => c.is_authorized === is_authorized);
    }
    if (source_type) {
      filtered = filtered.filter((c) => c.source_type === source_type);
    }
    return this.once({
      total_channels: filtered.length,
      limit,
      offset,
      channels: filtered.slice(offset, offset + limit),
    });
  }

  async registerChannel(payload: ChannelRegisterRequest): Promise<SourceChannelItem> {
    const existing = demoChannels.find((c) => c.channel_id === payload.channel_id);
    if (existing) {
      throw new TtiApiError(409, 'CHANNEL_ALREADY_REGISTERED', `Channel '${payload.channel_id}' is already registered.`);
    }
    const newChannel: SourceChannelItem = {
      tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
      channel_id: payload.channel_id,
      channel_title: payload.channel_title,
      channel_handle: payload.channel_handle || null,
      source_type: payload.source_type || 'telegram',
      is_authorized: payload.is_authorized ?? false,
      created_at_utc: new Date().toISOString(),
      updated_at_utc: new Date().toISOString(),
    };
    demoChannels.unshift(newChannel);
    return this.once(newChannel);
  }

  async updateChannel(channel_id: string, payload: ChannelUpdateRequest): Promise<SourceChannelItem> {
    const found = demoChannels.find((c) => c.channel_id === channel_id);
    if (!found) {
      throw new TtiApiError(404, 'CHANNEL_NOT_FOUND', `Channel '${channel_id}' not found.`);
    }
    if (payload.channel_title !== undefined) found.channel_title = payload.channel_title;
    if (payload.channel_handle !== undefined) found.channel_handle = payload.channel_handle;
    if (payload.is_authorized !== undefined) found.is_authorized = payload.is_authorized;
    found.updated_at_utc = new Date().toISOString();
    return this.once(found);
  }

  async searchThreats(
    query: string,
    channel_id?: string,
    limit: number = 50,
    offset: number = 0,
  ): Promise<ThreatSearchResponse> {
    let items = [...demoThreatMessages];
    if (channel_id) {
      items = items.filter((m) => m.channel_id === channel_id);
    }
    if (query && query.trim() !== '') {
      const q = query.toLowerCase();
      items = items.filter(
        (m) =>
          m.sanitized_text.toLowerCase().includes(q) ||
          (m.sender_username && m.sender_username.toLowerCase().includes(q)) ||
          m.channel_id.toLowerCase().includes(q),
      );
    }
    return this.once({
      query,
      total_results: items.length,
      limit,
      offset,
      items: items.slice(offset, offset + limit),
    });
  }

  async getThreadDetail(channel_id: string, thread_id: string): Promise<ThreatThreadResponse> {
    const items = demoThreatMessages.filter(
      (m) => m.channel_id === channel_id && (m.message_thread_id === thread_id || m.message_id === thread_id),
    );
    return this.once({
      channel_id,
      channel_title: demoChannels.find((c) => c.channel_id === channel_id)?.channel_title,
      thread_id,
      total_messages: items.length,
      messages: items,
    });
  }

  /* Users ---------------------------------------------------------- */

  async listUsers(): Promise<UserWithMembership[]> {
    return this.once([demoUserWithMemberships]);
  }
}


/* ------------------------------------------------------------------ */
/* Canonical backend endpoints (live via /api/v1 proxy)                 */
/* ------------------------------------------------------------------ */

const liveClient = new ApiClient();

/**
 * GET /api/v1/health — implemented by the backend.
 */
export async function fetchHealthStatus(): Promise<HealthStatusResponse> {
  return liveClient.get('/health');
}

/**
 * GET /api/v1/status — implemented by the backend.
 */
export async function fetchProjectStatus(tenantId?: string): Promise<ProjectStatusResponse> {
  return liveClient.get('/status', {
    headers: tenantId ? { 'X-Tenant-ID': tenantId } : {},
  });
}

/**
 * GET /api/v1/connectors — implemented by the backend.
 */
export async function fetchConnectors(): Promise<ConnectorHealth[]> {
  return liveClient.get('/connectors');
}

/**
 * GET /api/v1/integrations — implemented by the backend.
 * Live API integration inventory with connection/auth/test status.
 */
export async function fetchIntegrations(probe: boolean = true): Promise<ApiIntegrationsResponse> {
  return liveClient.get(`/integrations?probe=${String(probe)}`);
}


/* ------------------------------------------------------------------ */
/* Mock adapter continued — domain endpoints (demo data only)           */
/* ------------------------------------------------------------------ */

const demoOrganizations: Organization[] = [
  {
    id: 'tenant_00000000-0000-0000-0000-000000000001',
    name: 'Demo Organization',
    slug: 'demo-org',
    status: 'active',
    plan: 'Enterprise',
    member_count: 4,
    case_count: 12,
    created_at: '2026-01-15T08:00:00Z',
    approved_at: '2026-01-16T09:00:00Z',
    domain: 'demo.local',
  },
  {
    id: 'tenant_00000000-0000-0000-0000-000000000002',
    name: 'Acme Corporation',
    slug: 'acme-corp',
    status: 'pending',
    plan: 'Team',
    member_count: 2,
    case_count: 0,
    created_at: '2026-09-10T10:00:00Z',
    domain: 'acme.example',
  },
  {
    id: 'tenant_00000000-0000-0000-0000-000000000003',
    name: 'Globex Logistics',
    slug: 'globex',
    status: 'suspended',
    plan: 'Team',
    member_count: 3,
    case_count: 3,
    created_at: '2026-06-01T07:00:00Z',
    domain: 'globex.example',
  },
];

const demoRoles: Role[] = [
  {
    id: 'role_platform_admin',
    name: 'Platform Administrator',
    description: 'Full access across all tenants and subsystems.',
    subsystem_access: { ingestion: true, evidence: true, search: true, reports: true, audit: true, billing: true, users: true, settings: true },
    is_system: true,
  },
  {
    id: 'role_org_admin',
    name: 'Organization Administrator',
    description: 'Manages organization settings, members, and roles.',
    subsystem_access: { ingestion: true, evidence: true, search: true, reports: true, audit: true, billing: true, users: true, settings: true },
    is_system: false,
  },
  {
    id: 'role_analyst',
    name: 'Analyst',
    description: 'Read/write access to cases, threads, evidence and reports.',
    subsystem_access: { ingestion: true, evidence: true, search: true, reports: true, audit: false, billing: false, users: false, settings: false },
    is_system: false,
  },
  {
    id: 'role_viewer',
    name: 'Viewer',
    description: 'Read-only access to intelligence dashboards.',
    subsystem_access: { ingestion: false, evidence: false, search: true, reports: true, audit: true, billing: false, users: false, settings: false },
    is_system: false,
  },
];

const demoCases: Case[] = [
  {
    id: 'case_00000000-0000-0000-0000-000000000001',
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    title: 'Extortion thread — ransomware group claims',
    description: 'Investigation of Telegram thread claiming access to a logistics firm.',
    status: 'in_progress',
    severity: 'high',
    thread_count: 3,
    created_at: '2026-09-20T12:00:00Z',
    updated_at: '2026-09-24T14:30:00Z',
    assigned_to: 'user_00000000-0000-0000-0000-000000000001',
  },
  {
    id: 'case_00000000-0000-0000-0000-000000000002',
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    title: 'Leaked credentials exposure',
    description: 'Monitoring for leaked corporate credentials on forum sources.',
    status: 'open',
    severity: 'medium',
    thread_count: 1,
    created_at: '2026-09-22T09:00:00Z',
    updated_at: '2026-09-22T09:00:00Z',
  },
];

const demoThreads: Thread[] = [
  {
    id: 'thread_00000000-0000-0000-0000-000000000001',
    case_id: 'case_00000000-0000-0000-0000-000000000001',
    source: 'telegram',
    channel: '@example_threat_channel',
    title: 'Ransomware leak announcement',
    status: 'analyzed',
    message_count: 47,
    last_message_at: '2026-09-23T18:45:00Z',
    risk_score: 82,
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    created_at: '2026-09-20T12:00:00Z',
  },
  {
    id: 'thread_00000000-0000-0000-0000-000000000002',
    case_id: 'case_00000000-0000-0000-0000-000000000001',
    source: 'telegram',
    channel: '@example_threat_channel',
    title: 'Follow-up discussion',
    status: 'new',
    message_count: 12,
    last_message_at: '2026-09-24T10:15:00Z',
    risk_score: 41,
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    created_at: '2026-09-23T08:00:00Z',
  },
];

const demoMessages: ThreadMessage[] = [
  {
    id: 'msg_1',
    thread_id: 'thread_00000000-0000-0000-0000-000000000001',
    sender: 'actor_alpha',
    body: 'Sample sanitized message content for demonstration purposes only.',
    timestamp: '2026-09-20T12:05:00Z',
    sanitized: true,
  },
  {
    id: 'msg_2',
    thread_id: 'thread_00000000-0000-0000-0000-000000000001',
    sender: 'actor_beta',
    body: 'Another demo message — not real threat intelligence.',
    timestamp: '2026-09-20T12:12:00Z',
    sanitized: true,
  },
];

const demoEvidence: EvidenceItem[] = [
  {
    id: 'ev_00000000-0000-0000-0000-000000000001',
    case_id: 'case_00000000-0000-0000-0000-000000000001',
    thread_id: 'thread_00000000-0000-0000-0000-000000000001',
    type: 'screenshot',
    filename: 'thread_capture_001.png',
    size_bytes: 245760,
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    created_at: '2026-09-21T10:00:00Z',
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
  },
];

const demoReports: Report[] = [
  {
    id: 'rep_00000000-0000-0000-0000-000000000001',
    case_id: 'case_00000000-0000-0000-0000-000000000001',
    title: 'Weekly intelligence summary — September 2026',
    status: 'ready',
    format: 'pdf',
    generated_at: '2026-09-25T09:00:00Z',
    download_url: '#/mock/reports/rep_00000000-0000-0000-0000-000000000001/download',
  },
];

const demoCredits: CreditQuota = {
  tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
  plan: 'Enterprise',
  monthly_limit: 10000,
  used: 3420,
  reset_at: '2026-11-01T00:00:00Z',
  cost_per_query: 0.15,
  currency: 'USD',
};

const demoUsage: UsageEntry[] = [
  { date: '2026-09-18', queries: 124, cost: 18.6 },
  { date: '2026-09-19', queries: 98, cost: 14.7 },
  { date: '2026-09-20', queries: 210, cost: 31.5 },
  { date: '2026-09-21', queries: 165, cost: 24.75 },
  { date: '2026-09-22', queries: 89, cost: 13.35 },
  { date: '2026-09-23', queries: 140, cost: 21.0 },
  { date: '2026-09-24', queries: 176, cost: 26.4 },
];

const demoAudit: AuditEvent[] = [
  {
    id: 'audit_1',
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    user_id: 'user_00000000-0000-0000-0000-000000000001',
    user_name: 'Demo Analyst',
    action: 'case.view',
    resource: 'case_00000000-0000-0000-0000-000000000001',
    outcome: 'success',
    created_at: '2026-09-24T14:35:00Z',
    ip_address: '10.0.0.42',
  },
  {
    id: 'audit_2',
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    user_id: 'user_00000000-0000-0000-0000-000000000001',
    user_name: 'Demo Analyst',
    action: 'evidence.download',
    resource: 'ev_00000000-0000-0000-0000-000000000001',
    outcome: 'success',
    created_at: '2026-09-24T14:40:00Z',
    ip_address: '10.0.0.42',
  },
];

const demoChannels: SourceChannelItem[] = [
  {
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    channel_id: 'tg_leak_hub_alpha',
    channel_title: 'ShadowMarket Leak Hub',
    channel_handle: '@shadow_leaks_io',
    source_type: 'telegram',
    is_authorized: true,
    created_at_utc: '2026-10-25T12:00:00Z',
    updated_at_utc: '2026-10-28T16:30:00Z',
  },
  {
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    channel_id: 'tg_crypto_scams_sec',
    channel_title: 'Crypto Drainers & Phish Feed',
    channel_handle: '@drainer_ops',
    source_type: 'telegram',
    is_authorized: true,
    created_at_utc: '2026-10-26T08:15:00Z',
    updated_at_utc: '2026-10-29T10:00:00Z',
  },
  {
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    channel_id: 'tg_unauthorized_dump',
    channel_title: 'VIP Stealer Logs Drop (Pending Review)',
    channel_handle: '@vip_stealer_drops',
    source_type: 'telegram',
    is_authorized: false,
    created_at_utc: '2026-10-29T04:20:00Z',
    updated_at_utc: '2026-10-29T04:20:00Z',
  },
  {
    tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
    channel_id: 'dw_breached_mirror',
    channel_title: 'Breached Forum Mirror #4',
    channel_handle: null,
    source_type: 'darkweb',
    is_authorized: false,
    created_at_utc: '2026-10-28T19:00:00Z',
    updated_at_utc: '2026-10-28T19:00:00Z',
  },
];

const demoThreatMessages: ThreatMessageItem[] = [
  {
    message_id: 'msg_001_leak',
    channel_id: 'tg_leak_hub_alpha',
    source_sequence_id: 1042,
    message_thread_id: 'topic_corporate_creds',
    sender_username: 'red_broker_99',
    sender_native_id: 'tg_user_9921412',
    broadcast_timestamp_utc: '2026-10-29T14:22:00Z',
    reply_to_message_id: null,
    has_media: false,
    sanitized_text: 'Fresh corporate VPN access dump for North American tech firm. Portal at hxxps://vpn[.]victim-corp[.]com. Contact via Tox ID [REDACTED_TOX].',
    sanitization_flags: ['DEFANGED_URL', 'REDACTED_TOX'],
    content_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  {
    message_id: 'msg_002_drainer',
    channel_id: 'tg_crypto_scams_sec',
    source_sequence_id: 2055,
    message_thread_id: null,
    sender_username: 'drain_dev',
    sender_native_id: 'tg_user_7718291',
    broadcast_timestamp_utc: '2026-10-29T13:45:00Z',
    reply_to_message_id: null,
    has_media: true,
    sanitized_text: 'Updated Web3 wallet bypass script v3.4 targeting Solana & Ethereum phantom extensions. C2 infrastructure: 198.51.100.42 (port 8443).',
    sanitization_flags: ['DEFANGED_IP'],
    content_sha256: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
  },
  {
    message_id: 'msg_003_stealer',
    channel_id: 'tg_leak_hub_alpha',
    source_sequence_id: 1043,
    message_thread_id: 'topic_corporate_creds',
    sender_username: 'red_broker_99',
    sender_native_id: 'tg_user_9921412',
    broadcast_timestamp_utc: '2026-10-29T14:30:00Z',
    reply_to_message_id: 'msg_001_leak',
    has_media: false,
    sanitized_text: 'Sample preview: 2,400 user records with domain hashes and session tokens. Price: 0.5 BTC.',
    sanitization_flags: ['REDACTED_HASH'],
    content_sha256: '9f83c605d40a08e925b4ab4b60061e86a9f4c399b1a50b7b3c7b3c7b3c7b3c7b',
  },
];

const demoMemberships: Membership[] = [
  {
    user_id: 'user_00000000-0000-0000-0000-000000000001',
    organization_id: 'tenant_00000000-0000-0000-0000-000000000001',
    role: 'analyst',
    joined_at: '2026-01-16T09:00:00Z',
  },
];

const demoUserWithMemberships: UserWithMembership = {
  id: 'user_00000000-0000-0000-0000-000000000001',
  email: 'analyst@demo.local',
  name: 'Demo Analyst',
  role: 'analyst',
  tenant_id: 'tenant_00000000-0000-0000-0000-000000000001',
  tenant_name: 'Demo Organization',
  permissions: ['cases:read', 'threads:read', 'evidence:read', 'reports:read'],
  mfa_enabled: false,
  last_login_at: new Date().toISOString(),
  memberships: demoMemberships,
};

/* ------------------------------------------------------------------ */
/* Service facade — dispatches live vs mock by API_MODE                 */
/* ------------------------------------------------------------------ */

const mockAdapter = new MockAdapter();

function useMock<T>(mockCall: () => Promise<T>, liveCall: () => Promise<T>): Promise<T> {
  return API_MODE === 'mock' ? mockCall() : liveCall();
}

/**
 * TTI API services. All functions return promises and throw TtiApiError
 * on failed responses. In mock mode (default) calls are routed to
 * MockAdapter; in live mode they hit the FastAPI backend via /api/v1.
 */
export const ttiApi = {
  /* Canonical backend endpoints (always live) */
  health: () => fetchHealthStatus(),
  status: (tenantId?: string) => fetchProjectStatus(tenantId),
  connectors: () => fetchConnectors(),
  integrations: (probe: boolean = true) => fetchIntegrations(probe),

  /* Auth */
  login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
    if (API_MODE === 'mock') {
      const res = await mockAdapter.login(credentials);
      liveClient.setToken(res.token);
      return res;
    } else {
      const backendRes = await liveClient.post<{
        access_token: string;
        token_type: string;
        expires_in: number;
        user: { user_id: string; email_address: string; full_name: string; account_state: string };
        active_tenant_id: string;
        assigned_role: string;
        permissions: string[];
      }>('/auth/login', credentials);
      const token = backendRes.access_token;
      const user: AuthUser = {
        id: backendRes.user.user_id,
        email: backendRes.user.email_address,
        name: backendRes.user.full_name,
        role: backendRes.assigned_role === 'ROLE_PLATFORM_ADMIN' ? 'platform_admin'
            : backendRes.assigned_role === 'ROLE_TENANT_ADMIN' ? 'org_admin'
            : 'analyst',
        tenant_id: backendRes.active_tenant_id,
        permissions: backendRes.permissions,
        mfa_enabled: false,
      };
      liveClient.setToken(token);
      return { user, token };
    }
  },
  me: () =>
    useMock(() => mockAdapter.me(), () => liveClient.get('/auth/me')),
  logout: async () => {
    try {
      if (API_MODE === 'live') {
        await liveClient.post('/auth/logout');
      }
    } finally {
      liveClient.setToken(null);
    }
  },

  /* Phase 4 Source Channel Administration (SEC-THREAT-05) */
  listChannels: (limit: number = 50, offset: number = 0, is_authorized?: boolean, source_type?: string) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (is_authorized !== undefined) params.append('is_authorized', String(is_authorized));
    if (source_type) params.append('source_type', source_type);
    return useMock(
      () => mockAdapter.listChannels(limit, offset, is_authorized, source_type),
      () => liveClient.get<SourceChannelListResponse>(`/threat/channels?${params.toString()}`),
    );
  },
  registerChannel: (payload: ChannelRegisterRequest) =>
    useMock(
      () => mockAdapter.registerChannel(payload),
      () => liveClient.post<SourceChannelItem>('/threat/channels', payload),
    ),
  updateChannel: (channel_id: string, payload: ChannelUpdateRequest) =>
    useMock(
      () => mockAdapter.updateChannel(channel_id, payload),
      () => liveClient.patch<SourceChannelItem>(`/threat/channels/${channel_id}`, payload),
    ),

  /* Phase 3 Threat Search & Thread Exploration */
  searchThreats: (q: string, channel_id?: string, limit: number = 50, offset: number = 0) => {
    const params = new URLSearchParams({ q, limit: String(limit), offset: String(offset) });
    if (channel_id) params.append('channel_id', channel_id);
    return useMock(
      () => mockAdapter.searchThreats(q, channel_id, limit, offset),
      () => liveClient.get<ThreatSearchResponse>(`/threat/search?${params.toString()}`),
    );
  },
  getThreadDetail: (channel_id: string, thread_id: string) =>
    useMock(
      () => mockAdapter.getThreadDetail(channel_id, thread_id),
      () => liveClient.get<ThreatThreadResponse>(`/threat/threads/${channel_id}/${thread_id}`),
    ),

  /* Organizations */
  listOrganizations: () =>
    useMock(() => mockAdapter.listOrganizations(), () => liveClient.get('/organizations')),
  getOrganization: (id: TenantId) =>
    useMock(
      () => mockAdapter.getOrganization(id),
      () => liveClient.get(`/organizations/${id}`),
    ),
  updateOrganizationStatus: (id: TenantId, status: OrgStatus) =>
    useMock(
      () => mockAdapter.updateOrganizationStatus(id, status),
      () => liveClient.patch(`/organizations/${id}/status`, { status }),
    ),

  /* Roles */
  listRoles: () => useMock(() => mockAdapter.listRoles(), () => liveClient.get('/roles')),

  /* Cases */
  listCases: () => useMock(() => mockAdapter.listCases(), () => liveClient.get('/cases')),
  getCase: (id: CaseId) =>
    useMock(() => mockAdapter.getCase(id), () => liveClient.get(`/cases/${id}`)),

  /* Threads */
  listThreads: (caseId?: CaseId) =>
    useMock(
      () => mockAdapter.listThreads(caseId),
      () => liveClient.get(`/cases/${caseId ?? ''}/threads`),
    ),
  getThread: (id: ThreadId) =>
    useMock(() => mockAdapter.getThread(id), () => liveClient.get(`/threads/${id}`)),
  listThreadMessages: (threadId: ThreadId) =>
    useMock(
      () => mockAdapter.listThreadMessages(threadId),
      () => liveClient.get(`/threads/${threadId}/messages`),
    ),

  /* Evidence */
  listEvidence: (caseId?: CaseId) =>
    useMock(
      () => mockAdapter.listEvidence(caseId),
      () => liveClient.get(`/evidence${caseId ? `?case_id=${caseId}` : ''}`),
    ),

  /* Reports */
  listReports: (caseId?: CaseId) =>
    useMock(
      () => mockAdapter.listReports(caseId),
      () => liveClient.get(`/reports${caseId ? `?case_id=${caseId}` : ''}`),
    ),

  /* Credits & usage */
  getCreditQuota: () =>
    useMock(() => mockAdapter.getCreditQuota(), () => liveClient.get('/credits/quota')),
  listUsage: () => useMock(() => mockAdapter.listUsage(), () => liveClient.get('/credits/usage')),

  /* Audit */
  listAuditEvents: () =>
    useMock(() => mockAdapter.listAuditEvents(), () => liveClient.get('/audit/events')),

  /* Users */
  listUsers: () => useMock(() => mockAdapter.listUsers(), () => liveClient.get('/users')),
} as const;

export { mockAdapter, liveClient };
export type { LoginCredentials, LoginResponse, SessionState };
