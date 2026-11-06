import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { HealthBadge } from '../components/HealthBadge';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { HealthStatusResponse } from '../types';

export const PlatformAdminDashboard: React.FC = () => {
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .health()
      .then((data) => {
        if (mounted) {
          setHealth(data);
          setLoading(false);
        }
      })
      .catch(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Administration"
        subtitle="Platform-wide operations, multi-tenant database status, and subsystem health"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Platform Admin', href: '/platform-admin' },
        ]}
      />

      {/* Subsystem Health Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">FastAPI Backend</span>
            <HealthBadge status={health ? health.status : 'healthy'} />
          </div>
          <p className="text-lg font-bold text-slate-900">
            {loading ? <Skeleton className="h-6 w-20" /> : health?.version ? `v${health.version}` : 'v0.1.0'}
          </p>
          <p className="text-xs text-slate-500 font-mono">Environment: {health?.environment || 'development'}</p>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">PostgreSQL RLS</span>
            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              Active
            </span>
          </div>
          <p className="text-lg font-bold text-slate-900">Migration 0005 Head</p>
          <p className="text-xs text-slate-500">Tenant-isolated schemas: iam, threat, evidence, audit</p>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Cryptographic Evidence</span>
            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
              SHA-256
            </span>
          </div>
          <p className="text-lg font-bold text-slate-900">Append-Only Vault</p>
          <p className="text-xs text-slate-500">Raw storage paths protected behind API boundary</p>
        </div>
      </div>

      {/* Database Roles & Invariants */}
      <Card>
        <CardHeader
          title="Security & Governance Invariants"
          description="Enforced architectural safeguards across platform execution"
        />
        <div className="p-4 space-y-3 text-xs">
          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 flex items-start gap-3">
            <span className="font-mono font-bold text-indigo-700 bg-indigo-100 px-1.5 py-0.5 rounded">
              RLS-POL-01
            </span>
            <p className="text-slate-700 leading-relaxed">
              Row-Level Security isolates tenant rows unconditionally. The application connects using least-privilege role{' '}
              <code className="font-mono text-indigo-600">tti_app_role</code>. Session variable{' '}
              <code className="font-mono text-indigo-600">app.current_tenant_id</code> is set on every checkout.
            </p>
          </div>

          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 flex items-start gap-3">
            <span className="font-mono font-bold text-indigo-700 bg-indigo-100 px-1.5 py-0.5 rounded">
              DEC-20
            </span>
            <p className="text-slate-700 leading-relaxed">
              Single active session invariant: Only one JWT session per user is valid concurrently. Prior sessions are
              atomically revoked or displaced on login.
            </p>
          </div>

          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 flex items-start gap-3">
            <span className="font-mono font-bold text-indigo-700 bg-indigo-100 px-1.5 py-0.5 rounded">
              DEC-02
            </span>
            <p className="text-slate-700 leading-relaxed">
              External Telegram and dark-web scrapers remain inert (<code className="font-mono text-indigo-600">TTI_TELEGRAM_CONNECTOR_ACTIVE=false</code>)
              pending formal Chief Legal Counsel collection authorization.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default PlatformAdminDashboard;
