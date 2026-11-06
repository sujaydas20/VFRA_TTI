import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { HealthBadge } from '../components/HealthBadge';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { ApiIntegration, ApiIntegrationsResponse } from '../types';

/** Map backend auth status to a HealthBadge-compatible status. */
function authBadgeStatus(r: ApiIntegration): 'healthy' | 'degraded' | 'disabled' | 'unconfigured' | 'unavailable' {
  if (r.connected) return 'healthy';
  if (!r.enabled) return 'disabled';
  if (!r.credential_available) return 'unconfigured';
  if (r.authentication_status === 'failed') return 'unavailable';
  return 'degraded';
}

const CATEGORY_LABELS: Record<string, string> = {
  collection: 'Collection',
  intake: 'Intake',
  storage: 'Storage',
  infrastructure: 'Infrastructure',
  ai: 'AI / Analysis',
  enrichment: 'Enrichment',
};

export const ApiManagement: React.FC = () => {
  const [data, setData] = useState<ApiIntegrationsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showFingerprint, setShowFingerprint] = useState(false);

  const load = (probe: boolean) => {
    setLoading(true);
    setError(null);
    ttiApi
      .integrations(probe)
      .then((res) => {
        setData(res);
        setLoading(false);
      })
      .catch(() => {
        setError('Backend /api/v1/integrations unreachable. Start the backend (uvicorn app.main:app on port 8000) and retry.');
        setLoading(false);
      });
  };

  useEffect(() => {
    load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Management"
        subtitle="Automatic discovery, credential readiness, connection/auth/test health for every external API"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'API Management', href: '/api-management' },
        ]}
      />

      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-200 text-xs">{error}</div>
      )}

      {/* Summary strip */}
      {!loading && data && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0d1527] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wider">Total providers</p>
            <p className="text-2xl font-bold text-white mt-1">{data.total}</p>
          </div>
          <div className="bg-[#0d1527] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wider">Connected</p>
            <p className="text-2xl font-bold text-emerald-400 mt-1">{data.connected}</p>
          </div>
          <div className="bg-[#0d1527] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wider">Missing credentials</p>
            <p className="text-2xl font-bold text-amber-400 mt-1">{data.missing_credentials}</p>
          </div>
          <div className="bg-[#0d1527] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wider">Failed probes</p>
            <p className="text-2xl font-bold text-rose-400 mt-1">{data.failed}</p>
          </div>
        </div>
      )}

      <Card
        header={
          <CardHeader
            title="Integration Inventory"
            description="Live provider state. Secrets are never displayed - only availability and a fingerprint."
            action={
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowFingerprint((v) => !v)}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors"
                >
                  {showFingerprint ? 'Hide fingerprints' : 'Show credential fingerprints'}
                </button>
                <button
                  onClick={() => load(true)}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition-colors"
                >
                  Re-run probes
                </button>
              </div>
            }
          />
        }
      >
        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider">
                  <th className="py-2 pr-3 font-semibold">Provider</th>
                  <th className="py-2 pr-3 font-semibold">Purpose</th>
                  <th className="py-2 pr-3 font-semibold">Category</th>
                  <th className="py-2 pr-3 font-semibold">Connection</th>
                  <th className="py-2 pr-3 font-semibold">Auth</th>
                  <th className="py-2 pr-3 font-semibold">Credentials</th>
                  <th className="py-2 pr-3 font-semibold">Test</th>
                  <th className="py-2 pr-3 font-semibold">Last success</th>
                  <th className="py-2 font-semibold">Dependent modules</th>
                </tr>
              </thead>
              <tbody>
                {data?.integrations.map((r) => (
                  <tr key={r.provider} className="border-b border-slate-800/60 align-top">
                    <td className="py-3 pr-3">
                      <p className="font-semibold text-white">{r.provider}</p>
                      <p className="text-[10px] text-slate-500 font-mono mt-0.5">{r.endpoint || 'no endpoint'}</p>
                    </td>
                    <td className="py-3 pr-3 text-slate-300 max-w-[260px]">{r.purpose}</td>
                    <td className="py-3 pr-3 text-slate-400">{CATEGORY_LABELS[r.category] || r.category}</td>
                    <td className="py-3 pr-3">
                      <HealthBadge status={authBadgeStatus(r)} />
                    </td>
                    <td className="py-3 pr-3">
                      <span className="font-mono text-slate-300">{r.authentication_status}</span>
                    </td>
                    <td className="py-3 pr-3">
                      {r.credential_available ? (
                        <span>
                          <span className="inline-flex px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-mono text-[10px]">
                            available
                          </span>
                          {showFingerprint && r.credential_fingerprint && (
                            <p className="text-[10px] text-slate-500 font-mono mt-1">{r.credential_fingerprint}</p>
                          )}
                        </span>
                      ) : (
                        <span className="inline-flex px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 font-mono text-[10px]">
                          missing
                        </span>
                      )}
                    </td>
                    <td className="py-3 pr-3">
                      <span
                        className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${
                          r.test_status === 'passed'
                            ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                            : r.test_status === 'failed'
                            ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                            : 'bg-slate-500/10 text-slate-400 border-slate-600/30'
                        }`}
                      >
                        {r.test_status}
                      </span>
                    </td>
                    <td className="py-3 pr-3 text-slate-400 font-mono text-[10px]">
                      {r.last_success_utc ? new Date(r.last_success_utc).toLocaleString() : '—'}
                    </td>
                    <td className="py-3 pr-3">
                      <p className="font-mono text-[10px] text-slate-500 leading-relaxed">
                        {r.dependent_modules.length > 0 ? r.dependent_modules.join(', ') : '—'}
                      </p>
                      {(r.last_error || r.notes) && (
                        <p className="text-[10px] text-amber-300/90 mt-1 leading-relaxed">
                          {r.last_error || r.notes}
                        </p>
                      )}
                    </td>
                  </tr>
                ))}
                {!data && (
                  <tr>
                    <td className="py-6 text-center text-slate-500" colSpan={9}>
                      No integration data available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Missing-credential guidance */}
      {!loading && data && data.missing_credentials + data.failed + (data.integrations.filter((i) => !i.credential_available).length) > 0 && (
        <Card>
          <CardHeader
            title="Configuration Required"
            description="What to set to bring each integration online. Secrets themselves are never shown."
          />
          <div className="space-y-3">
            {data.integrations
              .filter((r) => !r.credential_available || r.test_status === 'failed' || !r.connected)
              .map((r) => (
                <div key={r.provider} className="p-3 rounded-lg border border-slate-800 bg-slate-900/40">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-semibold text-white">{r.provider}</p>
                    <span className="text-[10px] font-mono text-slate-500">{r.credential_env_vars.join(', ')}</span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{r.expected_configuration}</p>
                  {r.last_error && <p className="text-xs text-amber-300/90 mt-1 font-mono">{r.last_error}</p>}
                </div>
              ))}
          </div>
        </Card>
      )}
    </div>
  );
};

export default ApiManagement;