import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { CreditQuota as CreditQuotaType, UsageEntry } from '../types';

export const CreditQuota: React.FC = () => {
  const [quota, setQuota] = useState<CreditQuotaType | null>(null);
  const [usage, setUsage] = useState<UsageEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    Promise.all([ttiApi.getCreditQuota(), ttiApi.listUsage()])
      .then(([q, u]) => {
        if (mounted) {
          setQuota(q);
          setUsage(u);
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
        title="Credit Quota & Metering Ledger"
        subtitle="Tenant search consumption, rate limits, and deduction ledger (Phase 1 Ledger)"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Credit Quota', href: '/credit-quota' },
        ]}
      />

      {/* Quota Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs space-y-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Plan & Limit</span>
          <p className="text-xl font-bold text-slate-900">
            {loading ? <Skeleton className="h-6 w-20" /> : `${quota?.monthly_limit.toLocaleString()} Queries`}
          </p>
          <p className="text-xs text-indigo-600 font-medium">Enterprise Tier</p>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs space-y-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Consumed This Period</span>
          <p className="text-xl font-bold text-slate-900">
            {loading ? <Skeleton className="h-6 w-20" /> : `${quota?.used.toLocaleString()} Queries`}
          </p>
          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-indigo-600 h-1.5 rounded-full"
              style={{
                width: quota ? `${Math.min(100, (quota.used / quota.monthly_limit) * 100)}%` : '0%',
              }}
            />
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs space-y-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Remaining Balance</span>
          <p className="text-xl font-bold text-emerald-600">
            {loading ? <Skeleton className="h-6 w-20" /> : `${((quota?.monthly_limit || 0) - (quota?.used || 0)).toLocaleString()} Queries`}
          </p>
          <p className="text-xs text-slate-400">Resets on next billing cycle</p>
        </div>
      </div>

      {/* Daily Usage Table */}
      <Card>
        <CardHeader title="Daily Query Consumption" description="Recent query activity and metering logs" />
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                <th className="py-3 px-4">Date</th>
                <th className="py-3 px-4">Observable Queries</th>
                <th className="py-3 px-4">Estimated Unit Cost</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {usage.map((entry) => (
                <tr key={entry.date} className="hover:bg-slate-50/50">
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-700">{entry.date}</td>
                  <td className="py-3 px-4 font-semibold text-slate-900">{entry.queries.toLocaleString()}</td>
                  <td className="py-3 px-4 text-slate-600 font-mono">${entry.cost.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default CreditQuota;
