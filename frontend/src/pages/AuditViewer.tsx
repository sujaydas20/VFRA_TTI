import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { AuditEvent } from '../types';

export const AuditViewer: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .listAuditEvents()
      .then((data) => {
        if (mounted) {
          setEvents(data);
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
        title="Tamper-Evident Audit Log Viewer"
        subtitle="Cryptographically verified security and administrative lifecycle trail"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Audit Viewer', href: '/audit' },
        ]}
      />

      <Card>
        <CardHeader
          title="Security Event Ledger"
          description="Append-only audit records from audit.audit_event_records"
        />

        {loading ? (
          <div className="p-6 space-y-3">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                  <th className="py-3 px-4">Event ID</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Resource</th>
                  <th className="py-3 px-4">Investigator</th>
                  <th className="py-3 px-4">Outcome</th>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-50/50">
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-500">{evt.id}</td>
                    <td className="py-3 px-4 font-semibold text-slate-900 font-mono text-[11px]">
                      {evt.action}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-indigo-600">{evt.resource}</td>
                    <td className="py-3 px-4 text-slate-700">{evt.user_name}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          evt.outcome === 'success'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : 'bg-rose-50 text-rose-700 border border-rose-200'
                        }`}
                      >
                        {evt.outcome}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(evt.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

export default AuditViewer;
