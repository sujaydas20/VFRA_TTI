import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { ttiApi } from '../services/api';
import type { EvidenceItem, Report } from '../types';

export const EvidenceDetailReportPreview: React.FC = () => {
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    Promise.all([ttiApi.listEvidence(), ttiApi.listReports()])
      .then(([evList, repList]) => {
        if (mounted) {
          setEvidence(evList);
          setReports(repList);
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
        title="Evidence Vault & Deliverables (Phase 5/6 Planned)"
        subtitle="Cryptographic evidence artifacts, plain-text deliverable packages, and dual-scope screenshots (REP-TXT-SCREEN-001)"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Evidence Vault', href: '/evidence-detail' },
        ]}
      />

      {/* Planned Feature Banner */}
      <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
        <p className="font-bold flex items-center gap-1.5 text-amber-950">
          <span>ℹ️</span> Architectural Roadmap Milestone: Phase 5 & Phase 6
        </p>
        <p className="leading-relaxed">
          The Investigation Reporting Engine (<code className="font-mono bg-amber-100 px-1 rounded">REP-TXT-SCREEN-001</code>) and
          Case Management Subsystem are scheduled for Phase 5/6 backend migrations. The items displayed below represent
          mock demonstration assets conforming to the approved physical evidence schema.
        </p>
      </div>

      {/* Evidence Artifacts Table */}
      <Card>
        <CardHeader
          title="Evidence Artifact Ledger"
          description="Tenant-isolated blobs stored under evidence/tenant_{id}/ with SHA-256 verification"
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                <th className="py-3 px-4">Artifact ID</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Associated Case</th>
                <th className="py-3 px-4">SHA-256 Integrity Hash</th>
                <th className="py-3 px-4">Collected Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-6 text-center text-slate-500">
                    Loading evidence artifacts...
                  </td>
                </tr>
              ) : (
                evidence.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50/50">
                    <td className="py-3 px-4 font-mono font-semibold text-slate-900">{item.id}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-100 text-slate-700 border border-slate-200">
                        {item.type.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-indigo-600">{item.case_id}</td>
                    <td className="py-3 px-4 font-mono text-slate-500 text-[11px]">
                      {item.sha256.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Investigation Reports Table */}
      <Card>
        <CardHeader
          title="Investigation Deliverables"
          description="Cryptographically signed packages containing dual-scope screenshots and plain-text findings"
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                <th className="py-3 px-4">Report Package ID</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4">Review State</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {reports.map((rep) => (
                <tr key={rep.id} className="hover:bg-slate-50/50">
                  <td className="py-3 px-4 font-mono text-slate-900 font-semibold">{rep.id}</td>
                  <td className="py-3 px-4 font-medium text-slate-800">{rep.title}</td>
                  <td className="py-3 px-4 font-mono text-slate-600 uppercase text-[11px]">{rep.format}</td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                      APPROVED (DEC-05)
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      disabled
                      className="px-3 py-1 bg-slate-100 text-slate-400 rounded text-xs font-semibold cursor-not-allowed border border-slate-200"
                    >
                      Package (.zip)
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default EvidenceDetailReportPreview;
