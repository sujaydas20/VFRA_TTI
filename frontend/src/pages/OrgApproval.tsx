import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { ttiApi } from '../services/api';
import type { Organization } from '../types';

export const OrgApproval: React.FC = () => {
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .listOrganizations()
      .then((data) => {
        if (mounted) {
          setOrgs(data.filter((o) => o.status === 'pending'));
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
        title="Organization Tenant Approvals"
        subtitle="Platform administrator approval workflow for pending tenant registrations"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Org Admin', href: '/org-admin' },
          { label: 'Approvals', href: '/org-approval' },
        ]}
      />

      <Card>
        <CardHeader
          title="Pending Organizations"
          description="Organizations requiring compliance & security onboarding approval"
        />

        {loading ? (
          <div className="p-6 text-center text-xs text-slate-500">Checking pending requests...</div>
        ) : orgs.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            <p className="font-semibold text-slate-800 text-sm">No Pending Tenant Organizations</p>
            <p className="mt-1">All registered customer organizations have been approved and provisioned.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                  <th className="py-3 px-4">Organization Name</th>
                  <th className="py-3 px-4">Plan</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {orgs.map((org) => (
                  <tr key={org.id} className="hover:bg-slate-50/50">
                    <td className="py-3 px-4 font-semibold text-slate-900">{org.name}</td>
                    <td className="py-3 px-4">{org.plan}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                        PENDING
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button className="px-3 py-1 bg-emerald-600 text-white rounded text-xs font-semibold hover:bg-emerald-700">
                        Approve Tenant
                      </button>
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

export default OrgApproval;
