import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { ttiApi } from '../services/api';
import type { UserWithMembership } from '../types';

export const OrgAdminDashboard: React.FC = () => {
  const [members, setMembers] = useState<UserWithMembership[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .listUsers()
      .then((users) => {
        if (mounted) {
          setMembers(users);
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
        title="Organization Administration"
        subtitle="Tenant profile, security policy, and investigator team roster"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Org Admin', href: '/org-admin' },
        ]}
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader title="Tenant Workspace Profile" description="Active enterprise organization context" />
          <div className="p-4 space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Organization Name:</span>
              <span className="font-semibold text-slate-900">Acme Cyber Defense LLC</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Tenant ID:</span>
              <span className="font-mono text-slate-700">tenant_00000001</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Account Status:</span>
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                ACTIVE
              </span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-500 font-medium">Collection Authorization:</span>
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                PERM_ORG_MANAGE Active
              </span>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader title="Security Controls" description="Cryptographic and authentication posture" />
          <div className="p-4 space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Password Hashing:</span>
              <span className="font-mono text-slate-900">Argon2id (m=64MB, t=3, p=4)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Concurrent Session Policy:</span>
              <span className="font-semibold text-indigo-700">Single Active Session (DEC-20)</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-500 font-medium">Audit Record Retention:</span>
              <span className="font-mono text-slate-900">365 Days (Append-Only)</span>
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="Organization Members" description="Active investigators and administrators" />
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                <th className="py-3 px-4">Name & Email</th>
                <th className="py-3 px-4">Role</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Last Activity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={4} className="p-4 text-center text-slate-500">
                    Loading team members...
                  </td>
                </tr>
              ) : (
                members.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-50/50">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-900">{u.name}</div>
                      <div className="text-[11px] text-slate-400">{u.email}</div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                        {u.role.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                        ACTIVE
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500 font-mono text-[11px]">
                      {new Date().toLocaleDateString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default OrgAdminDashboard;
