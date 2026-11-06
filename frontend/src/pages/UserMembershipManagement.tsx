import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { ttiApi } from '../services/api';
import type { UserWithMembership } from '../types';

export const UserMembershipManagement: React.FC = () => {
  const [users, setUsers] = useState<UserWithMembership[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .listUsers()
      .then((data) => {
        if (mounted) {
          setUsers(data);
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
        title="User & Membership Management"
        subtitle="Manage investigator accounts, tenant memberships, and credential status"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Org Admin', href: '/org-admin' },
          { label: 'Members', href: '/user-membership' },
        ]}
      />

      <Card>
        <CardHeader
          title="Investigator Accounts"
          description="Provisioned user accounts with tenant isolation policies"
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Assigned Role</th>
                <th className="py-3 px-4">Tenant Scope</th>
                <th className="py-3 px-4">Account State</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-6 text-center text-slate-500">
                    Loading user directory...
                  </td>
                </tr>
              ) : (
                users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-50/50">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-900">{u.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono">{u.email}</div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded font-mono text-[11px] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                        {u.role.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-600 text-[11px]">
                      {u.tenant_name || u.tenant_id}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                        ACTIVE
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button className="px-2.5 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 rounded text-xs font-medium">
                        Edit Role
                      </button>
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

export default UserMembershipManagement;
