import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { ttiApi } from '../services/api';
import type { Role } from '../types';

export const RoleSubsystemAccess: React.FC = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .listRoles()
      .then((data) => {
        if (mounted) {
          setRoles(data);
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
        title="Role-Based Access Control (RBAC)"
        subtitle="Role mappings, subsystem permissions, and least-privilege matrix (DEC-14)"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Org Admin', href: '/org-admin' },
          { label: 'Roles', href: '/role-subsystem' },
        ]}
      />

      <Card>
        <CardHeader
          title="Canonical Role Subsystem Matrix"
          description="Operational permission boundaries enforced in app.core.rbac"
        />

        {loading ? (
          <div className="p-6 text-center text-xs text-slate-500">Loading role permissions...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold text-[11px] border-b border-slate-200">
                  <th className="py-3 px-4">Role Identifier</th>
                  <th className="py-3 px-4">Description</th>
                  <th className="py-3 px-4">Ingestion</th>
                  <th className="py-3 px-4">Search</th>
                  <th className="py-3 px-4">Channels</th>
                  <th className="py-3 px-4">Audit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {roles.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50/50">
                    <td className="py-3 px-4 font-mono font-semibold text-slate-900">{r.name}</td>
                    <td className="py-3 px-4 text-slate-600 max-w-xs">{r.description}</td>
                    <td className="py-3 px-4">
                      {r.subsystem_access.ingestion ? (
                        <span className="text-emerald-600 font-bold">✓ Full</span>
                      ) : (
                        <span className="text-slate-300">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {r.subsystem_access.search ? (
                        <span className="text-emerald-600 font-bold">✓ Full</span>
                      ) : (
                        <span className="text-slate-300">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {r.subsystem_access.settings ? (
                        <span className="text-indigo-600 font-bold font-mono">PERM_ORG_MANAGE</span>
                      ) : (
                        <span className="text-slate-300">Read-Only</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {r.subsystem_access.audit ? (
                        <span className="text-emerald-600 font-bold">✓ Read</span>
                      ) : (
                        <span className="text-slate-300">—</span>
                      )}
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

export default RoleSubsystemAccess;
