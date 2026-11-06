import React from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { API_BASE_URL, API_MODE } from '../services/api';

export const Settings: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        title="System Settings & Preferences"
        subtitle="Network endpoints, API connectivity mode, and investigator preferences"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Settings', href: '/settings' },
        ]}
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader title="API Connectivity Configuration" description="Current client connection settings" />
          <div className="p-4 space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Active API Mode:</span>
              <span
                className={`font-mono font-bold px-2 py-0.5 rounded text-[11px] ${
                  API_MODE === 'live'
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : 'bg-amber-50 text-amber-800 border border-amber-200'
                }`}
              >
                {API_MODE.toUpperCase()}
              </span>
            </div>

            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">API Base URL:</span>
              <span className="font-mono text-slate-800">{API_BASE_URL} (Vite Proxy: :8000)</span>
            </div>

            <div className="flex justify-between py-1.5">
              <span className="text-slate-500 font-medium">Session Token:</span>
              <span className="font-mono text-slate-500">
                {sessionStorage.getItem('tti_access_token') ? 'Active (Stored in SessionStorage)' : 'Mock In-Memory'}
              </span>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader title="Security Controls & Legal Safeguards" description="Standing policy controls" />
          <div className="p-4 space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Telegram Collector:</span>
              <span className="font-mono text-purple-700 font-semibold bg-purple-50 px-2 py-0.5 rounded border border-purple-200">
                Disabled (DEC-02)
              </span>
            </div>

            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500 font-medium">Dark-Web Scraper:</span>
              <span className="font-mono text-purple-700 font-semibold bg-purple-50 px-2 py-0.5 rounded border border-purple-200">
                Disabled (DEC-02)
              </span>
            </div>

            <div className="flex justify-between py-1.5">
              <span className="text-slate-500 font-medium">Evidence Path Exposure:</span>
              <span className="font-mono text-emerald-700 font-semibold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                Protected / Defanged
              </span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default Settings;
