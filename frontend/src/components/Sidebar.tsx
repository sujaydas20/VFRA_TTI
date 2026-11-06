import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ttiApi } from '../services/api';

interface SidebarProps {
  onCloseMobile?: () => void;
}

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  badge?: string;
  planned?: boolean;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({ onCloseMobile }) => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await ttiApi.logout();
    navigate('/login');
  };

  const navSections: NavSection[] = [
    {
      title: 'Threat Intelligence',
      items: [
        {
          to: '/threat-intel',
          label: 'Overview & Feeds',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          ),
        },
        {
          to: '/channels',
          label: 'Channel Management',
          badge: 'Phase 4',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
          ),
        },
        {
          to: '/search-thread',
          label: 'Search & Threads',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          ),
        },
      ],
    },
    {
      title: 'Investigations (Planned)',
      items: [
        {
          to: '/evidence-detail',
          label: 'Evidence & Reports',
          planned: true,
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          ),
        },
      ],
    },
    {
      title: 'Governance & Security',
      items: [
        {
          to: '/platform-admin',
          label: 'Platform Admin',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          ),
        },
        {
          to: '/org-admin',
          label: 'Organization Admin',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
            </svg>
          ),
        },
        {
          to: '/user-membership',
          label: 'User Memberships',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
          ),
        },
        {
          to: '/role-subsystem',
          label: 'Roles & RBAC',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          ),
        },
        {
          to: '/credit-quota',
          label: 'Credit Ledger',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
            </svg>
          ),
        },
        {
          to: '/audit',
          label: 'Audit Log Viewer',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          ),
        },
        {
          to: '/api-management',
          label: 'API Management',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          ),
        },
        {
          to: '/settings',
          label: 'Settings',
          icon: (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
          ),
        },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-[#0a0f1d] border-r border-slate-800/80 flex flex-col h-full flex-shrink-0 select-none">
      {/* Brand & Tenant Header */}
      <div className="p-4 border-b border-slate-800/80 bg-slate-900/40">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-indigo-600 flex items-center justify-center text-white font-extrabold text-sm shadow-[0_0_15px_rgba(6,182,212,0.35)] border border-cyan-400/30">
            TTI
          </div>
          <div>
            <h1 className="text-sm font-bold text-white tracking-tight flex items-center gap-1.5">
              Threat Intelligence
            </h1>
            <p className="text-[11px] text-cyan-400/80 font-mono">Enterprise CTI Suite</p>
          </div>
        </div>

        {/* Tenant Card */}
        <div className="mt-3.5 p-2 bg-[#0d1527] rounded-lg border border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 truncate">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse" />
            <span className="text-xs font-semibold text-slate-200 truncate">Acme Cyber Defense</span>
          </div>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
            RLS Active
          </span>
        </div>
      </div>

      {/* Navigation Sections */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
        {navSections.map((section) => (
          <div key={section.title}>
            <h3 className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
              {section.title}
            </h3>
            <div className="space-y-1">
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={onCloseMobile}
                  className={({ isActive }) =>
                    `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-200 border-l-2 border-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.12)] font-semibold'
                        : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border-l-2 border-transparent'
                    }`
                  }
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <span className="text-slate-400 group-hover:text-cyan-400">{item.icon}</span>
                    <span className="truncate">{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono">
                      {item.badge}
                    </span>
                  )}
                  {item.planned && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 font-mono">
                      Plan
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Ingestion Pipeline Architecture Status (DEC-02 Compliance) */}
      <div className="mx-3 mb-2 p-2.5 rounded-lg bg-[#0d1527] border border-slate-800 text-[10px] font-mono space-y-1">
        <div className="flex items-center justify-between text-slate-400">
          <span>INGESTION STATUS</span>
          <span className="text-purple-400 font-semibold">DEC-02 INERT</span>
        </div>
        <div className="flex items-center justify-between text-slate-300">
          <span>Collector Mode:</span>
          <span className="text-purple-300 font-semibold">Safe / Passive</span>
        </div>
        <div className="flex items-center justify-between text-slate-300">
          <span>Evidence Hash:</span>
          <span className="text-slate-400">SHA-256 (Savepoint)</span>
        </div>
      </div>

      {/* Investigator Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-900/60">
        <div className="flex items-center justify-between p-2 rounded-lg bg-[#0d1527] border border-slate-800">
          <div className="flex items-center gap-2.5 truncate">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-xs font-bold text-cyan-300">
              DA
            </div>
            <div className="truncate">
              <p className="text-xs font-semibold text-white truncate">Demo Analyst</p>
              <p className="text-[10px] text-slate-400 truncate font-mono">analyst@example.com</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            title="Sign out"
            className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-md transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
};
