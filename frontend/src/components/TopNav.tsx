import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ttiApi, API_MODE } from '../services/api';
import type { HealthStatusResponse } from '../types';

interface TopNavProps {
  onToggleMobileMenu?: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({ onToggleMobileMenu }) => {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);
  const [healthStatus, setHealthStatus] = useState<'checking' | 'healthy' | 'offline'>('checking');
  const [omniSearch, setOmniSearch] = useState('');
  const [showExportModal, setShowExportModal] = useState(false);

  useEffect(() => {
    let mounted = true;
    ttiApi
      .health()
      .then((data) => {
        if (mounted) {
          setHealth(data);
          setHealthStatus(data.status === 'healthy' ? 'healthy' : 'offline');
        }
      })
      .catch(() => {
        if (mounted) {
          setHealthStatus('offline');
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  const handleOmniSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (omniSearch.trim()) {
      navigate(`/search-thread?q=${encodeURIComponent(omniSearch.trim())}`);
    }
  };

  return (
    <header className="h-14 bg-[#0a0f1d] border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between flex-shrink-0 z-20">
      {/* Left: Mobile hamburger & Context */}
      <div className="flex items-center gap-3">
        {onToggleMobileMenu && (
          <button
            onClick={onToggleMobileMenu}
            className="p-1.5 -ml-1 text-slate-400 hover:text-white md:hidden rounded-lg hover:bg-slate-800"
            aria-label="Open sidebar"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        )}
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
            TTI Operations
          </span>
          <span className="text-slate-600">/</span>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700/80 text-cyan-300">
            Tenant: tenant_00000001
          </span>
        </div>
      </div>

      {/* Middle: Tactical Global Search (StealthMole Parity+) */}
      <div className="hidden lg:flex flex-1 max-w-md mx-6">
        <form onSubmit={handleOmniSearchSubmit} className="w-full relative">
          <div className="relative flex items-center">
            <svg
              className="w-4 h-4 text-slate-500 absolute left-3 pointer-events-none"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            <input
              type="text"
              value={omniSearch}
              onChange={(e) => setOmniSearch(e.target.value)}
              placeholder="Omni-search observables (TG:, IOC:, HASH:) [Enter]..."
              className="w-full pl-9 pr-12 py-1.5 bg-[#0d1527] border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all"
            />
            <span className="absolute right-2.5 px-1.5 py-0.5 text-[10px] font-mono text-slate-500 bg-slate-800 rounded border border-slate-700">
              ⌘K
            </span>
          </div>
        </form>
      </div>

      {/* Right: Security Safeguard, API Telemetry, Quick Export */}
      <div className="flex items-center gap-2.5">
        {/* Legal safeguard pill (DEC-02) */}
        <span
          className="hidden xl:inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30"
          title="DEC-02 Legal Safeguard: External Telegram & dark-web scrapers are legally inert."
        >
          <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
          DEC-02 SAFEGUARD
        </span>

        {/* Backend health status badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border bg-[#0d1527] border-slate-800">
          <span
            className={`w-2 h-2 rounded-full ${
              healthStatus === 'healthy'
                ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]'
                : healthStatus === 'checking'
                ? 'bg-amber-400 animate-pulse'
                : 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]'
            }`}
          />
          <span className="text-slate-200 font-mono text-xs">
            {healthStatus === 'healthy'
              ? `API ${health?.status || 'Online'}`
              : healthStatus === 'checking'
              ? 'Checking...'
              : 'API Offline'}
          </span>
          {health?.environment && (
            <span className="text-[10px] text-slate-500 font-mono">({health.environment})</span>
          )}
        </div>

        {/* API mode badge */}
        <span
          className={`text-[11px] font-mono px-2 py-1 rounded border font-semibold ${
            API_MODE === 'live'
              ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
              : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
          }`}
          title={API_MODE === 'live' ? 'Connected to live FastAPI backend' : 'Running with isolated mock data adapter'}
        >
          {API_MODE === 'live' ? '● LIVE API' : '⚋ MOCK DEMO'}
        </span>

        {/* Quick Export Trigger */}
        <button
          onClick={() => setShowExportModal(true)}
          className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-mono font-medium transition-colors"
          title="Export STIX 2.1 Threat Intelligence Bundle"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          STIX 2.1
        </button>
      </div>

      {/* Quick STIX Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0d1527] border border-cyan-500/40 rounded-xl max-w-lg w-full p-5 shadow-[0_0_30px_rgba(6,182,212,0.2)]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">STIX 2.1 Threat Bundle Export</h3>
              </div>
              <button
                onClick={() => setShowExportModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="mt-4 space-y-3 text-xs text-slate-300">
              <p>
                Standardized Cyber Threat Intelligence format compliant with OASIS STIX 2.1 specification (Specimen Template • To export active message threads, use the Thread Explorer view).
              </p>
              <div className="bg-[#070b14] p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-40">
                {`{\n  "type": "bundle",\n  "id": "bundle--tti-investigation-2026",\n  "spec_version": "2.1",\n  "objects": [\n    {\n      "type": "observed-data",\n      "id": "observed-data--7f921a9c",\n      "first_observed": "2026-10-29T14:22:00Z",\n      "number_observed": 3,\n      "objects": {\n        "0": { "type": "domain-name", "value": "victim-corp[.]com" }\n      }\n    }\n  ]\n}`}
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => setShowExportModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Close
              </button>
              <button
                onClick={() => {
                  navigator.clipboard?.writeText(`{"type":"bundle","spec_version":"2.1","tenant":"tenant_00000001"}`);
                  alert('STIX 2.1 Bundle JSON copied to clipboard!');
                  setShowExportModal(false);
                }}
                className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg transition-colors"
              >
                Copy STIX JSON
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
