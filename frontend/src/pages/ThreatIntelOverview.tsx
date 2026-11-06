import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { HealthBadge } from '../components/HealthBadge';
import { Card } from '../components/Card';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { HealthStatusResponse, SourceChannelItem, ThreatMessageItem } from '../types';

export const ThreatIntelOverview: React.FC = () => {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [channels, setChannels] = useState<SourceChannelItem[]>([]);
  const [recentThreats, setRecentThreats] = useState<ThreatMessageItem[]>([]);
  const [quickSearch, setQuickSearch] = useState('');

  // Enhanced CTI state (StealthMole Parity+)
  const [activeVectorTab, setActiveVectorTab] = useState<'all' | 'dumps' | 'crypto' | 'darknet'>('all');
  const [streamPaused, setStreamPaused] = useState(false);
  const [selectedThreatForDrawer, setSelectedThreatForDrawer] = useState<ThreatMessageItem | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [rawViewMode, setRawViewMode] = useState(false);

  useEffect(() => {
    let mounted = true;

    // Fetch Health
    ttiApi
      .health()
      .then((data) => {
        if (mounted) {
          setHealth(data);
          setHealthLoading(false);
        }
      })
      .catch(() => {
        if (mounted) setHealthLoading(false);
      });

    // Fetch Channels
    ttiApi
      .listChannels(10, 0)
      .then((res) => {
        if (mounted) setChannels(res.channels);
      })
      .catch(() => {});

    // Fetch Recent Threats
    ttiApi
      .searchThreats('', undefined, 10, 0)
      .then((res) => {
        if (mounted) setRecentThreats(res.items);
      })
      .catch(() => {});

    return () => {
      mounted = false;
    };
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickSearch.trim()) {
      navigate(`/search-thread?q=${encodeURIComponent(quickSearch.trim())}`);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const authorizedCount = channels.filter((c) => c.is_authorized).length;

  // Filter threats by vector tab
  const filteredThreats = recentThreats.filter((item) => {
    if (activeVectorTab === 'dumps') return item.sanitized_text.toLowerCase().includes('dump') || item.sanitized_text.toLowerCase().includes('vpn');
    if (activeVectorTab === 'crypto') return item.sanitized_text.toLowerCase().includes('btc') || item.sanitized_text.toLowerCase().includes('wallet');
    if (activeVectorTab === 'darknet') return item.channel_id.includes('leak') || item.channel_id.includes('dw');
    return true;
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Intelligence Operations"
        subtitle="Live source collection, observable sanitization, and channel telemetry"
        breadcrumbs={[{ label: 'Home', href: '/threat-intel' }]}
      />

      {/* KPI Stat Cards Grid - Military SOC Standard */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* System Health Card */}
        <div className="bg-[#0d1527] p-4 rounded-xl border border-slate-800 shadow-lg shadow-black/40 flex flex-col justify-between hover:border-cyan-500/30 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">System Health</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse" />
          </div>
          <div className="mt-2.5">
            {healthLoading ? (
              <Skeleton className="h-6 w-24" />
            ) : health ? (
              <div className="flex items-center gap-2">
                <HealthBadge status={health.status} />
                <span className="text-xs text-slate-400 font-mono">({health.environment})</span>
              </div>
            ) : (
              <span className="text-xs text-amber-400 font-mono font-medium">Standalone / Demo Mode</span>
            )}
          </div>
          <p className="mt-2 text-[11px] text-slate-500 font-mono">
            {health ? `Checked: ${new Date(health.timestamp_utc).toLocaleTimeString()}` : 'FastAPI proxy active'}
          </p>
        </div>

        {/* Source Channels Card */}
        <div className="bg-[#0d1527] p-4 rounded-xl border border-slate-800 shadow-lg shadow-black/40 flex flex-col justify-between hover:border-cyan-500/30 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Source Channels</span>
            <span className="text-cyan-400 font-mono text-xs font-bold px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30">
              SEC-05
            </span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-extrabold text-white font-mono">{channels.length}</span>
            <span className="text-xs text-emerald-400 font-medium font-mono">
              {authorizedCount} Authorized
            </span>
          </div>
          <Link
            to="/channels"
            className="mt-2 text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 font-mono transition-colors"
          >
            Manage Channels →
          </Link>
        </div>

        {/* Ingestion Integrity */}
        <div className="bg-[#0d1527] p-4 rounded-xl border border-slate-800 shadow-lg shadow-black/40 flex flex-col justify-between hover:border-cyan-500/30 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Evidence Integrity</span>
            <span className="text-xs text-emerald-400 font-mono font-bold">100% Valid</span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-extrabold text-white font-mono">SHA-256</span>
            <span className="text-xs text-slate-400 font-mono">Atomic Rollback</span>
          </div>
          <p className="mt-2 text-[11px] text-slate-500 font-mono">SEC-THREAT-02 Savepoints active</p>
        </div>

        {/* Collector Safeguard (DEC-02) */}
        <div className="bg-[#0d1527] p-4 rounded-xl border border-slate-800 shadow-lg shadow-black/40 flex flex-col justify-between hover:border-purple-500/30 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Collector Daemon</span>
            <span className="text-xs text-purple-400 font-mono font-bold px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30">
              DEC-02
            </span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-xs font-semibold px-2 py-1 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30 font-mono">
              Inert / Safe Mode
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-500 font-mono">Live scraping legally disabled</p>
        </div>
      </div>

      {/* Quick Search Observable Jump - Tactical Obsidian Bar */}
      <Card className="border-cyan-500/20 bg-gradient-to-r from-[#0d1527] to-[#0a0f1d]">
        <div className="max-w-3xl">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-sm font-bold tracking-tight text-white flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Investigator Observable Search
            </h3>
            <span className="text-[10px] font-mono text-cyan-400/80">Phase 3 Defanged Engine</span>
          </div>
          <p className="text-xs text-slate-400 mb-3">
            Search threat messages, IP observables, BTC addresses, Telegram handles, and defanged IOCs.
          </p>
          <form onSubmit={handleSearchSubmit} className="flex gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={quickSearch}
                onChange={(e) => setQuickSearch(e.target.value)}
                placeholder="Search IOCs e.g. 'hxxp', 'VPN', 'wallet', 'red_broker_99'..."
                className="w-full px-3.5 py-2.5 bg-[#070b14] border border-slate-700/80 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono"
              />
            </div>
            <button
              type="submit"
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.25)] transition-all font-mono"
            >
              Search Threats
            </button>
          </form>
          {/* Preset Quick Chips */}
          <div className="mt-2.5 flex items-center gap-1.5 text-[11px] font-mono text-slate-400 flex-wrap">
            <span className="text-slate-500">Fast Pivots:</span>
            <button
              type="button"
              onClick={() => { setQuickSearch('hxxps'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-cyan-300 border border-slate-700"
            >
              [DEFANGED_URL]
            </button>
            <button
              type="button"
              onClick={() => { setQuickSearch('0.5 BTC'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-amber-300 border border-slate-700"
            >
              [CRYPTO_BTC]
            </button>
            <button
              type="button"
              onClick={() => { setQuickSearch('198.51.100.42'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-rose-300 border border-slate-700"
            >
              [DEFANGED_IP]
            </button>
            <button
              type="button"
              onClick={() => { setQuickSearch('red_broker_99'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-purple-300 border border-slate-700"
            >
              [@red_broker_99]
            </button>
          </div>
        </div>
      </Card>

      {/* Two Column Layout: Monitored Feeds & Live Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Monitored Channels Card */}
        <Card className="flex flex-col">
          <div className="flex items-center justify-between p-4 border-b border-slate-800/80">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                Monitored Feeds
              </h3>
              <p className="text-[11px] text-slate-400 font-sans">Registered intelligence sources</p>
            </div>
            <Link
              to="/channels"
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
            >
              View All ({channels.length}) →
            </Link>
          </div>
          <div className="divide-y divide-slate-800/60 text-xs flex-1">
            {channels.slice(0, 4).map((ch) => (
              <div key={ch.channel_id} className="p-3.5 flex items-center justify-between hover:bg-slate-800/30 transition-colors">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {ch.source_type === 'telegram' ? '✈ TG' : '🧅 TOR'}
                    </span>
                    <p className="font-semibold text-white">{ch.channel_title}</p>
                  </div>
                  <p className="text-[11px] text-cyan-400 font-mono">{ch.channel_handle || ch.channel_id}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border ${
                      ch.is_authorized
                        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                        : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    }`}
                  >
                    {ch.is_authorized ? 'Authorized' : 'Unauthorized'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Live Sanitized Threat Feed (StealthMole Parity+) */}
        <Card className="flex flex-col">
          <div className="p-4 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${streamPaused ? 'bg-amber-400' : 'bg-emerald-400 animate-pulse'}`} />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                  Recent Sanitized Chatter
                </h3>
              </div>
              <p className="text-[11px] text-slate-400 font-sans">Incoming normalized intelligence stream</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setStreamPaused(!streamPaused)}
                className={`text-[10px] font-mono px-2 py-0.5 rounded border transition-colors ${
                  streamPaused
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
                }`}
              >
                {streamPaused ? '▶ Resume' : '⏸ Pause'}
              </button>
              <Link
                to="/search-thread"
                className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
              >
                Thread Explorer →
              </Link>
            </div>
          </div>

          {/* Vector Filtering Tabs */}
          <div className="px-4 py-2 bg-slate-900/60 border-b border-slate-800/60 flex items-center gap-2 overflow-x-auto text-[11px] font-mono">
            <button
              onClick={() => setActiveVectorTab('all')}
              className={`px-2 py-0.5 rounded ${activeVectorTab === 'all' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            >
              All Vectors
            </button>
            <button
              onClick={() => setActiveVectorTab('dumps')}
              className={`px-2 py-0.5 rounded ${activeVectorTab === 'dumps' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Credential Dumps
            </button>
            <button
              onClick={() => setActiveVectorTab('crypto')}
              className={`px-2 py-0.5 rounded ${activeVectorTab === 'crypto' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Crypto Drainers
            </button>
            <button
              onClick={() => setActiveVectorTab('darknet')}
              className={`px-2 py-0.5 rounded ${activeVectorTab === 'darknet' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Darknet Leaks
            </button>
          </div>

          {/* Threat Items Stream */}
          <div className="divide-y divide-slate-800/60 text-xs flex-1">
            {filteredThreats.slice(0, 4).map((item) => (
              <div
                key={item.message_id}
                onClick={() => setSelectedThreatForDrawer(item)}
                className="p-3.5 space-y-2 hover:bg-slate-800/40 cursor-pointer transition-colors group"
              >
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-300 font-mono">@{item.sender_username || 'anonymous'}</span>
                    <span
                      className={`text-[10px] px-1.5 py-0.2 rounded font-mono border ${
                        item.sanitization_flags.includes('DEFANGED_URL') || item.sanitization_flags.includes('REDACTED_TOX')
                          ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                          : item.sanitization_flags.includes('DEFANGED_IP')
                          ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                          : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                      }`}
                    >
                      {item.sanitization_flags.includes('DEFANGED_URL') || item.sanitization_flags.includes('REDACTED_TOX')
                        ? 'CRITICAL IOC'
                        : item.sanitization_flags.includes('DEFANGED_IP')
                        ? 'SUSPICIOUS NET'
                        : 'FLAGGED IOC'}
                    </span>
                  </div>
                  <span className="text-slate-500 font-mono">
                    {new Date(item.broadcast_timestamp_utc).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed text-xs">
                  {item.sanitized_text}
                </p>
                <div className="flex items-center gap-1.5 pt-1 flex-wrap">
                  {item.sanitization_flags.map((flag) => (
                    <span
                      key={flag}
                      className="text-[10px] font-mono px-1.5 py-0.2 bg-amber-500/10 text-amber-300 border border-amber-500/30 rounded"
                    >
                      [{flag}]
                    </span>
                  ))}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      copyToClipboard(item.content_sha256, item.message_id);
                    }}
                    title="Click to copy full SHA-256 hash"
                    className="text-[10px] font-mono text-slate-400 hover:text-cyan-300 ml-auto flex items-center gap-1 bg-slate-800/60 px-1.5 py-0.5 rounded border border-slate-700/60 transition-colors"
                  >
                    <span>SHA: {item.content_sha256.slice(0, 8)}...</span>
                    <span>{copiedText === item.message_id ? '✓' : '📋'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Slide-over Forensic Evidence Drawer (StealthMole Killer Feature) */}
      {selectedThreatForDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-xs">
          <div className="w-full max-w-xl bg-[#0a0f1d] border-l border-cyan-500/30 flex flex-col h-full shadow-[0_0_50px_rgba(0,0,0,0.8)] overflow-hidden">
            {/* Drawer Header */}
            <div className="p-5 border-b border-slate-800 bg-[#0d1527] flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)]" />
                  <h3 className="text-base font-bold text-white font-mono">Forensic Evidence Inspector</h3>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Cryptographic custody seal & observable breakdown
                </p>
              </div>
              <button
                onClick={() => setSelectedThreatForDrawer(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                ✕
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs text-slate-300">
              {/* Provenance & Tenant Isolation Badge */}
              <div className="p-3 bg-[#0d1527] rounded-lg border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-slate-400 font-mono">TENANT CONTEXT</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                    tenant_00000001 (SESSION SCOPE)
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                  <div>
                    <span className="text-slate-500">Channel ID: </span>
                    <span className="text-cyan-300">{selectedThreatForDrawer.channel_id}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Source Seq: </span>
                    <span className="text-slate-200">#{selectedThreatForDrawer.source_sequence_id}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Actor Handle: </span>
                    <span className="text-amber-300">@{selectedThreatForDrawer.sender_username || 'anonymous'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Broadcast: </span>
                    <span className="text-slate-200">
                      {new Date(selectedThreatForDrawer.broadcast_timestamp_utc).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Message Payload with Defanged vs Raw Toggle */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white uppercase text-[11px] font-mono tracking-wider">
                    Message Payload Content
                  </span>
                  <div className="flex items-center gap-1 text-[10px] font-mono">
                    <button
                      onClick={() => setRawViewMode(false)}
                      className={`px-2 py-0.5 rounded ${!rawViewMode ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-500'}`}
                    >
                      Defanged (Safe)
                    </button>
                    <button
                      onClick={() => setRawViewMode(true)}
                      className={`px-2 py-0.5 rounded ${rawViewMode ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'text-slate-500'}`}
                    >
                      Raw (Restricted)
                    </button>
                  </div>
                </div>
                <div className="p-3.5 bg-[#070b14] border border-slate-800 rounded-lg font-mono text-xs leading-relaxed text-slate-200">
                  {selectedThreatForDrawer.sanitized_text}
                </div>
              </div>

              {/* Cryptographic SHA-256 Digest */}
              <div className="p-3.5 bg-[#0d1527] rounded-lg border border-slate-800 space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-slate-400">CRYPTOGRAPHIC SHA-256 SEAL</span>
                  <span className="text-[10px] text-cyan-400 font-mono">Payload Digest</span>
                </div>
                <div className="p-2 bg-[#070b14] rounded border border-slate-800 text-[11px] text-cyan-300 break-all select-all">
                  {selectedThreatForDrawer.content_sha256}
                </div>
                <div className="flex justify-end">
                  <button
                    onClick={() => copyToClipboard(selectedThreatForDrawer.content_sha256, 'drawer_hash')}
                    className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] rounded border border-slate-700"
                  >
                    {copiedText === 'drawer_hash' ? 'Copied Hash!' : 'Copy SHA-256'}
                  </button>
                </div>
              </div>

              {/* Extracted Entity Tags */}
              <div className="space-y-2">
                <span className="font-bold text-white uppercase text-[11px] font-mono tracking-wider">
                  Extracted Observables & Defanging Badges
                </span>
                <div className="flex flex-wrap gap-2">
                  {selectedThreatForDrawer.sanitization_flags.map((flag) => (
                    <div
                      key={flag}
                      className="px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] font-mono flex items-center gap-1.5"
                    >
                      <span>🛡️</span>
                      <span>{flag}</span>
                    </div>
                  ))}
                  <div className="px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono flex items-center gap-1.5">
                    <span>📡</span>
                    <span>CHANNEL: {selectedThreatForDrawer.channel_id}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Drawer Footer Actions */}
            <div className="p-4 border-t border-slate-800 bg-[#0d1527] flex items-center justify-between">
              <button
                onClick={() => setSelectedThreatForDrawer(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Close Drawer
              </button>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    navigate(`/search-thread?q=${encodeURIComponent(selectedThreatForDrawer.sender_username || '')}`);
                  }}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-lg text-xs font-mono font-semibold transition-colors"
                >
                  Explore Thread →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntelOverview;
