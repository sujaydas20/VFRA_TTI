import React, { useEffect, useState } from 'react';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { SourceChannelItem, ChannelRegisterRequest } from '../types';

export const ChannelManagement: React.FC = () => {
  const [channels, setChannels] = useState<SourceChannelItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterAuth, setFilterAuth] = useState<'all' | 'authorized' | 'unauthorized'>('all');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // New channel modal state
  const [showModal, setShowModal] = useState(false);
  const [newChannelId, setNewChannelId] = useState('');
  const [newChannelTitle, setNewChannelTitle] = useState('');
  const [newChannelHandle, setNewChannelHandle] = useState('');
  const [newSourceType, setNewSourceType] = useState<'telegram' | 'darkweb'>('telegram');
  const [modalError, setModalError] = useState<string | null>(null);
  const [modalSubmitting, setModalSubmitting] = useState(false);

  const fetchChannels = async () => {
    setLoading(true);
    setError(null);
    try {
      const isAuthParam = filterAuth === 'authorized' ? true : filterAuth === 'unauthorized' ? false : undefined;
      const res = await ttiApi.listChannels(50, 0, isAuthParam);
      setChannels(res.channels);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve registered channels.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchChannels();
  }, [filterAuth]);

  const handleToggleAuth = async (channel: SourceChannelItem) => {
    setActionLoading(channel.channel_id);
    try {
      const updated = await ttiApi.updateChannel(channel.channel_id, {
        is_authorized: !channel.is_authorized,
      });
      setChannels((prev) =>
        prev.map((c) => (c.channel_id === channel.channel_id ? updated : c)),
      );
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update channel authorization.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalSubmitting(true);
    setModalError(null);

    const payload: ChannelRegisterRequest = {
      channel_id: newChannelId.trim(),
      channel_title: newChannelTitle.trim(),
      channel_handle: newChannelHandle.trim() || undefined,
      source_type: newSourceType,
      is_authorized: false, // Security invariant: default to unauthorized
    };

    try {
      const created = await ttiApi.registerChannel(payload);
      setChannels((prev) => [created, ...prev]);
      setShowModal(false);
      setNewChannelId('');
      setNewChannelTitle('');
      setNewChannelHandle('');
    } catch (err: unknown) {
      setModalError(err instanceof Error ? err.message : 'Failed to register channel.');
    } finally {
      setModalSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <PageHeader
          title="Source Channel Administration"
          subtitle="Tenant-scoped source authorization & collection registry (SEC-THREAT-05)"
          breadcrumbs={[
            { label: 'Home', href: '/threat-intel' },
            { label: 'Channels', href: '/channels' },
          ]}
        />
        <button
          onClick={() => setShowModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 text-xs font-bold font-mono rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.25)] transition-all self-start sm:self-auto"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Register Source Channel
        </button>
      </div>

      {/* Security Invariant Alert - Cyber SOC Standard */}
      <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-500/30 flex items-start gap-3.5 text-xs text-indigo-200 shadow-sm">
        <div className="w-6 h-6 rounded-lg bg-indigo-500/20 border border-indigo-500/40 text-indigo-300 flex items-center justify-center font-bold flex-shrink-0 mt-0.5">
          🔒
        </div>
        <div>
          <span className="font-bold text-white font-mono">SEC-THREAT-01 & SEC-THREAT-05 Invariants: </span>
          New channels default to <code className="font-mono text-cyan-300 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-700">is_authorized = false</code>.
          Unchecked client input cannot authorize collection. Only authorized channels accept incoming ingestion batches, protected by PostgreSQL Row-Level Security.
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex border-b border-slate-800 gap-6 text-xs font-mono font-medium">
        <button
          onClick={() => setFilterAuth('all')}
          className={`pb-2.5 transition-colors border-b-2 -mb-px ${
            filterAuth === 'all'
              ? 'border-cyan-400 text-cyan-300 font-bold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          All Channels ({channels.length})
        </button>
        <button
          onClick={() => setFilterAuth('authorized')}
          className={`pb-2.5 transition-colors border-b-2 -mb-px ${
            filterAuth === 'authorized'
              ? 'border-cyan-400 text-cyan-300 font-bold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Authorized Only
        </button>
        <button
          onClick={() => setFilterAuth('unauthorized')}
          className={`pb-2.5 transition-colors border-b-2 -mb-px ${
            filterAuth === 'unauthorized'
              ? 'border-cyan-400 text-cyan-300 font-bold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Unauthorized / Pending
        </button>
      </div>

      {/* Main Table Card */}
      <Card>
        <CardHeader
          title="Monitored Intelligence Feeds"
          description="Tenant-isolated threat sources eligible for batch ingestion and observable analysis"
        />

        {error && (
          <div className="p-4 bg-rose-500/10 border-b border-rose-500/30 text-rose-300 text-xs font-mono">
            {error}
          </div>
        )}

        {loading ? (
          <div className="p-6 space-y-3">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : channels.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs font-mono">
            <p className="font-medium text-slate-300">No channels found in current scope.</p>
            <p className="mt-1">Click "Register Source Channel" to register an intelligence feed.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-900/60 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-bold text-[11px] font-mono">
                  <th className="py-3 px-4">Channel Name & Handle</th>
                  <th className="py-3 px-4">Platform</th>
                  <th className="py-3 px-4">Channel Identifier</th>
                  <th className="py-3 px-4">Collection Status</th>
                  <th className="py-3 px-4">Last Updated</th>
                  <th className="py-3 px-4 text-right">Administrative Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {channels.map((ch) => (
                  <tr key={ch.channel_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{ch.channel_title}</div>
                      {ch.channel_handle && (
                        <div className="text-cyan-400 font-mono text-[11px]">{ch.channel_handle}</div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium ${
                          ch.source_type === 'telegram'
                            ? 'bg-sky-500/10 text-sky-300 border border-sky-500/30'
                            : 'bg-purple-500/10 text-purple-300 border border-purple-500/30'
                        }`}
                      >
                        {ch.source_type === 'telegram' ? '✈️ Telegram' : '🧅 Dark Web'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 text-[11px]">
                      {ch.channel_id}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold font-mono border ${
                          ch.is_authorized
                            ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                            : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            ch.is_authorized ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]' : 'bg-amber-400'
                          }`}
                        />
                        {ch.is_authorized ? 'Authorized' : 'Unauthorized'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(ch.updated_at_utc).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleToggleAuth(ch)}
                        disabled={actionLoading === ch.channel_id}
                        className={`px-3 py-1 rounded-lg text-xs font-semibold font-mono transition-colors border ${
                          ch.is_authorized
                            ? 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border-rose-500/30'
                            : 'bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border-cyan-500/40'
                        }`}
                      >
                        {actionLoading === ch.channel_id
                          ? 'Updating...'
                          : ch.is_authorized
                          ? 'Revoke Authorization'
                          : 'Authorize Collection'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Register Channel Modal - Sleek Obsidian Form */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0d1527] rounded-xl shadow-2xl max-w-md w-full border border-slate-700 overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">Register Intelligence Source Channel</h3>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            {modalError && (
              <div className="p-3 bg-rose-500/10 text-rose-300 text-xs border-b border-rose-500/30 font-mono">
                {modalError}
              </div>
            )}

            <form onSubmit={handleRegister} className="p-5 space-y-4 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1 font-mono">
                  Channel Identifier <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={newChannelId}
                  onChange={(e) => setNewChannelId(e.target.value)}
                  placeholder="e.g. tg_market_intel_01"
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-700 rounded-lg font-mono text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 focus:outline-hidden"
                />
                <p className="mt-1 text-[11px] text-slate-500 font-mono">
                  Alphanumeric channel key (letters, digits, underscores, dashes).
                </p>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1 font-mono">
                  Channel Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={newChannelTitle}
                  onChange={(e) => setNewChannelTitle(e.target.value)}
                  placeholder="e.g. VIP Market Infiltration Feed"
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1 font-mono">
                  Channel Handle (Optional)
                </label>
                <input
                  type="text"
                  value={newChannelHandle}
                  onChange={(e) => setNewChannelHandle(e.target.value)}
                  placeholder="e.g. @dark_market_bot"
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 focus:outline-hidden font-mono"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1 font-mono">
                  Source Platform Type
                </label>
                <select
                  value={newSourceType}
                  onChange={(e) => setNewSourceType(e.target.value as 'telegram' | 'darkweb')}
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-700 rounded-lg text-xs text-white focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 focus:outline-hidden font-mono"
                >
                  <option value="telegram">Telegram Channel / Supergroup</option>
                  <option value="darkweb">Dark-Web Forum / Mirror</option>
                </select>
              </div>

              <div className="pt-3 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-3.5 py-1.5 border border-slate-700 text-slate-300 rounded-lg hover:bg-slate-800 transition-colors font-mono"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalSubmitting}
                  className="px-4 py-1.5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 rounded-lg font-bold font-mono transition-colors disabled:opacity-50"
                >
                  {modalSubmitting ? 'Registering...' : 'Register Channel'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ChannelManagement;
