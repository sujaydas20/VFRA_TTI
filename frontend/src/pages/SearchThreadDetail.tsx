import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { Card, CardHeader } from '../components/Card';
import { Skeleton } from '../components/Skeleton';
import { ttiApi } from '../services/api';
import type { ThreatMessageItem, SourceChannelItem, ThreatThreadResponse } from '../types';

export const SearchThreadDetail: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || '';

  const [query, setQuery] = useState(initialQuery);
  const [selectedChannel, setSelectedChannel] = useState('');
  const [channels, setChannels] = useState<SourceChannelItem[]>([]);
  const [results, setResults] = useState<ThreatMessageItem[]>([]);
  const [totalResults, setTotalResults] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Active thread view state
  const [activeThread, setActiveThread] = useState<ThreatThreadResponse | null>(null);
  const [threadLoading, setThreadLoading] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Load available channels for filter dropdown
  useEffect(() => {
    let mounted = true;
    ttiApi
      .listChannels(100, 0)
      .then((res) => {
        if (mounted) setChannels(res.channels);
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  // Execute Search
  const executeSearch = async (searchTerm: string, channelFilter?: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await ttiApi.searchThreats(
        searchTerm,
        channelFilter || undefined,
        50,
        0,
      );
      setResults(res.items);
      setTotalResults(res.total_results);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Search query execution failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    executeSearch(query, selectedChannel);
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchParams(query ? { q: query } : {});
    executeSearch(query, selectedChannel);
  };

  const handleInspectThread = async (channelId: string, threadId: string) => {
    setThreadLoading(true);
    try {
      const threadRes = await ttiApi.getThreadDetail(channelId, threadId);
      setActiveThread(threadRes);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to retrieve thread.');
    } finally {
      setThreadLoading(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExportStixBundle = () => {
    if (!activeThread) return;
    const stixBundle = {
      type: 'bundle',
      id: `bundle--${activeThread.thread_id}`,
      spec_version: '2.1',
      objects: activeThread.messages.map((m) => ({
        type: 'observed-data',
        id: `observed-data--${m.message_id}`,
        first_observed: m.broadcast_timestamp_utc,
        number_observed: 1,
        objects: {
          '0': {
            type: 'user-account',
            user_id: m.sender_username,
            account_login: m.sender_username,
          },
          '1': {
            type: 'artifact',
            hashes: {
              'SHA-256': m.content_sha256,
            },
            payload_bin: m.sanitized_text,
          },
        },
      })),
    };
    navigator.clipboard?.writeText(JSON.stringify(stixBundle, null, 2));
    alert('STIX 2.1 Threat Bundle JSON copied to clipboard!');
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Observable Search & Thread Explorer"
        subtitle="Phase 3 tenant-isolated full-text search, defanged observables & thread reconstruction"
        breadcrumbs={[
          { label: 'Home', href: '/threat-intel' },
          { label: 'Search & Threads', href: '/search-thread' },
        ]}
      />

      {/* Tactical Search Input Bar */}
      <Card className="border-cyan-500/20 bg-[#0d1527]">
        <form onSubmit={handleSearchSubmit} className="p-4 space-y-3.5">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1 relative">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search threat messages, IP observables, handles, defanged IOCs (e.g. 'hxxp', 'VPN', 'wallet')..."
                className="w-full px-3.5 py-2.5 pl-9 text-xs bg-[#070b14] border border-slate-700/80 rounded-lg text-white placeholder-slate-500 focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 focus:outline-hidden font-mono"
              />
              <svg
                className="w-4 h-4 text-slate-500 absolute left-3 top-3 pointer-events-none"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>

            <select
              value={selectedChannel}
              onChange={(e) => setSelectedChannel(e.target.value)}
              className="px-3 py-2 text-xs border border-slate-700/80 rounded-lg bg-[#070b14] text-slate-200 focus:ring-1 focus:ring-cyan-400 focus:border-cyan-400 focus:outline-hidden sm:w-56 font-mono"
            >
              <option value="">All Channels</option>
              {channels.map((ch) => (
                <option key={ch.channel_id} value={ch.channel_id}>
                  {ch.channel_title} ({ch.channel_id})
                </option>
              ))}
            </select>

            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 text-xs font-bold font-mono rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.25)] transition-all flex items-center justify-center gap-2"
            >
              {loading ? 'Searching...' : 'Search'}
            </button>
          </div>

          {/* Syntax helper row */}
          <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono flex-wrap">
            <span className="font-semibold text-cyan-400">Syntax Quick Filters:</span>
            <button
              type="button"
              onClick={() => { setQuery('DEFANGED_URL'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-cyan-300 border border-slate-700"
            >
              IOC:URL
            </button>
            <button
              type="button"
              onClick={() => { setQuery('BTC'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-amber-300 border border-slate-700"
            >
              CRYPTO:BTC
            </button>
            <button
              type="button"
              onClick={() => { setQuery('198.51.100.42'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-rose-300 border border-slate-700"
            >
              NET:IP
            </button>
            <button
              type="button"
              onClick={() => { setQuery('red_broker_99'); }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-purple-300 border border-slate-700"
            >
              ACTOR:red_broker
            </button>
            <span className="ml-auto text-slate-500 text-[10px]">Auto-defanged & SEC-THREAT-02 savepoint verified</span>
          </div>
        </form>
      </Card>

      {/* Main Results Card */}
      <Card>
        <CardHeader
          title={`Search Results (${totalResults} observables found)`}
          description="Sanitized threat intelligence messages with cryptographic SHA-256 verification"
        />

        {error && (
          <div className="p-4 bg-rose-500/10 text-rose-300 text-xs border-b border-rose-500/30 font-mono">
            {error}
          </div>
        )}

        {loading ? (
          <div className="p-6 space-y-3">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : results.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs font-mono">
            <p className="font-semibold text-slate-300 text-sm">No threat records matched your query.</p>
            <p className="mt-1">Try searching for generic keywords like "VPN", "wallet", "login", or leaving query blank to view all.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-900/60 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-bold text-[11px] font-mono">
                  <th className="py-3 px-4">Message & Sender</th>
                  <th className="py-3 px-4">Channel</th>
                  <th className="py-3 px-4">Sanitized Content & Observables</th>
                  <th className="py-3 px-4">Integrity Hash</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {results.map((item) => (
                  <tr key={item.message_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 align-top">
                      <div className="font-mono text-cyan-300 font-semibold">{item.message_id}</div>
                      <div className="text-slate-400 text-[11px] font-mono">@{item.sender_username || 'anonymous'}</div>
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {new Date(item.broadcast_timestamp_utc).toLocaleString()}
                      </div>
                    </td>

                    <td className="py-3 px-4 align-top">
                      <span className="font-mono text-cyan-300 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30 text-[11px]">
                        {item.channel_id}
                      </span>
                      {item.message_thread_id && (
                        <div className="text-[10px] text-slate-400 font-mono mt-1">
                          Thread: #{item.message_thread_id}
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4 align-top max-w-md">
                      <p className="text-slate-200 leading-relaxed font-sans">{item.sanitized_text}</p>
                      <div className="flex flex-wrap gap-1 mt-1.5">
                        {item.sanitization_flags.map((flag) => (
                          <span
                            key={flag}
                            className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-500/10 text-amber-300 border border-amber-500/30 rounded font-semibold"
                          >
                            [{flag}]
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3 px-4 align-top font-mono text-[11px] text-slate-400">
                      <button
                        onClick={() => copyToClipboard(item.content_sha256, item.message_id)}
                        title="Click to copy full hash"
                        className="bg-[#070b14] hover:bg-slate-800 px-2 py-1 rounded border border-slate-700/80 text-cyan-300 flex items-center gap-1 transition-colors"
                      >
                        <span>{item.content_sha256.slice(0, 10)}...</span>
                        <span>{copiedHash === item.message_id ? '✓' : '📋'}</span>
                      </button>
                    </td>

                    <td className="py-3 px-4 align-top text-right">
                      <button
                        onClick={() =>
                          handleInspectThread(
                            item.channel_id,
                            item.message_thread_id || item.message_id,
                          )
                        }
                        className="px-3 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-semibold font-mono transition-colors"
                      >
                        Inspect Thread →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Forensic Conversation Tree Visualizer (StealthMole Killer) */}
      {activeThread && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0d1527] rounded-xl shadow-2xl max-w-2xl w-full border border-cyan-500/30 overflow-hidden flex flex-col max-h-[85vh]">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <h3 className="text-sm font-bold text-white font-mono">
                    Conversation Thread: #{activeThread.thread_id}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Channel: {activeThread.channel_title || activeThread.channel_id} • {activeThread.total_messages} messages
                </p>
              </div>
              <button
                onClick={() => setActiveThread(null)}
                className="text-slate-400 hover:text-white text-sm font-bold"
              >
                ✕
              </button>
            </div>

            {/* Conversation Flow with Visual Reply Branches */}
            <div className="p-5 overflow-y-auto space-y-4 flex-1">
              {threadLoading ? (
                <div className="space-y-3">
                  <Skeleton className="h-12 w-full" />
                  <Skeleton className="h-12 w-full" />
                </div>
              ) : (
                activeThread.messages.map((m, idx) => (
                  <div
                    key={m.message_id}
                    className={`p-4 rounded-xl border transition-colors ${
                      m.reply_to_message_id
                        ? 'border-indigo-500/30 bg-[#070b14]/90 ml-6 relative before:content-[""] before:absolute before:-left-4 before:top-5 before:w-4 before:h-0.5 before:bg-indigo-500/50'
                        : 'border-slate-700/80 bg-[#070b14]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-md bg-cyan-500/20 text-cyan-300 font-mono font-bold flex items-center justify-center text-[10px] border border-cyan-500/40">
                          {idx + 1}
                        </div>
                        <span className="font-bold text-white font-mono">
                          @{m.sender_username || 'anonymous'}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-400 font-mono">
                        {new Date(m.broadcast_timestamp_utc).toLocaleTimeString()}
                      </span>
                    </div>

                    {m.reply_to_message_id && (
                      <p className="text-[11px] text-cyan-400 font-mono mt-1 flex items-center gap-1">
                        <span>↳ In reply to message #{m.reply_to_message_id}</span>
                      </p>
                    )}

                    <p className="text-xs text-slate-200 leading-relaxed mt-2 font-sans">{m.sanitized_text}</p>

                    <div className="flex items-center justify-between pt-2 mt-1 border-t border-slate-800/60">
                      <div className="flex gap-1">
                        {m.sanitization_flags.map((f) => (
                          <span key={f} className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-500/10 text-amber-300 border border-amber-500/30 rounded">
                            [{f}]
                          </span>
                        ))}
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">
                        SHA: {m.content_sha256.slice(0, 8)}...
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="p-3.5 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
              <button
                onClick={handleExportStixBundle}
                className="px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-mono font-semibold transition-colors flex items-center gap-1.5"
              >
                <span>Export STIX 2.1 Bundle</span>
              </button>
              <button
                onClick={() => setActiveThread(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-mono font-semibold transition-colors"
              >
                Close Thread
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchThreadDetail;
