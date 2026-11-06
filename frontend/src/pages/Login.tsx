import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ttiApi, API_MODE } from '../services/api';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleFillDemo = () => {
    setEmail('analyst@example.com');
    setPassword('demo-pass');
    setError(null);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await ttiApi.login({ email, password });
      navigate('/threat-intel');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Authentication failed. Please verify credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] flex flex-col justify-center items-center p-4 sm:p-6 font-sans relative overflow-hidden select-none">
      {/* Background Cyber Grid Accent */}
      <div className="absolute inset-0 bg-radial from-cyan-950/20 via-[#070b14] to-[#050811] pointer-events-none" />

      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-indigo-600 text-white font-extrabold text-2xl shadow-[0_0_25px_rgba(6,182,212,0.35)] border border-cyan-400/40 mb-3.5">
            TTI
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">Telegram Threat Intelligence</h1>
          <p className="text-xs text-cyan-400/90 font-mono mt-1">Enterprise Cyber Threat Intelligence Platform</p>
        </div>

        {/* Login Card */}
        <div className="bg-[#0d1527] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl shadow-black/80 backdrop-blur-md">
          <div className="flex items-center justify-between pb-4 mb-5 border-b border-slate-800">
            <h2 className="text-base font-bold text-white tracking-tight">Investigator Sign In</h2>
            <span
              className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                API_MODE === 'live'
                  ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                  : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
              }`}
            >
              {API_MODE === 'live' ? 'LIVE MODE' : 'MOCK DEMO'}
            </span>
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2 font-mono">
              <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                Investigator Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@example.com"
                className="w-full px-3.5 py-2.5 text-xs bg-[#070b14] border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                Password
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3.5 py-2.5 text-xs bg-[#070b14] border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.25)] transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed font-mono"
            >
              {loading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-slate-950" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Authenticating...
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Demo Helper */}
          <div className="mt-5 pt-4 border-t border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-400 font-mono">Mock credentials available:</span>
            <button
              type="button"
              onClick={handleFillDemo}
              className="text-cyan-400 hover:text-cyan-300 font-semibold font-mono transition-colors"
            >
              Auto-fill Demo
            </button>
          </div>
        </div>

        {/* Security & Provenance Footer */}
        <div className="mt-6 text-center text-slate-500 text-xs space-y-1 font-mono">
          <p>Protected by PostgreSQL Multi-Tenant RLS & Argon2id</p>
          <p className="text-[11px] text-cyan-500/60">TTI Build v0.1.0 • Phase 4 Channel Security Active</p>
        </div>
      </div>
    </div>
  );
};

export default Login;
