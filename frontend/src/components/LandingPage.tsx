import React from 'react';
import { Link } from 'react-router-dom';

interface NavLink {
  to: string;
  label: string;
}

export const LandingPage: React.FC = () => {
  const navLinks: NavLink[] = [
    { to: '/threat-intel', label: 'Threat Intelligence' },
    { to: '/channels', label: 'Channel Management' },
    { to: '/search-thread', label: 'Search & Threads' },
    { to: '/platform-admin', label: 'Platform Admin' },
  ];

  return (
    <div className="min-h-screen bg-[#050811] via-[#070b14] to-[#0a0f1d] overflow-x-hidden">
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-slate-800/50 backdrop-blur-sm">
        <div className="max-w-[1600px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-emerald-500 flex items-center justify-center text-slate-950 font-bold">VTI</div>
            <span className="text-xl font-semibold text-white">Vigilant Threat Intelligence</span>
          </div>
          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link, i) => (
              <Link key={i} to={link.to} className="text-slate-400 hover:text-cyan-400 transition-colors text-sm font-medium">
                {link.label}
              </Link>
            ))}
            <button onClick={() => window.location.href = '/login' } className="px-4 py-2 bg-cyan-600 hover-cyan-400 text-slate-950 font-medium rounded-lg transition-colors text-sm">
              Login
            </button>
          </div>
          <button className="md:hidden p-2 rounded-lg hover:bg-slate-800 transition-colors" aria-label="Open menu">
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>
      </nav>

      <section className="max-w-[1600px] mx-auto px-6 py-24 md:py-32 relative">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <span className="inline-block mb-6 px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-medium uppercase tracking-wider rounded-full">
              NEW PREMIUM RELEASE
            </span>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white leading-tight mb-6">
              Enterprise-Grade<br />
              Threat Intelligence
            </h1>
            <p className="text-slate-400 text-lg mb-8 max-w-xl">
              Telegram Threat Intelligence (TTI) is a modular, multi-tenant cyber threat intelligence platform engineered to ingest, sanitize, analyze, and prioritize threat data from Telegram channels and dark-web sources.
            </p>
            <div className="flex flex-wrap gap-4">
              <button onClick={() => window.location.href = '/threat-intel' } className="px-6 py-3 bg-cyan-600 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg transition-colors text-lg">
                View Platform
              </button>
              <button onClick={() => window.location.href = '/login' } className="px-6 py-3 bg-transparent border-2 border-cyan-400 hover:bg-cyan-500/10 text-cyan-300 font-medium rounded-lg transition-colors text-lg">
                Get Started Free
              </button>
            </div>
          </div>
          <div className="relative">
            <div className="relative">
              <div className="absolute -top-4 -right-4 w-96 h-96 bg-cyan-500/10 rounded-2xl blur-3xl opacity-70 rotate-6"></div>
              <div className="bg-[#0d1527] border border-slate-800/50 rounded-2xl p-8 backdrop-blur-sm">
                <div className="h-64 w-full rounded-xl overflow-hidden bg-gradient-to-br from-[#070b14] to-[#0a0f1d]">
                  <div className="absolute inset-0 bg-[conic-gradient(from(225deg),#06b6d4,#0891b2,#06b6d4]) animate-spin opacity-30"></div>
                </div>
                <div className="relative pt-8">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium uppercase tracking-wider text-slate-500">MONITORING</span>
                    <div className="w-12 h-12 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                      <svg className="w-6 h-6 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M9 16L12 21L15 16M15 8l-3-3m0 0l-3 3m3-3v12" />
                      </svg>
                    </div>
                  </div>
                  <p className="mt-3 text-sm text-slate-500">Real-time threat feed monitoring</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};