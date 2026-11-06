import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopNav } from './TopNav';
import { DemoBanner } from './DemoBanner';

export const AppShell: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="flex h-screen bg-[#070b14] overflow-hidden font-sans text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Desktop Persistent Sidebar */}
      <div className="hidden md:flex md:flex-shrink-0">
        <Sidebar />
      </div>

      {/* Mobile Drawer Backdrop & Sidebar */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="relative flex-1 flex flex-col max-w-xs w-full bg-[#0a0f1d] border-r border-slate-800">
            <Sidebar onCloseMobile={() => setMobileMenuOpen(false)} />
          </div>
        </div>
      )}

      {/* Main Operations Column */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-radial from-slate-900/30 via-[#070b14] to-[#050811]">
        <TopNav onToggleMobileMenu={() => setMobileMenuOpen(!mobileMenuOpen)} />

        {/* Global Operational Transparency Banner */}
        <div className="px-4 sm:px-6 pt-3">
          <DemoBanner />
        </div>

        {/* Page Content Viewport */}
        <main className="flex-1 overflow-y-auto px-4 sm:px-6 pb-8 pt-3">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default AppShell;
