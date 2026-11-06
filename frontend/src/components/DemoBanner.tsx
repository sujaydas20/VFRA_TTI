export const DemoBanner = () => {
  return (
    <div className="bg-amber-500/10 border border-amber-500/30 text-amber-300 px-3.5 py-2 text-xs font-medium rounded-lg flex items-center justify-between gap-2 shadow-xs">
      <div className="flex items-center gap-2">
        <span className="text-amber-400">⚠️</span>
        <span>This is a demo interface — mock data only. No real threat indicators or credentials are embedded.</span>
      </div>
      <span className="hidden sm:inline-block font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-200">
        Demo Mode Active
      </span>
    </div>
  );
};
