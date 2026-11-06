export const PageHeader = ({ title, subtitle, breadcrumbs }: { title: string; subtitle?: string; breadcrumbs?: { label: string; href: string }[] }) => {
  return (
    <div className="page-header pb-4 border-b border-slate-800/80 mb-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <span className="w-1.5 h-5 bg-cyan-400 rounded-full inline-block shadow-[0_0_8px_rgba(34,211,238,0.8)]" />
            {title}
          </h2>
          {subtitle && (
            <p className="text-xs sm:text-sm mt-1 text-slate-400 font-sans">{subtitle}</p>
          )}
        </div>

        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav aria-label="breadcrumb" className="flex space-x-2">
            <ol className="flex items-center rounded-lg bg-slate-900/80 border border-slate-800 px-3 py-1.5 text-xs">
              {breadcrumbs.map((crumb, i) => (
                <li key={i} className="flex items-center">
                  <a
                    href={crumb.href}
                    className="
                      text-slate-400 hover:text-cyan-300 transition-colors font-medium
                      focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400
                    "
                  >
                    {crumb.label}
                  </a>
                  {i < breadcrumbs.length - 1 && <span className="mx-2 text-slate-600">/</span>}
                </li>
              ))}
            </ol>
          </nav>
        )}
      </div>
    </div>
  );
};
