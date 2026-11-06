import React from 'react';

interface CardHeaderProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const CardHeader: React.FC<CardHeaderProps> = ({ title, description, action }) => {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
      <div>
        <span className="text-sm font-semibold text-white tracking-tight">{title}</span>
        {description && (
          <p className="text-xs text-slate-400 mt-0.5">{description}</p>
        )}
      </div>
      {action && <div>{action}</div>}
    </div>
  );
};

interface CardProps {
  header?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ header, children, footer, className }) => {
  return (
    <div className={`bg-[#0d1527] border border-slate-800/80 rounded-xl shadow-lg shadow-black/30 overflow-hidden text-slate-100 transition-all duration-200 hover:border-slate-700/80 ${className || ''}`}>
      {header && <div className="p-4 border-b border-slate-800/80 bg-slate-900/40">{header}</div>}
      <div className="p-4 sm:p-5">{children}</div>
      {footer && <div className="p-4 border-t border-slate-800/80 bg-slate-900/30">{footer}</div>}
    </div>
  );
};
