import React from 'react';

interface TableColumn {
  key: string;
  label: string;
  align?: 'left' | 'center' | 'right';
}

interface TableRow {
  cells: Record<string, unknown>;
}

export const Table: React.FC<{
  columns: TableColumn[];
  rows: TableRow[];
  loading?: boolean;
  empty?: React.ReactNode;
  title?: string;
}> = ({ columns, rows, loading, empty, title }) => {
  if (loading) {
    return (
      <div className="p-4 text-text-secondary">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="skeleton-text h-[1.2em] rounded-sm my-1 animate-pulse" />
        ))}
      </div>
    );
  }

  if (rows.length === 0) {
    return empty || (
      <div className="p-8 text-center text-text-muted">
        <p>No data available</p>
      </div>
    );
  }

  return (
    <div>
      {title && <h3 className="text-sm font-medium text-text-primary mb-3">{title}</h3>}

      <div className="overflow-x-auto">
        <table className="w-full rounded-sm border-border-primary">
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key} className="p-2 text-xs font-medium text-text-secondary align-{col.align}">
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIdx) => (
              <tr key={rowIdx} className="transition-colors hover:bg-bg-hover">
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className="p-2 text-xs align-{col.align} text-text-primary"
                  >
                    {String(row.cells[col.key] || '-')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};