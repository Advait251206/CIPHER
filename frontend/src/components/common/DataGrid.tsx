import React from 'react';

interface Column {
  header: string;
  accessor: string;
  render?: (value: any, row: any) => React.ReactNode;
}

interface DataGridProps {
  columns: Column[];
  data: any[];
  keyExtractor: (row: any) => string | number;
  emptyMessage?: string;
}

export const DataGrid: React.FC<DataGridProps> = ({ columns, data, keyExtractor, emptyMessage = "No data available." }) => {
  return (
    <div style={{
      width: '100%',
      overflowX: 'auto',
      border: '1px solid var(--border-subtle)',
      borderRadius: '4px',
      background: 'var(--bg-surface)'
    }}>
      <table style={{
        width: '100%',
        borderCollapse: 'collapse',
        textAlign: 'left',
        fontSize: '0.85rem'
      }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-sidebar)' }}>
            {columns.map((col, idx) => (
              <th key={idx} style={{
                padding: '0.75rem 1rem',
                color: 'var(--text-secondary)',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                fontSize: '0.7rem'
              }}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((row, rIdx) => (
              <tr key={keyExtractor(row)} style={{
                borderBottom: rIdx === data.length - 1 ? 'none' : '1px solid var(--border-subtle)',
                transition: 'background 0.2s ease'
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-card-hover)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
              >
                {columns.map((col, cIdx) => (
                  <td key={cIdx} style={{ padding: '0.75rem 1rem', color: 'var(--text-primary)' }}>
                    {col.render ? col.render(row[col.accessor], row) : row[col.accessor]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};
