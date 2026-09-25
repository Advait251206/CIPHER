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
    <div className="w-full overflow-x-auto rounded-[6px] border border-line bg-surface">
      <table className="w-full border-collapse text-left text-[0.85rem]">
        <thead>
          <tr className="border-b-2 border-b-line bg-app">
            {columns.map((col, idx) => (
              <th key={idx} className="px-5 py-[0.85rem] text-[0.75rem] font-bold tracking-[0.08em] whitespace-nowrap text-fg-2 uppercase">
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-8 py-12 text-center text-fg-muted">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((row) => (
              <tr
                key={keyExtractor(row)}
                className="border-b border-l-[3px] border-b-line border-l-transparent [transition:background_0.2s_ease,border-left_0.2s_ease] last:border-b-0 hover:border-l-accent hover:bg-card-hover"
              >
                {columns.map((col, cIdx) => (
                  <td key={cIdx} className="px-5 py-[0.85rem] align-middle text-fg">
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
