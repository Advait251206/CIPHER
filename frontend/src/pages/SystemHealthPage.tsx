import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { HeartPulse, Database } from 'lucide-react';

export const SystemHealthPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="System Status"
          value="Healthy"
          icon={<HeartPulse size={20} />}
          highlight={true}
        />
        <MetricCard
          title="Database Status"
          value="Connected"
          icon={<Database size={20} />}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Component Health</h3>
        <DataGrid
          columns={[
            { header: 'Component', accessor: 'component' },
            { header: 'Status', accessor: 'status' },
            { header: 'Uptime', accessor: 'uptime' },
            { header: 'Last Check', accessor: 'last_check' }
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No health data available."
        />
      </div>
    </div>
  );
};
