import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { ShieldAlert, Lock } from 'lucide-react';

export const PreventionPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Active Blocks"
          value={0}
          icon={<ShieldAlert size={20} />}
          highlight={true}
        />
        <MetricCard
          title="IPS Mode"
          value="Detect Only"
          icon={<Lock size={20} />}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Active Blocklist & Firewall Rules</h3>
        <DataGrid
          columns={[
            { header: 'IP/Domain', accessor: 'target' },
            { header: 'Reason', accessor: 'reason' },
            { header: 'Timestamp', accessor: 'timestamp' },
            { header: 'Duration', accessor: 'duration' },
            { header: 'Status', accessor: 'status' }
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No active blocks."
        />
      </div>
    </div>
  );
};
