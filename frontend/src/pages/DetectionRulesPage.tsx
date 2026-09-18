import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { Sliders, Zap } from 'lucide-react';

export const DetectionRulesPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Active Rules"
          value={0}
          icon={<Sliders size={20} />}
          highlight={true}
        />
        <MetricCard
          title="Custom Rules Configured"
          value={0}
          icon={<Zap size={20} />}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Detection Rule Configuration</h3>
        <DataGrid
          columns={[
            { header: 'Rule ID', accessor: 'id' },
            { header: 'Name', accessor: 'name' },
            { header: 'Category', accessor: 'category' },
            { header: 'Severity', accessor: 'severity' },
            { header: 'Status', accessor: 'status', render: (val) => (
              <span style={{ color: val === 'Active' ? 'var(--benign-color)' : 'var(--text-muted)' }}>{val}</span>
            )}
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No rules configured."
        />
      </div>
    </div>
  );
};
