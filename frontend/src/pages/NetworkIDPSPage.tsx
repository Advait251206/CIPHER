import React, { useState, useEffect } from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { Network, Activity } from 'lucide-react';

export const NetworkIDPSPage: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Active Bidirectional Flows"
          value={0}
          icon={<Network size={20} />}
          highlight={true}
        />
        <MetricCard
          title="Dual RF ML Anomalies"
          value={0}
          icon={<Activity size={20} />}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Real-Time Network Flows</h3>
        <DataGrid
          columns={[
            { header: 'Src IP', accessor: 'src_ip' },
            { header: 'Src Port', accessor: 'src_port' },
            { header: 'Dst IP', accessor: 'dst_ip' },
            { header: 'Dst Port', accessor: 'dst_port' },
            { header: 'Protocol', accessor: 'protocol' },
            { header: 'ML Prediction', accessor: 'prediction' },
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No active flows detected."
        />
      </div>
    </div>
  );
};
