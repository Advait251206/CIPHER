import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { Radio, Cpu } from 'lucide-react';

export const SensorPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Sensor Status"
          value="Online"
          icon={<Radio size={20} />}
          highlight={true}
        />
        <MetricCard
          title="Packet Capture Rate"
          value="0 pps"
          icon={<Cpu size={20} />}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Live Sensor Telemetry</h3>
        <DataGrid
          columns={[
            { header: 'Metric', accessor: 'metric' },
            { header: 'Value', accessor: 'value' },
            { header: 'Status', accessor: 'status' }
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="Sensor data unavailable."
        />
      </div>
    </div>
  );
};
