import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { Database, UploadCloud } from 'lucide-react';

export const ThreatIntelPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Known IOCs Loaded"
          value={0}
          icon={<Database size={20} />}
        />
        <MetricCard
          title="Feeds Synced"
          value="0 / 0"
          icon={<UploadCloud size={20} />}
          highlight={true}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Threat Intel Integration</h3>
        <DataGrid
          columns={[
            { header: 'IOC', accessor: 'ioc' },
            { header: 'Type', accessor: 'type' },
            { header: 'Source Feed', accessor: 'source' },
            { header: 'Confidence', accessor: 'confidence' },
            { header: 'Last Seen', accessor: 'last_seen' },
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No threat intelligence data loaded."
        />
      </div>
    </div>
  );
};
