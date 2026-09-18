import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { Globe, AlertTriangle } from 'lucide-react';

export const PhishingPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="URLs Analyzed"
          value={0}
          icon={<Globe size={20} />}
        />
        <MetricCard
          title="Phishing Detected"
          value={0}
          icon={<AlertTriangle size={20} />}
          highlight={true}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Phishing Threat Detector</h3>
        <DataGrid
          columns={[
            { header: 'URL', accessor: 'url' },
            { header: 'ML Confidence', accessor: 'confidence' },
            { header: 'Features Extracted', accessor: 'features' },
            { header: 'Verdict', accessor: 'verdict' },
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No phishing events analyzed yet."
        />
      </div>
    </div>
  );
};
