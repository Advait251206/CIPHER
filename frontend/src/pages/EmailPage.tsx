import React from 'react';
import { DataGrid } from '../components/common/DataGrid';
import { MetricCard } from '../components/common/MetricCard';
import { Mail, Shield } from 'lucide-react';

export const EmailPage: React.FC = () => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Emails Scanned"
          value={0}
          icon={<Mail size={20} />}
        />
        <MetricCard
          title="Malicious Emails Blocked"
          value={0}
          icon={<Shield size={20} />}
          highlight={true}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Email Analyzer</h3>
        <DataGrid
          columns={[
            { header: 'Sender', accessor: 'sender' },
            { header: 'Subject', accessor: 'subject' },
            { header: 'SPF/DKIM', accessor: 'auth' },
            { header: 'Attachment Scan', accessor: 'attachments' },
            { header: 'Verdict', accessor: 'verdict' },
          ]}
          data={[]}
          keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
          emptyMessage="No emails analyzed yet."
        />
      </div>
    </div>
  );
};
