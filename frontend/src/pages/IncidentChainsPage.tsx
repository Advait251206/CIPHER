import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { IncidentItem } from '../api/types';
import { DataGrid } from '../components/common/DataGrid';

interface IncidentChainsPageProps {
  initialIncidentId?: string | null;
  refreshTrigger?: number;
}

export const IncidentChainsPage: React.FC<IncidentChainsPageProps> = ({ refreshTrigger }) => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);

  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        const res = await api.incidents.list({ limit: 50 });
        setIncidents(res.incidents);
      } catch (err) {}
    };
    fetchIncidents();
  }, [refreshTrigger]);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)' }}>Correlated Incident Chains</h3>
      <DataGrid
        columns={[
          { header: 'Incident ID', accessor: 'id' },
          { header: 'Status', accessor: 'status' },
          { header: 'Risk Score', accessor: 'severity', render: (val) => (
            <span style={{ color: val === 'CRITICAL' ? 'var(--crit-color)' : val === 'HIGH' ? 'var(--high-color)' : 'var(--text-primary)' }}>
              {val === 'CRITICAL' ? '90-100' : val === 'HIGH' ? '70-89' : '0-69'}
            </span>
          )},
          { header: 'Events in Chain', accessor: 'event_ids', render: (val) => val.length },
          { header: 'Action', accessor: 'id', render: () => (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button style={{ background: 'var(--border-accent)', color: 'var(--bg-app)', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '0.7rem' }}>View Details</button>
              <button style={{ background: 'transparent', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '0.7rem' }}>Resolve</button>
            </div>
          )}
        ]}
        data={incidents}
        keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
        emptyMessage="No incidents found."
      />
    </div>
  );
};
