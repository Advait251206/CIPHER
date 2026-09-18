import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { SecurityEventItem } from '../api/types';
import { DataGrid } from '../components/common/DataGrid';

interface SecurityEventsPageProps {
  onSelectIncident?: (incidentId: string) => void;
  refreshTrigger?: number;
}

export const SecurityEventsPage: React.FC<SecurityEventsPageProps> = ({ refreshTrigger }) => {
  const [events, setEvents] = useState<SecurityEventItem[]>([]);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const res = await api.events.list({ limit: 50 });
        setEvents(res.events);
      } catch (err) {}
    };
    fetchEvents();
  }, [refreshTrigger]);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)' }}>Raw Security Events Log</h3>
      <DataGrid
        columns={[
          { header: 'Timestamp', accessor: 'timestamp', render: (val) => new Date(val).toLocaleString() },
          { header: 'Event Type', accessor: 'event_type' },
          { header: 'Severity', accessor: 'severity', render: (val) => (
            <span style={{ color: val === 'CRITICAL' ? 'var(--crit-color)' : val === 'HIGH' ? 'var(--high-color)' : 'var(--text-primary)' }}>
              {val}
            </span>
          )},
          { header: 'Source IP', accessor: 'source_ip' },
          { header: 'Summary', accessor: 'summary' }
        ]}
        data={events}
        keyExtractor={(row) => row.incident_id || row.event_id || row.id || Math.random().toString()}
        emptyMessage="No events found."
      />
    </div>
  );
};
