import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { CorrelationStatsResponse, SecurityEventItem } from '../api/types';
import { MetricCard } from '../components/common/MetricCard';
import { DataGrid } from '../components/common/DataGrid';
import { Activity, ShieldAlert, Flame, Zap } from 'lucide-react';

interface OverviewPageProps {
  onNavigate: (tab: any) => void;
  onSelectIncident?: (incidentId: string) => void;
  refreshTrigger?: number;
  onOpenExtensionModal?: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ refreshTrigger }) => {
  const [corrStats, setCorrStats] = useState<CorrelationStatsResponse | null>(null);
  const [recentEvents, setRecentEvents] = useState<SecurityEventItem[]>([]);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const statsRes = await api.incidents.getStats();
        setCorrStats(statsRes);
        const eventsRes = await api.events.list({ limit: 5 });
        setRecentEvents(eventsRes.events);
      } catch (err) {}
    };
    fetchStats();
  }, [refreshTrigger]);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <MetricCard
          title="Total Incidents"
          value={corrStats?.total_incidents || 0}
          icon={<Activity size={20} />}
        />
        <MetricCard
          title="Open Incident Chains"
          value={corrStats?.open_incidents || 0}
          icon={<Flame size={20} />}
          highlight={true}
        />
        <MetricCard
          title="Threats Blocked"
          value={0}
          icon={<ShieldAlert size={20} />}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Recent Security Events</h3>
          <DataGrid
            columns={[
              { header: 'Time', accessor: 'timestamp', render: (val) => new Date(val).toLocaleTimeString() },
              { header: 'Type', accessor: 'event_type' },
              { header: 'Severity', accessor: 'severity', render: (val) => (
                <span style={{ color: val === 'CRITICAL' ? 'var(--crit-color)' : val === 'HIGH' ? 'var(--high-color)' : 'var(--text-primary)' }}>
                  {val}
                </span>
              )},
              { header: 'Source IP', accessor: 'source_ip' }
            ]}
            data={recentEvents}
            keyExtractor={(row) => row.event_id || Math.random().toString()}
            emptyMessage="No recent events."
          />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Quick Actions</h3>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <button style={{ background: 'var(--bg-sidebar)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', padding: '0.75rem', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
              <Zap size={16} color="var(--border-accent)" /> Run Manual Scan
            </button>
            <button style={{ background: 'var(--bg-sidebar)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)', padding: '0.75rem', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={16} /> Enable Lockdown Mode
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
