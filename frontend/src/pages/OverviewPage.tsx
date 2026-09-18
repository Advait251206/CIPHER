import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { CorrelationStatsResponse, SecurityEventItem } from '../api/types';
import { MetricCard } from '../components/common/MetricCard';
import { DataGrid } from '../components/common/DataGrid';
import { Activity, Flame, ShieldAlert } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';

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

  const severityData = corrStats?.incidents_by_severity 
    ? Object.entries(corrStats.incidents_by_severity).map(([name, value]) => ({ name, value }))
    : [];

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'var(--crit-color)';
      case 'HIGH': return 'var(--high-color)';
      case 'MEDIUM': return 'var(--med-color)';
      case 'LOW': return 'var(--low-color)';
      default: return 'var(--border-accent)';
    }
  };

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
          title="Avg Correlation Score"
          value={corrStats?.average_correlation_score ? corrStats.average_correlation_score.toFixed(1) : 0}
          icon={<ShieldAlert size={20} />}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.5fr', gap: '1.5rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Recent Security Events</h3>
          <DataGrid
            columns={[
              { header: 'Time', accessor: 'timestamp', render: (val) => new Date(val).toLocaleTimeString() },
              { header: 'Type', accessor: 'event_type' },
              { header: 'Severity', accessor: 'severity', render: (val) => (
                <span style={{ color: getSeverityColor(val), fontWeight: 600 }}>
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
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Incidents by Severity</h3>
          <div style={{ 
            background: 'var(--bg-surface)', 
            border: '1px solid var(--border-subtle)', 
            borderRadius: '6px', 
            padding: '1.5rem', 
            flex: 1,
            minHeight: '250px'
          }}>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis 
                    dataKey="name" 
                    tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} 
                    axisLine={{ stroke: 'var(--border-subtle)' }}
                    tickLine={false}
                  />
                  <YAxis 
                    tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'var(--bg-sidebar)', 
                      borderColor: 'var(--border-subtle)',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem',
                      borderRadius: '4px'
                    }} 
                    itemStyle={{ color: 'var(--text-primary)' }}
                    cursor={{ fill: 'var(--bg-card-hover)' }}
                  />
                  <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getSeverityColor(entry.name)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No incident data available.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
