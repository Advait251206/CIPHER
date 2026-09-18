import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { CorrelationStatsResponse, SecurityEventItem, SystemStatsResponse, NetworkStatsResponse } from '../api/types';
import { MetricCard } from '../components/common/MetricCard';
import { DataGrid } from '../components/common/DataGrid';
import { Activity, Flame, ShieldAlert, Crosshair, Network, Fingerprint, Shield, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell, PieChart, Pie } from 'recharts';

interface OverviewPageProps {
  onNavigate: (tab: any) => void;
  onSelectIncident?: (incidentId: string) => void;
  refreshTrigger?: number;
  onOpenExtensionModal?: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ refreshTrigger }) => {
  const [corrStats, setCorrStats] = useState<CorrelationStatsResponse | null>(null);
  const [sysStats, setSysStats] = useState<SystemStatsResponse | null>(null);
  const [netStats, setNetStats] = useState<NetworkStatsResponse | null>(null);
  const [iocCount, setIocCount] = useState<number>(0);
  const [recentEvents, setRecentEvents] = useState<SecurityEventItem[]>([]);

  useEffect(() => {
    const fetchAllData = async () => {
      try {
        const [corrRes, sysRes, netRes, iocRes, eventsRes] = await Promise.all([
          api.incidents.getStats().catch(() => null),
          api.events.getStats().catch(() => null),
          api.network.getStats().catch(() => null),
          api.threatIntel.list({ enabled_only: true, limit: 1 }).catch(() => null),
          api.events.list({ limit: 10 }).catch(() => null)
        ]);

        if (corrRes) setCorrStats(corrRes);
        if (sysRes) setSysStats(sysRes);
        if (netRes) setNetStats(netRes);
        if (iocRes) setIocCount(iocRes.total_matching || 0);
        if (eventsRes) setRecentEvents(eventsRes.events);
      } catch (err) {
        console.error("Dashboard fetch error:", err);
      }
    };
    fetchAllData();
  }, [refreshTrigger]);

  const severityData = corrStats?.incidents_by_severity 
    ? Object.entries(corrStats.incidents_by_severity).map(([name, value]) => ({ name, value }))
    : [];

  const networkCategoryData = netStats?.attacks_by_category
    ? Object.entries(netStats.attacks_by_category)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 5) // Top 5
    : [];

  const topAttackers = corrStats?.top_attacking_sources || [];

  const getSeverityColor = (severity?: string | null) => {
    if (!severity) return 'var(--border-accent)';
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'var(--crit-color)';
      case 'HIGH': return 'var(--high-color)';
      case 'MEDIUM': return 'var(--med-color)';
      case 'LOW': return 'var(--low-color)';
      default: return 'var(--border-accent)';
    }
  };

  const COLORS = ['#FF4444', '#FF8800', '#D4AF37', '#00AAFF', '#AA00FF'];

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* METRICS GRID - 2 Rows */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
        <MetricCard title="Total Incidents" value={corrStats?.total_incidents || 0} icon={<Activity size={20} />} />
        <MetricCard title="Open Incident Chains" value={corrStats?.open_incidents || 0} icon={<Flame size={20} />} highlight={true} />
        <MetricCard title="Avg Correlation Score" value={corrStats?.average_correlation_score ? corrStats.average_correlation_score.toFixed(1) : 0} icon={<ShieldAlert size={20} />} />
        <MetricCard title="Active Threat Intel IOCs" value={iocCount} icon={<Crosshair size={20} />} />
        
        <MetricCard title="Total System Scans" value={sysStats?.total_scans || 0} icon={<Fingerprint size={20} />} />
        <MetricCard title="Network Attack Flows" value={netStats?.attack_flows || 0} icon={<Network size={20} />} />
        <MetricCard title="Phishing Attempts" value={sysStats?.phishing_detected || 0} icon={<AlertTriangle size={20} />} />
        <MetricCard title="Legitimate Verified" value={sysStats?.legitimate_verified || 0} icon={<Shield size={20} />} />
      </div>

      {/* CHARTS GRID */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
        
        {/* Chart 1: Incidents by Severity */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Incidents by Severity</h3>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1rem', height: '220px' }}>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={{ stroke: 'var(--border-subtle)' }} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--bg-sidebar)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)', fontSize: '0.8rem', borderRadius: '4px' }} itemStyle={{ color: 'var(--text-primary)' }} cursor={{ fill: 'var(--bg-card-hover)' }} />
                  <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getSeverityColor(entry.name)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>No incident data</div>
            )}
          </div>
        </div>

        {/* Chart 2: Network Attacks by Category */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Network Attacks by ML Category</h3>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1rem', height: '220px' }}>
            {networkCategoryData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={networkCategoryData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} dataKey="value" stroke="none">
                    {networkCategoryData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: 'var(--bg-sidebar)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)', fontSize: '0.8rem', borderRadius: '4px' }} itemStyle={{ color: 'var(--text-primary)' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>No network attack data</div>
            )}
          </div>
        </div>

        {/* Chart 3: Top Attacking Sources */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Top Attacking IPs</h3>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1rem', height: '220px', overflow: 'hidden' }}>
            {topAttackers.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', height: '100%' }}>
                {topAttackers.slice(0, 5).map((attacker, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', background: 'var(--bg-sidebar)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <span style={{ color: getSeverityColor(attacker.max_severity), fontWeight: 'bold', fontSize: '0.7rem', padding: '0.1rem 0.3rem', border: `1px solid ${getSeverityColor(attacker.max_severity)}`, borderRadius: '3px' }}>
                        {attacker.max_severity}
                      </span>
                      <span style={{ color: 'var(--text-primary)', fontSize: '0.85rem', fontFamily: 'monospace' }}>{attacker.source_ip}</span>
                    </div>
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{attacker.count} events</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>No attacker data</div>
            )}
          </div>
        </div>
      </div>

      {/* RECENT EVENTS */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>Live Security Events</h3>
        <DataGrid
          columns={[
            { header: 'Time', accessor: 'timestamp', render: (val) => new Date(val).toLocaleTimeString() },
            { header: 'Classification', accessor: 'classification' },
            { header: 'Severity', accessor: 'severity', render: (val) => (
              <span style={{ color: getSeverityColor(val), fontWeight: 600 }}>{val}</span>
            )},
            { header: 'Source', accessor: 'source_ip', render: (val, row) => val || row.domain || row.source || 'N/A' },
            { header: 'Type', accessor: 'event_type' }
          ]}
          data={recentEvents}
          keyExtractor={(row) => row.event_id || Math.random().toString()}
          emptyMessage="No recent events."
        />
      </div>

    </div>
  );
};
