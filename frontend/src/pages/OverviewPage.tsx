import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { CorrelationStatsResponse, SecurityEventItem, SystemStatsResponse, NetworkStatsResponse } from '../api/types';
import { MetricCard } from '../components/common/MetricCard';
import { DataGrid } from '../components/common/DataGrid';
import { Activity, Flame, ShieldAlert, Crosshair, Network, Fingerprint, Shield, AlertTriangle, Compass } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell, PieChart, Pie } from 'recharts';

import { WafControlPanel } from '../components/common/WafControlPanel';
import { cn } from '../lib/cn';
import { controlBtn } from '../ui/classes';

interface OverviewPageProps {
  onNavigate: (tab: any) => void;
  onSelectIncident?: (incidentId: string) => void;
  refreshTrigger?: number;
  onOpenExtensionModal?: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ refreshTrigger, onOpenExtensionModal }) => {
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
    if (!severity) return 'var(--color-accent)';
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'var(--color-crit)';
      case 'HIGH': return 'var(--color-high)';
      case 'MEDIUM': return 'var(--color-med)';
      case 'LOW': return 'var(--color-low)';
      default: return 'var(--color-accent)';
    }
  };

  // Class equivalent of getSeverityColor for text/border (the chart needs the raw colour).
  const severityTone = (severity?: string | null) => {
    switch ((severity || '').toUpperCase()) {
      case 'CRITICAL': return { text: 'text-crit', border: 'border-crit' };
      case 'HIGH': return { text: 'text-high', border: 'border-high' };
      case 'MEDIUM': return { text: 'text-med', border: 'border-med' };
      case 'LOW': return { text: 'text-low', border: 'border-low' };
      default: return { text: 'text-accent', border: 'border-accent' };
    }
  };

  const COLORS = ['#FF4444', '#FF8800', '#D4AF37', '#00AAFF', '#AA00FF'];

  return (
    <div className="p-6 flex flex-col gap-6">
      
      {/* Browser Guard entry point: the modal had no way to be opened. */}
      {onOpenExtensionModal && (
        <div className="flex justify-end">
          <button className={controlBtn()} onClick={() => onOpenExtensionModal()}>
            <Compass size={14} />
            <span>Add Browser Guard Extension</span>
          </button>
        </div>
      )}

      {/* WAF CONTROLS */}
      <WafControlPanel />

      {/* METRICS GRID - 2 Rows */}
      <div className="grid grid-cols-[repeat(auto-fit,minmax(240px,1fr))] gap-4">
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
      <div className="grid grid-cols-[repeat(auto-fit,minmax(320px,1fr))] gap-6">
        
        {/* Chart 1: Incidents by Severity */}
        <div className="flex flex-col gap-3">
          <h3 className="text-[0.9rem] text-fg">Incidents by Severity</h3>
          <div className="bg-surface border border-line rounded-[6px] p-4 h-[220px]">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-line)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: 'var(--color-fg-2)', fontSize: 11 }} axisLine={{ stroke: 'var(--color-line)' }} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--color-fg-2)', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--color-sidebar)', borderColor: 'var(--color-line)', color: 'var(--color-fg)', fontSize: '0.8rem', borderRadius: '4px' }} itemStyle={{ color: 'var(--color-fg)' }} cursor={{ fill: 'var(--color-card-hover)' }} />
                  <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getSeverityColor(entry.name)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-fg-muted text-[0.85rem]">No incident data</div>
            )}
          </div>
        </div>

        {/* Chart 2: Network Attacks by Category */}
        <div className="flex flex-col gap-3">
          <h3 className="text-[0.9rem] text-fg">Network Attacks by ML Category</h3>
          <div className="bg-surface border border-line rounded-[6px] p-4 h-[220px]">
            {networkCategoryData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={networkCategoryData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} dataKey="value" stroke="none">
                    {networkCategoryData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: 'var(--color-sidebar)', borderColor: 'var(--color-line)', color: 'var(--color-fg)', fontSize: '0.8rem', borderRadius: '4px' }} itemStyle={{ color: 'var(--color-fg)' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-fg-muted text-[0.85rem]">No network attack data</div>
            )}
          </div>
        </div>

        {/* Chart 3: Top Attacking Sources */}
        <div className="flex flex-col gap-3">
          <h3 className="text-[0.9rem] text-fg">Top Attacking IPs</h3>
          <div className="bg-surface border border-line rounded-[6px] p-4 h-[220px] overflow-hidden">
            {topAttackers.length > 0 ? (
              <div className="flex flex-col gap-2 h-full">
                {topAttackers.slice(0, 5).map((attacker, idx) => (
                  <div key={idx} className="flex justify-between items-center p-2 bg-sidebar rounded-[4px] border border-line">
                    <div className="flex items-center gap-3">
                      <span className={cn('font-bold text-[0.7rem] py-[0.1rem] px-[0.3rem] rounded-[3px] border', severityTone(attacker.max_severity).text, severityTone(attacker.max_severity).border)}>
                        {attacker.max_severity}
                      </span>
                      <span className="text-fg text-[0.85rem] [font-family:monospace]">{attacker.source_ip}</span>
                    </div>
                    <span className="text-fg-2 text-[0.85rem]">{attacker.count} events</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex h-full items-center justify-center text-fg-muted text-[0.85rem]">No attacker data</div>
            )}
          </div>
        </div>
      </div>

      {/* RECENT EVENTS */}
      <div className="flex flex-col gap-3 mt-2">
        <h3 className="text-[0.9rem] text-fg">Live Security Events</h3>
        <DataGrid
          columns={[
            { header: 'Time', accessor: 'timestamp', render: (val) => new Date(val).toLocaleTimeString() },
            { header: 'Classification', accessor: 'classification' },
            { header: 'Severity', accessor: 'severity', render: (val) => (
              <span className={cn('font-semibold', severityTone(val).text)}>{val}</span>
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
