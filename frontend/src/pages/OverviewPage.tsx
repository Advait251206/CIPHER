import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  SecurityEventItem,
  IncidentItem,
  CorrelationStatsResponse,
  NetworkStatsResponse,
  SensorStatusResponse,
  BlocklistEntry,
  NetworkHealthResponse,
} from '../api/types';
import { StatCard } from '../components/common/StatCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { EventDetailModal } from '../components/events/EventDetailModal';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Shield,
  Flame,
  Activity,
  Lock,
  Radio,
  ExternalLink,
  ShieldCheck,
  Zap,
  CheckCircle2,
  Cpu,
  Compass,
} from 'lucide-react';
import { motion, type Variants } from 'framer-motion';

interface OverviewPageProps {
  onNavigate: (tab: any) => void;
  onSelectIncident?: (incidentId: string) => void;
  refreshTrigger?: number;
  onOpenExtensionModal?: () => void;
}

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.07,
      delayChildren: 0.04,
    },
  },
};

const itemVariants: Variants = {
  hidden: { opacity: 0, y: 14 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.35, ease: [0.25, 0.1, 0.25, 1] as const },
  },
};

export const OverviewPage: React.FC<OverviewPageProps> = ({
  onNavigate,
  onSelectIncident,
  refreshTrigger,
  onOpenExtensionModal,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Subsystem states
  const [recentEvents, setRecentEvents] = useState<SecurityEventItem[]>([]);
  const [activeIncidents, setActiveIncidents] = useState<IncidentItem[]>([]);
  const [corrStats, setCorrStats] = useState<CorrelationStatsResponse | null>(null);
  const [netStats, setNetStats] = useState<NetworkStatsResponse | null>(null);
  const [sensorStatus, setSensorStatus] = useState<SensorStatusResponse | null>(null);
  const [activeBlocklist, setActiveBlocklist] = useState<BlocklistEntry[]>([]);
  const [netHealth, setNetHealth] = useState<NetworkHealthResponse | null>(null);

  // Inspector modal
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);

  const fetchOverviewData = async () => {
    try {
      setError(null);
      const [eventsRes, incidentsRes, corrStatsRes, netStatsRes, sensorRes, blocklistRes, netHealthRes] =
        await Promise.allSettled([
          api.events.list({ limit: 10 }),
          api.incidents.list({ status: 'OPEN', limit: 5 }),
          api.incidents.getStats(),
          api.network.getStats(),
          api.network.getSensorStatus(),
          api.network.getBlocklist('ACTIVE'),
          api.network.getHealth(),
        ]);

      if (eventsRes.status === 'fulfilled') {
        setRecentEvents(eventsRes.value.events);
      }
      if (incidentsRes.status === 'fulfilled') {
        setActiveIncidents(incidentsRes.value.incidents);
      }
      if (corrStatsRes.status === 'fulfilled') {
        setCorrStats(corrStatsRes.value);
      }
      if (netStatsRes.status === 'fulfilled') {
        setNetStats(netStatsRes.value);
      }
      if (sensorRes.status === 'fulfilled') {
        setSensorStatus(sensorRes.value);
      }
      if (blocklistRes.status === 'fulfilled') {
        setActiveBlocklist(blocklistRes.value);
      }
      if (netHealthRes.status === 'fulfilled') {
        setNetHealth(netHealthRes.value);
      }

      if (eventsRes.status === 'rejected' && netHealthRes.status === 'rejected') {
        throw new Error('Unable to communicate with CIPHER backend endpoints.');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load security overview data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverviewData();
  }, [refreshTrigger]);

  if (loading) {
    return <LoadingState message="Loading security operations hub..." />;
  }

  if (error && recentEvents.length === 0 && !netHealth) {
    return <ErrorState title="CIPHER Backend Offline" error={error} onRetry={fetchOverviewData} />;
  }

  // Derive counts from actual data
  const critCount =
    corrStats?.incidents_by_severity?.CRITICAL ??
    recentEvents.filter((e) => e.severity === 'CRITICAL').length;
  const highCount =
    corrStats?.incidents_by_severity?.HIGH ??
    recentEvents.filter((e) => e.severity === 'HIGH').length;
  const medCount =
    corrStats?.incidents_by_severity?.MEDIUM ??
    recentEvents.filter((e) => e.severity === 'MEDIUM').length;
  const lowCount =
    corrStats?.incidents_by_severity?.LOW ??
    recentEvents.filter((e) => e.severity === 'LOW').length;

  const totalFlows = netStats?.total_flows ?? recentEvents.length;
  const openIncidentsCount = corrStats?.open_incidents ?? activeIncidents.length;
  const blockedIpsCount = activeBlocklist.length;
  const isSensorActive = sensorStatus?.is_running ?? false;

  // Attack categories distribution from netStats or recentEvents
  const categoryMap: Record<string, number> = netStats?.attacks_by_category || {};
  if (Object.keys(categoryMap).length === 0) {
    recentEvents.forEach((ev) => {
      const cat = ev.attack_type || ev.classification || 'UNKNOWN';
      categoryMap[cat] = (categoryMap[cat] || 0) + 1;
    });
  }

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* 1. Executive Security Command Center Deck */}
      <motion.div
        variants={itemVariants}
        className={`command-deck ${openIncidentsCount > 0 ? 'threat-active' : ''}`}
      >
        <div className="command-deck-grid">
          {/* Live High-Tech Radar Screen */}
          <div className="radar-gauge-container">
            <div className={`radar-sweep-disc ${openIncidentsCount > 0 ? 'danger' : ''}`} />
            <div className={`radar-beam ${openIncidentsCount > 0 ? 'danger' : ''}`} />
            <svg
              viewBox="0 0 100 100"
              style={{
                position: 'absolute',
                inset: 0,
                width: '100%',
                height: '100%',
                pointerEvents: 'none',
              }}
            >
              <circle cx="50" cy="50" r="48" fill="none" stroke={openIncidentsCount > 0 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'} strokeWidth="1" strokeDasharray="3 3" />
              <circle cx="50" cy="50" r="34" fill="none" stroke={openIncidentsCount > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)'} strokeWidth="1" />
              <circle cx="50" cy="50" r="20" fill="none" stroke={openIncidentsCount > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'} strokeWidth="1" />
              <line x1="50" y1="2" x2="50" y2="98" stroke={openIncidentsCount > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)'} strokeWidth="0.8" />
              <line x1="2" y1="50" x2="98" y2="50" stroke={openIncidentsCount > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)'} strokeWidth="0.8" />
              {openIncidentsCount > 0 && (
                <>
                  <circle cx="70" cy="32" r="3" fill="var(--crit-color)" />
                  <circle cx="28" cy="65" r="2.5" fill="var(--high-color)" />
                </>
              )}
            </svg>
            <div className={`radar-icon-center ${openIncidentsCount > 0 ? 'danger' : ''}`}>
              {openIncidentsCount > 0 ? (
                <ShieldAlert size={22} color="var(--crit-color)" />
              ) : (
                <ShieldCheck size={22} color="var(--benign-color)" />
              )}
            </div>
          </div>

          {/* Center Posture Feed */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem', flexWrap: 'wrap' }}>
              <span
                style={{
                  fontSize: '1.15rem',
                  fontWeight: 800,
                  color: openIncidentsCount > 0 ? 'var(--crit-color)' : 'var(--text-primary)',
                  letterSpacing: '-0.02em',
                }}
              >
                {openIncidentsCount > 0
                  ? `${openIncidentsCount} Security Incident${openIncidentsCount > 1 ? 's' : ''} Require Immediate Attention`
                  : 'Perimeter Nominal — Continuous Air-Gapped Monitoring'}
              </span>
              <span
                className="mono"
                style={{
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  padding: '0.18rem 0.55rem',
                  borderRadius: '9999px',
                  background: openIncidentsCount > 0 ? 'var(--crit-bg)' : 'var(--benign-bg)',
                  color: openIncidentsCount > 0 ? 'var(--crit-color)' : 'var(--benign-color)',
                  border: `1px solid ${openIncidentsCount > 0 ? 'var(--crit-border)' : 'var(--benign-border)'}`,
                }}
              >
                {openIncidentsCount > 0 ? 'CONTAINMENT REQUIRED' : 'LOCAL SOC ACTIVE'}
              </span>
            </div>

            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.65rem' }}>
              {openIncidentsCount > 0
                ? 'Multi-stage correlated attack sequence detected. Review incident graph and take prevention action.'
                : 'Dual Random Forest models (CIC-IDS2017 & PhiUSIIL) and heuristic rule engine actively parsing local telemetry.'}
            </p>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <div className="telemetry-chip">
                <span className="pulse-dot" />
                <span className="telemetry-chip-label">Telemetry:</span>
                <span className="telemetry-chip-val">127.0.0.1:8000</span>
              </div>
              <div className="telemetry-chip">
                <span className="telemetry-chip-label">Inference:</span>
                <span className="telemetry-chip-val">Dual RF + Rules</span>
              </div>
              <div className="telemetry-chip">
                <span className="telemetry-chip-label">IPS Mode:</span>
                <span className="telemetry-chip-val">{(netHealth?.prevention_mode || 'detect_only').replace('_', ' ')}</span>
              </div>
              <div className="telemetry-chip">
                <span className="telemetry-chip-label">Sensor:</span>
                <span className="telemetry-chip-val" style={{ color: isSensorActive ? 'var(--benign-color)' : 'var(--text-muted)' }}>
                  {isSensorActive ? 'ACTIVE' : 'STANDBY'}
                </span>
              </div>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div style={{ flexShrink: 0, display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
            {onOpenExtensionModal && (
              <motion.button
                whileHover={{ scale: 1.04, y: -1 }}
                whileTap={{ scale: 0.96 }}
                className="control-btn"
                onClick={onOpenExtensionModal}
                title="Add CIPHER Browser Guard Extension"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  padding: '0.48rem 0.85rem',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  border: '1px solid var(--accent-cyan)',
                  background: 'rgba(6, 182, 212, 0.12)',
                  color: 'var(--text-primary)',
                }}
              >
                <Compass size={14} color="var(--accent-cyan)" />
                <span>Add Extension</span>
              </motion.button>
            )}
            <motion.button
              whileHover={{ scale: 1.04, y: -1 }}
              whileTap={{ scale: 0.96 }}
              className="control-btn cta-attack"
              onClick={() => onNavigate('network')}
              title="Open Network IDS Flow Sandbox to simulate live attacks"
            >
              <Zap size={15} />
              <span>Simulate Attack Flow</span>
            </motion.button>
          </div>
        </div>
      </motion.div>

      {/* 2. Unified Threat Severity Ribbon (Cohesive, not 4 separate boxes) */}
      <motion.div variants={itemVariants} className="threat-spectrum-ribbon">
        <div className="threat-spectrum-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={15} color="var(--accent-blue)" />
            <span style={{ fontSize: '0.82rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
              Threat Severity Spectrum
            </span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Real-time alert distribution by severity tier
          </span>
        </div>

        <div className="threat-spectrum-grid">
          <motion.div
            whileHover={{ y: -3 }}
            className="spectrum-card critical"
            onClick={() => onNavigate('events')}
          >
            <div>
              <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--crit-color)', letterSpacing: '0.05em' }}>
                Critical
              </div>
              <div className="mono" style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--crit-color)', lineHeight: 1.1, marginTop: '2px' }}>
                {critCount}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                Immediate action
              </div>
            </div>
            <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--crit-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--crit-color)' }}>
              <ShieldAlert size={16} />
            </div>
          </motion.div>

          <motion.div
            whileHover={{ y: -3 }}
            className="spectrum-card high"
            onClick={() => onNavigate('events')}
          >
            <div>
              <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--high-color)', letterSpacing: '0.05em' }}>
                High
              </div>
              <div className="mono" style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--high-color)', lineHeight: 1.1, marginTop: '2px' }}>
                {highCount}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                Elevated threat
              </div>
            </div>
            <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--high-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--high-color)' }}>
              <AlertTriangle size={16} />
            </div>
          </motion.div>

          <motion.div
            whileHover={{ y: -3 }}
            className="spectrum-card medium"
            onClick={() => onNavigate('events')}
          >
            <div>
              <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--med-color)', letterSpacing: '0.05em' }}>
                Medium
              </div>
              <div className="mono" style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--med-color)', lineHeight: 1.1, marginTop: '2px' }}>
                {medCount}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                Suspicious flow
              </div>
            </div>
            <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--med-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--med-color)' }}>
              <AlertCircle size={16} />
            </div>
          </motion.div>

          <motion.div
            whileHover={{ y: -3 }}
            className="spectrum-card low"
            onClick={() => onNavigate('events')}
          >
            <div>
              <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--low-color)', letterSpacing: '0.05em' }}>
                Low / Normal
              </div>
              <div className="mono" style={{ fontSize: '1.65rem', fontWeight: 800, color: 'var(--low-color)', lineHeight: 1.1, marginTop: '2px' }}>
                {lowCount}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                Baseline activity
              </div>
            </div>
            <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--low-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--low-color)' }}>
              <Shield size={16} />
            </div>
          </motion.div>
        </div>
      </motion.div>

      {/* 3. Operational Defense Grid (4 Columns Balanced, NO gaps!) */}
      <motion.div variants={itemVariants} className="telemetry-grid-4">
        <motion.div
          whileHover={{ y: -3 }}
          className="telemetry-card"
          onClick={() => onNavigate('incidents')}
        >
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">Active Incidents</span>
            <div className="telemetry-card-icon" style={{ color: openIncidentsCount > 0 ? 'var(--crit-color)' : 'var(--text-muted)' }}>
              <Flame size={16} />
            </div>
          </div>
          <div className="telemetry-card-value" style={{ color: openIncidentsCount > 0 ? 'var(--crit-color)' : 'var(--text-primary)' }}>
            {openIncidentsCount}
          </div>
          <div className="telemetry-card-sub">
            {openIncidentsCount > 0 ? 'Correlated multi-event chains' : '0 open kill-chains'}
          </div>
        </motion.div>

        <motion.div
          whileHover={{ y: -3 }}
          className="telemetry-card"
          onClick={() => onNavigate('network')}
        >
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">Flows Evaluated</span>
            <div className="telemetry-card-icon" style={{ color: 'var(--accent-blue)' }}>
              <Activity size={16} />
            </div>
          </div>
          <div className="telemetry-card-value">
            {totalFlows.toLocaleString()}
          </div>
          <div className="telemetry-card-sub">
            Dual RF ML + CIC-IDS2017
          </div>
        </motion.div>

        <motion.div
          whileHover={{ y: -3 }}
          className="telemetry-card"
          onClick={() => onNavigate('prevention')}
        >
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">Blocked IPs</span>
            <div className="telemetry-card-icon" style={{ color: blockedIpsCount > 0 ? 'var(--high-color)' : 'var(--text-muted)' }}>
              <Lock size={16} />
            </div>
          </div>
          <div className="telemetry-card-value" style={{ color: blockedIpsCount > 0 ? 'var(--high-color)' : 'var(--text-primary)' }}>
            {blockedIpsCount}
          </div>
          <div className="telemetry-card-sub">
            Active sliding-window firewall
          </div>
        </motion.div>

        <motion.div
          whileHover={{ y: -3 }}
          className="telemetry-card"
          onClick={() => onNavigate('sensor')}
        >
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">Packet Sensor</span>
            <div className="telemetry-card-icon" style={{ color: isSensorActive ? 'var(--benign-color)' : 'var(--text-muted)' }}>
              <Radio size={16} />
            </div>
          </div>
          <div className="telemetry-card-value" style={{ fontSize: '1.45rem', color: isSensorActive ? 'var(--benign-color)' : 'var(--text-primary)' }}>
            {isSensorActive ? 'ACTIVE' : 'STANDBY'}
          </div>
          <div className="telemetry-card-sub">
            {sensorStatus?.interface || 'Npcap user-space capture'}
          </div>
        </motion.div>
      </motion.div>

      {/* 4. Subsystem Policy & Telemetry Strip (Compact Dual Panel) */}
      <motion.div variants={itemVariants} className="subsystem-deck">
        <div className="subsystem-panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'var(--low-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--low-color)' }}>
              <Lock size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Prevention Engine (IPS)
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Policy: <code>CIPHER_PREVENTION_MODE</code>
              </div>
            </div>
          </div>
          <span className={`mode-badge ${netHealth?.prevention_mode || 'detect_only'}`}>
            {(netHealth?.prevention_mode || 'detect_only').replace('_', ' ')}
          </span>
        </div>

        <div className="subsystem-panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: 'var(--benign-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--benign-color)' }}>
              <Radio size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Live Packet Ingestion
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Captured: <strong className="mono">{sensorStatus?.packets_captured ?? 0}</strong> | Active Flows: <strong className="mono">{sensorStatus?.active_flows ?? 0}</strong>
              </div>
            </div>
          </div>
          <span className={`mode-badge ${isSensorActive ? 'detect_only' : 'simulate'}`}>
            {isSensorActive ? 'RUNNING' : 'STANDBY'}
          </span>
        </div>
      </motion.div>

      {/* 5. Main Grid: Active Incidents & Attack Categories Bento */}
      <motion.div
        variants={itemVariants}
        style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}
      >
        {/* Active Incidents */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Flame size={16} color="var(--crit-color)" />
              <span>Active Correlated Incidents</span>
            </div>
            <button className="control-btn" onClick={() => onNavigate('incidents')}>
              <span>View All</span>
              <ExternalLink size={12} />
            </button>
          </div>
          {activeIncidents.length === 0 ? (
            <div style={{ padding: '2.5rem 1.5rem', textAlign: 'center' }}>
              <div
                style={{
                  width: '46px',
                  height: '46px',
                  borderRadius: '50%',
                  background: 'var(--benign-bg)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 0.75rem auto',
                  border: '1px solid var(--benign-border)',
                }}
              >
                <CheckCircle2 size={22} color="var(--benign-color)" />
              </div>
              <div style={{ fontWeight: 700, fontSize: '0.94rem', marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
                Zero Active Security Incidents
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem', maxWidth: '360px', margin: '0 auto 1.15rem auto' }}>
                Perimeter is nominal. Multi-event correlations, escalation bursts, and lateral scans will automatically surface here.
              </div>
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                className="control-btn"
                style={{ fontSize: '0.78rem', margin: '0 auto' }}
                onClick={() => onNavigate('network')}
              >
                <Zap size={13} />
                <span>Simulate Flow in Sandbox</span>
              </motion.button>
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Source IP</th>
                    <th>Target IP</th>
                    <th>Events</th>
                    <th>Escalated</th>
                  </tr>
                </thead>
                <tbody>
                  {activeIncidents.map((inc) => (
                    <tr
                      key={inc.incident_id}
                      onClick={() => {
                        if (onSelectIncident) {
                          onSelectIncident(inc.incident_id);
                        } else {
                          onNavigate('incidents');
                        }
                      }}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <SeverityBadge severity={inc.severity} size="sm" />
                      </td>
                      <td className="mono">{inc.source_ip || 'N/A'}</td>
                      <td className="mono">{inc.destination_ip || 'N/A'}</td>
                      <td className="mono">{inc.event_count}</td>
                      <td>
                        {inc.escalation_detected ? (
                          <span className="nav-badge danger" style={{ fontSize: '0.68rem' }}>
                            ESCALATED
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Attack Category Breakdown */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} color="var(--accent-blue)" />
              <span>Attack Category Distribution</span>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {Object.keys(categoryMap).length === 0 ? (
              <div style={{ padding: '2.5rem 1.5rem', textAlign: 'center' }}>
                <div
                  style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '50%',
                    background: 'var(--bg-surface-elevated)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 0.75rem auto',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <Activity size={20} color="var(--text-muted)" />
                </div>
                <div style={{ fontWeight: 700, fontSize: '0.94rem', marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
                  Awaiting Telemetry Classification
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem', maxWidth: '340px', margin: '0 auto' }}>
                  Simulate test flows in Network IDS or activate the live packet sensor to populate real-time classification.
                </div>
              </div>
            ) : (
              Object.entries(categoryMap).map(([category, count]) => {
                const maxVal = Math.max(...Object.values(categoryMap), 1);
                const pct = Math.round((count / maxVal) * 100);
                const isBenign = category.toUpperCase() === 'BENIGN';
                return (
                  <div key={category} style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                      <span className="mono" style={{ fontWeight: 600 }}>{category}</span>
                      <span className="mono" style={{ color: 'var(--text-muted)' }}>{count} flows</span>
                    </div>
                    <div style={{ width: '100%', height: '8px', background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div
                        style={{
                          height: '100%',
                          width: `${pct}%`,
                          background: isBenign ? 'var(--benign-color)' : 'var(--crit-color)',
                          borderRadius: '4px',
                          transition: 'width 0.4s ease',
                        }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </motion.div>

      {/* 6. Recent Security Events Feed */}
      <motion.div variants={itemVariants} className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={16} color="var(--accent-cyan)" />
            <span>Recent Security Events Stream</span>
          </div>
          <button className="control-btn" onClick={() => onNavigate('events')}>
            <span>View Full Stream</span>
            <ExternalLink size={12} />
          </button>
        </div>
        {recentEvents.length === 0 ? (
          <div style={{ padding: '2.5rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <div style={{ fontWeight: 700, fontSize: '0.94rem', marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
              No Security Events in Local Buffer
            </div>
            <div style={{ fontSize: '0.82rem', maxWidth: '400px', margin: '0 auto 1.15rem auto' }}>
              Database is clean. Use the Network IDS Sandbox or Phishing Inspector to generate verified security events.
            </div>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              className="control-btn primary"
              style={{ fontSize: '0.78rem', margin: '0 auto' }}
              onClick={() => onNavigate('network')}
            >
              <Zap size={13} />
              <span>Open Attack Flow Simulator</span>
            </motion.button>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Classification / Attack</th>
                  <th>Risk</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Method</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.map((ev) => (
                  <tr
                    key={ev.event_id}
                    onClick={() => setSelectedEvent(ev)}
                    style={{ cursor: 'pointer' }}
                    title="Click to view detailed evidence"
                  >
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {ev.timestamp.replace('T', ' ').replace('Z', '')}
                    </td>
                    <td>
                      <SeverityBadge severity={ev.severity} size="sm" />
                    </td>
                    <td>
                      <span style={{ fontWeight: 600 }}>{ev.attack_type || ev.classification}</span>
                    </td>
                    <td className="mono" style={{ fontWeight: 700 }}>
                      {ev.risk_score}
                    </td>
                    <td className="mono">{ev.source_ip || ev.domain || 'N/A'}</td>
                    <td className="mono">{ev.destination_ip || 'N/A'}</td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {ev.detection_method || ev.source}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Event Detail Modal */}
      <EventDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
        onNavigateToIncident={(incId) => {
          setSelectedEvent(null);
          if (onSelectIncident) {
            onSelectIncident(incId);
          } else {
            onNavigate('incidents');
          }
        }}
      />
    </motion.div>
  );
};


