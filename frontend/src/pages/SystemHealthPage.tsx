import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  HealthResponse,
  SystemStatusResponse,
  NetworkHealthResponse,
  SensorStatusResponse,
} from '../api/types';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { HeartPulse, Server, Database, Cpu, Radio, Shield, CheckCircle2, AlertOctagon } from 'lucide-react';
import { motion, type Variants } from 'framer-motion';

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.04,
    },
  },
};

const itemVariants: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, ease: [0.25, 0.1, 0.25, 1] as const },
  },
};

export const SystemHealthPage: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatusResponse | null>(null);
  const [netHealth, setNetHealth] = useState<NetworkHealthResponse | null>(null);
  const [sensorStatus, setSensorStatus] = useState<SensorStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    try {
      setLoading(true);
      setError(null);
      const [hRes, sRes, netHRes, sensorRes] = await Promise.allSettled([
        api.health.getHealth(),
        api.health.getSystemStatus(),
        api.network.getHealth(),
        api.network.getSensorStatus(),
      ]);

      if (hRes.status === 'fulfilled') setHealth(hRes.value);
      if (sRes.status === 'fulfilled') setSystemStatus(sRes.value);
      if (netHRes.status === 'fulfilled') setNetHealth(netHRes.value);
      if (sensorRes.status === 'fulfilled') setSensorStatus(sensorRes.value);

      if (hRes.status === 'rejected' && netHRes.status === 'rejected') {
        throw new Error('Unable to connect to CIPHER backend service.');
      }
    } catch (err: any) {
      setError(err.message || 'Health check query failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  if (loading) {
    return <LoadingState message="Checking system diagnostics..." />;
  }

  if (error && !health && !netHealth) {
    return <ErrorState title="System Health Unavailable" error={error} onRetry={fetchHealth} />;
  }

  const formatUptime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const hrs = Math.floor(mins / 60);
    const remainingMins = mins % 60;
    const remainingSecs = Math.floor(seconds % 60);
    return `${hrs}h ${remainingMins}m ${remainingSecs}s`;
  };

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Overview Status Banner */}
      <motion.div
        variants={itemVariants}
        className="card"
        style={{ marginBottom: '1.5rem', borderLeft: '4px solid var(--benign-color)' }}
      >
        <div className="card-header">
          <div className="card-title">
            <HeartPulse size={18} color="var(--benign-color)" />
            <span>Local SOC Diagnostic Health</span>
          </div>
          <span
            className="mono"
            style={{
              fontSize: '0.78rem',
              fontWeight: 700,
              padding: '0.3rem 0.75rem',
              borderRadius: '6px',
              background: health?.status === 'ok' ? 'var(--benign-bg)' : 'var(--med-bg)',
              color: health?.status === 'ok' ? 'var(--benign-color)' : 'var(--med-color)',
              border: `1px solid ${health?.status === 'ok' ? 'var(--benign-border)' : 'var(--med-border)'}`,
              display: 'flex',
              alignItems: 'center',
              gap: '0.45rem',
            }}
          >
            {health?.status === 'ok' && <span className="pulse-dot" />}
            {health?.status === 'ok' ? 'ALL SYSTEMS NOMINAL' : health?.status?.toUpperCase() || 'UNKNOWN'}
          </span>
        </div>

        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
          All diagnostics are polled locally from in-process backend engines. No external cloud dependencies, external telemetry, or remote telemetry feeds are contacted.
        </p>
      </motion.div>

      {/* Subsystem Component Health Grid */}
      <motion.div
        variants={itemVariants}
        style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem', marginBottom: '1.5rem' }}
      >
        {/* 1. FastAPI Core */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Server size={16} color="var(--accent-cyan)" />
              <span>API Gateway</span>
            </div>
            {health ? (
              <CheckCircle2 size={16} color="var(--benign-color)" />
            ) : (
              <AlertOctagon size={16} color="var(--crit-color)" />
            )}
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">API Version</span>
              <span className="kv-value mono">{health?.version || '1.1.0'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Environment</span>
              <span className="kv-value mono">{systemStatus?.environment || 'local'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Local Only</span>
              <span className="kv-value">{health?.local_only ? 'True (Air-Gapped)' : 'False'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Server Uptime</span>
              <span className="kv-value mono">
                {systemStatus?.uptime_seconds !== undefined
                  ? formatUptime(systemStatus.uptime_seconds)
                  : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        {/* 2. SQLite Local Database */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Database size={16} color="var(--accent-blue)" />
              <span>Local Storage (SQLite)</span>
            </div>
            {health?.database_connected ? (
              <CheckCircle2 size={16} color="var(--benign-color)" />
            ) : (
              <AlertOctagon size={16} color="var(--crit-color)" />
            )}
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">DB Connection</span>
              <span className="kv-value" style={{ color: health?.database_connected ? 'var(--benign-color)' : 'var(--crit-color)' }}>
                {health?.database_connected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <div className="kv-item" style={{ gridColumn: '1 / -1' }}>
              <span className="kv-label">Database Path</span>
              <span className="kv-value mono" style={{ fontSize: '0.75rem' }}>
                {systemStatus?.database_path || 'cipher.db'}
              </span>
            </div>
          </div>
        </div>

        {/* 3. Phishing ML Subsystem */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={16} color="var(--accent-cyan)" />
              <span>Phishing ML Subsystem</span>
            </div>
            {health?.model_loaded ? (
              <CheckCircle2 size={16} color="var(--benign-color)" />
            ) : (
              <AlertOctagon size={16} color="var(--med-color)" />
            )}
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Model Status</span>
              <span className="kv-value">
                {health?.model_loaded ? 'Loaded (Pre-warmed)' : 'Not Loaded'}
              </span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Model Version</span>
              <span className="kv-value mono">{systemStatus?.model_version || 'phiusiil-rf-v1'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Features Extracted</span>
              <span className="kv-value mono">{systemStatus?.feature_count || 28} lexical features</span>
            </div>
          </div>
        </div>

        {/* 4. Network IDS Subsystem */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={16} color="var(--accent-cyan)" />
              <span>Network IDS Subsystem</span>
            </div>
            {netHealth?.model_loaded ? (
              <CheckCircle2 size={16} color="var(--benign-color)" />
            ) : (
              <AlertOctagon size={16} color="var(--med-color)" />
            )}
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Model Status</span>
              <span className="kv-value">
                {netHealth?.model_loaded ? 'Dual RF Gate Active' : 'Not Loaded'}
              </span>
            </div>
            <div className="kv-item">
              <span className="kv-label">CIC Features</span>
              <span className="kv-value mono">{netHealth?.feature_count || 67} features</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Model Version</span>
              <span className="kv-value mono">{netHealth?.model_version || 'cicids2017-dual-rf-v1'}</span>
            </div>
          </div>
        </div>

        {/* 5. IPS Prevention Engine */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} color="var(--accent-blue)" />
              <span>Prevention Engine (IPS)</span>
            </div>
            <span className={`mode-badge ${netHealth?.prevention_mode || 'detect_only'}`}>
              {(netHealth?.prevention_mode || 'detect_only').replace('_', ' ')}
            </span>
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Current Mode</span>
              <span className="kv-value mono">{netHealth?.prevention_mode || 'detect_only'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Rate Limiter</span>
              <span className="kv-value">Sliding Window Active</span>
            </div>
          </div>
        </div>

        {/* 6. Live Packet Sensor */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Radio size={16} color="var(--accent-cyan)" />
              <span>Packet Capture Sensor</span>
            </div>
            <span className={`mode-badge ${sensorStatus?.is_running ? 'detect_only' : 'simulate'}`}>
              {sensorStatus?.is_running ? 'RUNNING' : 'STOPPED'}
            </span>
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Interface</span>
              <span className="kv-value mono">{sensorStatus?.interface || 'Unbound'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Packets Captured</span>
              <span className="kv-value mono">{sensorStatus?.packets_captured ?? 0}</span>
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};
