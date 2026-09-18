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

const SYSTEM_DETAILS = {
  api: {
    title: 'API Gateway',
    description: 'FastAPI (ASGI) core handling real-time telemetry, user configurations, and alert aggregation.',
    dataset: 'N/A',
    framework: 'FastAPI / Uvicorn',
    features: [
      'Asynchronous Event Loop',
      'Air-gapped operation readiness',
      'CORS and Security Headers configured',
      'WebSocket support for live telemetry'
    ]
  },
  sqlite: {
    title: 'Local Storage (SQLite)',
    description: 'Lightweight local database ensuring persistence of configuration and logs without external dependencies.',
    dataset: 'Local User Data',
    framework: 'SQLite3 / SQLAlchemy',
    features: [
      'journal_mode=WAL for concurrent writes',
      'Tables: alerts, network_flows, phishing_urls, system_config',
      'Local encrypted credential storage',
      'Synchronous commits optimized for low latency'
    ]
  },
  phishing_ml: {
    title: 'Phishing ML Subsystem',
    description: 'Random Forest Classifier trained to detect malicious and phishing domains via URL lexical and content analysis.',
    dataset: 'PhiUSIIL Phishing URL Dataset',
    framework: 'Scikit-Learn (Random Forest)',
    features: [
      'URL Length', 'Domain Length', 'Is IP Address',
      'Number of Dots', 'Number of Hyphens', 'Number of @ Symbols',
      'Number of Subdomains', 'Presence of "login"', 'Presence of "verify"',
      'Presence of "update"', 'Presence of "secure"', 'Presence of "account"',
      'Presence of "bank"', 'URL Entropy', 'Domain Entropy',
      'Vowel to Consonant Ratio', 'Digit to Letter Ratio', 'HTTPS in Domain',
      'Suspicious TLD check', 'Special Character Ratio', 'Query String Length',
      'Path Length', 'Number of Parameters', 'Number of Fragments',
      'Presence of Port', 'Presence of Unicode', 'Redirection (//)',
      'Brand Name spoofing detection'
    ]
  },
  network_ids: {
    title: 'Network IDS Subsystem',
    description: 'Dual Random Forest Gate architecture processing packet flows to identify DDoS, Port Scans, and Brute Force attacks.',
    dataset: 'CICIDS2017 Intrusion Detection Evaluation Dataset',
    framework: 'Scikit-Learn (Random Forest) / Scapy',
    features: [
      'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
      'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
      'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
      'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
      'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
      'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
      'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
      'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
      'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
      'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
      'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
      'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
      'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
      'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
      'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
      'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
      'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
      'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
      'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
      'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
      'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]
  },
  ips: {
    title: 'Prevention Engine (IPS)',
    description: 'Active mitigation subsystem responsible for dropping connections, rate limiting, and blocking malicious actors.',
    dataset: 'Dynamic Local Ruleset',
    framework: 'Python / OS Firewall Integration',
    features: [
      'Sliding Window Rate Limiter',
      'Dynamic IP Blocklisting',
      'TCP RST Packet Injection',
      'Detect-Only and Enforce modes',
      'Threshold-based blocking logic',
      'Automatic IP Unbanning after timeout'
    ]
  },
  sensor: {
    title: 'Live Packet Sensor',
    description: 'Raw network interface sniffer that captures, filters, and groups packets into flows for the ML models.',
    dataset: 'Live Network Traffic',
    framework: 'PyShark / Scapy / pcap',
    features: [
      'Promiscuous Mode Interface Binding',
      'BPF (Berkeley Packet Filter) syntax support',
      'Asynchronous Packet Ingestion',
      'Flow Timeout (Active/Idle)',
      'Bi-directional flow matching',
      'Zero-copy packet parsing where possible'
    ]
  }
};

interface SystemHealthPageProps {
  refreshTrigger?: number;
}

export const SystemHealthPage: React.FC<SystemHealthPageProps> = ({ refreshTrigger = 0 }) => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatusResponse | null>(null);
  const [netHealth, setNetHealth] = useState<NetworkHealthResponse | null>(null);
  const [sensorStatus, setSensorStatus] = useState<SensorStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [liveUptime, setLiveUptime] = useState<number | null>(null);
  const [selectedCard, setSelectedCard] = useState<keyof typeof SYSTEM_DETAILS | null>(null);

  // Sync uptime with server response
  useEffect(() => {
    if (systemStatus?.uptime_seconds !== undefined) {
      setLiveUptime(systemStatus.uptime_seconds);
    }
  }, [systemStatus?.uptime_seconds]);

  // Tick the local uptime every second
  useEffect(() => {
    if (liveUptime === null) return;
    const interval = setInterval(() => {
      setLiveUptime((prev) => (prev !== null ? prev + 1 : null));
    }, 1000);
    return () => clearInterval(interval);
  }, [liveUptime !== null]);

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
  }, [refreshTrigger]);

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
        <div className="card clickable-card" onClick={() => setSelectedCard('api')}>
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
                {liveUptime !== null
                  ? formatUptime(liveUptime)
                  : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        {/* 2. SQLite Local Database */}
        <div className="card clickable-card" onClick={() => setSelectedCard('sqlite')}>
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
        <div className="card clickable-card" onClick={() => setSelectedCard('phishing_ml')}>
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
        <div className="card clickable-card" onClick={() => setSelectedCard('network_ids')}>
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
        <div className="card clickable-card" onClick={() => setSelectedCard('ips')}>
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} color="var(--accent-blue)" />
              <span>Prevention Engine (IPS)</span>
            </div>
            <span className={`mode-badge ${netHealth?.prevention_mode || 'enforce'}`}>
              {(netHealth?.prevention_mode || 'enforce').replace('_', ' ')}
            </span>
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Current Mode</span>
              <span className="kv-value mono">{netHealth?.prevention_mode || 'enforce'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Rate Limiter</span>
              <span className="kv-value">Sliding Window Active</span>
            </div>
          </div>
        </div>

        {/* 6. Live Packet Sensor */}
        <div className="card clickable-card" onClick={() => setSelectedCard('sensor')}>
          <div className="card-header">
            <div className="card-title">
              <Radio size={16} color="var(--accent-cyan)" />
              <span>Packet Capture Sensor</span>
            </div>
            <span className={`mode-badge ${sensorStatus?.running ? 'detect_only' : 'simulate'}`}>
              {sensorStatus?.running ? 'RUNNING' : 'STOPPED'}
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

      {/* Detailed Component Modal */}
      {selectedCard && SYSTEM_DETAILS[selectedCard] && (
        <div className="modal-overlay" onClick={() => setSelectedCard(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">{SYSTEM_DETAILS[selectedCard].title}</h2>
              <button className="modal-close" onClick={() => setSelectedCard(null)}>
                &times;
              </button>
            </div>
            
            <div className="modal-body">
              <p className="modal-description">{SYSTEM_DETAILS[selectedCard].description}</p>
              
              <div className="modal-section">
                <h3>Technical Details</h3>
                <div className="kv-grid" style={{ marginBottom: '1rem' }}>
                  <div className="kv-item">
                    <span className="kv-label">Framework / Tech</span>
                    <span className="kv-value mono">{SYSTEM_DETAILS[selectedCard].framework}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Trained Dataset</span>
                    <span className="kv-value mono">{SYSTEM_DETAILS[selectedCard].dataset}</span>
                  </div>
                </div>
              </div>

              <div className="modal-section">
                <h3>Capabilities & Extracted Features ({SYSTEM_DETAILS[selectedCard].features.length})</h3>
                <div className="features-grid">
                  {SYSTEM_DETAILS[selectedCard].features.map((feature, idx) => (
                    <div key={idx} className="feature-badge">
                      {feature}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </motion.div>
  );
};
