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
import { cn } from '../lib/cn';
import { card, cardHeader, cardTitle, clickableCard, kvGrid, kvItem, kvLabel, kvValue, modalBody, modalHeader, modalPanel, modalTitle, modeBadge, mono, pageBody } from '../ui/classes';

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
    framework: 'Scikit-Learn (Random Forest) / C++',
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
    framework: 'PyShark / C++ / pcap',
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
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Overview Status Banner */}
      <motion.div
        variants={itemVariants}
        className={cn(card, 'mb-6 border-l-[4px] border-l-benign')}

      >
        <div className={cardHeader}>
          <div className={cardTitle}>
            <HeartPulse size={18} color="var(--color-benign)" />
            <span>Local SOC Diagnostic Health</span>
          </div>
          <span
            className={cn(mono, 'text-[0.78rem] font-bold py-[0.3rem] px-3 rounded-[6px] flex items-center gap-[0.45rem]', (health?.status === 'ok' ? 'bg-benign-bg' : 'bg-med-bg'), (health?.status === 'ok' ? 'text-benign' : 'text-med'), 'border', health?.status === 'ok' ? 'border-benign' : 'border-med')}
          >
            {health?.status === 'ok' && <span className="inline-block size-[8px] animate-pulse-green rounded-[50%] bg-benign" />}
            {health?.status === 'ok' ? 'ALL SYSTEMS NOMINAL' : health?.status?.toUpperCase() || 'UNKNOWN'}
          </span>
        </div>

        <p className="text-[0.82rem] text-fg-2 leading-[1.5] m-0">
          All diagnostics are polled locally from in-process backend engines. No external cloud dependencies, external telemetry, or remote telemetry feeds are contacted.
        </p>
      </motion.div>

      {/* Subsystem Component Health Grid */}
      <motion.div
        variants={itemVariants}
        className="grid grid-cols-[repeat(auto-fit,minmax(280px,1fr))] gap-5 mb-6"
      >
        {/* 1. FastAPI Core */}
        <div className={cn(card, clickableCard)} onClick={() => setSelectedCard('api')}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Server size={16} color="var(--color-accent)" />
              <span>API Gateway</span>
            </div>
            {health ? (
              <CheckCircle2 size={16} color="var(--color-benign)" />
            ) : (
              <AlertOctagon size={16} color="var(--color-crit)" />
            )}
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>API Version</span>
              <span className={cn(mono, kvValue)}>{health?.version || '1.1.0'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Environment</span>
              <span className={cn(mono, kvValue)}>{systemStatus?.environment || 'local'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Local Only</span>
              <span className={kvValue}>{health?.local_only ? 'True (Air-Gapped)' : 'False'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Server Uptime</span>
              <span className={cn(mono, kvValue)}>
                {liveUptime !== null
                  ? formatUptime(liveUptime)
                  : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        {/* 2. SQLite Local Database */}
        <div className={cn(card, clickableCard)} onClick={() => setSelectedCard('sqlite')}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Database size={16} color="var(--color-accent)" />
              <span>Local Storage (SQLite)</span>
            </div>
            {health?.database_connected ? (
              <CheckCircle2 size={16} color="var(--color-benign)" />
            ) : (
              <AlertOctagon size={16} color="var(--color-crit)" />
            )}
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>DB Connection</span>
              <span className={cn(kvValue, (health?.database_connected ? 'text-benign' : 'text-crit'))}>
                {health?.database_connected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <div className={cn(kvItem, '[grid-column:1_/_-1]')}>
              <span className={kvLabel}>Database Path</span>
              <span className={cn(mono, kvValue, 'text-[0.75rem]')}>
                {systemStatus?.database_path || 'cipher.db'}
              </span>
            </div>
          </div>
        </div>

        {/* 3. Phishing ML Subsystem */}
        <div className={cn(card, clickableCard)} onClick={() => setSelectedCard('phishing_ml')}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Cpu size={16} color="var(--color-accent)" />
              <span>Phishing ML Subsystem</span>
            </div>
            {health?.model_loaded ? (
              <CheckCircle2 size={16} color="var(--color-benign)" />
            ) : (
              <AlertOctagon size={16} color="var(--color-med)" />
            )}
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>Model Status</span>
              <span className={kvValue}>
                {health?.model_loaded ? 'Loaded (Pre-warmed)' : 'Not Loaded'}
              </span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Model Version</span>
              <span className={cn(mono, kvValue)}>{systemStatus?.model_version || 'phiusiil-rf-v1'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Features Extracted</span>
              <span className={cn(mono, kvValue)}>{systemStatus?.feature_count || 28} lexical features</span>
            </div>
          </div>
        </div>

        {/* 4. Network IDS Subsystem */}
        <div className={cn(card, clickableCard)} onClick={() => setSelectedCard('network_ids')}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Cpu size={16} color="var(--color-accent)" />
              <span>Network IDS Subsystem</span>
            </div>
            {netHealth?.model_loaded ? (
              <CheckCircle2 size={16} color="var(--color-benign)" />
            ) : (
              <AlertOctagon size={16} color="var(--color-med)" />
            )}
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>Model Status</span>
              <span className={kvValue}>
                {netHealth?.model_loaded ? 'Dual RF Gate Active' : 'Not Loaded'}
              </span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>CIC Features</span>
              <span className={cn(mono, kvValue)}>{netHealth?.feature_count || 67} features</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Model Version</span>
              <span className={cn(mono, kvValue)}>{netHealth?.model_version || 'cicids2017-dual-rf-v1'}</span>
            </div>
          </div>
        </div>

        {/* 5. IPS Prevention Engine */}
        <div className={cn(card, clickableCard)} onClick={() => setSelectedCard('ips')}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Shield size={16} color="var(--color-accent)" />
              <span>Prevention Engine (IPS)</span>
            </div>
            <span className={modeBadge(netHealth?.prevention_mode || 'enforce')}>
              {(netHealth?.prevention_mode || 'enforce').replace('_', ' ')}
            </span>
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>Current Mode</span>
              <span className={cn(mono, kvValue)}>{netHealth?.prevention_mode || 'enforce'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Rate Limiter</span>
              <span className={kvValue}>Sliding Window Active</span>
            </div>
          </div>
        </div>

        {/* 6. Live Packet Sensor */}
        <div className={cn(card, clickableCard)} onClick={() => setSelectedCard('sensor')}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Radio size={16} color="var(--color-accent)" />
              <span>Packet Capture Sensor</span>
            </div>
            <span className={modeBadge(sensorStatus?.running ? 'detect_only' : 'simulate')}>
              {sensorStatus?.running ? 'RUNNING' : 'STOPPED'}
            </span>
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>Interface</span>
              <span className={cn(mono, kvValue)}>{sensorStatus?.interface || 'Unbound'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Packets Captured</span>
              <span className={cn(mono, kvValue)}>{sensorStatus?.packets_captured ?? 0}</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Detailed Component Modal */}
      {selectedCard && SYSTEM_DETAILS[selectedCard] && (
        <div className="fixed top-0 left-0 z-[9999] flex h-screen w-screen items-center justify-center bg-[rgba(11,11,11,0.85)] [backdrop-filter:blur(2px)]" onClick={() => setSelectedCard(null)}>
          <div className={modalPanel} onClick={(e) => e.stopPropagation()}>
            <div className={modalHeader}>
              <h2 className={modalTitle}>{SYSTEM_DETAILS[selectedCard].title}</h2>
              <button className="m-0 cursor-pointer border-none bg-transparent p-0 text-[1.5rem] leading-none text-fg-2 hover:text-accent" onClick={() => setSelectedCard(null)}>
                &times;
              </button>
            </div>
            
            <div className={modalBody}>
              <p className="mb-6 text-[0.9rem] leading-[1.5] text-fg-2">{SYSTEM_DETAILS[selectedCard].description}</p>
              
              <div className="mb-6 last:mb-0 [&_h3]:mb-[0.85rem] [&_h3]:border-b [&_h3]:border-b-line [&_h3]:pb-2 [&_h3]:text-[0.85rem] [&_h3]:tracking-[0.05em] [&_h3]:text-accent [&_h3]:uppercase">
                <h3>Technical Details</h3>
                <div className={cn(kvGrid, 'mb-4')}>
                  <div className={kvItem}>
                    <span className={kvLabel}>Framework / Tech</span>
                    <span className={cn(mono, kvValue)}>{SYSTEM_DETAILS[selectedCard].framework}</span>
                  </div>
                  <div className={kvItem}>
                    <span className={kvLabel}>Trained Dataset</span>
                    <span className={cn(mono, kvValue)}>{SYSTEM_DETAILS[selectedCard].dataset}</span>
                  </div>
                </div>
              </div>

              <div className="mb-6 last:mb-0 [&_h3]:mb-[0.85rem] [&_h3]:border-b [&_h3]:border-b-line [&_h3]:pb-2 [&_h3]:text-[0.85rem] [&_h3]:tracking-[0.05em] [&_h3]:text-accent [&_h3]:uppercase">
                <h3>Capabilities & Extracted Features ({SYSTEM_DETAILS[selectedCard].features.length})</h3>
                <div className="flex flex-wrap gap-2">
                  {SYSTEM_DETAILS[selectedCard].features.map((feature, idx) => (
                    <div key={idx} className="rounded-[4px] border border-line bg-app px-[0.65rem] py-[0.35rem] font-mono text-[0.75rem] text-fg">
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
