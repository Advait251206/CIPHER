import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  NetworkModelInfoResponse,
  NetworkStatsResponse,
  NetworkHealthResponse,
  NetworkDetectionResponse,
  SecurityEventItem,
} from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { EventDetailModal } from '../components/events/EventDetailModal';
import {
  Network,
  Cpu,
  BookOpen,
  Radio,
  Play,
  CheckCircle,
  AlertTriangle,
  Activity,
  Zap,
  Flame,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Server,
  Layers,
  Sparkles,
  Award,
  Info,
  TrendingUp,
  SlidersHorizontal,
  Target,
  BarChart3,
  HelpCircle,
} from 'lucide-react';
import { motion, AnimatePresence, type Variants } from 'framer-motion';

interface FeatureIntelligence {
  name: string;
  category: 'geometry' | 'volume' | 'timing' | 'tcp';
  categoryLabel: string;
  humanTitle: string;
  description: string;
  attackRelevance: string;
  baselineContext: string;
}

const FEATURE_KNOWLEDGE: Record<string, Omit<FeatureIntelligence, 'name'>> = {
  'Bwd Packet Length Std': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Backward Packet Length Std Dev',
    description: 'Measures dispersion and jitter in the size of return packets sent by the destination server.',
    attackRelevance: 'Crucial for detecting DoS floods (low variance, 0-byte ACKs) vs asymmetric C2 data exfiltration.',
    baselineContext: 'Benign HTTPS typically shows moderate standard deviation (200-800 bytes) due to varied web resources.',
  },
  'Fwd Packet Length Max': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Max Forward Packet Length',
    description: 'The peak byte length of any single packet transmitted from the source initiator.',
    attackRelevance: 'Flags oversized exploit delivery, SQL injection / buffer overflow buffers, and file upload spikes.',
    baselineContext: 'Standard SYN scan probes have max length of 0 to 40 bytes; legitimate uploads reach standard 1500 byte MTU.',
  },
  'Avg Fwd Segment Size': {
    category: 'tcp',
    categoryLabel: 'TCP Framing',
    humanTitle: 'Average Forward Segment Size',
    description: 'Mean TCP segment payload size dispatched by the client during transmission windows.',
    attackRelevance: 'Differentiates rapid reconnaissance scanners (Nmap SYN scan) from complete application payloads.',
    baselineContext: 'Reconnaissance tools typically negotiate tiny or zero-byte segment sizes to minimize bandwidth footprint.',
  },
  'Subflow Fwd Bytes': {
    category: 'volume',
    categoryLabel: 'Flow Volume',
    humanTitle: 'Forward Subflow Byte Volume',
    description: 'Total cumulative bytes dispatched in forward subflow clusters within the session.',
    attackRelevance: 'Identifies volumetric DoS/DDoS flooding and credential stuffing bursts targeting authentication endpoints.',
    baselineContext: 'Normal API queries transmit under 2 KB per subflow; brute force replay pushes megabytes per second.',
  },
  'Fwd Packet Length Mean': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Mean Forward Packet Length',
    description: 'Average packet payload size in the forward transmission direction.',
    attackRelevance: 'Delineates automated scripted bot requests from legitimate interactive human web browsing.',
    baselineContext: 'Scripted bots generate rigid, uniform packet lengths; human browsing produces diverse dynamic averages.',
  },
  'Total Length of Fwd Packets': {
    category: 'volume',
    categoryLabel: 'Flow Volume',
    humanTitle: 'Total Forward Packet Bytes',
    description: 'Sum total of all payload bytes transferred from source initiator to target server.',
    attackRelevance: 'Key signature for detecting bulk data exfiltration and large volumetric pipe saturation attempts.',
    baselineContext: 'Alerts trigger when outbound client bytes drastically outnumber inbound server response bytes.',
  },
  'Packet Length Variance': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Bidirectional Packet Length Variance',
    description: 'Statistical spread of packet lengths across both forward and backward communication channels.',
    attackRelevance: 'Extreme uniformity (variance ~ 0) indicates automated SYN/UDP floods, while extreme variance flags exfiltration.',
    baselineContext: 'Interactive TLS flows exhibit diverse packet sizes resulting in high healthy variance.',
  },
  'Packet Length Std': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Bidirectional Packet Length Std Dev',
    description: 'Standard deviation of all observed packet sizes across the entire bidirectional conversation.',
    attackRelevance: 'Provides normalized sensitivity to burst-type anomalies and automated attack scripts.',
    baselineContext: 'A sudden plunge towards zero standard deviation during high packet rates is a textbook DoS indicator.',
  },
  'Bwd Packet Length Mean': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Mean Backward Packet Length',
    description: 'Average size of response packets dispatched from the target server back to the client.',
    attackRelevance: 'Separates server HTTP 404/403 scan error responses from successful file downloads and payload execution.',
    baselineContext: 'Web directory enumeration attacks generate clusters of uniform small error payloads (100-300 bytes).',
  },
  'Average Packet Size': {
    category: 'geometry',
    categoryLabel: 'Packet Geometry',
    humanTitle: 'Mean Global Packet Size',
    description: 'Global mean byte length computed across every single packet recorded in the bidirectional flow.',
    attackRelevance: 'Primary baseline gauge for overall traffic profile classification in the Random Forest model.',
    baselineContext: 'Serves as the root scaling factor against which individual directional means are compared.',
  },
  'Idle Min': {
    category: 'timing',
    categoryLabel: 'Temporal & Idle',
    humanTitle: 'Minimum Flow Idle Silence',
    description: 'The shortest measured duration of inactivity between consecutive packet bursts.',
    attackRelevance: 'Detects programmed periodic beaconing intervals characteristic of C2 trojans and botnet implants.',
    baselineContext: 'Human web sessions have irregular, stochastic idle times; malware agents operate on timed loops.',
  },
  'Idle Mean': {
    category: 'timing',
    categoryLabel: 'Temporal & Idle',
    humanTitle: 'Mean Flow Idle Duration',
    description: 'Average duration of silent intervals across the entire lifetime of the TCP connection.',
    attackRelevance: 'Reveals long-dwell persistent backdoors maintaining stealthy dormant connections.',
    baselineContext: 'Benign connections close quickly or maintain short standard keep-alives (15-60s).',
  },
  'Init_Win_bytes_backward': {
    category: 'tcp',
    categoryLabel: 'TCP Framing',
    humanTitle: 'Responder Initial Window Size',
    description: 'Initial TCP receive window size (in bytes) advertised by the responder in its SYN-ACK response.',
    attackRelevance: 'Used for passive OS TCP/IP stack fingerprinting and detecting spoofed SYN-ACK reflections.',
    baselineContext: 'Windows, Linux, and FreeBSD OS kernels advertise distinct initial default window sizes.',
  },
  'Idle Max': {
    category: 'timing',
    categoryLabel: 'Temporal & Idle',
    humanTitle: 'Maximum Flow Idle Silence',
    description: 'The longest silent period recorded between packet exchanges in the connection.',
    attackRelevance: 'Identifies slow-rate exfiltration channels and dormant APT implants evading volumetric thresholds.',
    baselineContext: 'Extended idle gaps exceeding 300 seconds indicate either persistent tunnels or abandoned sockets.',
  },
  'Subflow Bwd Bytes': {
    category: 'volume',
    categoryLabel: 'Flow Volume',
    humanTitle: 'Backward Subflow Byte Volume',
    description: 'Total volume of bytes returned by the server inside partitioned subflow intervals.',
    attackRelevance: 'Detects amplification attacks (DNS, NTP, SNMP) where minute requests generate massive response flows.',
    baselineContext: 'Normal web traffic shows 1:3 to 1:10 request-to-response ratio; amplification exceeds 1:50.',
  },
};

function getFeatureInfo(featureName: string): FeatureIntelligence {
  if (FEATURE_KNOWLEDGE[featureName]) {
    return { name: featureName, ...FEATURE_KNOWLEDGE[featureName] };
  }
  const lower = featureName.toLowerCase();
  let category: 'geometry' | 'volume' | 'timing' | 'tcp' = 'geometry';
  let categoryLabel = 'Packet Geometry';
  if (lower.includes('byte') || lower.includes('vol') || lower.includes('length of fwd')) {
    category = 'volume';
    categoryLabel = 'Flow Volume';
  } else if (lower.includes('idle') || lower.includes('iat') || lower.includes('time') || lower.includes('duration')) {
    category = 'timing';
    categoryLabel = 'Temporal & Idle';
  } else if (lower.includes('win') || lower.includes('flag') || lower.includes('seg') || lower.includes('port')) {
    category = 'tcp';
    categoryLabel = 'TCP Framing';
  }
  return {
    name: featureName,
    category,
    categoryLabel,
    humanTitle: featureName.replace(/_/g, ' '),
    description: 'Statistical flow metric computed during CIC-IDS2017 bidirectional session reconstruction.',
    attackRelevance: 'Evaluated across 100 decision trees to detect behavioral anomalies in network traffic.',
    baselineContext: 'Serves as an input feature for Random Forest Gini impurity reduction split points.',
  };
}

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.05,
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

export const NetworkIdsPage: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<NetworkModelInfoResponse | null>(null);
  const [netStats, setNetStats] = useState<NetworkStatsResponse | null>(null);
  const [netHealth, setNetHealth] = useState<NetworkHealthResponse | null>(null);
  const [recentNetworkEvents, setRecentNetworkEvents] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Flow testing sandbox
  const [testSourceIp, setTestSourceIp] = useState('192.168.1.150');
  const [testDestIp, setTestDestIp] = useState('192.168.1.1');
  const [testDestPort, setTestDestPort] = useState(80);
  const [testProtocol, setTestProtocol] = useState('TCP');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [testResult, setTestResult] = useState<NetworkDetectionResponse | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  // Inspector modal
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);

  // Model Features Interpretability state
  const [featureCategory, setFeatureCategory] = useState<'all' | 'geometry' | 'volume' | 'timing' | 'tcp'>('all');
  const [inspectedFeatureName, setInspectedFeatureName] = useState<string | null>(null);

  const fetchNetworkData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [modelRes, statsRes, healthRes, eventsRes] = await Promise.allSettled([
        api.network.getModelInfo(),
        api.network.getStats(),
        api.network.getHealth(),
        api.network.getBlocklist('ACTIVE'),
      ]);

      if (modelRes.status === 'fulfilled') setModelInfo(modelRes.value);
      if (statsRes.status === 'fulfilled') setNetStats(statsRes.value);
      if (healthRes.status === 'fulfilled') setNetHealth(healthRes.value);

      // Also fetch recent network events from backend
      try {
        const evRes = await api.events.list({ event_type: 'NETWORK', limit: 10 });
        setRecentNetworkEvents(evRes.events);
      } catch {
        // Soft fallback
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load Network IDS subsystem data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNetworkData();
  }, []);

  const handleTestFlow = async (presetType?: 'benign' | 'port_scan' | 'dos' | 'ssh_brute_force' | 'udp_flood') => {
    try {
      setIsAnalyzing(true);
      setTestError(null);
      setTestResult(null);

      let features: Record<string, number> = {};
      let srcIp = testSourceIp;
      let dstIp = testDestIp;
      let dstPort = testDestPort;
      let proto = testProtocol;

      if (presetType === 'port_scan') {
        srcIp = '10.0.0.99';
        dstIp = '192.168.1.5';
        dstPort = 22;
        proto = 'TCP';
        setTestSourceIp(srcIp);
        setTestDestIp(dstIp);
        setTestDestPort(dstPort);
        setTestProtocol(proto);
        features = {
          'Destination Port': 22,
          'Flow Duration': 500,
          'Total Fwd Packets': 1,
          'Total Backward Packets': 0,
          'SYN Flag Count': 1,
          'ACK Flag Count': 0,
          'Fwd Packets/s': 2000,
        };
      } else if (presetType === 'dos') {
        srcIp = '172.16.0.45';
        dstIp = '192.168.1.10';
        dstPort = 80;
        proto = 'TCP';
        setTestSourceIp(srcIp);
        setTestDestIp(dstIp);
        setTestDestPort(dstPort);
        setTestProtocol(proto);
        features = {
          'Destination Port': 80,
          'Flow Duration': 10000,
          'Total Fwd Packets': 5000,
          'Total Backward Packets': 5,
          'Fwd Packets/s': 500000,
          'Flow Bytes/s': 6000000,
          'Down/Up Ratio': 0,
        };
      } else if (presetType === 'ssh_brute_force') {
        srcIp = '185.220.101.5';
        dstIp = '192.168.1.20';
        dstPort = 22;
        proto = 'TCP';
        setTestSourceIp(srcIp);
        setTestDestIp(dstIp);
        setTestDestPort(dstPort);
        setTestProtocol(proto);
        features = {
          'Destination Port': 22,
          'Flow Duration': 45000,
          'Total Fwd Packets': 120,
          'Total Backward Packets': 95,
          'Fwd Packet Length Mean': 128,
          'Bwd Packet Length Mean': 96,
          'Fwd Packets/s': 260,
        };
      } else if (presetType === 'udp_flood') {
        srcIp = '45.142.212.8';
        dstIp = '192.168.1.1';
        dstPort = 53;
        proto = 'UDP';
        setTestSourceIp(srcIp);
        setTestDestIp(dstIp);
        setTestDestPort(dstPort);
        setTestProtocol(proto);
        features = {
          'Destination Port': 53,
          'Flow Duration': 2500,
          'Total Fwd Packets': 3500,
          'Total Backward Packets': 0,
          'Fwd Packets/s': 1400000,
          'Flow Bytes/s': 85000000,
        };
      } else {
        // Benign flow
        srcIp = '192.168.1.150';
        dstIp = '192.168.1.1';
        dstPort = 443;
        proto = 'TCP';
        setTestSourceIp(srcIp);
        setTestDestIp(dstIp);
        setTestDestPort(dstPort);
        setTestProtocol(proto);
        features = {
          'Destination Port': 443,
          'Flow Duration': 120000,
          'Total Fwd Packets': 15,
          'Total Backward Packets': 18,
          'Fwd Packet Length Mean': 250,
          'Bwd Packet Length Mean': 850,
          'Fwd Packets/s': 125,
        };
      }

      const res = await api.network.analyze({
        source_ip: srcIp,
        destination_ip: dstIp,
        source_port: 49152,
        destination_port: dstPort,
        protocol: proto,
        features,
      });

      setTestResult(res);
      // Also refresh recent network events list
      try {
        const evRes = await api.events.list({ event_type: 'NETWORK', limit: 10 });
        setRecentNetworkEvents(evRes.events);
      } catch {
        // non-blocking
      }
    } catch (err: any) {
      setTestError(err.message || 'Flow evaluation failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  if (loading) {
    return <LoadingState message="Loading Network IDS parameters..." />;
  }

  if (error && !modelInfo && !netHealth) {
    return <ErrorState title="Network IDS Unavailable" error={error} onRetry={fetchNetworkData} />;
  }
  const allTopFeatures = Object.entries(modelInfo?.top_features || {})
    .sort(([, a], [, b]) => b - a)
    .map(([feature, weight], idx) => ({
      name: feature,
      weight,
      rank: idx + 1,
      info: getFeatureInfo(feature),
    }));

  const maxFeatureWeight = allTopFeatures[0]?.weight || 0.05;
  const meanFeatureWeight = allTopFeatures.length > 0
    ? allTopFeatures.reduce((acc, f) => acc + f.weight, 0) / allTopFeatures.length
    : 0.03;
  const totalCapturedWeight = allTopFeatures.reduce((acc, f) => acc + f.weight, 0);

  const top3Podium = allTopFeatures.slice(0, 3);

  const filteredFeaturesList = allTopFeatures.filter(
    (f) => featureCategory === 'all' || f.info.category === featureCategory
  );

  const activeInspectedFeature = allTopFeatures.find(
    (f) => f.name === (inspectedFeatureName || allTopFeatures[0]?.name)
  ) || allTopFeatures[0];

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Real-World Model Disclaimer Alert */}
      <motion.div variants={itemVariants} className="alert-box info">
        <Network size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Detection Engine Architecture:</strong> CIPHER employs a multi-tiered approach:
          (1) Model-Based Inference using a Dual Random Forest trained on CIC-IDS2017,
          (2) Deterministic Flow Heuristics, and
          (3) Live Packet Aggregation.
          <em> Real-world live capture accuracy may vary based on flow duration and host network telemetry.</em>
        </div>
      </motion.div>

      {/* Model Metadata Cards (dynamically populated from backend) */}
      <motion.div
        variants={itemVariants}
        style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem', marginBottom: '1.5rem' }}
      >
        {/* Model Architecture & Runtime */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={16} color="var(--accent-cyan)" />
              <span>Machine Learning Architecture</span>
            </div>
            <span className={`mode-badge ${netHealth?.model_loaded ? 'detect_only' : 'simulate'}`}>
              {netHealth?.model_loaded ? 'LOADED' : 'UNAVAILABLE'}
            </span>
          </div>
          {modelInfo ? (
            <div className="kv-grid">
              <div className="kv-item">
                <span className="kv-label">Model Name</span>
                <span className="kv-value">{modelInfo.model_name}</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Architecture</span>
                <span className="kv-value">{modelInfo.model_architecture}</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Training Dataset</span>
                <span className="kv-value mono">{modelInfo.dataset}</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Engine Features</span>
                <span className="kv-value mono">{modelInfo.feature_count} features</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Supported Classes</span>
                <span className="kv-value">{modelInfo.classes?.length ?? 0} attack categories</span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Dataset Split</span>
                <span className="kv-value mono">
                  {modelInfo.training_samples?.toLocaleString() ?? 'N/A'} train /{' '}
                  {modelInfo.test_samples?.toLocaleString() ?? 'N/A'} test
                </span>
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              Model metadata response not available from backend.
            </div>
          )}
        </div>

        {/* Held-Out Test Evaluation Metrics (Backend Sourced) */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} color="var(--benign-color)" />
              <span>Held-Out Test Metrics</span>
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>CIC-IDS2017 Test Set</span>
          </div>
          {modelInfo?.binary_metrics ? (
            <div className="kv-grid">
              <div className="kv-item">
                <span className="kv-label">Binary Gate Accuracy</span>
                <span className="kv-value mono" style={{ color: 'var(--benign-color)' }}>
                  {modelInfo.binary_metrics.accuracy !== undefined
                    ? `${(modelInfo.binary_metrics.accuracy * 100).toFixed(3)}%`
                    : 'N/A'}
                </span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Binary Precision</span>
                <span className="kv-value mono">
                  {modelInfo.binary_metrics.precision !== undefined
                    ? `${(modelInfo.binary_metrics.precision * 100).toFixed(3)}%`
                    : 'N/A'}
                </span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Binary Recall</span>
                <span className="kv-value mono">
                  {modelInfo.binary_metrics.recall !== undefined
                    ? `${(modelInfo.binary_metrics.recall * 100).toFixed(3)}%`
                    : 'N/A'}
                </span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Binary F1-Score</span>
                <span className="kv-value mono">
                  {modelInfo.binary_metrics.f1 !== undefined
                    ? `${(modelInfo.binary_metrics.f1 * 100).toFixed(3)}%`
                    : 'N/A'}
                </span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Multiclass Macro F1</span>
                <span className="kv-value mono">
                  {modelInfo.multiclass_metrics?.macro_f1 !== undefined
                    ? `${(modelInfo.multiclass_metrics.macro_f1 * 100).toFixed(2)}%`
                    : 'N/A'}
                </span>
              </div>
              <div className="kv-item">
                <span className="kv-label">Multiclass Weighted F1</span>
                <span className="kv-value mono">
                  {modelInfo.multiclass_metrics?.weighted_f1 !== undefined
                    ? `${(modelInfo.multiclass_metrics.weighted_f1 * 100).toFixed(2)}%`
                    : 'N/A'}
                </span>
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              Evaluation metrics not returned by <code>/api/network/model</code>.
            </div>
          )}
        </div>
      </motion.div>

      {/* Top Model Features by Importance */}
      {modelInfo?.top_features && Object.keys(modelInfo.top_features).length > 0 && (
        <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <div className="card-title">
              <BookOpen size={16} color="var(--accent-cyan)" />
              <span>Top Model Features by Importance</span>
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Gini impurity decrease · CIC-IDS2017 · {Object.keys(modelInfo.top_features).length} features shown
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
            {Object.entries(modelInfo.top_features)
              .sort(([, a], [, b]) => b - a)
              .map(([feature, weight], idx) => {
                const maxWeight = Object.values(modelInfo.top_features).reduce((m, v) => Math.max(m, v), 0);
                const barWidth = Math.min(100, (weight / maxWeight) * 100);
                const isTop3 = idx < 3;
                const barColor =
                  idx === 0 ? 'linear-gradient(90deg, #0284c7, #06b6d4)' :
                  idx === 1 ? 'linear-gradient(90deg, #4f46e5, #818cf8)' :
                  idx === 2 ? 'linear-gradient(90deg, #059669, #34d399)' :
                  'linear-gradient(90deg, #64748b, #94a3b8)';
                const rankBadgeColor =
                  idx === 0 ? { bg: '#eff6ff', color: '#0284c7', border: '#bfdbfe' } :
                  idx === 1 ? { bg: '#eef2ff', color: '#4f46e5', border: '#c7d2fe' } :
                  idx === 2 ? { bg: '#ecfdf5', color: '#059669', border: '#a7f3d0' } :
                  { bg: '#f8fafc', color: '#64748b', border: '#e2e8f0' };

                return (
                  <motion.div
                    key={feature}
                    whileHover={{ y: -2, boxShadow: '0 6px 18px rgba(15,23,42,0.09)' }}
                    transition={{ duration: 0.18 }}
                    style={{
                      background: '#ffffff',
                      padding: '0.85rem 1rem',
                      borderRadius: '10px',
                      border: isTop3 ? `1px solid ${rankBadgeColor.border}` : '1px solid var(--border-subtle)',
                      boxShadow: '0 1px 4px rgba(15,23,42,0.05)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.55rem',
                      cursor: 'default',
                    }}
                  >
                    {/* Top row: rank badge + weight value */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{
                        fontSize: '0.65rem',
                        fontWeight: 800,
                        fontFamily: 'var(--font-mono)',
                        background: rankBadgeColor.bg,
                        color: rankBadgeColor.color,
                        border: `1px solid ${rankBadgeColor.border}`,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px',
                        letterSpacing: '0.03em',
                      }}>
                        #{String(idx + 1).padStart(2, '0')}
                      </span>
                      <span style={{
                        fontSize: '1rem',
                        fontWeight: 800,
                        fontFamily: 'var(--font-mono)',
                        color: rankBadgeColor.color,
                        lineHeight: 1,
                      }}>
                        {(weight * 100).toFixed(2)}%
                      </span>
                    </div>

                    {/* Feature name */}
                    <div>
                      <div style={{
                        fontSize: '0.8rem',
                        fontWeight: 700,
                        color: 'var(--text-primary)',
                        lineHeight: 1.25,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}>
                        {feature}
                      </div>
                    </div>

                    {/* Gradient bar */}
                    <div style={{ height: '7px', background: '#f1f5f9', borderRadius: '4px', overflow: 'hidden' }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${barWidth}%` }}
                        transition={{ duration: 0.7, delay: idx * 0.04, ease: 'easeOut' }}
                        style={{
                          height: '100%',
                          borderRadius: '4px',
                          background: barColor,
                        }}
                      />
                    </div>
                  </motion.div>
                );
              })}
          </div>
        </motion.div>
      )}
      {/* Flow Analysis Sandbox */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Play size={16} color="var(--accent-blue)" />
            <span>Network Attack Simulation & Flow Analysis Sandbox</span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>POST /api/network/analyze</span>
        </div>

        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
          Evaluate synthetic network flows against the backend dual RF model, heuristic rules, and IPS prevention logic without requiring raw packet injection.
        </p>

        {/* 1-Click Attack Preset Cyber Cards */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Simulation Vectors (1-Click Launch):
            </span>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Click card to load vector and execute</span>
          </div>

          <div className="attack-preset-grid">
            <motion.div
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              className="attack-preset-card danger"
              onClick={() => handleTestFlow('port_scan')}
            >
              <div className="attack-preset-card-top">
                <div className="attack-preset-icon">
                  <Zap size={15} />
                </div>
                <span className="nav-badge danger" style={{ fontSize: '0.65rem' }}>RECON</span>
              </div>
              <div className="attack-preset-title">SYN Port Scan</div>
              <div className="attack-preset-desc">Stealthy service discovery probing open server ports</div>
              <div className="attack-preset-vector">TCP Port 22 / SYN=1</div>
            </motion.div>

            <motion.div
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              className="attack-preset-card danger"
              onClick={() => handleTestFlow('dos')}
            >
              <div className="attack-preset-card-top">
                <div className="attack-preset-icon">
                  <Flame size={15} />
                </div>
                <span className="nav-badge danger" style={{ fontSize: '0.65rem' }}>EXHAUSTION</span>
              </div>
              <div className="attack-preset-title">DoS / TCP SYN Flood</div>
              <div className="attack-preset-desc">High-rate volumetric packet burst to exhaust connection backlog</div>
              <div className="attack-preset-vector">15,000 Pkts/sec</div>
            </motion.div>

            <motion.div
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              className="attack-preset-card warning"
              onClick={() => handleTestFlow('ssh_brute_force')}
            >
              <div className="attack-preset-card-top">
                <div className="attack-preset-icon">
                  <Lock size={15} />
                </div>
                <span className="nav-badge warn" style={{ fontSize: '0.65rem' }}>AUTH BURST</span>
              </div>
              <div className="attack-preset-title">SSH Brute Force</div>
              <div className="attack-preset-desc">Automated credential stuffing and dictionary attack burst</div>
              <div className="attack-preset-vector">Port 22 Dictionary</div>
            </motion.div>

            <motion.div
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              className="attack-preset-card warning"
              onClick={() => handleTestFlow('udp_flood')}
            >
              <div className="attack-preset-card-top">
                <div className="attack-preset-icon">
                  <Radio size={15} />
                </div>
                <span className="nav-badge warn" style={{ fontSize: '0.65rem' }}>UDP BURST</span>
              </div>
              <div className="attack-preset-title">UDP DNS Amplification</div>
              <div className="attack-preset-desc">Non-connection protocol flood targeting DNS resolver</div>
              <div className="attack-preset-vector">UDP Port 53 / 8k pkts</div>
            </motion.div>

            <motion.div
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}
              className="attack-preset-card benign"
              onClick={() => handleTestFlow('benign')}
            >
              <div className="attack-preset-card-top">
                <div className="attack-preset-icon">
                  <ShieldCheck size={15} />
                </div>
                <span className="nav-badge active" style={{ fontSize: '0.65rem' }}>BASELINE</span>
              </div>
              <div className="attack-preset-title">Benign HTTPS Flow</div>
              <div className="attack-preset-desc">Standard balanced bidirectional web application payload</div>
              <div className="attack-preset-vector">Port 443 TLS Session</div>
            </motion.div>
          </div>
        </div>

        {/* Manual Parameter Customization */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '0.75rem',
            background: 'var(--bg-surface-elevated)',
            padding: '0.85rem 1rem',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            marginBottom: '1rem',
          }}
        >
          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label" style={{ fontSize: '0.72rem' }}>Source IP</label>
            <input
              type="text"
              className="form-input mono"
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.6rem' }}
              value={testSourceIp}
              onChange={(e) => setTestSourceIp(e.target.value)}
              disabled={isAnalyzing}
            />
          </div>
          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label" style={{ fontSize: '0.72rem' }}>Destination IP</label>
            <input
              type="text"
              className="form-input mono"
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.6rem' }}
              value={testDestIp}
              onChange={(e) => setTestDestIp(e.target.value)}
              disabled={isAnalyzing}
            />
          </div>
          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label" style={{ fontSize: '0.72rem' }}>Target Port</label>
            <input
              type="number"
              className="form-input mono"
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.6rem' }}
              value={testDestPort}
              onChange={(e) => setTestDestPort(Number(e.target.value))}
              disabled={isAnalyzing}
            />
          </div>
          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label" style={{ fontSize: '0.72rem' }}>Protocol</label>
            <select
              className="form-select mono"
              style={{ fontSize: '0.78rem', padding: '0.35rem 0.6rem' }}
              value={testProtocol}
              onChange={(e) => setTestProtocol(e.target.value)}
              disabled={isAnalyzing}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>
        </div>

        {testError && (
          <div className="alert-box danger" style={{ marginBottom: '1rem' }}>
            <AlertTriangle size={16} />
            <span>{testError}</span>
          </div>
        )}

        {testResult && (
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.99 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.28 }}
            style={{
              background: testResult.is_attack
                ? 'linear-gradient(180deg, #ffffff 0%, #fff5f5 100%)'
                : 'linear-gradient(180deg, #ffffff 0%, #f0fdf4 100%)',
              border: `1px solid ${testResult.is_attack ? 'var(--crit-border)' : 'var(--benign-border)'}`,
              borderRadius: '12px',
              padding: '1.25rem',
              marginBottom: '1.25rem',
              boxShadow: testResult.is_attack
                ? '0 6px 20px -4px rgba(220, 38, 38, 0.12)'
                : '0 6px 20px -4px rgba(22, 163, 74, 0.12)',
            }}
          >
            {/* Verdict Header Banner */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <div
                  style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '50%',
                    background: testResult.is_attack ? 'var(--crit-bg)' : 'var(--benign-bg)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: `1px solid ${testResult.is_attack ? 'var(--crit-border)' : 'var(--benign-border)'}`,
                  }}
                >
                  {testResult.is_attack ? (
                    <ShieldAlert size={20} color="var(--crit-color)" />
                  ) : (
                    <ShieldCheck size={20} color="var(--benign-color)" />
                  )}
                </div>
                <div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 800, color: testResult.is_attack ? 'var(--crit-color)' : 'var(--benign-color)' }}>
                    {testResult.is_attack ? 'MALICIOUS ATTACK FLOW IDENTIFIED' : 'BENIGN NETWORK TRAFFIC VERIFIED'}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Dual Random Forest (CIC-IDS2017) & Heuristic Flow Inspection
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <SeverityBadge severity={testResult.severity} size="md" />
                <span
                  className="mono"
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    padding: '0.2rem 0.6rem',
                    borderRadius: '6px',
                    background: testResult.prevention_action === 'BLOCK' ? 'var(--crit-bg)' : 'var(--bg-surface-elevated)',
                    color: testResult.prevention_action === 'BLOCK' ? 'var(--crit-color)' : 'var(--text-secondary)',
                    border: `1px solid ${testResult.prevention_action === 'BLOCK' ? 'var(--crit-border)' : 'var(--border-subtle)'}`,
                  }}
                >
                  IPS ACTION: {testResult.prevention_action}
                </span>
              </div>
            </div>

            {/* Metrics Breakdown Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', marginBottom: '0.85rem' }}>
              <div style={{ background: '#ffffff', padding: '0.75rem 0.9rem', borderRadius: '8px', border: '1px solid rgba(226, 232, 240, 0.8)' }}>
                <span style={{ fontSize: '0.68rem', textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>Classification</span>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: testResult.is_attack ? 'var(--crit-color)' : 'var(--benign-color)', marginTop: '2px' }}>
                  {testResult.predicted_category}
                </div>
              </div>

              <div style={{ background: '#ffffff', padding: '0.75rem 0.9rem', borderRadius: '8px', border: '1px solid rgba(226, 232, 240, 0.8)' }}>
                <span style={{ fontSize: '0.68rem', textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>Threat Risk Score</span>
                <div className="mono" style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {testResult.risk_score} <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 500 }}>/ 100</span>
                </div>
              </div>

              <div style={{ background: '#ffffff', padding: '0.75rem 0.9rem', borderRadius: '8px', border: '1px solid rgba(226, 232, 240, 0.8)' }}>
                <span style={{ fontSize: '0.68rem', textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>ML Inference Confidence</span>
                <div className="mono" style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--accent-blue)', marginTop: '2px' }}>
                  {(testResult.ml_confidence * 100).toFixed(1)}%
                </div>
              </div>

              <div style={{ background: '#ffffff', padding: '0.75rem 0.9rem', borderRadius: '8px', border: '1px solid rgba(226, 232, 240, 0.8)' }}>
                <span style={{ fontSize: '0.68rem', textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>Target Host Flow</span>
                <div className="mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-secondary)', marginTop: '4px' }}>
                  {testSourceIp} → {testDestIp}:{testDestPort}
                </div>
              </div>
            </div>

            {/* Recommendation & Evidence Guidance */}
            <div style={{ background: '#ffffff', padding: '0.8rem 1rem', borderRadius: '8px', border: '1px solid rgba(226, 232, 240, 0.8)', fontSize: '0.82rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>SOC Action Guidance: </strong>
              <span style={{ color: 'var(--text-secondary)' }}>{testResult.recommendation}</span>
            </div>
          </motion.div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
            className="control-btn primary"
            onClick={() => handleTestFlow()}
            disabled={isAnalyzing}
          >
            <Play size={14} />
            <span>{isAnalyzing ? 'Submitting to Backend...' : 'Analyze Custom Flow'}</span>
          </motion.button>
        </div>
      </motion.div>

      {/* Recent Network Events */}
      {recentNetworkEvents.length > 0 && (
        <motion.div variants={itemVariants} className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} color="var(--accent-cyan)" />
              <span>Recent Network Detection Events</span>
            </div>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Attack Category</th>
                  <th>Risk Score</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentNetworkEvents.map((ev) => (
                  <tr
                    key={ev.event_id}
                    onClick={() => setSelectedEvent(ev)}
                    style={{ cursor: 'pointer' }}
                    title="Inspect event details"
                  >
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{ev.timestamp}</td>
                    <td><SeverityBadge severity={ev.severity} size="sm" /></td>
                    <td><span style={{ fontWeight: 600 }}>{ev.attack_type || ev.classification}</span></td>
                    <td className="mono" style={{ fontWeight: 700 }}>{ev.risk_score}</td>
                    <td className="mono">{ev.source_ip || 'N/A'}</td>
                    <td className="mono">{ev.destination_ip || 'N/A'}</td>
                    <td className="mono">{ev.action || 'ALERT'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}

      {/* Event Detail Modal */}
      <EventDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </motion.div>
  );
};
