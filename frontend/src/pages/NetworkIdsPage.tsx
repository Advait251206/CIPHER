import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  NetworkModelInfoResponse,
  NetworkStatsResponse,
  NetworkHealthResponse,
  SecurityEventItem,
  SensorStatusResponse,
  NetworkInterfaceItem,
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


  // Live Sensor Control State
  const [sensorStatus, setSensorStatus] = useState<SensorStatusResponse | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceItem[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [sensorError, setSensorError] = useState<string | null>(null);
  const [isSensorLoading, setIsSensorLoading] = useState(false);

  const fetchSensorData = async () => {
    try {
      const [ifacesRes, statusRes] = await Promise.all([
        api.network.getInterfaces(),
        api.network.getSensorStatus(),
      ]);
      setInterfaces(ifacesRes.interfaces);
      setSensorStatus(statusRes);
      if (ifacesRes.interfaces.length > 0 && !selectedInterface) {
        // Pre-select active interface or first
        if (statusRes.is_running && statusRes.interface) {
          setSelectedInterface(statusRes.interface);
        } else {
          setSelectedInterface(ifacesRes.interfaces[0].name);
        }
      }
    } catch (err: any) {
      setSensorError(err.message || 'Failed to fetch sensor data.');
    }
  };

  useEffect(() => {
    fetchSensorData();
  }, []);

  // Poll sensor status every 2 seconds if it's running
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (sensorStatus?.is_running) {
      interval = setInterval(async () => {
        try {
          const res = await api.network.getSensorStatus();
          setSensorStatus(res);
        } catch {
          // ignore polling errors
        }
      }, 2000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [sensorStatus?.is_running]);

  const handleToggleSensor = async () => {
    try {
      setIsSensorLoading(true);
      setSensorError(null);
      if (sensorStatus?.is_running) {
        const res = await api.network.stopSensor();
        setSensorStatus(res);
      } else {
        if (!selectedInterface) throw new Error('No interface selected.');
        const res = await api.network.startSensor({ interface: selectedInterface });
        setSensorStatus(res);
      }
    } catch (err: any) {
      setSensorError(err.message || 'Failed to toggle sensor.');
    } finally {
      setIsSensorLoading(false);
    }
  };




  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >

      {/* Live Sensor Control Panel */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Radio size={16} color={sensorStatus?.is_running ? 'var(--accent-green)' : 'var(--text-muted)'} />
            <span>Live Network Sensor Control</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {sensorStatus?.is_running ? (
              <span className="nav-badge active" style={{ fontSize: '0.65rem', animation: 'pulse 2s infinite' }}>CAPTURING</span>
            ) : (
              <span className="nav-badge" style={{ fontSize: '0.65rem' }}>STOPPED</span>
            )}
          </div>
        </div>

        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
          Select a local network interface to begin real-time flow aggregation and ML intrusion detection inference.
        </p>

        <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ margin: 0, flex: 1, minWidth: '200px' }}>
            <label className="form-label">Network Interface</label>
            <select
              className="form-select mono"
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={sensorStatus?.is_running || isSensorLoading}
            >
              {interfaces.map(iface => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} - {iface.description} {iface.ipv4_addresses.length > 0 ? `(${iface.ipv4_addresses[0]})` : ''}
                </option>
              ))}
            </select>
          </div>
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className={`control-btn ${sensorStatus?.is_running ? 'danger' : 'primary'}`}
            onClick={handleToggleSensor}
            disabled={isSensorLoading || interfaces.length === 0}
            style={{ padding: '0.65rem 1.25rem', height: '42px', fontWeight: 600 }}
          >
            {isSensorLoading ? (
              <span>Processing...</span>
            ) : sensorStatus?.is_running ? (
              <>
                <Flame size={16} />
                <span>Stop Sensor</span>
              </>
            ) : (
              <>
                <Play size={16} />
                <span>Start Live Capture</span>
              </>
            )}
          </motion.button>
        </div>

        {sensorError && (
          <div className="alert-box danger" style={{ marginBottom: '1.5rem' }}>
            <AlertTriangle size={16} />
            <span>{sensorError}</span>
          </div>
        )}

        {/* Live Metrics Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.85rem' }}>
          <div style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '0.25rem' }}>Packets Captured</div>
            <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              {sensorStatus?.packets_captured?.toLocaleString() || '0'}
            </div>
          </div>
          <div style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '0.25rem' }}>Flows Analyzed</div>
            <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-blue)' }}>
              {sensorStatus?.analyzed_flows?.toLocaleString() || '0'}
            </div>
          </div>
          <div style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '0.25rem' }}>Attacks Detected</div>
            <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: sensorStatus?.detected_attacks ? 'var(--crit-color)' : 'var(--benign-color)' }}>
              {sensorStatus?.detected_attacks?.toLocaleString() || '0'}
            </div>
          </div>
          <div style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '0.25rem' }}>Time Active</div>
            <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              {sensorStatus?.is_running && sensorStatus.started_at
                ? Math.floor((new Date().getTime() - new Date(sensorStatus.started_at).getTime()) / 60000) + ' min'
                : 'Offline'}
            </div>
          </div>
        </div>
      </motion.div>

      {/* Event Detail Modal */}
      <EventDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </motion.div>
  );
};
