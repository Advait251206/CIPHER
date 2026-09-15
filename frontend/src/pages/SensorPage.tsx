import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { NetworkInterfaceItem, SensorStatusResponse } from '../api/types';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { Radio, Play, Square, AlertTriangle, CheckCircle, RefreshCw, Cpu, Activity } from 'lucide-react';
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

interface SensorPageProps {
  refreshTrigger?: number;
}

export const SensorPage: React.FC<SensorPageProps> = ({ refreshTrigger }) => {
  const [interfaces, setInterfaces] = useState<NetworkInterfaceItem[]>([]);
  const [sensorStatus, setSensorStatus] = useState<SensorStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Start Sensor Form
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [bpfFilter, setBpfFilter] = useState<string>('ip or ip6');
  const [flowIdleTimeout, setFlowIdleTimeout] = useState<number>(5);
  const [flowActiveTimeout, setFlowActiveTimeout] = useState<number>(120);

  // Dialogs
  const [isConfirmStartOpen, setIsConfirmStartOpen] = useState(false);
  const [isConfirmStopOpen, setIsConfirmStopOpen] = useState(false);
  const [isOperating, setIsOperating] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const fetchSensorData = async () => {
    try {
      setError(null);
      const [ifacesRes, statusRes] = await Promise.allSettled([
        api.network.getInterfaces(),
        api.network.getSensorStatus(),
      ]);

      if (ifacesRes.status === 'fulfilled') {
        const availableIfaces = ifacesRes.value.interfaces;
        setInterfaces(availableIfaces);
        setSelectedInterface((prev) => {
          if (prev) return prev; // Preserve existing user selection
          // Auto-select active Wi-Fi or interface with valid non-loopback IP
          const bestIface =
            availableIfaces.find(
              (i) => {
                const addr = i.address || i.ip_address;
                return addr && addr !== '127.0.0.1' && !addr.startsWith('169.254');
              }
            ) ||
            availableIfaces.find(
              (i) =>
                i.name.toLowerCase().includes('wi-fi') ||
                (i.description && i.description.toLowerCase().includes('wi-fi'))
            ) ||
            availableIfaces[0];
          return bestIface ? bestIface.name : '';
        });
      }
      if (statusRes.status === 'fulfilled') {
        setSensorStatus(statusRes.value);
        const runningNow = Boolean(statusRes.value.running ?? statusRes.value.is_running);
        if (runningNow && statusRes.value.interface) {
          setSelectedInterface(statusRes.value.interface);
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve sensor state.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSensorData();
    // Refresh telemetry every 3 seconds while sensor page is visible
    const timer = setInterval(() => {
      api.network
        .getSensorStatus()
        .then((s) => setSensorStatus(s))
        .catch(() => {});
    }, 3000);
    return () => clearInterval(timer);
  }, [refreshTrigger]);

  const handleConfirmStart = async () => {
    try {
      setIsOperating(true);
      setError(null);
      const res = await api.network.startSensor({
        interface: selectedInterface,
        bpf_filter: bpfFilter.trim() || undefined,
        flow_idle_timeout: flowIdleTimeout,
        flow_active_timeout: flowActiveTimeout,
      });
      setSensorStatus(res);
      setActionNotice(`Packet capture started on interface '${selectedInterface}'.`);
      setIsConfirmStartOpen(false);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to start live network sensor.');
    } finally {
      setIsOperating(false);
    }
  };

  const handleConfirmStop = async () => {
    try {
      setIsOperating(true);
      setError(null);
      const res = await api.network.stopSensor();
      setSensorStatus(res);
      setActionNotice('Live network sensor gracefully stopped. Remaining flows finalized.');
      setIsConfirmStopOpen(false);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to stop live network sensor.');
    } finally {
      setIsOperating(false);
    }
  };

  if (loading) {
    return <LoadingState message="Loading live sensor telemetry..." />;
  }

  const isRunning = Boolean(sensorStatus?.running ?? sensorStatus?.is_running);

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Privilege & Privacy Disclaimer Banner */}
      <motion.div variants={itemVariants} className="alert-box warning">
        <AlertTriangle size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Npcap & Scapy Live Capture Architecture:</strong> Live packet capture runs in user space through Scapy/Npcap.
          Depending on the Windows interface and Npcap configuration, packet capture may require elevated privileges.
          <em> Notice: CIPHER strictly extracts 67 flow header statistical features and does not store or inspect raw packet payloads.</em>
        </div>
      </motion.div>

      {actionNotice && (
        <motion.div variants={itemVariants} className="alert-box success">
          <CheckCircle size={16} />
          <span>{actionNotice}</span>
        </motion.div>
      )}

      {error && (
        <motion.div variants={itemVariants} className="alert-box danger">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </motion.div>
      )}

      {/* Sensor Status Banner */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Radio size={18} color={isRunning ? 'var(--benign-color)' : 'var(--text-muted)'} />
            <span>Sensor Runtime Telemetry</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span
              className="mono"
              style={{
                fontSize: '0.78rem',
                fontWeight: 700,
                padding: '0.3rem 0.75rem',
                borderRadius: '6px',
                background: isRunning ? 'var(--benign-bg)' : 'var(--bg-surface-elevated)',
                color: isRunning ? 'var(--benign-color)' : 'var(--text-muted)',
                border: `1px solid ${isRunning ? 'var(--benign-border)' : 'var(--border-subtle)'}`,
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
              }}
            >
              {isRunning && <span className="pulse-dot" />}
              {!isRunning && <span className="status-indicator offline" style={{ width: '7px', height: '7px' }} />}
              {isRunning ? 'SENSOR ACTIVE' : 'SENSOR STANDBY'}
            </span>
          </div>
        </div>

        {/* Real-Time Metrics Grid */}
        <div className="telemetry-grid-4" style={{ marginTop: '0.75rem', marginBottom: '1rem' }}>
          <motion.div whileHover={{ y: -2 }} className="telemetry-card">
            <div className="telemetry-card-header">
              <span className="telemetry-card-label">Packets Captured</span>
              <div className="telemetry-card-icon" style={{ color: 'var(--text-primary)' }}>
                <Activity size={16} />
              </div>
            </div>
            <div className="telemetry-card-value">
              {sensorStatus?.packets_captured?.toLocaleString() ?? 0}
            </div>
            <div className="telemetry-card-sub">Raw frames parsed via Scapy</div>
          </motion.div>

          <motion.div whileHover={{ y: -2 }} className="telemetry-card">
            <div className="telemetry-card-header">
              <span className="telemetry-card-label">Active Flows</span>
              <div className="telemetry-card-icon" style={{ color: 'var(--accent-blue)' }}>
                <Radio size={16} />
              </div>
            </div>
            <div className="telemetry-card-value" style={{ color: 'var(--accent-blue)' }}>
              {sensorStatus?.active_flows?.toLocaleString() ?? 0}
            </div>
            <div className="telemetry-card-sub">Sliding-window tracking table</div>
          </motion.div>

          <motion.div whileHover={{ y: -2 }} className="telemetry-card">
            <div className="telemetry-card-header">
              <span className="telemetry-card-label">Finalized Flows</span>
              <div className="telemetry-card-icon" style={{ color: 'var(--benign-color)' }}>
                <CheckCircle size={16} />
              </div>
            </div>
            <div className="telemetry-card-value" style={{ color: 'var(--benign-color)' }}>
              {(sensorStatus?.finalized_flows ?? sensorStatus?.completed_flows ?? 0).toLocaleString()}
            </div>
            <div className="telemetry-card-sub">Exported to Network IDS ML</div>
          </motion.div>

          <motion.div whileHover={{ y: -2 }} className="telemetry-card">
            <div className="telemetry-card-header">
              <span className="telemetry-card-label">Dropped Packets</span>
              <div className="telemetry-card-icon" style={{ color: (sensorStatus?.packets_dropped ?? sensorStatus?.errors) ? 'var(--crit-color)' : 'var(--text-muted)' }}>
                <AlertTriangle size={16} />
              </div>
            </div>
            <div className="telemetry-card-value" style={{ color: (sensorStatus?.packets_dropped ?? sensorStatus?.errors) ? 'var(--crit-color)' : 'var(--text-primary)' }}>
              {(sensorStatus?.packets_dropped ?? sensorStatus?.errors ?? 0).toLocaleString()}
            </div>
            <div className="telemetry-card-sub">Ring buffer overrun count</div>
          </motion.div>
        </div>

        {/* Current Config Details */}
        <div className="kv-grid" style={{ marginTop: '1.25rem' }}>
          <div className="kv-item">
            <span className="kv-label">Bound Interface</span>
            <span className="kv-value mono">{sensorStatus?.interface || 'None'}</span>
          </div>
          <div className="kv-item">
            <span className="kv-label">BPF Filter</span>
            <span className="kv-value mono">{sensorStatus?.bpf_filter || 'None'}</span>
          </div>
          <div className="kv-item">
            <span className="kv-label">Flow Idle Timeout</span>
            <span className="kv-value mono">{sensorStatus?.flow_idle_timeout ?? 5} seconds</span>
          </div>
          <div className="kv-item">
            <span className="kv-label">Flow Active Timeout</span>
            <span className="kv-value mono">{sensorStatus?.flow_active_timeout ?? 120} seconds</span>
          </div>
          <div className="kv-item">
            <span className="kv-label">Started At</span>
            <span className="kv-value mono">{sensorStatus?.started_at || 'Idle'}</span>
          </div>
          <div className="kv-item">
            <span className="kv-label">Default Prevention Safety</span>
            <span className="kv-value mono" style={{ color: 'var(--low-color)' }}>
              {sensorStatus?.prevention_mode || 'detect_only'}
            </span>
          </div>
        </div>
      </motion.div>

      {/* Sensor Controls Card */}
      <motion.div variants={itemVariants} className="card">
        <div className="card-header">
          <div className="card-title">
            <Cpu size={16} color="var(--accent-blue)" />
            <span>Packet Sensor Configuration & Control</span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Network Interface</label>
            <select
              className="form-select"
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning}
            >
              {interfaces.map((iface) => {
                const addr = iface.address || iface.ip_address;
                return (
                  <option key={iface.name} value={iface.name}>
                    {iface.description || iface.name} {addr ? `(${addr})` : ''}
                  </option>
                );
              })}
            </select>
          </div>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">BPF Capture Filter</label>
            <input
              type="text"
              className="form-input mono"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              placeholder="e.g. ip or ip6, tcp, or port 80"
              disabled={isRunning}
            />
          </div>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Flow Idle Timeout (s)</label>
            <input
              type="number"
              className="form-input mono"
              value={flowIdleTimeout}
              onChange={(e) => setFlowIdleTimeout(Number(e.target.value))}
              disabled={isRunning}
            />
          </div>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Flow Active Timeout (s)</label>
            <input
              type="number"
              className="form-input mono"
              value={flowActiveTimeout}
              onChange={(e) => setFlowActiveTimeout(Number(e.target.value))}
              disabled={isRunning}
            />
          </div>
        </div>

        {/* Quick BPF Filter Presets */}
        {!isRunning && (
          <div style={{ marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              BPF Filter Presets:
            </span>
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '0.35rem' }}>
              {[
                { label: 'All IPv4/IPv6', filter: 'ip or ip6' },
                { label: 'TCP Only', filter: 'tcp' },
                { label: 'Web (80, 443)', filter: 'tcp port 80 or tcp port 443' },
                { label: 'DNS (53)', filter: 'udp port 53' },
                { label: 'SSH (22)', filter: 'tcp port 22' },
              ].map((p) => (
                <button
                  key={p.filter}
                  type="button"
                  className="preset-pill"
                  onClick={() => setBpfFilter(p.filter)}
                  style={{ fontSize: '0.72rem', padding: '0.2rem 0.55rem' }}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          {isRunning ? (
            <button
              className="control-btn danger"
              onClick={() => setIsConfirmStopOpen(true)}
              disabled={isOperating}
            >
              <Square size={14} />
              <span>Stop Packet Capture</span>
            </button>
          ) : (
            <button
              className="control-btn primary"
              onClick={() => setIsConfirmStartOpen(true)}
              disabled={isOperating || !selectedInterface}
            >
              <Play size={14} />
              <span>Start Packet Capture</span>
            </button>
          )}
        </div>
      </motion.div>

      {/* Confirmation Dialog to Start Sensor (with Privilege Warning) */}
      <ConfirmDialog
        isOpen={isConfirmStartOpen}
        onClose={() => setIsConfirmStartOpen(false)}
        onConfirm={handleConfirmStart}
        title="Start Live Packet Capture Sensor"
        message={
          <div>
            <p>
              Are you sure you want to start live packet capture on interface{' '}
              <strong className="mono">{selectedInterface}</strong> with filter{' '}
              <code className="mono">{bpfFilter}</code>?
            </p>
            <div className="alert-box warning" style={{ marginTop: '0.75rem', marginBottom: 0 }}>
              <AlertTriangle size={16} style={{ flexShrink: 0 }} />
              <div>
                <strong>Operating System Privilege Notice:</strong> Live packet capture runs through Scapy/Npcap.
                Depending on your Windows network configuration, starting packet capture may require elevated permissions.
              </div>
            </div>
          </div>
        }
        confirmLabel="Confirm & Start Sensor"
        isLoading={isOperating}
      />

      {/* Confirmation Dialog to Stop Sensor */}
      <ConfirmDialog
        isOpen={isConfirmStopOpen}
        onClose={() => setIsConfirmStopOpen(false)}
        onConfirm={handleConfirmStop}
        title="Stop Live Packet Capture"
        message="Are you sure you want to stop live capture? Active flow buffers will be processed and finalized against the Network IDS before the capture thread halts."
        confirmLabel="Stop Sensor"
        isDestructive
        isLoading={isOperating}
      />
    </motion.div>
  );
};
