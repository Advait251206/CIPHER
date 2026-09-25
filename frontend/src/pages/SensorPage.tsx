import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { NetworkInterfaceItem, SensorStatusResponse } from '../api/types';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { Radio, Play, Square, AlertTriangle, CheckCircle, RefreshCw, Cpu, Activity } from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, codeTag, controlBtn, formGroup, formInput, formLabel, formSelect, kvGrid, kvItem, kvLabel, kvValue, mono, pageBody, presetPill } from '../ui/classes';

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
        const runningNow = Boolean(statusRes.value.running);
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
    }, 5000);
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

  const isRunning = Boolean(sensorStatus?.running);

  return (
    <motion.div
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Privilege & Privacy Disclaimer Banner */}
      <motion.div variants={itemVariants} className={alertBox('warning')}>
        <AlertTriangle size={18} className="shrink-0" />
        <div>
          <strong>Npcap & High-Performance C++ Capture Architecture:</strong> Live packet capture runs in user space through a custom C++ engine leveraging Npcap.
          Depending on the Windows interface and Npcap configuration, packet capture may require elevated privileges.
          <em> Notice: CIPHER strictly extracts 67 flow header statistical features and does not store or inspect raw packet payloads.</em>
        </div>
      </motion.div>

      {actionNotice && (
        <motion.div variants={itemVariants} className={alertBox('success')}>
          <CheckCircle size={16} />
          <span>{actionNotice}</span>
        </motion.div>
      )}

      {error && (
        <motion.div variants={itemVariants} className={alertBox('danger')}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </motion.div>
      )}

      {/* Sensor Status Banner */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-6')}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <Radio size={18} color={isRunning ? 'var(--color-benign)' : 'var(--color-fg-muted)'} />
            <span>Sensor Runtime Telemetry</span>
          </div>
          <div className="flex items-center gap-3">
            <span
              className={cn(mono, 'text-[0.78rem] font-bold py-[0.3rem] px-3 rounded-[6px] flex items-center gap-[0.45rem]', (isRunning ? 'bg-benign-bg' : 'bg-elevated'), (isRunning ? 'text-benign' : 'text-fg-muted'), 'border', isRunning ? 'border-benign' : 'border-line')}
            >
              {isRunning && <span className="inline-block size-[8px] animate-pulse-green rounded-[50%] bg-benign" />}
              {!isRunning && <span className={cn('mr-[6px] inline-block size-[8px] rounded-[50%] bg-benign', 'bg-crit', 'w-[7px] h-[7px]')} />}
              {isRunning ? 'SENSOR ACTIVE' : 'SENSOR STANDBY'}
            </span>
          </div>
        </div>

        {/* Real-Time Metrics Grid */}
        <div className={cn('mb-6 grid grid-cols-[repeat(4,1fr)] gap-[1.1rem] lte-960:grid-cols-[repeat(2,1fr)] lte-540:grid-cols-[1fr]', 'mt-3 mb-4')}>
          <motion.div whileHover={{ y: -2 }} className="relative cursor-pointer overflow-hidden rounded-none border border-line-card bg-surface px-5 py-[1.15rem] [transition:all_0.2s_cubic-bezier(0.4,0,0.2,1)] hover:border-elevated hover:transform-[translateY(-2px)]">
            <div className="mb-[0.65rem] flex items-center justify-between">
              <span className="text-[0.76rem] font-bold tracking-[0.05em] text-fg-muted uppercase">Packets Captured</span>
              <div className={cn('flex size-[32px] items-center justify-center rounded-none bg-elevated text-fg-2', 'text-fg')}>
                <Activity size={16} />
              </div>
            </div>
            <div className="mb-[0.35rem] font-sans text-[1.75rem] leading-[1.1] font-extrabold text-fg">
              {sensorStatus?.packets_captured?.toLocaleString() ?? 0}
            </div>
            <div className="text-[0.74rem] font-medium text-fg-muted">Raw frames parsed via C++ Engine</div>
          </motion.div>

          <motion.div whileHover={{ y: -2 }} className="relative cursor-pointer overflow-hidden rounded-none border border-line-card bg-surface px-5 py-[1.15rem] [transition:all_0.2s_cubic-bezier(0.4,0,0.2,1)] hover:border-elevated hover:transform-[translateY(-2px)]">
            <div className="mb-[0.65rem] flex items-center justify-between">
              <span className="text-[0.76rem] font-bold tracking-[0.05em] text-fg-muted uppercase">Active Flows</span>
              <div className={cn('flex size-[32px] items-center justify-center rounded-none bg-elevated text-fg-2', 'text-accent')}>
                <Radio size={16} />
              </div>
            </div>
            <div className={cn('mb-[0.35rem] font-sans text-[1.75rem] leading-[1.1] font-extrabold text-fg', 'text-accent')}>
              {sensorStatus?.active_flows?.toLocaleString() ?? 0}
            </div>
            <div className="text-[0.74rem] font-medium text-fg-muted">Sliding-window tracking table</div>
          </motion.div>

          <motion.div whileHover={{ y: -2 }} className="relative cursor-pointer overflow-hidden rounded-none border border-line-card bg-surface px-5 py-[1.15rem] [transition:all_0.2s_cubic-bezier(0.4,0,0.2,1)] hover:border-elevated hover:transform-[translateY(-2px)]">
            <div className="mb-[0.65rem] flex items-center justify-between">
              <span className="text-[0.76rem] font-bold tracking-[0.05em] text-fg-muted uppercase">Finalized Flows</span>
              <div className={cn('flex size-[32px] items-center justify-center rounded-none bg-elevated text-fg-2', 'text-benign')}>
                <CheckCircle size={16} />
              </div>
            </div>
            <div className={cn('mb-[0.35rem] font-sans text-[1.75rem] leading-[1.1] font-extrabold text-fg', 'text-benign')}>
              {(sensorStatus?.finalized_flows ?? sensorStatus?.completed_flows ?? 0).toLocaleString()}
            </div>
            <div className="text-[0.74rem] font-medium text-fg-muted">Exported to Network IDS ML</div>
          </motion.div>

          <motion.div whileHover={{ y: -2 }} className="relative cursor-pointer overflow-hidden rounded-none border border-line-card bg-surface px-5 py-[1.15rem] [transition:all_0.2s_cubic-bezier(0.4,0,0.2,1)] hover:border-elevated hover:transform-[translateY(-2px)]">
            <div className="mb-[0.65rem] flex items-center justify-between">
              <span className="text-[0.76rem] font-bold tracking-[0.05em] text-fg-muted uppercase">Dropped Packets</span>
              <div className={cn('flex size-[32px] items-center justify-center rounded-none bg-elevated text-fg-2', ((sensorStatus?.packets_dropped ?? sensorStatus?.errors) ? 'text-crit' : 'text-fg-muted'))}>
                <AlertTriangle size={16} />
              </div>
            </div>
            <div className={cn('mb-[0.35rem] font-sans text-[1.75rem] leading-[1.1] font-extrabold text-fg', ((sensorStatus?.packets_dropped ?? sensorStatus?.errors) ? 'text-crit' : 'text-fg'))}>
              {(sensorStatus?.packets_dropped ?? sensorStatus?.errors ?? 0).toLocaleString()}
            </div>
            <div className="text-[0.74rem] font-medium text-fg-muted">Ring buffer overrun count</div>
          </motion.div>
        </div>

        {/* Current Config Details */}
        <div className={cn(kvGrid, 'mt-5')}>
          <div className={kvItem}>
            <span className={kvLabel}>Bound Interface</span>
            <span className={cn(mono, kvValue)}>{sensorStatus?.interface || 'None'}</span>
          </div>
          <div className={kvItem}>
            <span className={kvLabel}>BPF Filter</span>
            <span className={cn(mono, kvValue)}>{sensorStatus?.bpf_filter || 'None'}</span>
          </div>
          <div className={kvItem}>
            <span className={kvLabel}>Flow Idle Timeout</span>
            <span className={cn(mono, kvValue)}>{sensorStatus?.flow_idle_timeout ?? 5} seconds</span>
          </div>
          <div className={kvItem}>
            <span className={kvLabel}>Flow Active Timeout</span>
            <span className={cn(mono, kvValue)}>{sensorStatus?.flow_active_timeout ?? 120} seconds</span>
          </div>
          <div className={kvItem}>
            <span className={kvLabel}>Started At</span>
            <span className={cn(mono, kvValue)}>{sensorStatus?.started_at || 'Idle'}</span>
          </div>
          <div className={kvItem}>
            <span className={kvLabel}>Default Prevention Safety</span>
              <span className={cn(mono, kvValue, 'text-accent')}>
                {sensorStatus?.prevention_mode || 'enforce'}
              </span>
          </div>
        </div>
      </motion.div>

      {/* Sensor Controls Card */}
      <motion.div variants={itemVariants} className={card}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <Cpu size={16} color="var(--color-accent)" />
            <span>Packet Sensor Configuration & Control</span>
          </div>
        </div>

        <div className="grid grid-cols-[repeat(auto-fit,minmax(260px,1fr))] gap-4 mb-4">
          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Network Interface</label>
            <select
              className={formSelect}
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

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>BPF Capture Filter</label>
            <input
              type="text"
              className={cn(mono, formInput)}
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              placeholder="e.g. ip or ip6, tcp, or port 80"
              disabled={isRunning}
            />
          </div>

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Flow Idle Timeout (s)</label>
            <input
              type="number"
              className={cn(mono, formInput)}
              value={flowIdleTimeout}
              onChange={(e) => setFlowIdleTimeout(Number(e.target.value))}
              disabled={isRunning}
            />
          </div>

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Flow Active Timeout (s)</label>
            <input
              type="number"
              className={cn(mono, formInput)}
              value={flowActiveTimeout}
              onChange={(e) => setFlowActiveTimeout(Number(e.target.value))}
              disabled={isRunning}
            />
          </div>
        </div>

        {/* Quick BPF Filter Presets */}
        {!isRunning && (
          <div className="mb-5">
            <span className="text-[0.72rem] font-semibold text-fg-muted uppercase tracking-[0.04em]">
              BPF Filter Presets:
            </span>
            <div className="flex gap-[0.4rem] flex-wrap mt-[0.35rem]">
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
                  className={cn(presetPill, 'text-[0.72rem] py-[0.2rem] px-[0.55rem]')}
                  onClick={() => setBpfFilter(p.filter)}

                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="flex justify-end gap-3">
          {isRunning ? (
            <button
              className={controlBtn('danger')}
              onClick={() => setIsConfirmStopOpen(true)}
              disabled={isOperating}
            >
              <Square size={14} />
              <span>Stop Packet Capture</span>
            </button>
          ) : (
            <button
              className={controlBtn('primary')}
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
              <strong className={mono}>{selectedInterface}</strong> with filter{' '}
              <code className={cn(codeTag, mono)}>{bpfFilter}</code>?
            </p>
            <div className={cn(alertBox('warning'), 'mt-3 mb-0')}>
              <AlertTriangle size={16} className="shrink-0" />
              <div>
                <strong>Operating System Privilege Notice:</strong> Live packet capture runs through the custom C++ Engine and Npcap.
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
