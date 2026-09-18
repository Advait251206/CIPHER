import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { BlocklistEntry, NetworkHealthResponse, SecurityEventItem } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { ShieldAlert, Lock, Unlock, Clock, AlertTriangle, CheckCircle } from 'lucide-react';
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

interface PreventionPageProps {
  refreshTrigger?: number;
  onSetMode?: (mode: 'detect_only' | 'enforce') => Promise<void>;
}

export const PreventionPage: React.FC<PreventionPageProps> = ({ refreshTrigger = 0, onSetMode }) => {
  const [health, setHealth] = useState<NetworkHealthResponse | null>(null);
  const [activeBlocks, setActiveBlocks] = useState<BlocklistEntry[]>([]);
  const [expiredBlocks, setExpiredBlocks] = useState<BlocklistEntry[]>([]);
  const [preventionEvents, setPreventionEvents] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Unblock confirmation
  const [ipToUnblock, setIpToUnblock] = useState<string | null>(null);
  const [isUnblocking, setIsUnblocking] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const fetchPreventionData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [hRes, activeRes, expiredRes, eventsRes] = await Promise.allSettled([
        api.network.getHealth(),
        api.network.getBlocklist('ACTIVE'),
        api.network.getBlocklist('EXPIRED'),
        api.events.list({ limit: 20 }),
      ]);

      if (hRes.status === 'fulfilled') setHealth(hRes.value);
      if (activeRes.status === 'fulfilled') setActiveBlocks(activeRes.value);
      if (expiredRes.status === 'fulfilled') setExpiredBlocks(expiredRes.value);
      if (eventsRes.status === 'fulfilled') {
        const pEvents = eventsRes.value.events.filter(
          (e) => e.action === 'BLOCK' || e.metadata?.prevention_action
        );
        setPreventionEvents(pEvents);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load IPS prevention data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPreventionData();
  }, [refreshTrigger]);

  const handleConfirmUnblock = async () => {
    if (!ipToUnblock) return;
    try {
      setIsUnblocking(true);
      await api.network.unblockIp(ipToUnblock);
      setActionNotice(`IP ${ipToUnblock} successfully removed from active blocklist.`);
      setIpToUnblock(null);
      fetchPreventionData();
    } catch (err: any) {
      setError(err.message || `Failed to unblock IP ${ipToUnblock}.`);
    } finally {
      setIsUnblocking(false);
    }
  };

  const mode = health?.prevention_mode || 'enforce';

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {actionNotice && (
        <motion.div variants={itemVariants} className="alert-box success">
          <CheckCircle size={16} />
          <span>{actionNotice}</span>
        </motion.div>
      )}

      {/* Mode Governance Warning */}
      <motion.div variants={itemVariants} className="alert-box info">
        <Lock size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Server-Enforced IPS Architecture:</strong> Prevention mode is strictly controlled via backend configuration (<code>CIPHER_PREVENTION_MODE</code>).
          The dashboard displays authoritative server state and does not execute raw host firewall commands directly.
        </div>
      </motion.div>

      {/* Prevention Modes Breakdown Card */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <ShieldAlert size={18} color="var(--crit-color)" />
            <span>Operational Prevention Mode</span>
          </div>
          <span className={`mode-badge ${mode}`}>{mode.replace('_', ' ')}</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', marginTop: '0.75rem' }}>
          <motion.div
            onClick={() => onSetMode && mode !== 'detect_only' && onSetMode('detect_only')}
            whileHover={{ y: -3, scale: 1.01 }}
            style={{
              padding: '1.25rem',
              borderRadius: '8px',
              background: mode === 'detect_only' ? 'linear-gradient(135deg, rgba(22, 163, 74, 0.1) 0%, rgba(22, 163, 74, 0.15) 100%)' : 'var(--bg-surface-elevated)',
              border: `1.5px solid ${mode === 'detect_only' ? 'var(--benign-color)' : 'var(--border-subtle)'}`,
              boxShadow: mode === 'detect_only' ? '0 4px 12px rgba(22, 163, 74, 0.15)' : 'none',
              transition: 'all 0.2s ease',
              cursor: mode === 'detect_only' ? 'default' : 'pointer',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span className="mono" style={{ fontWeight: 800, fontSize: '0.85rem', color: 'var(--low-color)' }}>
                1. DETECT ONLY
              </span>
              {mode === 'detect_only' && <span className="nav-badge active" style={{ fontSize: '0.68rem' }}>ACTIVE MODE</span>}
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              Passively records security anomalies and logs alerts. Safe default for evaluation without host network disruption.
            </p>
          </motion.div>

          <motion.div
            onClick={() => onSetMode && mode !== 'enforce' && onSetMode('enforce')}
            whileHover={{ y: -3, scale: 1.01 }}
            style={{
              padding: '1.25rem',
              borderRadius: '8px',
              background: mode === 'enforce' ? 'linear-gradient(135deg, rgba(220, 38, 38, 0.1) 0%, rgba(220, 38, 38, 0.15) 100%)' : 'var(--bg-surface-elevated)',
              border: `1.5px solid ${mode === 'enforce' ? 'var(--crit-color)' : 'var(--border-subtle)'}`,
              boxShadow: mode === 'enforce' ? '0 4px 12px rgba(220, 38, 38, 0.15)' : 'none',
              transition: 'all 0.2s ease',
              cursor: mode === 'enforce' ? 'default' : 'pointer',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span className="mono" style={{ fontWeight: 800, fontSize: '0.85rem', color: 'var(--crit-color)' }}>
                2. ENFORCE
              </span>
              {mode === 'enforce' && <span className="nav-badge danger" style={{ fontSize: '0.68rem' }}>ACTIVE MODE</span>}
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              Actively applies temporary blocks with automatic sliding-window TTL expiration on confirmed malicious source IPs.
            </p>
          </motion.div>
        </div>
      </motion.div>

      {/* Active Blocklist Table */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Lock size={16} color="var(--crit-color)" />
            <span>Active Blocklist ({activeBlocks.length})</span>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Temporary IP blocks with automated sliding-window expiration
          </span>
        </div>

        {loading ? (
          <LoadingState message="Loading active blocklist..." />
        ) : error && activeBlocks.length === 0 ? (
          <ErrorState title="Failed to Load Blocklist" error={error} onRetry={fetchPreventionData} />
        ) : activeBlocks.length === 0 ? (
          <EmptyState
            title="No actively blocked IPs."
            description="All monitored hosts are permitted. When threats trigger block conditions under enforce or simulate modes, entries appear here."
          />
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason / Category</th>
                  <th>Blocked At</th>
                  <th>Expires At</th>
                  <th>Remaining TTL</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {activeBlocks.map((b) => (
                  <tr key={b.ip}>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--crit-color)' }}>
                      {b.ip}
                    </td>
                    <td>{b.reason}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{b.blocked_at}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{b.expires_at || 'Indefinite'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {b.ttl_remaining_seconds !== undefined ? `${b.ttl_remaining_seconds}s` : 'N/A'}
                    </td>
                    <td>
                      <button
                        className="control-btn"
                        style={{ padding: '3px 8px', fontSize: '0.75rem' }}
                        onClick={() => setIpToUnblock(b.ip)}
                        title="Remove IP from blocklist"
                      >
                        <Unlock size={12} />
                        <span>Unblock</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Prevention Events Log */}
      {preventionEvents.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Clock size={16} color="var(--accent-cyan)" />
              <span>Recent Prevention Actions Log</span>
            </div>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Classification</th>
                  <th>Severity</th>
                  <th>Action Applied</th>
                </tr>
              </thead>
              <tbody>
                {preventionEvents.map((pe) => (
                  <tr key={pe.event_id}>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{pe.timestamp}</td>
                    <td className="mono">{pe.source_ip || 'N/A'}</td>
                    <td>{pe.attack_type || pe.classification}</td>
                    <td><SeverityBadge severity={pe.severity} size="sm" /></td>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--crit-color)' }}>
                      {pe.action || pe.metadata?.prevention_action || 'BLOCK'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Unblock Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(ipToUnblock)}
        onClose={() => setIpToUnblock(null)}
        onConfirm={handleConfirmUnblock}
        title="Manual IP Unblock"
        message={
          <div>
            <p>
              Are you sure you want to manually unblock IP <strong className="mono">{ipToUnblock}</strong>?
            </p>
            <p style={{ marginTop: '0.5rem', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              This will remove the address from the active blocklist cache and restore network accessibility.
            </p>
          </div>
        }
        confirmLabel="Unblock IP"
        isLoading={isUnblocking}
      />
    </motion.div>
  );
};
