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
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, codeTag, controlBtn, dataTable, modeBadge, mono, navBadge, pageBody, tableContainer } from '../ui/classes';

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
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {actionNotice && (
        <motion.div variants={itemVariants} className={alertBox('success')}>
          <CheckCircle size={16} />
          <span>{actionNotice}</span>
        </motion.div>
      )}

      {/* Mode Governance Warning */}
      <motion.div variants={itemVariants} className={alertBox('info')}>
        <Lock size={18} className="shrink-0" />
        <div>
          <strong>Server-Enforced IPS Architecture:</strong> Prevention mode is strictly controlled via backend configuration (<code className={codeTag}>CIPHER_PREVENTION_MODE</code>).
          The dashboard displays authoritative server state and does not execute raw host firewall commands directly.
        </div>
      </motion.div>

      {/* Prevention Modes Breakdown Card */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-6')}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <ShieldAlert size={18} color="var(--color-crit)" />
            <span>Operational Prevention Mode</span>
          </div>
          <span className={modeBadge(mode)}>{mode.replace('_', ' ')}</span>
        </div>

        <div className="grid grid-cols-[repeat(auto-fit,minmax(260px,1fr))] gap-4 mt-3">
          <motion.div
            onClick={() => onSetMode && mode !== 'detect_only' && onSetMode('detect_only')}
            whileHover={{ y: -3, scale: 1.01 }}
            className={cn('p-5 rounded-[8px] [transition:all_0.2s_ease]', (mode === 'detect_only' ? '[background:linear-gradient(135deg,rgba(22,163,74,0.1)_0%,rgba(22,163,74,0.15)_100%)]' : 'bg-elevated'), (mode === 'detect_only' ? '[box-shadow:0_4px_12px_rgba(22,163,74,0.15)]' : '[box-shadow:none]'), (mode === 'detect_only' ? 'cursor-default' : 'cursor-pointer'), 'border-[1.5px]', mode === 'detect_only' ? 'border-benign' : 'border-line')}
          >
            <div className="flex items-center justify-between mb-2">
              <span className={cn(mono, 'font-extrabold text-[0.85rem] text-low')}>
                1. DETECT ONLY
              </span>
              {mode === 'detect_only' && <span className={navBadge('active', 'text-[0.68rem]')}>ACTIVE MODE</span>}
            </div>
            <p className="text-[0.8rem] text-fg-2 leading-[1.5] m-0">
              Passively records security anomalies and logs alerts. Safe default for evaluation without host network disruption.
            </p>
          </motion.div>

          <motion.div
            onClick={() => onSetMode && mode !== 'enforce' && onSetMode('enforce')}
            whileHover={{ y: -3, scale: 1.01 }}
            className={cn('p-5 rounded-[8px] [transition:all_0.2s_ease]', (mode === 'enforce' ? '[background:linear-gradient(135deg,rgba(220,38,38,0.1)_0%,rgba(220,38,38,0.15)_100%)]' : 'bg-elevated'), (mode === 'enforce' ? '[box-shadow:0_4px_12px_rgba(220,38,38,0.15)]' : '[box-shadow:none]'), (mode === 'enforce' ? 'cursor-default' : 'cursor-pointer'), 'border-[1.5px]', mode === 'enforce' ? 'border-crit' : 'border-line')}
          >
            <div className="flex items-center justify-between mb-2">
              <span className={cn(mono, 'font-extrabold text-[0.85rem] text-crit')}>
                2. ENFORCE
              </span>
              {mode === 'enforce' && <span className={navBadge('danger', 'text-[0.68rem]')}>ACTIVE MODE</span>}
            </div>
            <p className="text-[0.8rem] text-fg-2 leading-[1.5] m-0">
              Actively applies temporary blocks with automatic sliding-window TTL expiration on confirmed malicious source IPs.
            </p>
          </motion.div>
        </div>
      </motion.div>

      {/* Active Blocklist Table */}
      <div className={cn(card, 'mb-6')}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <Lock size={16} color="var(--color-crit)" />
            <span>Active Blocklist ({activeBlocks.length})</span>
          </div>
          <span className="text-[0.75rem] text-fg-muted">
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
          <div className={tableContainer}>
            <table className={dataTable}>
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
                    <td className={cn(mono, 'font-bold! text-crit!')}>
                      {b.ip}
                    </td>
                    <td>{b.reason}</td>
                    <td className={cn(mono, 'text-[0.75rem]!')}>{b.blocked_at}</td>
                    <td className={cn(mono, 'text-[0.75rem]!')}>{b.expires_at || 'Indefinite'}</td>
                    <td className={cn(mono, 'text-[0.75rem]!')}>
                      {b.ttl_remaining_seconds !== undefined ? `${b.ttl_remaining_seconds}s` : 'N/A'}
                    </td>
                    <td>
                      <button
                        className={cn(controlBtn(), 'py-[3px] px-[8px] text-[0.75rem]')}

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
        <div className={card}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Clock size={16} color="var(--color-accent)" />
              <span>Recent Prevention Actions Log</span>
            </div>
          </div>
          <div className={tableContainer}>
            <table className={dataTable}>
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
                    <td className={cn(mono, 'text-[0.75rem]!')}>{pe.timestamp}</td>
                    <td className={mono}>{pe.source_ip || 'N/A'}</td>
                    <td>{pe.attack_type || pe.classification}</td>
                    <td><SeverityBadge severity={pe.severity} size="sm" /></td>
                    <td className={cn(mono, 'font-bold! text-crit!')}>
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
              Are you sure you want to manually unblock IP <strong className={mono}>{ipToUnblock}</strong>?
            </p>
            <p className="mt-2 text-[0.82rem] text-fg-muted">
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
