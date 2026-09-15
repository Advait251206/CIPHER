import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { IncidentItem, IncidentDetailResponse } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { RiskGauge } from '../components/common/RiskGauge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { Modal } from '../components/common/Modal';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { Flame, CheckCircle, ShieldAlert, GitBranch, ArrowRight, Eye } from 'lucide-react';
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

interface IncidentsPageProps {
  initialIncidentId?: string | null;
  refreshTrigger?: number;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({ initialIncidentId, refreshTrigger }) => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [sourceIpFilter, setSourceIpFilter] = useState<string>('');

  // Detail Modal
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetailResponse | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Resolution confirmation dialog (incorporates user's instruction: server-confirmed, non-optimistic)
  const [incidentToResolve, setIncidentToResolve] = useState<IncidentItem | null>(null);
  const [isResolving, setIsResolving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.incidents.list({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        source_ip: sourceIpFilter.trim() || undefined,
        limit: 50,
      });
      setIncidents(res.incidents);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve incidents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter, severityFilter, refreshTrigger]);

  // Load initial incident if passed
  useEffect(() => {
    if (initialIncidentId) {
      handleOpenDetail(initialIncidentId);
    }
  }, [initialIncidentId]);

  const handleOpenDetail = async (incidentId: string) => {
    try {
      setLoadingDetail(true);
      const detail = await api.incidents.get(incidentId);
      setSelectedIncident(detail);
    } catch (err: any) {
      setActionError(err.message || 'Failed to fetch incident details.');
    } finally {
      setLoadingDetail(false);
    }
  };

  // Resolve incident with strict server confirmation
  const handleConfirmResolve = async () => {
    if (!incidentToResolve) return;
    try {
      setIsResolving(true);
      setActionError(null);

      // Server confirmation step
      const result = await api.incidents.resolve(incidentToResolve.incident_id);

      setActionSuccess(`Incident ${result.incident_id} successfully marked as RESOLVED.`);
      setIncidentToResolve(null);

      // Refresh data only after backend confirms success
      await fetchIncidents();

      // If detail modal is currently open for this incident, refresh detail too
      if (selectedIncident && selectedIncident.incident.incident_id === incidentToResolve.incident_id) {
        handleOpenDetail(incidentToResolve.incident_id);
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to resolve incident on server.');
    } finally {
      setIsResolving(false);
    }
  };

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Action alerts */}
      {actionSuccess && (
        <motion.div variants={itemVariants} className="alert-box success">
          <CheckCircle size={16} />
          <span>{actionSuccess}</span>
        </motion.div>
      )}
      {actionError && (
        <motion.div variants={itemVariants} className="alert-box danger">
          <ShieldAlert size={16} />
          <span>{actionError}</span>
        </motion.div>
      )}

      {/* Filter Bar */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ width: '180px', margin: 0 }}>
            <label className="form-label">Status</label>
            <select
              className="form-select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open Incidents</option>
              <option value="RESOLVED">Resolved Incidents</option>
            </select>
          </div>

          <div className="form-group" style={{ width: '180px', margin: 0 }}>
            <label className="form-label">Severity</label>
            <select
              className="form-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="form-group" style={{ flex: '1 1 200px', margin: 0 }}>
            <label className="form-label">Filter by Source IP</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g. 192.168.1.100"
              value={sourceIpFilter}
              onChange={(e) => setSourceIpFilter(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') fetchIncidents();
              }}
            />
          </div>

          <button className="control-btn primary" onClick={fetchIncidents}>
            Filter
          </button>
        </div>
      </motion.div>

      {/* Incidents Table */}
      <motion.div variants={itemVariants} className="card">
        <div className="card-header">
          <div className="card-title">
            <Flame size={18} color="var(--crit-color)" />
            <span>Correlated Security Incidents</span>
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Showing {incidents.length} incident chains
          </span>
        </div>

        {loading ? (
          <LoadingState message="Loading correlated incidents..." />
        ) : error ? (
          <ErrorState title="Failed to Load Incidents" error={error} onRetry={fetchIncidents} />
        ) : incidents.length === 0 ? (
          <div style={{ padding: '3rem 1.5rem', textAlign: 'center' }}>
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '50%',
                background: 'var(--benign-bg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem auto',
                border: '1px solid var(--benign-border)',
              }}
            >
              <Flame size={24} color="var(--benign-color)" />
            </div>
            <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
              {statusFilter || severityFilter || sourceIpFilter
                ? 'No Incidents Match Query'
                : 'Zero Active Incident Chains'}
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.84rem', maxWidth: '420px', margin: '0 auto' }}>
              {statusFilter || severityFilter || sourceIpFilter
                ? 'Try adjusting or clearing your filters to view historical incidents.'
                : 'All network flows and alerts are within isolated thresholds. Multi-event correlations will appear here.'}
            </div>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Incident ID</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Categories</th>
                  <th>Events</th>
                  <th>Risk Score</th>
                  <th>Escalation</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.incident_id}>
                    <td>
                      <span
                        className="mono"
                        style={{
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: inc.status === 'OPEN' ? 'var(--crit-bg)' : 'var(--benign-bg)',
                          color: inc.status === 'OPEN' ? 'var(--crit-color)' : 'var(--benign-color)',
                          border: `1px solid ${inc.status === 'OPEN' ? 'var(--crit-border)' : 'var(--benign-border)'}`,
                        }}
                      >
                        {inc.status}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={inc.severity} size="sm" />
                    </td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>
                      {inc.incident_id}
                    </td>
                    <td className="mono">{inc.source_ip || 'N/A'}</td>
                    <td className="mono">{inc.destination_ip || 'N/A'}</td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                        {inc.attack_categories.map((cat, idx) => (
                          <span
                            key={idx}
                            className="mono"
                            style={{
                              fontSize: '0.68rem',
                              background: 'var(--bg-surface-elevated)',
                              border: '1px solid var(--border-subtle)',
                              padding: '2px 6px',
                              borderRadius: '4px',
                            }}
                          >
                            {cat}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="mono" style={{ fontWeight: 700 }}>
                      {inc.event_count}
                    </td>
                    <td className="mono" style={{ fontWeight: 700 }}>
                      {inc.correlation_score}
                    </td>
                    <td>
                      {inc.escalation_detected ? (
                        <span className="nav-badge danger" style={{ fontSize: '0.68rem' }}>
                          ESCALATED
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>None</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.4rem' }}>
                        <button
                          className="control-btn"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => handleOpenDetail(inc.incident_id)}
                          title="View incident events and correlation evidence"
                        >
                          <Eye size={12} />
                          <span>Details</span>
                        </button>
                        {inc.status === 'OPEN' && (
                          <button
                            className="control-btn success"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                            onClick={() => setIncidentToResolve(inc)}
                            title="Mark incident as resolved"
                          >
                            <CheckCircle size={12} />
                            <span>Resolve</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <Modal
          isOpen={Boolean(selectedIncident)}
          onClose={() => setSelectedIncident(null)}
          wide
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <GitBranch size={18} color="var(--accent-cyan)" />
              <span>Incident Detail: {selectedIncident.incident.incident_id}</span>
              <SeverityBadge severity={selectedIncident.incident.severity} size="sm" />
            </div>
          }
          footer={
            <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
              <div>
                {selectedIncident.incident.status === 'OPEN' && (
                  <button
                    className="control-btn success"
                    onClick={() => setIncidentToResolve(selectedIncident.incident)}
                  >
                    <CheckCircle size={14} />
                    <span>Resolve Incident</span>
                  </button>
                )}
              </div>
              <button className="control-btn" onClick={() => setSelectedIncident(null)}>
                Close
              </button>
            </div>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="evidence-section">
              <div className="evidence-header">
                <Flame size={14} />
                <span>Correlation Summary</span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                {selectedIncident.incident.summary}
              </p>
              <div className="kv-grid">
                <div className="kv-item">
                  <span className="kv-label">Status</span>
                  <span className="kv-value">{selectedIncident.incident.status}</span>
                </div>
                <div className="kv-item">
                  <span className="kv-label">First Seen</span>
                  <span className="kv-value mono">{selectedIncident.incident.first_seen}</span>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Last Seen</span>
                  <span className="kv-value mono">{selectedIncident.incident.last_seen}</span>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Total Correlated Events</span>
                  <span className="kv-value mono">{selectedIncident.incident.event_count}</span>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Escalation State</span>
                  <span className="kv-value" style={{ color: selectedIncident.incident.escalation_detected ? 'var(--crit-color)' : 'var(--benign-color)' }}>
                    {selectedIncident.incident.escalation_detected ? 'ESCALATED (High Frequency / Repetition)' : 'Normal'}
                  </span>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Recommended Action</span>
                  <span className="kv-value" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    {selectedIncident.incident.recommended_action || 'Monitor traffic'}
                  </span>
                </div>
              </div>
            </div>

            {/* Linked Events List */}
            <div className="evidence-section">
              <div className="evidence-header">
                <GitBranch size={14} />
                <span>Associated Security Events ({selectedIncident.events.length})</span>
              </div>
              {selectedIncident.events.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  No event records found linked to this incident.
                </div>
              ) : (
                <div className="table-container" style={{ maxHeight: '300px' }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Event ID</th>
                        <th>Timestamp</th>
                        <th>Classification</th>
                        <th>Risk Score</th>
                        <th>Source IP</th>
                        <th>Dest IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedIncident.events.map((ev: any, idx: number) => (
                        <tr key={ev.event_id || idx}>
                          <td className="mono" style={{ fontSize: '0.75rem' }}>
                            {ev.event_id}
                          </td>
                          <td className="mono" style={{ fontSize: '0.75rem' }}>
                            {ev.timestamp}
                          </td>
                          <td>
                            <span style={{ fontWeight: 600 }}>
                              {ev.attack_type || ev.classification || 'UNKNOWN'}
                            </span>
                          </td>
                          <td className="mono">{ev.risk_score ?? ev.threat_score ?? 0}</td>
                          <td className="mono">{ev.source_ip || ev.domain || 'N/A'}</td>
                          <td className="mono">{ev.destination_ip || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* Confirmation Dialog for Incident Resolution */}
      <ConfirmDialog
        isOpen={Boolean(incidentToResolve)}
        onClose={() => setIncidentToResolve(null)}
        onConfirm={handleConfirmResolve}
        title="Resolve Security Incident"
        message={
          incidentToResolve ? (
            <div>
              <p>
                Are you sure you want to mark incident{' '}
                <strong className="mono">{incidentToResolve.incident_id}</strong> as{' '}
                <strong>RESOLVED</strong>?
              </p>
              <p style={{ marginTop: '0.5rem', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                This will submit a resolution request to the backend correlation engine. The incident state will only be updated once the server confirms success.
              </p>
            </div>
          ) : (
            ''
          )
        }
        confirmLabel="Resolve Incident"
        isLoading={isResolving}
      />
    </motion.div>
  );
};
