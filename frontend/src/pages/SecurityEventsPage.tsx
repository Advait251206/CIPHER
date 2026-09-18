import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { SecurityEventItem, Severity } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { EventDetailModal } from '../components/events/EventDetailModal';
import { Filter, Search, ChevronLeft, ChevronRight, Shield, Database } from 'lucide-react';
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

interface SecurityEventsPageProps {
  onSelectIncident?: (incidentId: string) => void;
  refreshTrigger?: number;
}

export const SecurityEventsPage: React.FC<SecurityEventsPageProps> = ({ onSelectIncident, refreshTrigger }) => {
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('');
  const [searchSource, setSearchSource] = useState<string>('');
  const [limit] = useState<number>(25);
  const [offset, setOffset] = useState<number>(0);
  const [totalReturned, setTotalReturned] = useState<number>(0);

  // Selected event for detail modal
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);

  const fetchEvents = async () => {
    try {
      setLoading(true);
      setError(null);

      const res = await api.events.list({
        limit,
        offset,
        severity: severityFilter || undefined,
        event_type: eventTypeFilter || undefined,
        source_ip: searchSource.trim() || undefined,
      });

      setEvents(res.events);
      setTotalReturned(res.total_returned);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve security events.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [severityFilter, eventTypeFilter, offset, refreshTrigger]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    fetchEvents();
  };

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Filters Bar */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.25rem' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: '1 1 200px', margin: 0 }}>
            <label className="form-label">Search Source IP / Domain</label>
            <div style={{ position: 'relative' }}>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. 192.168.1.100 or bad-domain.xyz"
                value={searchSource}
                onChange={(e) => setSearchSource(e.target.value)}
              />
              <Search
                size={14}
                style={{
                  position: 'absolute',
                  right: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted)',
                }}
              />
            </div>
          </div>

          <div className="form-group" style={{ width: '180px', margin: 0 }}>
            <label className="form-label">Severity Level</label>
            <select
              className="form-select"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low / Benign</option>
            </select>
          </div>

          <div className="form-group" style={{ width: '180px', margin: 0 }}>
            <label className="form-label">Event Source Type</label>
            <select
              className="form-select"
              value={eventTypeFilter}
              onChange={(e) => {
                setEventTypeFilter(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">All Types</option>
              <option value="NETWORK">Network Flow (IDS)</option>
              <option value="PHISHING">Phishing Analyzer</option>
              <option value="RULE">Deterministic Rule</option>
            </select>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="submit" className="control-btn primary">
              <Filter size={14} />
              <span>Apply Filters</span>
            </button>
            {(severityFilter || eventTypeFilter || searchSource) && (
              <button
                type="button"
                className="control-btn"
                onClick={() => {
                  setSeverityFilter('');
                  setEventTypeFilter('');
                  setSearchSource('');
                  setOffset(0);
                }}
              >
                Reset
              </button>
            )}
          </div>
        </form>
      </motion.div>

      {/* Events Table or States */}
      <motion.div variants={itemVariants} className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={18} color="var(--accent-cyan)" />
            <span>Live Security Events Stream</span>
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Showing {events.length} records (Page {Math.floor(offset / limit) + 1})
          </span>
        </div>

        {loading ? (
          <LoadingState message="Querying security events..." />
        ) : error ? (
          <ErrorState title="Failed to Query Events" error={error} onRetry={fetchEvents} />
        ) : events.length === 0 ? (
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
              <Shield size={24} color="var(--benign-color)" />
            </div>
            <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
              {severityFilter || searchSource || eventTypeFilter
                ? 'No Security Events Match Filters'
                : 'Zero Anomalous Events in Buffer'}
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.84rem', maxWidth: '420px', margin: '0 auto' }}>
              {severityFilter || searchSource || eventTypeFilter
                ? 'Try clearing or relaxing your query parameters to see more records.'
                : 'The local event buffer is clean. Start the Live Sensor in the Network IDS tab to capture real-time traffic.'}
            </div>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Classification / Attack</th>
                    <th>Risk</th>
                    <th>Conf</th>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Source / Rule / IOC</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => {
                    const metadata = ev.metadata || {};
                    const hasIoc = Boolean(metadata.ioc_match || metadata.ioc_matched);
                    const rawRule =
                      metadata.rule_id ||
                      (metadata.rules_triggered && metadata.rules_triggered[0]) ||
                      (metadata.rule_matches && metadata.rule_matches[0]);
                    const ruleId =
                      typeof rawRule === 'object' && rawRule !== null
                        ? (rawRule as any).rule_id || (rawRule as any).name || null
                        : typeof rawRule === 'string'
                        ? rawRule
                        : null;

                    return (
                      <tr
                        key={ev.event_id}
                        onClick={() => setSelectedEvent(ev)}
                        style={{ cursor: 'pointer' }}
                        title="Click to view full evidence details"
                      >
                        <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {ev.timestamp.replace('T', ' ').replace('Z', '')}
                        </td>
                        <td>
                          <SeverityBadge severity={ev.severity} size="sm" />
                        </td>
                        <td>
                          <span style={{ fontWeight: 600 }}>
                            {ev.attack_type || ev.classification}
                          </span>
                        </td>
                        <td className="mono" style={{ fontWeight: 700 }}>
                          {ev.risk_score}
                        </td>
                        <td className="mono" style={{ fontSize: '0.75rem' }}>
                          {(ev.confidence * 100).toFixed(0)}%
                        </td>
                        <td className="mono">{ev.source_ip || ev.domain || 'N/A'}</td>
                        <td className="mono">{ev.destination_ip || 'N/A'}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', flexWrap: 'wrap' }}>
                            <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                              {ev.detection_method || ev.source}
                            </span>
                            {ruleId && (
                              <span className="mono" style={{ fontSize: '0.65rem', background: 'rgba(56, 189, 248, 0.15)', color: 'var(--low-color)', padding: '1px 4px', borderRadius: '3px' }}>
                                {ruleId}
                              </span>
                            )}
                            {hasIoc && (
                              <span className="mono" style={{ fontSize: '0.65rem', background: 'var(--crit-bg)', color: 'var(--crit-color)', padding: '1px 4px', borderRadius: '3px', display: 'flex', alignItems: 'center', gap: '2px' }}>
                                <Database size={10} /> IOC
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span
                            className="mono"
                            style={{
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              color: ev.action === 'BLOCK' ? 'var(--crit-color)' : 'var(--text-secondary)',
                            }}
                          >
                            {ev.action || 'ALERT'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', padding: '0 0.5rem' }}>
              <button
                className="control-btn"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}
              >
                <ChevronLeft size={14} />
                <span>Previous Page</span>
              </button>

              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Offset: {offset} | Page {Math.floor(offset / limit) + 1}
              </span>

              <button
                className="control-btn"
                disabled={events.length < limit}
                onClick={() => setOffset(offset + limit)}
              >
                <span>Next Page</span>
                <ChevronRight size={14} />
              </button>
            </div>
          </>
        )}
      </motion.div>

      {/* Structured Event Detail Modal */}
      <EventDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
        onNavigateToIncident={onSelectIncident}
      />
    </motion.div>
  );
};
