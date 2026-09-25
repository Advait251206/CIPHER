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
import { cn } from '../lib/cn';
import { card, cardHeader, cardTitle, controlBtn, dataTable, formGroup, formInput, formLabel, formSelect, mono, pageBody, tableContainer } from '../ui/classes';

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
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Filters Bar */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-5')}>
        <form onSubmit={handleSearchSubmit} className="flex flex-wrap gap-4 items-end">
          <div className={cn(formGroup, 'flex-[1_1_200px] m-0')}>
            <label className={formLabel}>Search Source IP / Domain</label>
            <div className="relative">
              <input
                type="text"
                className={formInput}
                placeholder="e.g. 192.168.1.100 or bad-domain.xyz"
                value={searchSource}
                onChange={(e) => setSearchSource(e.target.value)}
              />
              <Search
                size={14}
                className="absolute top-[50%] right-[10px] transform-[translateY(-50%)] text-fg-muted"
              />
            </div>
          </div>

          <div className={cn(formGroup, 'w-[180px] m-0')}>
            <label className={formLabel}>Severity Level</label>
            <select
              className={formSelect}
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

          <div className={cn(formGroup, 'w-[180px] m-0')}>
            <label className={formLabel}>Event Source Type</label>
            <select
              className={formSelect}
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

          <div className="flex gap-2">
            <button type="submit" className={controlBtn('primary')}>
              <Filter size={14} />
              <span>Apply Filters</span>
            </button>
            {(severityFilter || eventTypeFilter || searchSource) && (
              <button
                type="button"
                className={controlBtn()}
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
      <motion.div variants={itemVariants} className={card}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <Shield size={18} color="var(--color-accent)" />
            <span>Live Security Events Stream</span>
          </div>
          <span className="text-[0.78rem] text-fg-muted">
            Showing {events.length} records (Page {Math.floor(offset / limit) + 1})
          </span>
        </div>

        {loading ? (
          <LoadingState message="Querying security events..." />
        ) : error ? (
          <ErrorState title="Failed to Query Events" error={error} onRetry={fetchEvents} />
        ) : events.length === 0 ? (
          <div className="py-12 px-6 text-center">
            <div
              className="w-[48px] h-[48px] rounded-[50%] bg-benign-bg flex items-center justify-center mt-0 mx-auto mb-4 border border-benign"
            >
              <Shield size={24} color="var(--color-benign)" />
            </div>
            <div className="font-bold text-[1rem] mb-[0.35rem] text-fg">
              {severityFilter || searchSource || eventTypeFilter
                ? 'No Security Events Match Filters'
                : 'Zero Anomalous Events in Buffer'}
            </div>
            <div className="text-fg-muted text-[0.84rem] max-w-[420px] my-0 mx-auto">
              {severityFilter || searchSource || eventTypeFilter
                ? 'Try clearing or relaxing your query parameters to see more records.'
                : 'The local event buffer is clean. Start the Live Sensor in the Network IDS tab to capture real-time traffic.'}
            </div>
          </div>
        ) : (
          <>
            <div className={tableContainer}>
              <table className={dataTable}>
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
                        className="cursor-pointer"
                        title="Click to view full evidence details"
                      >
                        <td className={cn(mono, 'text-[0.75rem]! text-fg-muted!')}>
                          {ev.timestamp.replace('T', ' ').replace('Z', '')}
                        </td>
                        <td>
                          <SeverityBadge severity={ev.severity} size="sm" />
                        </td>
                        <td>
                          <span className="font-semibold">
                            {ev.attack_type || ev.classification}
                          </span>
                        </td>
                        <td className={cn(mono, 'font-bold!')}>
                          {ev.risk_score}
                        </td>
                        <td className={cn(mono, 'text-[0.75rem]!')}>
                          {(ev.confidence * 100).toFixed(0)}%
                        </td>
                        <td className={mono}>{ev.source_ip || ev.domain || 'N/A'}</td>
                        <td className={mono}>{ev.destination_ip || 'N/A'}</td>
                        <td>
                          <div className="flex items-center gap-[0.35rem] flex-wrap">
                            <span className={cn(mono, 'text-[0.7rem] text-fg-muted')}>
                              {ev.detection_method || ev.source}
                            </span>
                            {ruleId && (
                              <span className={cn(mono, 'text-[0.65rem] bg-[rgba(56,189,248,0.15)] text-low py-[1px] px-[4px] rounded-[3px]')}>
                                {ruleId}
                              </span>
                            )}
                            {hasIoc && (
                              <span className={cn(mono, 'text-[0.65rem] bg-crit-bg text-crit py-[1px] px-[4px] rounded-[3px] flex items-center gap-[2px]')}>
                                <Database size={10} /> IOC
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span
                            className={cn(mono, 'text-[0.75rem] font-semibold', (ev.action === 'BLOCK' ? 'text-crit' : 'text-fg-2'))}

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
            <div className="flex justify-between items-center mt-4 py-0 px-2">
              <button
                className={controlBtn()}
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}
              >
                <ChevronLeft size={14} />
                <span>Previous Page</span>
              </button>

              <span className="text-[0.78rem] text-fg-muted font-mono">
                Offset: {offset} | Page {Math.floor(offset / limit) + 1}
              </span>

              <button
                className={controlBtn()}
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
