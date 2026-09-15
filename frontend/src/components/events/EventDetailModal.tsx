import React from 'react';
import { SecurityEventItem } from '../../api/types';
import { Modal } from '../common/Modal';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskGauge } from '../common/RiskGauge';
import { Shield, Network, AlertTriangle, BookOpen, Database, GitBranch, Lock } from 'lucide-react';

interface EventDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  event: SecurityEventItem | null;
  onNavigateToIncident?: (incidentId: string) => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({
  isOpen,
  onClose,
  event,
  onNavigateToIncident,
}) => {
  if (!event) return null;

  const metadata = event.metadata || {};
  const hasNetwork =
    event.source_ip ||
    event.destination_ip ||
    event.source_port !== undefined ||
    event.destination_port !== undefined ||
    event.protocol;

  const ruleMatches = metadata.rule_matches || metadata.rules_triggered;
  const hasRuleEvidence = Boolean(
    metadata.rule_id ||
    (Array.isArray(ruleMatches) && ruleMatches.length > 0) ||
    metadata.heuristic_reasons
  );

  const iocMatch = metadata.ioc_match || metadata.ioc_matched;
  const hasThreatIntel = Boolean(iocMatch || metadata.threat_intel);

  const incidentId = metadata.incident_id || metadata.correlated_incident_id;
  const hasCorrelation = Boolean(incidentId || metadata.escalation_detected !== undefined);

  const hasPrevention = Boolean(
    metadata.prevention_mode ||
    metadata.prevention_action ||
    event.action ||
    event.recommendation
  );

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      wide
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Shield size={20} color="var(--accent-cyan)" />
          <span>Security Event Details</span>
          <SeverityBadge severity={event.severity} size="sm" />
        </div>
      }
      footer={
        <button className="control-btn" onClick={onClose}>
          Close Inspector
        </button>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {/* 1. EVENT SECTION */}
        <div className="evidence-section">
          <div className="evidence-header">
            <Shield size={14} />
            <span>Event Metadata</span>
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Event ID</span>
              <span className="kv-value mono">{event.event_id}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Timestamp</span>
              <span className="kv-value mono">{event.timestamp}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Event Type</span>
              <span className="kv-value">{event.event_type || 'SECURITY_EVENT'}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Detection Source</span>
              <span className="kv-value">{event.source || 'CIPHER Engine'}</span>
            </div>
            {event.status && (
              <div className="kv-item">
                <span className="kv-label">Status</span>
                <span className="kv-value">{event.status}</span>
              </div>
            )}
          </div>
        </div>

        {/* 2. THREAT VERDICT SECTION */}
        <div className="evidence-section">
          <div className="evidence-header">
            <AlertTriangle size={14} />
            <span>Threat Assessment</span>
          </div>
          <div style={{ marginBottom: '0.85rem' }}>
            <RiskGauge score={event.risk_score} label="Threat Score" />
          </div>
          <div className="kv-grid">
            <div className="kv-item">
              <span className="kv-label">Classification</span>
              <span className="kv-value">{event.classification}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Attack Category</span>
              <span className="kv-value">{event.attack_type || event.classification}</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Classifier Confidence</span>
              <span className="kv-value mono">{(event.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Detection Method</span>
              <span className="kv-value">{event.detection_method || 'ML + Heuristic'}</span>
            </div>
            {event.ml_score !== undefined && (
              <div className="kv-item">
                <span className="kv-label">ML Attack Probability</span>
                <span className="kv-value mono">{(event.ml_score * 100).toFixed(1)}%</span>
              </div>
            )}
            {event.heuristic_score !== undefined && (
              <div className="kv-item">
                <span className="kv-label">Heuristic Threat Score</span>
                <span className="kv-value mono">{event.heuristic_score} / 100</span>
              </div>
            )}
          </div>

          {event.reasons && event.reasons.length > 0 && (
            <div style={{ marginTop: '0.85rem' }}>
              <span className="kv-label">Evidence & Reasons:</span>
              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.35rem', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                {event.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* 3. NETWORK SECTION */}
        {hasNetwork && (
          <div className="evidence-section">
            <div className="evidence-header">
              <Network size={14} />
              <span>Network Coordinates</span>
            </div>
            <div className="kv-grid">
              {event.source_ip && (
                <div className="kv-item">
                  <span className="kv-label">Source IP</span>
                  <span className="kv-value mono">{event.source_ip}</span>
                </div>
              )}
              {event.source_port !== undefined && event.source_port !== null && (
                <div className="kv-item">
                  <span className="kv-label">Source Port</span>
                  <span className="kv-value mono">{event.source_port}</span>
                </div>
              )}
              {event.destination_ip && (
                <div className="kv-item">
                  <span className="kv-label">Destination IP</span>
                  <span className="kv-value mono">{event.destination_ip}</span>
                </div>
              )}
              {event.destination_port !== undefined && event.destination_port !== null && (
                <div className="kv-item">
                  <span className="kv-label">Destination Port</span>
                  <span className="kv-value mono">{event.destination_port}</span>
                </div>
              )}
              {event.protocol && (
                <div className="kv-item">
                  <span className="kv-label">Protocol</span>
                  <span className="kv-value mono">{event.protocol}</span>
                </div>
              )}
              {event.domain && (
                <div className="kv-item">
                  <span className="kv-label">Domain / Host</span>
                  <span className="kv-value mono">{event.domain}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 4. RULE EVIDENCE */}
        {hasRuleEvidence && (
          <div className="evidence-section">
            <div className="evidence-header">
              <BookOpen size={14} />
              <span>Deterministic Rule Evidence</span>
            </div>
            <div className="kv-grid">
              {metadata.rule_id && (
                <div className="kv-item">
                  <span className="kv-label">Rule ID</span>
                  <span className="kv-value mono">
                    {typeof metadata.rule_id === 'object' ? (metadata.rule_id.rule_id || JSON.stringify(metadata.rule_id)) : String(metadata.rule_id)}
                  </span>
                </div>
              )}
              {metadata.rule_name && (
                <div className="kv-item">
                  <span className="kv-label">Rule Name</span>
                  <span className="kv-value">
                    {typeof metadata.rule_name === 'object' ? (metadata.rule_name.name || JSON.stringify(metadata.rule_name)) : String(metadata.rule_name)}
                  </span>
                </div>
              )}
            </div>
            {Array.isArray(ruleMatches) && ruleMatches.length > 0 && (
              <div style={{ marginTop: '0.65rem' }}>
                <span className="kv-label">Matched Rules:</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.35rem' }}>
                  {ruleMatches.map((rule: any, idx: number) => {
                    const rId = typeof rule === 'string' ? rule : rule.rule_id || JSON.stringify(rule);
                    return (
                      <span key={idx} className="mono" style={{ background: 'var(--low-bg)', border: '1px solid var(--low-border)', color: 'var(--low-color)', padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                        {rId}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 5. THREAT INTELLIGENCE (IOC) */}
        {hasThreatIntel && (
          <div className="evidence-section">
            <div className="evidence-header">
              <Database size={14} />
              <span>Local Threat Intelligence (IOC Match)</span>
            </div>
            <div className="kv-grid">
              {iocMatch?.indicator && (
                <div className="kv-item">
                  <span className="kv-label">Matched Indicator</span>
                  <span className="kv-value mono" style={{ color: 'var(--crit-color)' }}>
                    {iocMatch.indicator}
                  </span>
                </div>
              )}
              {iocMatch?.ioc_type && (
                <div className="kv-item">
                  <span className="kv-label">IOC Type</span>
                  <span className="kv-value">{iocMatch.ioc_type}</span>
                </div>
              )}
              {iocMatch?.category && (
                <div className="kv-item">
                  <span className="kv-label">IOC Category</span>
                  <span className="kv-value">{iocMatch.category}</span>
                </div>
              )}
              {iocMatch?.severity && (
                <div className="kv-item">
                  <span className="kv-label">IOC Severity</span>
                  <span className="kv-value">
                    <SeverityBadge severity={iocMatch.severity} size="sm" />
                  </span>
                </div>
              )}
              {iocMatch?.confidence !== undefined && (
                <div className="kv-item">
                  <span className="kv-label">IOC Confidence</span>
                  <span className="kv-value mono">{(iocMatch.confidence * 100).toFixed(0)}%</span>
                </div>
              )}
              {iocMatch?.source && (
                <div className="kv-item">
                  <span className="kv-label">Intelligence Source</span>
                  <span className="kv-value">{iocMatch.source}</span>
                </div>
              )}
            </div>
            {iocMatch?.description && (
              <div style={{ marginTop: '0.65rem' }}>
                <span className="kv-label">Explanation:</span>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                  {iocMatch.description}
                </p>
              </div>
            )}
          </div>
        )}

        {/* 6. CORRELATION & INCIDENTS */}
        {hasCorrelation && (
          <div className="evidence-section">
            <div className="evidence-header">
              <GitBranch size={14} />
              <span>Incident Correlation</span>
            </div>
            <div className="kv-grid">
              {incidentId && (
                <div className="kv-item">
                  <span className="kv-label">Associated Incident ID</span>
                  <span className="kv-value mono" style={{ color: 'var(--accent-cyan)' }}>
                    {incidentId}
                  </span>
                </div>
              )}
              {metadata.event_count !== undefined && (
                <div className="kv-item">
                  <span className="kv-label">Correlated Event Count</span>
                  <span className="kv-value mono">{metadata.event_count}</span>
                </div>
              )}
              {metadata.escalation_detected !== undefined && (
                <div className="kv-item">
                  <span className="kv-label">Escalation Detected</span>
                  <span className="kv-value" style={{ color: metadata.escalation_detected ? 'var(--crit-color)' : 'var(--benign-color)' }}>
                    {metadata.escalation_detected ? 'YES (Aggressive Repetition)' : 'NO'}
                  </span>
                </div>
              )}
            </div>
            {incidentId && onNavigateToIncident && (
              <button
                className="control-btn primary"
                style={{ marginTop: '0.75rem' }}
                onClick={() => {
                  onClose();
                  onNavigateToIncident(incidentId);
                }}
              >
                View Correlated Incident
              </button>
            )}
          </div>
        )}

        {/* 7. PREVENTION */}
        {hasPrevention && (
          <div className="evidence-section">
            <div className="evidence-header">
              <Lock size={14} />
              <span>Prevention & IPS Action</span>
            </div>
            <div className="kv-grid">
              {metadata.prevention_mode && (
                <div className="kv-item">
                  <span className="kv-label">Active Mode</span>
                  <span className="kv-value mono">{metadata.prevention_mode}</span>
                </div>
              )}
              {(event.action || metadata.prevention_action) && (
                <div className="kv-item">
                  <span className="kv-label">Action Applied</span>
                  <span className="kv-value" style={{ fontWeight: 700, color: event.action === 'BLOCK' ? 'var(--crit-color)' : 'var(--low-color)' }}>
                    {event.action || metadata.prevention_action}
                  </span>
                </div>
              )}
              {event.recommendation && (
                <div className="kv-item" style={{ gridColumn: '1 / -1' }}>
                  <span className="kv-label">Security Recommendation</span>
                  <span className="kv-value" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    {event.recommendation}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
