import React from 'react';
import { SecurityEventItem } from '../../api/types';
import { Modal } from '../common/Modal';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskGauge } from '../common/RiskGauge';
import { Shield, Network, AlertTriangle, BookOpen, Database, GitBranch, Lock, FileText, Printer } from 'lucide-react';

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

  const generateReportTxt = () => {
    if (!event) return;
    
    const metadata = event.metadata || {};
    
    const reportContent = `
================================================================================
                       CIPHER OFFICIAL THREAT REPORT
================================================================================
Generated On: ${new Date().toISOString()}
Report ID: RPT-${event.event_id?.substring(0, 8).toUpperCase() || Math.random().toString(36).substring(2, 10).toUpperCase()}

[ 1. EVENT SUMMARY ]
--------------------------------------------------------------------------------
Timestamp:       ${event.timestamp}
Event Type:      ${event.event_type || 'SECURITY_EVENT'}
Detection Src:   ${event.source || 'CIPHER Engine'}
Severity:        ${event.severity.toUpperCase()}
Status:          ${event.status || 'N/A'}

[ 2. THREAT SYNTHESIS ]
--------------------------------------------------------------------------------
Classification:  ${event.classification}
Attack Type:     ${event.attack_type || event.classification}
Risk Score:      ${event.risk_score} / 100
Confidence:      ${(event.confidence * 100).toFixed(1)}%
Detection Model: ${event.detection_method || 'ML + Heuristic'}
${event.reasons && event.reasons.length > 0 ? '\nReasons for Detection:\n' + event.reasons.map(r => `  - ${r}`).join('\n') : ''}

[ 3. TARGET ASSET & NETWORK METRICS ]
--------------------------------------------------------------------------------
${event.source_ip ? `Source IP:       ${event.source_ip}` : ''}
${event.source_port !== undefined ? `Source Port:     ${event.source_port}` : ''}
${event.destination_ip ? `Target IP:       ${event.destination_ip}` : ''}
${event.destination_port !== undefined ? `Target Port:     ${event.destination_port}` : ''}
${event.protocol ? `Protocol:        ${event.protocol}` : ''}
${event.domain ? `Domain/Host:     ${event.domain}` : ''}

[ 4. DETERMINISTIC RULE MATCHES ]
--------------------------------------------------------------------------------
${metadata.rule_id ? `Rule ID:         ${typeof metadata.rule_id === 'object' ? metadata.rule_id.rule_id || JSON.stringify(metadata.rule_id) : metadata.rule_id}` : 'No deterministic rules triggered.'}

[ 5. MITIGATION & RESPONSE ]
--------------------------------------------------------------------------------
Action Taken:    ${event.action || metadata.prevention_action || 'DETECT_ONLY'}
Recommendation:  ${event.recommendation || 'Review event telemetry for further context.'}
================================================================================
END OF REPORT
================================================================================
`.trim();

    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CIPHER_Report_${event.event_id?.substring(0,8) || 'Event'}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const generateReportPdf = () => {
    if (!event) return;
    const metadata = event.metadata || {};
    
    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <title>CIPHER Threat Report - ${event.event_id}</title>
  <style>
    body {
      font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 800px;
      margin: 0 auto;
      padding: 40px;
    }
    .header {
      border-bottom: 3px solid #3b82f6;
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .logo {
      font-size: 28px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: 1px;
    }
    .logo span { color: #3b82f6; }
    .report-meta {
      text-align: right;
      font-size: 12px;
      color: #64748b;
    }
    .section {
      margin-bottom: 30px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 20px;
      page-break-inside: avoid;
    }
    .section-title {
      font-size: 16px;
      font-weight: 700;
      color: #0f172a;
      text-transform: uppercase;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 10px;
      margin-top: 0;
      margin-bottom: 15px;
      letter-spacing: 0.5px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solid #e2e8f0;
    }
    th {
      width: 160px;
      font-weight: 600;
      color: #475569;
      background-color: #f1f5f9;
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge.high { background: #fee2e2; color: #ef4444; border: 1px solid #fca5a5; }
    .badge.medium { background: #fef3c7; color: #f59e0b; border: 1px solid #fcd34d; }
    .badge.low { background: #dcfce3; color: #22c55e; border: 1px solid #86efac; }
    
    .footer {
      margin-top: 50px;
      text-align: center;
      font-size: 10px;
      color: #94a3b8;
      border-top: 1px solid #e2e8f0;
      padding-top: 20px;
    }
    @media print {
      body { padding: 0; }
      .section { border: 1px solid #cbd5e1; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">CIPHER<span>.</span></div>
    <div class="report-meta">
      <strong>OFFICIAL THREAT INCIDENT REPORT</strong><br>
      Report ID: RPT-${event.event_id?.substring(0, 8).toUpperCase() || Math.random().toString(36).substring(2, 10).toUpperCase()}<br>
      Generated: ${new Date().toLocaleString()}
    </div>
  </div>

  <div class="section">
    <h2 class="section-title">1. Event Summary</h2>
    <table>
      <tr><th>Timestamp</th><td>${event.timestamp}</td></tr>
      <tr><th>Event Type</th><td>${event.event_type || 'SECURITY_EVENT'}</td></tr>
      <tr><th>Detection Source</th><td>${event.source || 'CIPHER Engine'}</td></tr>
      <tr><th>Severity</th><td><span class="badge ${event.severity.toLowerCase()}">${event.severity}</span></td></tr>
      <tr><th>Status</th><td>${event.status || 'N/A'}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2 class="section-title">2. Threat Synthesis</h2>
    <table>
      <tr><th>Classification</th><td><strong>${event.classification}</strong></td></tr>
      <tr><th>Attack Type</th><td>${event.attack_type || event.classification}</td></tr>
      <tr><th>Risk Score</th><td>${event.risk_score} / 100</td></tr>
      <tr><th>Confidence</th><td>${(event.confidence * 100).toFixed(1)}%</td></tr>
      <tr><th>Detection Model</th><td>${event.detection_method || 'ML + Heuristic'}</td></tr>
    </table>
    ${event.reasons && event.reasons.length > 0 ? 
      `<h3 style="font-size:14px; margin-top:15px; color:#475569;">Detection Reasons:</h3>
       <ul style="margin-top:5px;">${event.reasons.map(r => `<li>${r}</li>`).join('')}</ul>` 
      : ''}
  </div>

  <div class="section">
    <h2 class="section-title">3. Target Asset & Network Metrics</h2>
    <table>
      ${event.source_ip ? `<tr><th>Source IP</th><td>${event.source_ip}</td></tr>` : ''}
      ${event.source_port !== undefined ? `<tr><th>Source Port</th><td>${event.source_port}</td></tr>` : ''}
      ${event.destination_ip ? `<tr><th>Target IP</th><td>${event.destination_ip}</td></tr>` : ''}
      ${event.destination_port !== undefined ? `<tr><th>Target Port</th><td>${event.destination_port}</td></tr>` : ''}
      ${event.protocol ? `<tr><th>Protocol</th><td>${event.protocol}</td></tr>` : ''}
      ${event.domain ? `<tr><th>Domain/Host</th><td>${event.domain}</td></tr>` : ''}
    </table>
  </div>

  <div class="section">
    <h2 class="section-title">4. Mitigation & Response</h2>
    <table>
      <tr><th>Rule Matches</th><td>${metadata.rule_id ? (typeof metadata.rule_id === 'object' ? metadata.rule_id.rule_id || JSON.stringify(metadata.rule_id) : metadata.rule_id) : 'No deterministic rules triggered.'}</td></tr>
      <tr><th>Action Taken</th><td><strong>${event.action || metadata.prevention_action || 'DETECT_ONLY'}</strong></td></tr>
      <tr><th>Recommendation</th><td>${event.recommendation || 'Review event telemetry for further context.'}</td></tr>
    </table>
  </div>

  <div class="footer">
    CONFIDENTIAL - DO NOT DISTRIBUTE<br>
    Cyber Intrusion Prevention & Heuristic Event Response (CIPHER) Automated System
  </div>
  
  <script>
    window.onload = function() {
      setTimeout(function() {
        window.print();
      }, 500);
    }
  </script>
</body>
</html>
    `;

    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(htmlContent);
      printWindow.document.close();
    } else {
      alert("Please allow popups to generate the PDF report.");
    }
  };

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
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="control-btn" onClick={generateReportTxt} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1' }}>
            <FileText size={16} /> TXT Report
          </button>
          <button className="control-btn primary" onClick={generateReportPdf} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--accent-cyan)', color: 'white', border: 'none' }}>
            <Printer size={16} /> Print / Save as PDF
          </button>
          <div style={{ flex: 1 }}></div>
          <button className="control-btn" onClick={onClose}>
            Close Inspector
          </button>
        </div>
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
