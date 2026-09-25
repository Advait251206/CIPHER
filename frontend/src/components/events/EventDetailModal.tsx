import React, { useState } from 'react';
import { SecurityEventItem } from '../../api/types';
import { Modal } from '../common/Modal';
import { SeverityBadge } from '../common/SeverityBadge';
import { RiskGauge } from '../common/RiskGauge';
import { Shield, Network, AlertTriangle, BookOpen, Database, GitBranch, Lock, FileText, Printer } from 'lucide-react';
import { cn } from '../../lib/cn';
import { controlBtn, evidenceHeader, evidenceSection, kvGrid, kvItem, kvLabel, kvValue, mono } from '../../ui/classes';

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
  const [popupBlocked, setPopupBlocked] = useState(false);
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
    const reportId = `RPT-${event.event_id?.substring(0, 8).toUpperCase() || Math.random().toString(36).substring(2, 10).toUpperCase()}`;
    
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <title>CIPHER Intelligence Report - ${event.event_id}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');
    
    :root {
      --bg: #0B0B0B;
      --surface: #141414;
      --border: #2A2A2A;
      --text-main: #F8FAFC;
      --text-muted: #94A3B8;
      --accent-gold: #D4AF37;
      --accent-cyan: #22D3EE;
    }
    
    * {
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
      box-sizing: border-box;
    }

    @page {
      size: A4 portrait;
      margin: 0;
    }

    body {
      font-family: 'Inter', -apple-system, sans-serif;
      line-height: 1.6;
      color: var(--text-main);
      background-color: var(--bg);
      margin: 0;
      padding: 0;
    }

    /* Cover Page */
    .cover-page {
      height: 297mm;
      width: 210mm;
      padding: 3cm;
      display: flex;
      flex-direction: column;
      justify-content: center;
      position: relative;
      page-break-after: always;
      background: var(--bg);
    }
    
    .cover-bg-element {
      position: absolute;
      top: 0; right: 0; bottom: 0; left: 0;
      background: radial-gradient(circle at 100% 0%, rgba(34, 211, 238, 0.05) 0%, transparent 50%),
                  radial-gradient(circle at 0% 100%, rgba(212, 175, 55, 0.05) 0%, transparent 50%);
      z-index: 0;
    }

    .cover-content {
      position: relative;
      z-index: 1;
      border-left: 4px solid var(--accent-gold);
      padding-left: 2rem;
    }

    .cover-brand {
      font-size: 48px;
      font-weight: 900;
      letter-spacing: 4px;
      margin-bottom: 0.5rem;
      color: #FFF;
    }
    .cover-brand span { color: var(--accent-gold); }

    .cover-subtitle {
      font-size: 14px;
      color: var(--accent-cyan);
      text-transform: uppercase;
      letter-spacing: 3px;
      font-weight: 600;
      margin-bottom: 4rem;
    }

    .cover-title {
      font-size: 36px;
      font-weight: 700;
      line-height: 1.2;
      color: #FFF;
      margin-bottom: 2rem;
      max-width: 80%;
    }

    .cover-meta {
      margin-top: 4rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--text-muted);
    }
    .cover-meta table {
      width: 100%;
      border-collapse: collapse;
    }
    .cover-meta td {
      padding: 8px 0;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }
    .cover-meta td:first-child {
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      width: 150px;
    }
    .cover-meta td:last-child {
      color: #FFF;
      font-weight: 600;
    }

    /* Content Pages */
    .content-page {
      padding: 1cm 2.5cm;
      background: var(--bg);
      width: 210mm;
      position: relative;
    }
    .content-page:nth-of-type(2) {
      padding-top: 2.5cm;
    }
    .content-page:last-child {
      padding-bottom: 2.5cm;
    }

    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 3rem;
    }
    .page-header-brand {
      font-size: 16px;
      font-weight: 900;
      letter-spacing: 2px;
      color: #FFF;
    }
    .page-header-brand span { color: var(--accent-gold); }
    .page-header-meta {
      font-size: 9px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .section {
      margin-bottom: 3rem;
    }

    .section-title {
      font-size: 18px;
      font-weight: 300;
      color: var(--accent-cyan);
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }

    .prose {
      font-size: 13px;
      color: #E2E8F0;
      line-height: 1.8;
      font-weight: 300;
      text-align: justify;
    }
    .prose p {
      margin-bottom: 1.25rem;
    }
    
    .two-column-prose {
      display: column;
      column-count: 2;
      column-gap: 2rem;
      text-align: justify;
      font-size: 11px;
      color: #94A3B8;
      line-height: 1.7;
    }

    .info-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }
    .info-table th, .info-table td {
      padding: 12px 0;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    .info-table th {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 500;
      width: 30%;
    }
    .info-table td {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #FFF;
    }

    .json-block {
      background: #0f172a;
      border: 1px solid var(--border);
      padding: 1.5rem;
      color: #e2e8f0;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 2px;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-family: 'Inter', sans-serif;
    }
    .badge.critical, .badge.high { color: #ef4444; border: 1px solid rgba(239,68,68,0.3); background: rgba(239,68,68,0.05); }
    .badge.medium { color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); background: rgba(245,158,11,0.05); }
    .badge.low { color: #22c55e; border: 1px solid rgba(34,197,94,0.3); background: rgba(34,197,94,0.05); }

    .tech-box {
      border-left: 3px solid var(--accent-cyan);
      padding: 1rem 1.5rem;
      background: var(--surface);
      margin-bottom: 1.5rem;
    }
    .tech-box h4 {
      margin: 0 0 0.5rem 0;
      font-size: 12px;
      color: var(--accent-cyan);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    @media print {
      body { background: var(--bg) !important; }
      .cover-page, .content-page { box-shadow: none; margin: 0; padding: 2cm; }
    }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="cover-page">
    <div class="cover-bg-element"></div>
    <div class="cover-content">
      <div class="cover-brand">CIPHER<span>.</span></div>
      <div class="cover-subtitle">Cyber Intelligence & Heuristic Response</div>
      
      <div class="cover-title">Threat Intelligence<br>Event Diagnostics</div>
      
      <div class="cover-meta">
        <table>
          <tr><td>Report ID</td><td>EVT-${event.event_id.substring(0, 8).toUpperCase()}</td></tr>
          <tr><td>Date Generated</td><td>${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</td></tr>
          <tr><td>Target Platform</td><td>CIPHER Security Network</td></tr>
          <tr><td>Classification</td><td>RESTRICTED / CONFIDENTIAL</td></tr>
        </table>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">1.0 Event Telemetry</h2>
      <table class="info-table">
        <tr><th>Event Identifier</th><td><span style="color:var(--accent-cyan)">${event.event_id}</span></td></tr>
        <tr><th>Timestamp (UTC)</th><td>${new Date(event.timestamp).toISOString().replace('T', ' ').substring(0, 19)}</td></tr>
        <tr><th>Classification</th><td>${event.classification || event.event_type}</td></tr>
        <tr><th>Threat Level</th><td><span class="badge ${event.severity.toLowerCase()}">${event.severity}</span></td></tr>
        <tr><th>Source Infrastructure</th><td>${event.source_ip || 'N/A'}</td></tr>
        <tr><th>Target Infrastructure</th><td>${event.destination_ip || 'N/A'}</td></tr>
        <tr><th>Protocol</th><td>${event.protocol || 'N/A'}</td></tr>
        ${event.domain ? `<tr><th>Target Domain/Host</th><td>${event.domain}</td></tr>` : ''}
        ${event.source_port !== undefined ? `<tr><th>Source Port</th><td>${event.source_port}</td></tr>` : ''}
        ${event.destination_port !== undefined ? `<tr><th>Target Port</th><td>${event.destination_port}</td></tr>` : ''}
      </table>
    </div>

    <div class="section">
      <h2 class="section-title">2.0 Mitigation & Response</h2>
      <table class="info-table">
        <tr>
          <th>Risk Score</th>
          <td>${event.risk_score || 0} / 100</td>
        </tr>
        <tr>
          <th>Confidence</th>
          <td>${((event.confidence || 0) * 100).toFixed(1)}%</td>
        </tr>
        <tr>
          <th>Rule Matches</th>
          <td>${metadata.rule_id ? (typeof metadata.rule_id === 'object' ? metadata.rule_id.rule_id || JSON.stringify(metadata.rule_id) : metadata.rule_id) : 'No deterministic rules triggered.'}</td>
        </tr>
        <tr>
          <th>Action Taken</th>
          <td style="color:var(--accent-gold);font-weight:700">${event.action || metadata.prevention_action || 'DETECT_ONLY'}</td>
        </tr>
        <tr>
          <th>Recommendation</th>
          <td>${event.recommendation || 'Review event telemetry for further context.'}</td>
        </tr>
      </table>
    </div>

    <div class="section">
      <h2 class="section-title">3.0 Raw Heuristic Payload</h2>
    <div class="section">
      <h2 class="section-title">4.0 CIPHER Detection Methodology</h2>
      <div class="prose">
        <p>The Cyber Intrusion Prevention & Heuristic Event Response (CIPHER) engine utilizes a multi-layered detection pipeline combining signature-based pattern matching, behavioral anomaly detection (Heuristics), and temporal clustering to identify active threats in high-noise network environments.</p>
        
        <div class="tech-box">
          <h4>Single-Event Contextualization</h4>
          <p style="margin:0;font-size:12px">Individual security events (firewall drops, WAF alerts, IDS triggers) are instantly passed through a deterministic rules engine before being scored by the heuristic anomaly model. CIPHER analyzes protocol anomalies, rate-limit thresholds, and known malicious payload signatures (e.g. SNORT/Suricata signatures) to provide an immediate mitigation decision.</p>
        </div>

        <div class="tech-box">
          <h4>Heuristic Risk Scoring</h4>
          <p style="margin:0;font-size:12px">Risk is calculated using a dynamic baseline model. A base score is assigned via static classification (e.g., SQLi carries a higher base weight than a Port Scan). The score is then modulated by frequency (velocity of requests), target criticality, and historical reputation of the source ASN. An incident is deemed "Escalated" when the aggregate risk gradient exceeds the acceptable operational threshold for 3 consecutive timeframes.</p>
        </div>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">5.0 Threat Vector Intelligence Glossary</h2>
      <div class="two-column-prose">
        <p><strong style="color:var(--text-main)">Distributed Denial of Service (DDoS):</strong> An attack in which multiple compromised computer systems attack a target, such as a server, website or other network resource, and cause a denial of service for users of the targeted resource. The flood of incoming messages, connection requests or malformed packets to the target system forces it to slow down or even crash and shut down, thereby denying service to legitimate users or systems. CIPHER detects these through volumetric thresholding and TCP connection-state tracking.</p>

        <p><strong style="color:var(--text-main)">SQL Injection (SQLi):</strong> A code injection technique used to attack data-driven applications. Malicious SQL statements are inserted into entry fields for execution (e.g., to dump the database contents to the attacker). CIPHER identifies SQLi through rigorous regex pattern matching against incoming HTTP requests, inspecting payloads, headers, and query parameters for anomalous SQL syntaxes (e.g., UNION SELECT, WAITFOR DELAY).</p>

        <p><strong style="color:var(--text-main)">Cross-Site Scripting (XSS):</strong> A type of security vulnerability typically found in web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls. Detected by CIPHER's WAF module identifying DOM-altering script tags or encoded javascript pseudo-protocols.</p>

        <p><strong style="color:var(--text-main)">Phishing / Malicious URLs:</strong> The fraudulent attempt to obtain sensitive information or data, such as usernames, passwords, and credit card details, by disguising oneself as a trustworthy entity in an electronic communication. CIPHER's URL inspector utilizes deep learning models (such as BERT) to extract lexical features from URLs, comparing topological similarities against known malicious domains and analyzing domain age and entropy.</p>

        <p><strong style="color:var(--text-main)">Network Reconnaissance (Port Scanning):</strong> A technique used by attackers to discover open doors (ports) on a network, identifying active hosts, running services, and potential vulnerabilities before launching an actual exploit. Detected via rapid SYN/ACK connection attempts across non-standard port ranges emanating from a singular source IP.</p>
      </div>
    </div>
    <div class="page-header">
      <div class="page-header-brand">CIPHER<span>.</span></div>
      <div class="page-header-meta">REMEDIATION & PROTOCOLS | PAGE 3 OF 3</div>
    </div>

    <div class="section">
      <h2 class="section-title">6.0 Standard Operating Procedures (SOP)</h2>
      <div class="prose">
        <p>In the event of a verified cyber incident matching the patterns detailed in Section 1.0, Security Operations Center (SOC) personnel must adhere to the following phased response protocols to contain the threat and restore nominal operational capacity.</p>
      </div>

      <table class="info-table">
        <tr>
          <th style="width:15%">Phase I</th>
          <td><strong>Triage & Identification</strong><br><span style="color:var(--text-muted);font-size:11px">Validate the IOCs provided in this dossier. Cross-reference the Source Infrastructure against trusted intelligence feeds (e.g., VirusTotal, AlienVault OTX) to confirm malicious intent and rule out false positives.</span></td>
        </tr>
        <tr>
          <th>Phase II</th>
          <td><strong>Containment</strong><br><span style="color:var(--text-muted);font-size:11px">If an active attack (e.g., DDoS or Brute Force) is ongoing, implement immediate blackhole routing for the offending IP space. For application-layer attacks (SQLi, XSS), enforce strict WAF blocking rules for the identified patterns and immediately terminate the attacker's active session tokens.</span></td>
        </tr>
        <tr>
          <th>Phase III</th>
          <td><strong>Eradication</strong><br><span style="color:var(--text-muted);font-size:11px">Identify the root cause vulnerability that permitted the attack vector. Patch affected software, update firewall policies, and sanitize any systems or databases that may have been compromised or altered during the intrusion window.</span></td>
        </tr>
        <tr>
          <th>Phase IV</th>
          <td><strong>Recovery</strong><br><span style="color:var(--text-muted);font-size:11px">Restore systems to normal operation. Validate that the eradication was successful by monitoring the affected infrastructure for 24-48 hours. Ensure that business continuity has been maintained and assess any potential data exfiltration for legal compliance reporting.</span></td>
        </tr>
      </table>
    </div>

    <div style="margin-top:5rem;border-top:1px solid var(--border);padding-top:2rem;text-align:center;">
      <div style="font-size:10px;color:var(--accent-gold);letter-spacing:3px;text-transform:uppercase;font-weight:700;margin-bottom:1rem;">END OF REPORT</div>
      <div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">
        CIPHER SOC Automated Intelligence Engine<br>
        CONFIDENTIAL — INTERNAL USE ONLY
      </div>
    </div>
  </div>

  <script>
    window.onload = function() {
      setTimeout(function() { window.print(); }, 800);
    }
  <\/script>
</body>
</html>`;

    const iframe = document.createElement('iframe');
    iframe.style.position = 'fixed';
    iframe.style.right = '0';
    iframe.style.bottom = '0';
    iframe.style.width = '0';
    iframe.style.height = '0';
    iframe.style.border = '0';
    document.body.appendChild(iframe);

    const doc = iframe.contentWindow?.document;
    if (doc) {
      doc.open();
      doc.write(htmlContent);
      doc.close();
      
      setTimeout(() => {
        iframe.contentWindow?.focus();
        iframe.contentWindow?.print();
        setTimeout(() => document.body.removeChild(iframe), 1000);
      }, 800);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      wide
      title={
        <div className="flex items-center gap-3">
          <Shield size={20} color="var(--color-accent)" />
          <span>Security Event Details</span>
          <SeverityBadge severity={event.severity} size="sm" />
        </div>
      }
      footer={
        <div className="flex gap-3">
          <button className={cn(controlBtn(), 'flex items-center gap-2 bg-[#f1f5f9] text-[#334155] border border-[#cbd5e1] not-disabled:hover:bg-[#f1f5f9] not-disabled:hover:text-[#334155] not-disabled:hover:border-[#cbd5e1]')} onClick={generateReportTxt}>
            <FileText size={16} /> TXT Report
          </button>
          <button className={cn(controlBtn('primary'), 'flex items-center gap-2 bg-accent text-white border-none')} onClick={generateReportPdf}>
            <Printer size={16} /> Print / Save as PDF
          </button>
          <div className="flex-1"></div>
          <button className={controlBtn()} onClick={onClose}>
            Close Inspector
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-4">
        {/* Popup Blocker Warning */}
        {popupBlocked && (
          <div className="py-3 px-4 bg-med-bg border border-[#D4AF37] rounded-[6px] flex items-center justify-between gap-3">
            <span className="text-accent text-[0.85rem] font-semibold">
              ⚠ Popup blocked — allow popups in your browser to open the print/PDF window.
            </span>
            <button
              onClick={() => setPopupBlocked(false)}
              className="bg-transparent border-none text-fg-muted cursor-pointer text-[1.1rem] leading-none"
            >
              &times;
            </button>
          </div>
        )}
        {/* 1. EVENT SECTION */}
        <div className={evidenceSection}>
          <div className={evidenceHeader}>
            <Shield size={14} />
            <span>Event Metadata</span>
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>Event ID</span>
              <span className={cn(mono, kvValue)}>{event.event_id}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Timestamp</span>
              <span className={cn(mono, kvValue)}>{event.timestamp}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Event Type</span>
              <span className={kvValue}>{event.event_type || 'SECURITY_EVENT'}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Detection Source</span>
              <span className={kvValue}>{event.source || 'CIPHER Engine'}</span>
            </div>
            {event.status && (
              <div className={kvItem}>
                <span className={kvLabel}>Status</span>
                <span className={kvValue}>{event.status}</span>
              </div>
            )}
          </div>
        </div>

        {/* 2. THREAT VERDICT SECTION */}
        <div className={evidenceSection}>
          <div className={evidenceHeader}>
            <AlertTriangle size={14} />
            <span>Threat Assessment</span>
          </div>
          <div className="mb-[0.85rem]">
            <RiskGauge score={event.risk_score} label="Threat Score" />
          </div>
          <div className={kvGrid}>
            <div className={kvItem}>
              <span className={kvLabel}>Classification</span>
              <span className={kvValue}>{event.classification}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Attack Category</span>
              <span className={kvValue}>{event.attack_type || event.classification}</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Classifier Confidence</span>
              <span className={cn(mono, kvValue)}>{(event.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Detection Method</span>
              <span className={kvValue}>{event.detection_method || 'ML + Heuristic'}</span>
            </div>
            {event.ml_score !== undefined && (
              <div className={kvItem}>
                <span className={kvLabel}>ML Attack Probability</span>
                <span className={cn(mono, kvValue)}>{(event.ml_score * 100).toFixed(1)}%</span>
              </div>
            )}
            {event.heuristic_score !== undefined && (
              <div className={kvItem}>
                <span className={kvLabel}>Heuristic Threat Score</span>
                <span className={cn(mono, kvValue)}>{event.heuristic_score} / 100</span>
              </div>
            )}
          </div>

          {event.reasons && event.reasons.length > 0 && (
            <div className="mt-[0.85rem]">
              <span className={kvLabel}>Evidence & Reasons:</span>
              <ul className="pl-5 mt-[0.35rem] text-fg-2 text-[0.82rem]">
                {event.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* 3. NETWORK SECTION */}
        {hasNetwork && (
          <div className={evidenceSection}>
            <div className={evidenceHeader}>
              <Network size={14} />
              <span>Network Coordinates</span>
            </div>
            <div className={kvGrid}>
              {event.source_ip && (
                <div className={kvItem}>
                  <span className={kvLabel}>Source IP</span>
                  <span className={cn(mono, kvValue)}>{event.source_ip}</span>
                </div>
              )}
              {event.source_port !== undefined && event.source_port !== null && (
                <div className={kvItem}>
                  <span className={kvLabel}>Source Port</span>
                  <span className={cn(mono, kvValue)}>{event.source_port}</span>
                </div>
              )}
              {event.destination_ip && (
                <div className={kvItem}>
                  <span className={kvLabel}>Destination IP</span>
                  <span className={cn(mono, kvValue)}>{event.destination_ip}</span>
                </div>
              )}
              {event.destination_port !== undefined && event.destination_port !== null && (
                <div className={kvItem}>
                  <span className={kvLabel}>Destination Port</span>
                  <span className={cn(mono, kvValue)}>{event.destination_port}</span>
                </div>
              )}
              {event.protocol && (
                <div className={kvItem}>
                  <span className={kvLabel}>Protocol</span>
                  <span className={cn(mono, kvValue)}>{event.protocol}</span>
                </div>
              )}
              {event.domain && (
                <div className={kvItem}>
                  <span className={kvLabel}>Domain / Host</span>
                  <span className={cn(mono, kvValue)}>{event.domain}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 4. RULE EVIDENCE */}
        {hasRuleEvidence && (
          <div className={evidenceSection}>
            <div className={evidenceHeader}>
              <BookOpen size={14} />
              <span>Deterministic Rule Evidence</span>
            </div>
            <div className={kvGrid}>
              {metadata.rule_id && (
                <div className={kvItem}>
                  <span className={kvLabel}>Rule ID</span>
                  <span className={cn(mono, kvValue)}>
                    {typeof metadata.rule_id === 'object' ? (metadata.rule_id.rule_id || JSON.stringify(metadata.rule_id)) : String(metadata.rule_id)}
                  </span>
                </div>
              )}
              {metadata.rule_name && (
                <div className={kvItem}>
                  <span className={kvLabel}>Rule Name</span>
                  <span className={kvValue}>
                    {typeof metadata.rule_name === 'object' ? (metadata.rule_name.name || JSON.stringify(metadata.rule_name)) : String(metadata.rule_name)}
                  </span>
                </div>
              )}
            </div>
            {Array.isArray(ruleMatches) && ruleMatches.length > 0 && (
              <div className="mt-[0.65rem]">
                <span className={kvLabel}>Matched Rules:</span>
                <div className="flex flex-wrap gap-[0.4rem] mt-[0.35rem]">
                  {ruleMatches.map((rule: any, idx: number) => {
                    const rId = typeof rule === 'string' ? rule : rule.rule_id || JSON.stringify(rule);
                    return (
                      <span key={idx} className={cn(mono, 'bg-low-bg border border-low text-low py-[0.15rem] px-[0.45rem] rounded-[4px] text-[0.75rem]')}>
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
          <div className={evidenceSection}>
            <div className={evidenceHeader}>
              <Database size={14} />
              <span>Local Threat Intelligence (IOC Match)</span>
            </div>
            <div className={kvGrid}>
              {iocMatch?.indicator && (
                <div className={kvItem}>
                  <span className={kvLabel}>Matched Indicator</span>
                  <span className={cn(mono, kvValue, 'text-crit')}>
                    {iocMatch.indicator}
                  </span>
                </div>
              )}
              {iocMatch?.ioc_type && (
                <div className={kvItem}>
                  <span className={kvLabel}>IOC Type</span>
                  <span className={kvValue}>{iocMatch.ioc_type}</span>
                </div>
              )}
              {iocMatch?.category && (
                <div className={kvItem}>
                  <span className={kvLabel}>IOC Category</span>
                  <span className={kvValue}>{iocMatch.category}</span>
                </div>
              )}
              {iocMatch?.severity && (
                <div className={kvItem}>
                  <span className={kvLabel}>IOC Severity</span>
                  <span className={kvValue}>
                    <SeverityBadge severity={iocMatch.severity} size="sm" />
                  </span>
                </div>
              )}
              {iocMatch?.confidence !== undefined && (
                <div className={kvItem}>
                  <span className={kvLabel}>IOC Confidence</span>
                  <span className={cn(mono, kvValue)}>{(iocMatch.confidence * 100).toFixed(0)}%</span>
                </div>
              )}
              {iocMatch?.source && (
                <div className={kvItem}>
                  <span className={kvLabel}>Intelligence Source</span>
                  <span className={kvValue}>{iocMatch.source}</span>
                </div>
              )}
            </div>
            {iocMatch?.description && (
              <div className="mt-[0.65rem]">
                <span className={kvLabel}>Explanation:</span>
                <p className="text-[0.82rem] text-fg-2 mt-[0.2rem]">
                  {iocMatch.description}
                </p>
              </div>
            )}
          </div>
        )}

        {/* 6. CORRELATION & INCIDENTS */}
        {hasCorrelation && (
          <div className={evidenceSection}>
            <div className={evidenceHeader}>
              <GitBranch size={14} />
              <span>Incident Correlation</span>
            </div>
            <div className={kvGrid}>
              {incidentId && (
                <div className={kvItem}>
                  <span className={kvLabel}>Associated Incident ID</span>
                  <span className={cn(mono, kvValue, 'text-accent')}>
                    {incidentId}
                  </span>
                </div>
              )}
              {metadata.event_count !== undefined && (
                <div className={kvItem}>
                  <span className={kvLabel}>Correlated Event Count</span>
                  <span className={cn(mono, kvValue)}>{metadata.event_count}</span>
                </div>
              )}
              {metadata.escalation_detected !== undefined && (
                <div className={kvItem}>
                  <span className={kvLabel}>Escalation Detected</span>
                  <span className={cn(kvValue, (metadata.escalation_detected ? 'text-crit' : 'text-benign'))}>
                    {metadata.escalation_detected ? 'YES (Aggressive Repetition)' : 'NO'}
                  </span>
                </div>
              )}
            </div>
            {incidentId && onNavigateToIncident && (
              <button
                className={cn(controlBtn('primary'), 'mt-3')}

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
          <div className={evidenceSection}>
            <div className={evidenceHeader}>
              <Lock size={14} />
              <span>Prevention & IPS Action</span>
            </div>
            <div className={kvGrid}>
              {metadata.prevention_mode && (
                <div className={kvItem}>
                  <span className={kvLabel}>Active Mode</span>
                  <span className={cn(mono, kvValue)}>{metadata.prevention_mode}</span>
                </div>
              )}
              {(event.action || metadata.prevention_action) && (
                <div className={kvItem}>
                  <span className={kvLabel}>Action Applied</span>
                  <span className={cn(kvValue, 'font-bold', (event.action === 'BLOCK' ? 'text-crit' : 'text-low'))}>
                    {event.action || metadata.prevention_action}
                  </span>
                </div>
              )}
              {event.recommendation && (
                <div className={cn(kvItem, '[grid-column:1_/_-1]')}>
                  <span className={kvLabel}>Security Recommendation</span>
                  <span className={cn(kvValue, 'text-fg font-semibold')}>
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
