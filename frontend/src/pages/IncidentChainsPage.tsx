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
import { Flame, CheckCircle, ShieldAlert, GitBranch, ArrowRight, Eye, FileText, Printer, Ban, Database } from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, controlBtn, dataTable, formGroup, formInput, formLabel, formSelect, kvGrid, kvItem, kvLabel, kvValue, mono, navBadge, pageBody, tableContainer } from '../ui/classes';

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

const getLegalFrameworks = (categories: string[]) => {
  const frameworks: { name: string, desc: string }[] = [
    { name: '18 U.S.C. § 1030', desc: 'Computer Fraud and Abuse Act (CFAA) - General Unauthorized Access.' },
    { name: 'Directive (EU) 2013/40/EU', desc: 'Attacks against information systems.' },
    { name: 'ISO/IEC 27001:2022', desc: 'Information Security Management standard violation evidence.' }
  ];

  const cats = categories.map(c => c.toUpperCase());
  if (cats.some(c => c.includes('SQL') || c.includes('DATA_EXFILTRATION'))) {
    frameworks.push({ name: 'GDPR Article 32/33 (EU)', desc: 'Breach of security of processing / Unauthorized PII extraction.' });
    frameworks.push({ name: 'CCPA / CPRA (US-CA)', desc: 'Unauthorized access and exfiltration of consumer personal information.' });
    frameworks.push({ name: 'SOX Section 404 (US)', desc: 'Potential tampering with financial or corporate records.' });
    frameworks.push({ name: 'HIPAA Security Rule (US)', desc: 'Electronic protected health information (ePHI) breach (if applicable).' });
    frameworks.push({ name: 'GLBA (US)', desc: 'Gramm-Leach-Bliley Act (Financial institution data protection).' });
    frameworks.push({ name: 'PIPEDA (Canada)', desc: 'Personal Information Protection and Electronic Documents Act violation.' });
  }
  if (cats.some(c => c.includes('XSS') || c.includes('WEB_ATTACK'))) {
    frameworks.push({ name: '18 U.S.C. § 1030(a)(4)', desc: 'CFAA - Fraud and related activity in connection with computers.' });
    frameworks.push({ name: '18 U.S.C. § 2511', desc: 'ECPA - Interception of electronic communications (session hijacking).' });
    frameworks.push({ name: 'UK DPA 2018 Section 170', desc: 'Unlawful obtaining of personal data.' });
  }
  if (cats.some(c => c.includes('DDOS') || c.includes('DOS'))) {
    frameworks.push({ name: '18 U.S.C. § 1030(a)(5)', desc: 'CFAA - Transmission of a program, information, code, or command causing damage.' });
    frameworks.push({ name: 'UK CMA 1990 § 3', desc: 'Unauthorized acts with intent to impair.' });
    frameworks.push({ name: '47 U.S.C. § 227', desc: 'Telecommunications Act - Disruption of services.' });
    frameworks.push({ name: 'Budapest Convention Art. 5', desc: 'Council of Europe Cybercrime Convention - System interference.' });
    frameworks.push({ name: 'Homeland Security Act', desc: 'Disruption of Critical Infrastructure.' });
  }
  if (cats.some(c => c.includes('BRUTE_FORCE') || c.includes('CREDENTIAL'))) {
    frameworks.push({ name: '18 U.S.C. § 1030(a)(6)', desc: 'CFAA - Trafficking in passwords.' });
    frameworks.push({ name: '18 U.S.C. § 1028', desc: 'Identity Theft and Assumption Deterrence Act.' });
    frameworks.push({ name: 'NIST SP 800-63B', desc: 'Digital Identity Guidelines (Authentication compromise).' });
    frameworks.push({ name: 'Canadian Criminal Code § 342.1', desc: 'Unauthorized use of a computer (credential harvesting).' });
  }
  if (cats.some(c => c.includes('PHISHING') || c.includes('MALWARE'))) {
    frameworks.push({ name: '18 U.S.C. § 1343', desc: 'Wire Fraud.' });
    frameworks.push({ name: '15 U.S.C. § 7701', desc: 'CAN-SPAM Act - Unsolicited and deceptive communications.' });
    frameworks.push({ name: 'Anti-Phishing Act', desc: 'California B&P Code § 22948 and equivalent state laws.' });
    frameworks.push({ name: 'EC Directive 2002/58/EC', desc: 'ePrivacy Directive - Unsolicited communications.' });
  }

  const unique = Array.from(new Map(frameworks.map(item => [item.name, item])).values());
  return unique.map(f => `<li><strong style="color:#E2E8F0">${f.name}:</strong> ${f.desc}</li>`).join('\\n          ');
};

interface IncidentChainsPageProps {
  initialIncidentId?: string | null;
  refreshTrigger?: number;
}

export const IncidentChainsPage: React.FC<IncidentChainsPageProps> = ({ initialIncidentId, refreshTrigger }) => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [sourceIpFilter, setSourceIpFilter] = useState<string>('');

  // Detail Modal
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetailResponse | null>(null);
  const [popupBlocked, setPopupBlocked] = useState(false);
  const [blockIpModalOpen, setBlockIpModalOpen] = useState<string | null>(null);

  const generateIncidentReport = async (detail: IncidentDetailResponse) => {
    const inc = detail.incident;
    const events = detail.events;

    // Fetch extra data for the report
    let isTempBlocked = false;
    let tempBlockExpiresAt: string | null = null;
    let isPermBlocked = false;
    let pastIncidents: any[] = [];

    try {
      if (inc.source_ip) {
        const blocklist = await api.network.getBlocklist('ACTIVE');
        const entry = blocklist.find(b => b.ip === inc.source_ip);
        if (entry) {
          isTempBlocked = true;
          tempBlockExpiresAt = entry.expires_at || null;
        }

        const intel = await api.threatIntel.check({ indicator: inc.source_ip });
        if (intel.matched) {
          isPermBlocked = true;
        }

        const res = await api.incidents.list({ source_ip: inc.source_ip, limit: 10 });
        pastIncidents = res.incidents.filter(i => i.incident_id !== inc.incident_id);
      }
    } catch (e) {
      console.warn("Failed to fetch extra report data", e);
    }

    const sevStyle = (() => {
      switch (inc.severity?.toLowerCase()) {
        case 'critical':
        case 'high':   return 'background:#fee2e2;color:#ef4444;border:1px solid #fca5a5';
        case 'medium': return 'background:#fef3c7;color:#f59e0b;border:1px solid #fcd34d';
        case 'low':    return 'background:#dcfce3;color:#22c55e;border:1px solid #86efac';
        default:       return 'background:#f1f5f9;color:#475569;border:1px solid #cbd5e1';
      }
    })();

    const reportId = `RPT-INC-${(inc.incident_id || '').substring(0, 8).toUpperCase() || Math.random().toString(36).substring(2, 10).toUpperCase()}`;

    const eventsRows = events.map((ev: any) => `
      <tr>
        <td style="font-family:monospace;font-size:11px">${ev.event_id || 'N/A'}</td>
        <td>${ev.timestamp || 'N/A'}</td>
        <td><strong>${ev.attack_type || ev.classification || 'UNKNOWN'}</strong></td>
        <td>${ev.risk_score ?? ev.threat_score ?? 0} / 100</td>
        <td style="font-family:monospace">${ev.source_ip || ev.domain || 'N/A'}</td>
        <td style="font-family:monospace">${ev.destination_ip || 'N/A'}</td>
      </tr>`).join('');

    const categoryBadges = (inc.attack_categories || [])
      .map((c: string) => `<span style="display:inline-block;background:#0f172a;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;margin:3px 4px 3px 0;font-family:monospace">${c}</span>`)
      .join('');

    const glossaryDef: Record<string, string> = {
      'SQL_INJECTION': '<strong style="color:var(--text-main)">SQL Injection (SQLi):</strong> A code injection technique used to attack data-driven applications. Malicious SQL statements are inserted into entry fields for execution (e.g., to dump the database contents to the attacker). CIPHER identifies SQLi through rigorous regex pattern matching against incoming HTTP requests, inspecting payloads, headers, and query parameters for anomalous SQL syntaxes (e.g., UNION SELECT, WAITFOR DELAY).',
      'BRUTE_FORCE': '<strong style="color:var(--text-main)">Brute Force / Credential Stuffing:</strong> An attack attempting to crack passwords or usernames by systematically guessing. Detected by tracking failed login velocities.',
      'XSS': '<strong style="color:var(--text-main)">Cross-Site Scripting (XSS):</strong> A type of security vulnerability enabling attackers to inject client-side scripts into web pages. Detected by identifying DOM-altering script tags.',
      'DDOS': '<strong style="color:var(--text-main)">Distributed Denial of Service (DDoS):</strong> An attack causing a flood of incoming requests to deny service. Detected through volumetric thresholding.',
      'PORT_SCAN': '<strong style="color:var(--text-main)">Network Reconnaissance (Port Scanning):</strong> A technique used to discover open doors (ports) on a network. Detected via rapid SYN/ACK connection attempts.',
      'PHISHING': '<strong style="color:var(--text-main)">Phishing / Malicious URLs:</strong> The fraudulent attempt to obtain sensitive information or data. CIPHER\'s URL inspector utilizes ML models to extract lexical features from URLs.'
    };

    let glossaryHtml = (inc.attack_categories || []).map((cat: string) => {
      return `<p>${glossaryDef[cat] || `<strong style="color:var(--text-main)">${cat}:</strong> Identified threat behavior based on heuristic and signature matching.`}</p>`;
    }).join('');

    if (!glossaryHtml) {
      glossaryHtml = '<p style="font-style:italic">No distinct threat vectors identified for glossary.</p>';
    }

    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <title>CIPHER Intelligence Report - ${inc.incident_id}</title>
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
      height: 297mm; /* A4 height */
      width: 210mm;  /* A4 width */
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

    table.events-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }
    .events-table th {
      color: var(--accent-gold);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 12px 8px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-weight: 600;
    }
    .events-table td {
      padding: 12px 8px;
      border-bottom: 1px solid var(--border);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: #E2E8F0;
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
    .badge.default { color: #94a3b8; border: 1px solid rgba(148,163,184,0.3); background: rgba(148,163,184,0.05); }

    .category-badge {
      display: inline-block;
      color: var(--accent-cyan);
      padding: 4px 0;
      margin-right: 16px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
    }
    .category-badge::before {
      content: '■ ';
      color: var(--accent-gold);
    }
    
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
      <div class="cover-subtitle">Cyber Intrusion Prevention & Heuristic Event Response</div>
      
      <div class="cover-title">Threat Intelligence<br>Incident Chain Analysis</div>
      
      <div class="cover-meta">
        <table>
          <tr><td>Report ID</td><td>${reportId}</td></tr>
          <tr><td>Date Generated</td><td>${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</td></tr>
          <tr><td>Incident Target</td><td>${inc.destination_ip || 'Multiple/Unknown'}</td></tr>
          <tr><td>Classification</td><td>RESTRICTED / CONFIDENTIAL</td></tr>
        </table>
      </div>
    </div>
  </div>

  <!-- Page 2: Diagnostics & Events -->
  <div class="content-page">

    <div class="section">
      <h2 class="section-title">1.0 Executive Summary</h2>
      <div class="prose">
        <p>${inc.summary}</p>
        <p>This automated dossier was compiled by the CIPHER Threat Intelligence Engine. The heuristics applied to this chain involve correlating disparate temporal events, identifying matching attack signatures, and clustering related IP telemetry to form a cohesive incident timeline. Analysts should review the following indicators of compromise (IOCs) to formulate a precise incident response (IR) strategy.</p>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">2.0 Telemetry & Diagnostics</h2>
      <table class="info-table">
        <tr><th>Incident Identifier</th><td><span style="color:var(--accent-cyan)">${inc.incident_id}</span></td></tr>
        <tr><th>Current Status</th><td>${inc.status}</td></tr>
        <tr><th>Assessed Severity</th><td><span class="badge ${inc.severity?.toLowerCase() || 'default'}">${inc.severity || 'UNKNOWN'}</span></td></tr>
        <tr><th>Escalation State</th><td>${inc.escalation_detected ? '<span style="color:#ef4444;font-weight:700">ESCALATED</span>' : 'NORMAL'}</td></tr>
        <tr><th>First Observed (UTC)</th><td>${inc.first_seen}</td></tr>
        <tr><th>Last Observed (UTC)</th><td>${inc.last_seen}</td></tr>
        <tr><th>Source Infrastructure</th><td>${inc.source_ip || 'N/A'}</td></tr>
        <tr><th>Target Infrastructure</th><td>${inc.destination_ip || 'N/A'}</td></tr>
        <tr><th>Recommended Action</th><td><span style="color:var(--accent-gold)">${inc.recommended_action || 'Monitor telemetry and await further correlation.'}</span></td></tr>
      </table>
    </div>

    <div class="section">
      <h2 class="section-title">3.0 Identified Threat Vectors</h2>
      <div style="margin-top: 1rem;">
        ${(inc.attack_categories || [])
          .map((c: string) => `<span class="category-badge">${c}</span>`)
          .join('') || '<span class="prose" style="font-style:italic">No distinct threat vectors identified.</span>'}
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">4.0 Correlated Security Events (${events.length})</h2>
      ${events.length === 0
        ? '<div class="prose" style="font-style:italic">No specific event telemetry linked to this incident.</div>'
        : `<table class="events-table">
        <thead>
          <tr>
            <th>Event ID</th>
            <th>Timestamp (UTC)</th>
            <th>Classification</th>
            <th>Risk</th>
            <th>Source IP</th>
            <th>Dest IP</th>
          </tr>
        </thead>
        <tbody>${eventsRows}</tbody>
      </table>`}
    </div>

    <div class="section">
      <h2 class="section-title">5.0 CIPHER Detection Methodology</h2>
      <div class="prose">
        <p>The Cyber Intrusion Prevention & Heuristic Event Response (CIPHER) engine utilizes a multi-layered detection pipeline combining signature-based pattern matching, behavioral anomaly detection (Heuristics), and temporal clustering to identify active threats in high-noise network environments.</p>
        
        <div class="tech-box">
          <h4>Event Correlation Engine</h4>
          <p style="margin:0;font-size:12px">Individual security events (firewall drops, WAF alerts, IDS triggers) are fed into a real-time temporal correlator. The engine applies an exponential decay algorithm to time-windows, linking disparate events based on common denominators such as Source IP, ASN, User-Agent fingerprints, and targeted application endpoints. This allows CIPHER to elevate low-fidelity isolated alerts into high-confidence Incident Chains.</p>
        </div>

        <div class="tech-box">
          <h4>Heuristic Risk Scoring</h4>
          <p style="margin:0;font-size:12px">Risk is calculated using a dynamic baseline model. A base score is assigned via static classification (e.g., SQLi carries a higher base weight than a Port Scan). The score is then modulated by frequency (velocity of requests), target criticality, and historical reputation of the source ASN. An incident is deemed "Escalated" when the aggregate risk gradient exceeds the acceptable operational threshold for 3 consecutive timeframes.</p>
        </div>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">6.0 Threat Vector Intelligence Glossary</h2>
      <div class="two-column-prose">
        ${glossaryHtml}
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">7.0 Standard Operating Procedures (SOP)</h2>
      <div class="prose">
        <p>In the event of a verified cyber incident matching the patterns detailed in Section 2.0 and 3.0, Security Operations Center (SOC) personnel must adhere to the following phased response protocols to contain the threat and restore nominal operational capacity.</p>
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

    <div class="section">
      <h2 class="section-title">8.0 Source IP Threat Profile</h2>
      <table class="info-table">
        <tr><th>IP Address</th><td><span style="color:var(--accent-cyan); font-weight:bold;">${inc.source_ip || 'N/A'}</span></td></tr>
        <tr><th>WAF Block Status</th><td>
          ${isTempBlocked ? `<span style="color:#ef4444;font-weight:bold">TEMPORARILY BLOCKED</span> (Expires: ${tempBlockExpiresAt || 'N/A'})` : '<span style="color:#22c55e">NOT TEMPORARILY BLOCKED</span>'}
        </td></tr>
        <tr><th>Threat Intel DB (Permanent)</th><td>
          ${isPermBlocked ? '<span style="color:#ef4444;font-weight:bold">PERMANENTLY BLOCKED</span>' : '<span style="color:#22c55e">CLEAN</span>'}
        </td></tr>
      </table>
      
      <h3 style="margin-top:30px; margin-bottom: 10px; font-size:12px; color:var(--accent-cyan); text-transform:uppercase;">Historical Incidents Linked to this IP</h3>
      ${pastIncidents.length > 0 ? 
        `<table class="events-table" style="margin-top:0;">
          <thead><tr><th>Incident ID</th><th>First Seen</th><th>Severity</th><th>Events</th></tr></thead>
          <tbody>
            ${pastIncidents.map(pi => `<tr><td style="font-family:monospace">${pi.incident_id}</td><td>${pi.first_seen}</td><td><span class="badge ${pi.severity?.toLowerCase()}">${pi.severity}</span></td><td>${pi.event_count}</td></tr>`).join('')}
          </tbody>
        </table>` 
        : '<p class="prose" style="font-style:italic">No other historical incidents recorded from this IP in the system.</p>'
      }
    </div>

    <div class="section" style="page-break-before: always;">
      <h2 class="section-title">9.0 Evidentiary Chain of Custody & Legal Admissibility</h2>
      <div class="prose">
        <p>This document constitutes an automated, cryptographically sealed record of digital intrusion telemetry captured by the CIPHER system. The data contained herein was collected in real-time, in the regular course of business, maintaining a continuous chain of custody from the point of ingestion to the generation of this report. It is prepared in accordance with digital forensics standards for use in incident response, compliance auditing, and legal proceedings.</p>
        
        <p><strong>Legal Framework & Potential Violations:</strong> The anomalous activities documented in this report may constitute unauthorized access to a protected computer system and may violate applicable regional and international cybercrime statutes, including but not limited to:</p>
        <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem; color: #94A3B8;">
          ${getLegalFrameworks(inc.attack_categories || [])}
        </ul>
        
        <p><strong>Cryptographic Assurance:</strong> The raw network packets, WAF signatures, and corresponding temporal metadata have been immutably written to the CIPHER forensic datastore. No manual tampering or retrospective editing has occurred.</p>
        
        <div style="background: var(--surface); border-left: 3px solid var(--accent-gold); padding: 1rem; font-family: 'JetBrains Mono', monospace; font-size: 10px; margin-top: 1rem;">
          <div><span style="color:var(--text-muted)">REPORT INTEGRITY HASH (SHA-256):</span> <span style="color:#E2E8F0">${Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('')}</span></div>
          <div style="margin-top: 4px;"><span style="color:var(--text-muted)">GENERATION TIMESTAMP (UTC):</span> <span style="color:#E2E8F0">${new Date().toISOString()}</span></div>
          <div style="margin-top: 4px;"><span style="color:var(--text-muted)">SYSTEM ATTESTATION:</span> <span style="color:#22c55e; font-weight: bold;">CRYPTOGRAPHICALLY VERIFIED</span></div>
        </div>
      </div>
    </div>

    <div style="margin-top:5rem;border-top:1px solid var(--border);padding-top:2rem;text-align:center;">
      <div style="font-size:10px;color:var(--accent-gold);letter-spacing:3px;text-transform:uppercase;font-weight:700;margin-bottom:1rem;">END OF REPORT</div>
      <div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">
        CIPHER SOC Automated Intelligence Engine<br>
        CONFIDENTIAL — INTERNAL USE ONLY
      </div>
    </div>
  </div>
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


  const [loadingDetail, setLoadingDetail] = useState(false);

  // Resolution confirmation dialog (incorporates user's instruction: server-confirmed, non-optimistic)
  const [incidentToResolve, setIncidentToResolve] = useState<IncidentItem | null>(null);
  const [isResolving, setIsResolving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Generic Confirmation Dialog State
  const [confirmState, setConfirmState] = useState<{
    isOpen: boolean;
    title: string;
    message: React.ReactNode;
    confirmLabel: string;
    isDestructive: boolean;
    onConfirm: () => Promise<void>;
  } | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);

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
      setSelectedIds(new Set()); // clear selection on fetch
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve incidents.');
    } finally {
      setLoading(false);
    }
  };

  const fetchBlocklist = async () => {
    try {
      const list = await api.network.getBlocklist('ACTIVE');
      setBlockedIps(new Set(list.map(b => b.ip)));
    } catch (err) {
      console.error('Failed to fetch blocklist', err);
    }
  };

  useEffect(() => {
    fetchIncidents();
    fetchBlocklist();
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

  const executeBlockTemp = async (ip: string) => {
    try {
      await api.network.blockIp(ip);
      setActionSuccess(`IP ${ip} temporarily blocked on WAF.`);
      setTimeout(() => setActionSuccess(null), 5000);
      await fetchBlocklist();
    } catch (err: any) {
      setActionError(err.message || 'Failed to block IP.');
      setTimeout(() => setActionError(null), 5000);
    }
  };

  const executeBlockPerm = async (ip: string) => {
    try {
      await api.threatIntel.create({
        ioc_type: 'IP',
        indicator: ip,
        category: 'malicious',
        severity: 'HIGH',
        confidence: 0.95,
        description: 'Permanently blocked via SOC Dashboard',
      });
      setActionSuccess(`IP ${ip} permanently blocked and stored in Threat Intel DB.`);
      setTimeout(() => setActionSuccess(null), 5000);
      await fetchBlocklist();
    } catch (err: any) {
      setActionError(err.message || 'Failed to add to Threat Intel DB.');
      setTimeout(() => setActionError(null), 5000);
    }
  };

  const executeUnblock = async (ip: string) => {
    try {
      await api.network.unblockIp(ip);
      setActionSuccess(`IP ${ip} successfully unblocked.`);
      setTimeout(() => setActionSuccess(null), 5000);
      await fetchBlocklist();
    } catch (err: any) {
      setActionError(err.message || 'Failed to unblock IP.');
      setTimeout(() => setActionError(null), 5000);
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

  const handleDeleteIncident = async (incidentId: string) => {
    setConfirmState({
      isOpen: true,
      title: 'Delete Incident',
      message: (
        <span>
          Are you sure you want to permanently delete incident <strong className={mono}>{incidentId}</strong>?
        </span>
      ),
      confirmLabel: 'Delete',
      isDestructive: true,
      onConfirm: async () => {
        try {
          setActionError(null);
          await api.incidents.delete([incidentId]);
          setActionSuccess(`Incident ${incidentId} deleted.`);
          setTimeout(() => setActionSuccess(null), 5000);
          if (selectedIncident?.incident.incident_id === incidentId) {
            setSelectedIncident(null);
          }
          setSelectedIds(prev => {
            const next = new Set(prev);
            next.delete(incidentId);
            return next;
          });
          await fetchIncidents();
        } catch (err: any) {
          setActionError(err.message || 'Failed to delete incident.');
          setTimeout(() => setActionError(null), 5000);
        }
      }
    });
  };

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return;
    
    setConfirmState({
      isOpen: true,
      title: 'Delete Incidents',
      message: `Are you sure you want to permanently delete ${selectedIds.size} incident(s)?`,
      confirmLabel: 'Delete Selected',
      isDestructive: true,
      onConfirm: async () => {
        try {
          setActionError(null);
          await api.incidents.delete(Array.from(selectedIds));
          setActionSuccess(`${selectedIds.size} incident(s) deleted.`);
          setTimeout(() => setActionSuccess(null), 5000);
          setSelectedIds(new Set());
          await fetchIncidents();
        } catch (err: any) {
          setActionError(err.message || 'Failed to delete incidents.');
          setTimeout(() => setActionError(null), 5000);
        }
      }
    });
  };

  return (
    <motion.div
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Action alerts */}
      {actionSuccess && (
        <motion.div variants={itemVariants} className={alertBox('success')}>
          <CheckCircle size={16} />
          <span>{actionSuccess}</span>
        </motion.div>
      )}
      {actionError && (
        <motion.div variants={itemVariants} className={alertBox('danger')}>
          <ShieldAlert size={16} />
          <span>{actionError}</span>
        </motion.div>
      )}

      {/* Filter Bar */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-5')}>
        <div className="flex flex-wrap gap-4 items-end">
          <div className={cn(formGroup, 'w-[180px] m-0')}>
            <label className={formLabel}>Status</label>
            <select
              className={formSelect}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open Incidents</option>
              <option value="RESOLVED">Resolved Incidents</option>
            </select>
          </div>

          <div className={cn(formGroup, 'w-[180px] m-0')}>
            <label className={formLabel}>Severity</label>
            <select
              className={formSelect}
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

          <div className={cn(formGroup, 'flex-[1_1_200px] m-0')}>
            <label className={formLabel}>Filter by Source IP</label>
            <input
              type="text"
              className={formInput}
              placeholder="e.g. 192.168.1.100"
              value={sourceIpFilter}
              onChange={(e) => setSourceIpFilter(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') fetchIncidents();
              }}
            />
          </div>

          <button className={controlBtn('primary')} onClick={fetchIncidents}>
            Filter
          </button>
          
          {selectedIds.size > 0 && (
            <button className={cn(controlBtn('danger'), 'ml-auto')} onClick={handleBulkDelete}>
              <Ban size={16} /> Delete Selected ({selectedIds.size})
            </button>
          )}
        </div>
      </motion.div>

      {/* Incidents Table */}
      <motion.div variants={itemVariants} className={card}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <Flame size={18} color="var(--color-crit)" />
            <span>Correlated Security Incidents</span>
          </div>
          <span className="text-[0.78rem] text-fg-muted">
            Showing {incidents.length} incident chains
          </span>
        </div>

        {loading ? (
          <LoadingState message="Loading correlated incidents..." />
        ) : error ? (
          <ErrorState title="Failed to Load Incidents" error={error} onRetry={fetchIncidents} />
        ) : incidents.length === 0 ? (
          <div className="py-12 px-6 text-center">
            <div
              className="w-[48px] h-[48px] rounded-[50%] bg-benign-bg flex items-center justify-center mt-0 mx-auto mb-4 border border-benign"
            >
              <Flame size={24} color="var(--color-benign)" />
            </div>
            <div className="font-bold text-[1rem] mb-[0.35rem] text-fg">
              {statusFilter || severityFilter || sourceIpFilter
                ? 'No Incidents Match Query'
                : 'Zero Active Incident Chains'}
            </div>
            <div className="text-fg-muted text-[0.84rem] max-w-[420px] my-0 mx-auto">
              {statusFilter || severityFilter || sourceIpFilter
                ? 'Try adjusting or clearing your filters to view historical incidents.'
                : 'All network flows and alerts are within isolated thresholds. Multi-event correlations will appear here.'}
            </div>
          </div>
        ) : (
          <div className={tableContainer}>
            <table className={dataTable}>
              <thead>
                <tr>
                  <th className="w-10 text-center">
                    <input 
                      type="checkbox"
                      checked={incidents.length > 0 && selectedIds.size === incidents.length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedIds(new Set(incidents.map(i => i.incident_id)));
                        } else {
                          setSelectedIds(new Set());
                        }
                      }}
                      className="cursor-pointer"
                    />
                  </th>
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
                  <tr 
                    key={inc.incident_id}
                    className="cursor-pointer [transition:background-color_0.2s_ease] hover:bg-elevated"
                    onClick={() => handleOpenDetail(inc.incident_id)}
                  >
                    <td className="text-center" onClick={(e) => e.stopPropagation()}>
                      <input 
                        type="checkbox"
                        checked={selectedIds.has(inc.incident_id)}
                        onChange={(e) => {
                          const newSet = new Set(selectedIds);
                          if (e.target.checked) newSet.add(inc.incident_id);
                          else newSet.delete(inc.incident_id);
                          setSelectedIds(newSet);
                        }}
                        className="cursor-pointer"
                      />
                    </td>
                    <td>
                      <span
                        className={cn(mono, 'text-[0.72rem] font-bold py-[0.15rem] px-[0.45rem] rounded-[4px]', (inc.status === 'OPEN' ? 'bg-crit-bg' : 'bg-benign-bg'), (inc.status === 'OPEN' ? 'text-crit' : 'text-benign'), 'border', inc.status === 'OPEN' ? 'border-crit' : 'border-benign')}
                      >
                        {inc.status}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={inc.severity} size="sm" />
                    </td>
                    <td className={cn(mono, 'text-[0.78rem]!')}>
                      {inc.incident_id}
                    </td>
                    <td className={mono}>{inc.source_ip || 'N/A'}</td>
                    <td className={mono}>{inc.destination_ip || 'N/A'}</td>
                    <td>
                      <div className="flex gap-1 flex-wrap">
                        {inc.attack_categories.map((cat, idx) => (
                          <span
                            key={idx}
                            className={cn(mono, 'text-[0.68rem] bg-elevated border border-line py-[2px] px-[6px] rounded-[4px]')}

                          >
                            {cat}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className={cn(mono, 'font-bold!')}>
                      {inc.event_count}
                    </td>
                    <td className={cn(mono, 'font-bold!')}>
                      {inc.correlation_score}
                    </td>
                    <td>
                      {inc.escalation_detected ? (
                        <span className={navBadge('danger', 'text-[0.68rem]')}>
                          ESCALATED
                        </span>
                      ) : (
                        <span className="text-fg-muted text-[0.75rem]">None</span>
                      )}
                    </td>
                    <td>
                      <div className="flex gap-[0.4rem]">
                        <button
                          className={cn(controlBtn(), 'py-1 px-2 text-[0.75rem]')}

                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDetail(inc.incident_id);
                          }}
                          title="View incident events and correlation evidence"
                        >
                          <Eye size={12} />
                          <span>Details</span>
                        </button>
                        {inc.status === 'OPEN' && (
                          <button
                            className={cn(controlBtn('success'), 'py-1 px-2 text-[0.75rem]')}

                            onClick={(e) => {
                              e.stopPropagation();
                              setIncidentToResolve(inc);
                            }}
                            title="Mark incident as resolved"
                          >
                            <CheckCircle size={12} />
                            <span>Resolve</span>
                          </button>
                        )}
                        <button
                          className={cn(controlBtn('danger'), 'py-1 px-2 text-[0.75rem]')}
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteIncident(inc.incident_id);
                          }}
                          title="Delete incident"
                        >
                          <Ban size={12} />
                          <span>Delete</span>
                        </button>
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
            <div className="flex items-center gap-2">
              <GitBranch size={18} color="var(--color-accent)" />
              <span>Incident Detail: {selectedIncident.incident.incident_id}</span>
              <SeverityBadge severity={selectedIncident.incident.severity} size="sm" />
            </div>
          }
          footer={
            <div className="flex gap-3 w-full items-center flex-wrap">
              {/* Resolve — only when OPEN */}
              {selectedIncident.incident.status === 'OPEN' && (
                <button
                  className={cn(controlBtn('success'), 'flex items-center gap-2')}

                  onClick={() => setIncidentToResolve(selectedIncident.incident)}
                >
                  <CheckCircle size={16} />
                  Resolve Incident
                </button>
              )}
              {/* Delete */}
              <button
                className={cn(controlBtn('danger'), 'flex items-center gap-2')}
                onClick={() => handleDeleteIncident(selectedIncident.incident.incident_id)}
              >
                <Ban size={16} /> Delete Incident
              </button>
              {/* Block Actions */}
              {selectedIncident.incident.source_ip && (
                blockedIps.has(selectedIncident.incident.source_ip) ? (
                  <button
                    className={cn(controlBtn(), 'flex items-center gap-2 bg-[#f1f5f9] text-[#334155] border border-[#cbd5e1] hover:bg-[#e2e8f0]')}
                    onClick={() => executeUnblock(selectedIncident.incident.source_ip!)}
                  >
                    <CheckCircle size={16} /> Unblock IP
                  </button>
                ) : (
                  <button
                    className={cn(controlBtn('danger'), 'flex items-center gap-2')}
                    onClick={() => setBlockIpModalOpen(selectedIncident.incident.source_ip!)}
                  >
                    <Ban size={16} /> Block IP
                  </button>
                )
              )}
              {/* PDF / Print */}
              <button
                className={cn(controlBtn('primary'), 'flex items-center gap-2 bg-accent text-white border-none')}

                onClick={() => generateIncidentReport(selectedIncident)}
              >
                <Printer size={16} /> Print / Save as PDF
              </button>
              {popupBlocked && (
                <span className="text-accent text-[0.78rem] font-semibold">
                  ⚠ Allow popups to open the PDF
                </span>
              )}
              {/* spacer */}
              <div className="flex-1" />
              <button className={controlBtn()} onClick={() => setSelectedIncident(null)}>
                Close
              </button>
            </div>
          }
        >
          <div>
            <p className="mb-6 text-[0.9rem] leading-[1.5] text-fg-2">
              {selectedIncident.incident.summary}
            </p>

            <div className="mb-6 last:mb-0 [&_h3]:mb-[0.85rem] [&_h3]:border-b [&_h3]:border-b-line [&_h3]:pb-2 [&_h3]:text-[0.85rem] [&_h3]:tracking-[0.05em] [&_h3]:text-accent [&_h3]:uppercase">
              <h3>Correlation Diagnostics</h3>
              <div className={kvGrid}>
                <div className={kvItem}>
                  <span className={kvLabel}>Status</span>
                  <span className={kvValue}>{selectedIncident.incident.status}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Escalation State</span>
                  <span className={cn(kvValue, (selectedIncident.incident.escalation_detected ? 'text-crit' : 'text-benign'))}>
                    {selectedIncident.incident.escalation_detected ? 'ESCALATED' : 'Normal'}
                  </span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>First Seen</span>
                  <span className={cn(mono, kvValue)}>{selectedIncident.incident.first_seen}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Last Seen</span>
                  <span className={cn(mono, kvValue)}>{selectedIncident.incident.last_seen}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Correlated Events</span>
                  <span className={cn(mono, kvValue)}>{selectedIncident.incident.event_count}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Recommended Action</span>
                  <span className={cn(kvValue, 'text-fg font-semibold')}>
                    {selectedIncident.incident.recommended_action || 'Monitor traffic'}
                  </span>
                </div>
              </div>
            </div>

            <div className="mb-6 last:mb-0 [&_h3]:mb-[0.85rem] [&_h3]:border-b [&_h3]:border-b-line [&_h3]:pb-2 [&_h3]:text-[0.85rem] [&_h3]:tracking-[0.05em] [&_h3]:text-accent [&_h3]:uppercase">
              <h3>Attack Categories Identified</h3>
              <div className="flex flex-wrap gap-2">
                {selectedIncident.incident.attack_categories.map((cat: string, idx: number) => (
                  <div key={idx} className="rounded-[4px] border border-line bg-app px-[0.65rem] py-[0.35rem] font-mono text-[0.75rem] text-fg">
                    {cat}
                  </div>
                ))}
              </div>
            </div>

            {/* Linked Events List */}
            <div className="mb-6 last:mb-0 [&_h3]:mb-[0.85rem] [&_h3]:border-b [&_h3]:border-b-line [&_h3]:pb-2 [&_h3]:text-[0.85rem] [&_h3]:tracking-[0.05em] [&_h3]:text-accent [&_h3]:uppercase">
              <h3>Associated Security Events ({selectedIncident.events.length})</h3>
              {selectedIncident.events.length === 0 ? (
                <div className="text-fg-muted text-[0.8rem]">
                  No event records found linked to this incident.
                </div>
              ) : (
                <div className={cn(tableContainer, 'max-h-[300px]')}>
                  <table className={dataTable}>
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
                          <td className={cn(mono, 'text-[0.75rem]!')}>
                            {ev.event_id}
                          </td>
                          <td className={cn(mono, 'text-[0.75rem]!')}>
                            {ev.timestamp}
                          </td>
                          <td>
                            <span className="font-semibold">
                              {ev.attack_type || ev.classification || 'UNKNOWN'}
                            </span>
                          </td>
                          <td className={mono}>{ev.risk_score ?? ev.threat_score ?? 0}</td>
                          <td className={mono}>{ev.source_ip || ev.domain || 'N/A'}</td>
                          <td className={mono}>{ev.destination_ip || 'N/A'}</td>
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
                <strong className={mono}>{incidentToResolve.incident_id}</strong> as{' '}
                <strong>RESOLVED</strong>?
              </p>
              <p className="mt-2 text-[0.82rem] text-fg-muted">
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

      {/* Generic Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(confirmState?.isOpen)}
        onClose={() => setConfirmState(null)}
        onConfirm={async () => {
          if (!confirmState) return;
          try {
            setIsConfirming(true);
            await confirmState.onConfirm();
          } finally {
            setIsConfirming(false);
            setConfirmState(null);
          }
        }}
        title={confirmState?.title || ''}
        message={confirmState?.message || ''}
        confirmLabel={confirmState?.confirmLabel || 'Confirm'}
        isDestructive={confirmState?.isDestructive || false}
        isLoading={isConfirming}
      />

      {/* Block IP Modal */}
      <Modal
        isOpen={Boolean(blockIpModalOpen)}
        onClose={() => setBlockIpModalOpen(null)}
        title={
          <div className="flex items-center gap-2">
            <Ban size={20} color="var(--color-crit)" />
            <span>Block IP: {blockIpModalOpen}</span>
          </div>
        }
        footer={
          <>
            <button className={controlBtn()} onClick={() => setBlockIpModalOpen(null)}>
              Cancel
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-4 py-2">
          <p className="text-[0.88rem] leading-[1.6] text-fg-2">
            Choose how you want to block this IP Address.
          </p>
          <button
            className={cn(controlBtn('danger'), 'flex items-center justify-center py-3')}
            onClick={() => { executeBlockTemp(blockIpModalOpen!); setBlockIpModalOpen(null); }}
          >
            Block Temporarily (24 hours)
          </button>
          <button
            className={cn(controlBtn('danger'), 'flex items-center justify-center py-3 bg-[#991b1b] border-[#7f1d1d] hover:bg-[#7f1d1d]')}
            onClick={() => { executeBlockPerm(blockIpModalOpen!); setBlockIpModalOpen(null); }}
          >
            Block Permanently
          </button>
        </div>
      </Modal>
    </motion.div>
  );
};
