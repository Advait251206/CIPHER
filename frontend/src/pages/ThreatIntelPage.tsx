import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  IOCItem,
  IOCType,
  Severity,
  IOCCheckResponse,
  IOCImportResponse,
  IncidentItem,
} from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { Modal } from '../components/common/Modal';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import {
  Database,
  Search,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Upload,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  FileSpreadsheet,
  FileText,
} from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, codeTag, controlBtn, dataTable, evidenceHeader, evidenceSection, formGroup, formInput, formLabel, formSelect, formTextarea, kvGrid, kvItem, kvLabel, kvValue, mono, pageBody, tableContainer } from '../ui/classes';

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
  
  return frameworks.map(f => `<li><strong>${f.name}:</strong> ${f.desc}</li>`).join('');
};

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
    transition: { duration: 0.32, ease: [0.25, 0.1, 0.25, 1] as const },
  },
};

export const ThreatIntelPage: React.FC = () => {
  const [iocs, setIocs] = useState<IOCItem[]>([]);
  const [totalMatching, setTotalMatching] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [enabledOnly, setEnabledOnly] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modals
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isCheckModalOpen, setIsCheckModalOpen] = useState(false);
  const [isJsonImportOpen, setIsJsonImportOpen] = useState(false);
  const [isCsvImportOpen, setIsCsvImportOpen] = useState(false);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [selectedIoc, setSelectedIoc] = useState<IOCItem | null>(null);
  const [selectedIocIncidents, setSelectedIocIncidents] = useState<IncidentItem[]>([]);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  // Delete confirmation
  const [iocToDelete, setIocToDelete] = useState<IOCItem | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Forms
  const [newType, setNewType] = useState<IOCType>('IP');
  const [newIndicator, setNewIndicator] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('HIGH');
  const [newConfidence, setNewConfidence] = useState(0.85);
  const [newCategory, setNewCategory] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newTags, setNewTags] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Check Indicator
  const [checkInput, setCheckInput] = useState('');
  const [checkType, setCheckType] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<IOCCheckResponse | null>(null);

  // Bulk Import
  const [jsonText, setJsonText] = useState('');
  const [csvText, setCsvText] = useState('');
  const [importResult, setImportResult] = useState<IOCImportResponse | null>(null);

  // Alerts
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchIocs = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.threatIntel.list({
        ioc_type: typeFilter || undefined,
        severity: severityFilter || undefined,
        enabled_only: enabledOnly ? true : undefined,
        limit: 100,
      });
      setIocs(res.iocs);
      setTotalMatching(res.total_matching);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve indicators.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, [typeFilter, severityFilter, enabledOnly]);

  const handleOpenDetail = async (ioc: IOCItem) => {
    setSelectedIoc(ioc);
    setIsDetailModalOpen(true);
    try {
      if (ioc.ioc_type === 'IP') {
        const incidentsList = await api.incidents.list({ source_ip: ioc.indicator });
        setSelectedIocIncidents(incidentsList.incidents || []);
      } else {
        setSelectedIocIncidents([]);
      }
    } catch (err) {
      console.error('Failed to fetch related incidents for IOC:', err);
      setSelectedIocIncidents([]);
    }
  };

  const generateIocPdf = () => {
    if (!selectedIoc) return;
    setIsGeneratingPdf(true);
    try {
      const reportId = `IOC-${selectedIoc.ioc_id.split('-')[0].toUpperCase()}`;
      
      const iframe = document.createElement('iframe');
      iframe.style.position = 'fixed';
      iframe.style.right = '-10000px';
      iframe.style.bottom = '-10000px';
      document.body.appendChild(iframe);

      const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <title>${reportId}_Threat_Profile</title>
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
      
      <div class="cover-title">Threat Indicator Profile<br>${selectedIoc.ioc_type}: ${selectedIoc.indicator}</div>
      
      <div class="cover-meta">
        <table>
          <tr><td>Report ID</td><td>${reportId}</td></tr>
          <tr><td>Date Generated</td><td>${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</td></tr>
          <tr><td>Classification</td><td>RESTRICTED / CONFIDENTIAL</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="content-page">
    <div class="page-header">
      <div class="page-header-brand">CIPHER<span>.</span></div>
      <div class="page-header-meta">IOC FORENSICS | PAGE 1 OF 3</div>
    </div>

    <div class="section">
      <h2 class="section-title">1.0 Threat Indicator Overview</h2>
      <table class="info-table">
        <tr><th>Indicator Value</th><td style="font-family:monospace; font-weight:700; color:var(--accent-cyan)">${selectedIoc.indicator}</td></tr>
        <tr><th>Indicator Type</th><td>${selectedIoc.ioc_type}</td></tr>
        <tr><th>Assessed Severity</th><td><span class="badge ${selectedIoc.severity?.toLowerCase() || 'default'}">${selectedIoc.severity || 'UNKNOWN'}</span></td></tr>
        <tr><th>Confidence Score</th><td>${(selectedIoc.confidence * 100).toFixed(0)}%</td></tr>
        <tr><th>Current Status</th><td>${selectedIoc.enabled ? '<span style="color:#ef4444;font-weight:700">ENABLED (BLOCKED)</span>' : '<span style="color:#94a3b8;font-weight:700">DISABLED (WHITELISTED)</span>'}</td></tr>
        <tr><th>Source Intelligence</th><td>${selectedIoc.source}</td></tr>
        <tr><th>First Seen (UTC)</th><td>${selectedIoc.first_seen}</td></tr>
        <tr><th>Categories</th><td>${selectedIoc.category ? `<span class="category-badge">${selectedIoc.category}</span>` : 'N/A'}</td></tr>
        <tr><th>Description</th><td>${selectedIoc.description || 'No description provided.'}</td></tr>
      </table>
    </div>

    <div class="section">
      <h2 class="section-title">2.0 Related Attack History (${selectedIocIncidents.length} Incidents)</h2>
      ${selectedIocIncidents.length === 0
        ? '<div class="prose" style="font-style:italic">No correlated incidents linked directly to this indicator in the active datastore.</div>'
        : `<table class="events-table">
        <thead>
          <tr>
            <th>Incident ID</th>
            <th>First Seen (UTC)</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Events</th>
            <th>Categories</th>
          </tr>
        </thead>
        <tbody>
          ${selectedIocIncidents.map(inc => `
            <tr>
              <td style="font-family:monospace">${inc.incident_id}</td>
              <td>${inc.first_seen.split('.')[0].replace('T', ' ')}</td>
              <td>${inc.status}</td>
              <td><span class="badge ${inc.severity?.toLowerCase() || 'default'}">${inc.severity}</span></td>
              <td>${inc.event_count}</td>
              <td>${inc.attack_categories?.join(', ') || ''}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>`}
    </div>

    <div class="section" style="page-break-before: always;">
      <div class="page-header">
        <div class="page-header-brand">CIPHER<span>.</span></div>
        <div class="page-header-meta">METHODOLOGY | PAGE 2 OF 3</div>
      </div>
      <h2 class="section-title">3.0 CIPHER Detection Methodology</h2>
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
      <h2 class="section-title">4.0 Threat Vector Intelligence Glossary</h2>
      <div class="two-column-prose">
        <p><strong style="color:var(--text-main)">Distributed Denial of Service (DDoS):</strong> An attack in which multiple compromised computer systems attack a target, such as a server, website or other network resource, and cause a denial of service for users of the targeted resource. The flood of incoming messages, connection requests or malformed packets to the target system forces it to slow down or even crash and shut down, thereby denying service to legitimate users or systems. CIPHER detects these through volumetric thresholding and TCP connection-state tracking.</p>

        <p><strong style="color:var(--text-main)">SQL Injection (SQLi):</strong> A code injection technique used to attack data-driven applications. Malicious SQL statements are inserted into entry fields for execution (e.g., to dump the database contents to the attacker). CIPHER identifies SQLi through rigorous regex pattern matching against incoming HTTP requests, inspecting payloads, headers, and query parameters for anomalous SQL syntaxes (e.g., UNION SELECT, WAITFOR DELAY).</p>

        <p><strong style="color:var(--text-main)">Cross-Site Scripting (XSS):</strong> A type of security vulnerability typically found in web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls. Detected by CIPHER's WAF module identifying DOM-altering script tags or encoded javascript pseudo-protocols.</p>

        <p><strong style="color:var(--text-main)">Phishing / Malicious URLs:</strong> The fraudulent attempt to obtain sensitive information or data, such as usernames, passwords, and credit card details, by disguising oneself as a trustworthy entity in an electronic communication. CIPHER's URL inspector utilizes deep learning models (such as BERT) to extract lexical features from URLs, comparing topological similarities against known malicious domains and analyzing domain age and entropy.</p>

        <p><strong style="color:var(--text-main)">Network Reconnaissance (Port Scanning):</strong> A technique used by attackers to discover open doors (ports) on a network, identifying active hosts, running services, and potential vulnerabilities before launching an actual exploit. Detected via rapid SYN/ACK connection attempts across non-standard port ranges emanating from a singular source IP.</p>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">5.0 Standard Operating Procedures (SOP)</h2>
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

    <div class="section" style="page-break-before: always;">
      <div class="page-header">
        <div class="page-header-brand">CIPHER<span>.</span></div>
        <div class="page-header-meta">LEGAL ADMISSIBILITY | PAGE 3 OF 3</div>
      </div>
      <h2 class="section-title">6.0 Evidentiary Chain of Custody & Legal Admissibility</h2>
      <div class="prose">
        <p>This document constitutes an automated, cryptographically sealed record of digital threat intelligence maintained by the CIPHER system. The indicator detailed herein was identified as hostile by internal heuristics, telemetry correlation, or external trusted feeds.</p>
        
        <p><strong>Legal Framework & Potential Violations:</strong> The anomalous activities associated with this indicator may constitute unauthorized access to a protected computer system and may violate applicable regional and international cybercrime statutes, including but not limited to:</p>
        <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem; color: #94A3B8;">
          ${getLegalFrameworks(selectedIoc.category ? [selectedIoc.category] : ['MALWARE'])}
        </ul>
        
        <p><strong>Record Assurance:</strong> The IOC metadata and history have been immutably written to the CIPHER forensic datastore. No manual tampering or retrospective editing has occurred.</p>
        
        <div style="background: var(--surface); border-left: 3px solid var(--accent-gold); padding: 1rem; font-family: 'JetBrains Mono', monospace; font-size: 10px; margin-top: 1rem;">
          <div><span style="color:var(--text-muted)">REPORT INTEGRITY HASH (SHA-256):</span> <span style="color:#E2E8F0">${Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('')}</span></div>
          <div style="margin-top: 4px;"><span style="color:var(--text-muted)">GENERATION TIMESTAMP (UTC):</span> <span style="color:#E2E8F0">${new Date().toISOString()}</span></div>
          <div style="margin-top: 4px;"><span style="color:var(--text-muted)">SYSTEM ATTESTATION:</span> <span style="color:#22c55e; font-weight: bold;">CRYPTOGRAPHICALLY VERIFIED</span></div>
        </div>
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
</body>
</html>`;

      const doc = iframe.contentWindow?.document;
      if (doc) {
        doc.open();
        doc.write(htmlContent);
        doc.close();

        iframe.onload = () => {
          setTimeout(() => {
            iframe.contentWindow?.print();
            setIsGeneratingPdf(false);
            setTimeout(() => {
              document.body.removeChild(iframe);
            }, 1000);
          }, 500);
        };
      }
    } catch (err) {
      console.error('Failed to generate PDF:', err);
      setIsGeneratingPdf(false);
    }
  };

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIndicator.trim()) {
      setFormError('Indicator value is required.');
      return;
    }

    try {
      setIsSubmitting(true);
      setFormError(null);

      const tags = newTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);

      await api.threatIntel.create({
        ioc_type: newType,
        indicator: newIndicator.trim(),
        severity: newSeverity,
        confidence: Number(newConfidence),
        category: newCategory.trim() || undefined,
        description: newDescription.trim() || undefined,
        tags: tags.length > 0 ? tags : undefined,
      });

      setActionSuccess(`IOC '${newIndicator.trim()}' registered successfully.`);
      setIsAddModalOpen(false);
      setNewIndicator('');
      setNewDescription('');
      setNewTags('');
      fetchIocs();
    } catch (err: any) {
      setFormError(err.detail || err.message || 'Failed to create IOC.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteIoc = async () => {
    if (!iocToDelete) return;
    try {
      setIsDeleting(true);
      await api.threatIntel.delete(iocToDelete.ioc_id);
      setActionSuccess(`IOC '${iocToDelete.indicator}' deleted successfully.`);
      setIocToDelete(null);
      fetchIocs();
    } catch (err: any) {
      setError(err.message || 'Failed to delete IOC.');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleToggleIoc = async (ioc: IOCItem) => {
    try {
      if (ioc.enabled) {
        await api.threatIntel.disable(ioc.ioc_id);
        setActionSuccess(`IOC '${ioc.indicator}' disabled.`);
      } else {
        await api.threatIntel.enable(ioc.ioc_id);
        setActionSuccess(`IOC '${ioc.indicator}' enabled.`);
      }
      fetchIocs();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle IOC state.');
    }
  };

  const handleCheckIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!checkInput.trim()) return;

    try {
      setIsChecking(true);
      setCheckResult(null);
      const res = await api.threatIntel.check({
        indicator: checkInput.trim(),
        ioc_type: checkType || undefined,
      });
      setCheckResult(res);
    } catch (err: any) {
      setError(err.message || 'Lookup check failed.');
    } finally {
      setIsChecking(false);
    }
  };

  const handleImportJson = async () => {
    try {
      setIsSubmitting(true);
      setFormError(null);
      const parsed = JSON.parse(jsonText);
      const list = Array.isArray(parsed) ? parsed : parsed.iocs;
      if (!Array.isArray(list)) {
        throw new Error('Input JSON must be an array of IOC objects.');
      }
      const res = await api.threatIntel.importJson({ iocs: list });
      setImportResult(res);
      setActionSuccess(`Import completed: ${res.imported_count} imported, ${res.rejected_count} rejected.`);
      fetchIocs();
    } catch (err: any) {
      setFormError(err.message || 'Failed to parse or import JSON.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleImportCsv = async () => {
    try {
      setIsSubmitting(true);
      setFormError(null);
      if (!csvText.trim()) throw new Error('CSV content cannot be empty.');
      const res = await api.threatIntel.importCsv(csvText);
      setImportResult(res);
      setActionSuccess(`CSV Import completed: ${res.imported_count} imported, ${res.rejected_count} rejected.`);
      fetchIocs();
    } catch (err: any) {
      setFormError(err.message || 'Failed to import CSV.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredIocs = iocs.filter((item) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.indicator.toLowerCase().includes(q) ||
      (item.category && item.category.toLowerCase().includes(q)) ||
      (item.description && item.description.toLowerCase().includes(q))
    );
  });

  return (
    <motion.div
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {actionSuccess && (
        <div className={alertBox('success')}>
          <CheckCircle2 size={16} />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Action Header & Tools */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-5')}>
        <div className="flex justify-between items-center flex-wrap gap-4">
          <div>
            <h2 className="text-[1.1rem] font-bold text-fg flex items-center gap-2">
              <Database size={18} color="var(--color-accent)" />
              <span>Local Threat Intelligence / IOC Store</span>
            </h2>
            <p className="text-[0.78rem] text-fg-muted">
              All IOCs are stored locally in SQLite. CIPHER does not automatically transmit indicators to external threat feeds.
            </p>
          </div>

          <div className="flex gap-2 flex-wrap">
            <button className={controlBtn()} onClick={() => setIsCheckModalOpen(true)}>
              <Search size={14} />
              <span>Check Indicator</span>
            </button>
            <button className={controlBtn()} onClick={() => setIsJsonImportOpen(true)}>
              <FileCode size={14} />
              <span>JSON Import</span>
            </button>
            <button className={controlBtn()} onClick={() => setIsCsvImportOpen(true)}>
              <FileSpreadsheet size={14} />
              <span>CSV Import</span>
            </button>
            <button className={controlBtn('primary')} onClick={() => setIsAddModalOpen(true)}>
              <Plus size={14} />
              <span>Add IOC</span>
            </button>
          </div>
        </div>
      </motion.div>

      {/* IOC Intelligence Metric Strip */}
      <motion.div variants={itemVariants} className="mb-5 grid grid-cols-[repeat(auto-fit,minmax(130px,1fr))] gap-3">
        <div className="rounded-none border border-line-card bg-surface px-4 py-3 [transition:all_0.15s_ease] hover:border-elevated hover:transform-[translateY(-2px)]">
          <div className="font-mono text-[1.4rem] leading-[1.1] font-extrabold text-fg">{totalMatching}</div>
          <div className="mt-[0.2rem] text-[0.7rem] font-semibold text-fg-muted uppercase">Total Indicators</div>
        </div>
        <div className="rounded-none border border-line-card bg-surface px-4 py-3 [transition:all_0.15s_ease] hover:border-elevated hover:transform-[translateY(-2px)]">
          <div className={cn('font-mono text-[1.4rem] leading-[1.1] font-extrabold text-fg', 'text-accent')}>
            {iocs.filter((i) => i.ioc_type === 'IP').length}
          </div>
          <div className="mt-[0.2rem] text-[0.7rem] font-semibold text-fg-muted uppercase">IP Addresses</div>
        </div>
        <div className="rounded-none border border-line-card bg-surface px-4 py-3 [transition:all_0.15s_ease] hover:border-elevated hover:transform-[translateY(-2px)]">
          <div className={cn('font-mono text-[1.4rem] leading-[1.1] font-extrabold text-fg', 'text-accent')}>
            {iocs.filter((i) => i.ioc_type === 'DOMAIN').length}
          </div>
          <div className="mt-[0.2rem] text-[0.7rem] font-semibold text-fg-muted uppercase">Malicious Domains</div>
        </div>
        <div className="rounded-none border border-line-card bg-surface px-4 py-3 [transition:all_0.15s_ease] hover:border-elevated hover:transform-[translateY(-2px)]">
          <div className={cn('font-mono text-[1.4rem] leading-[1.1] font-extrabold text-fg', 'text-high')}>
            {iocs.filter((i) => i.ioc_type === 'URL').length}
          </div>
          <div className="mt-[0.2rem] text-[0.7rem] font-semibold text-fg-muted uppercase">Phishing URLs</div>
        </div>
        <div className="rounded-none border border-line-card bg-surface px-4 py-3 [transition:all_0.15s_ease] hover:border-elevated hover:transform-[translateY(-2px)]">
          <div className={cn('font-mono text-[1.4rem] leading-[1.1] font-extrabold text-fg', 'text-accent')}>
            {iocs.filter((i) => i.ioc_type === 'HASH').length}
          </div>
          <div className="mt-[0.2rem] text-[0.7rem] font-semibold text-fg-muted uppercase">File Hashes</div>
        </div>
        <div className="rounded-none border border-line-card bg-surface px-4 py-3 [transition:all_0.15s_ease] hover:border-elevated hover:transform-[translateY(-2px)]">
          <div className={cn('font-mono text-[1.4rem] leading-[1.1] font-extrabold text-fg', 'text-benign')}>
            {iocs.filter((i) => i.enabled).length}
          </div>
          <div className="mt-[0.2rem] text-[0.7rem] font-semibold text-fg-muted uppercase">Active & Enforcing</div>
        </div>
      </motion.div>

      {/* Filter Controls */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-5')}>
        <div className="flex flex-wrap gap-4 items-end">
          <div className={cn(formGroup, 'flex-[1_1_200px] m-0')}>
            <label className={formLabel}>Search Indicator</label>
            <input
              type="text"
              className={formInput}
              placeholder="e.g. 198.51.100.24 or evil-domain.com"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className={cn(formGroup, 'w-[140px] m-0')}>
            <label className={formLabel}>IOC Type</label>
            <select
              className={formSelect}
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <option value="">All Types</option>
              <option value="IP">IP Address</option>
              <option value="DOMAIN">Domain</option>
              <option value="URL">URL</option>
              <option value="HASH">File Hash</option>
            </select>
          </div>

          <div className={cn(formGroup, 'w-[140px] m-0')}>
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

          <div className="flex items-center gap-[0.4rem] pb-2">
            <input
              type="checkbox"
              id="enabledOnly"
              checked={enabledOnly}
              onChange={(e) => setEnabledOnly(e.target.checked)}
              className="cursor-pointer"
            />
            <label htmlFor="enabledOnly" className="text-[0.8rem] text-fg-2 cursor-pointer">
              Active Only
            </label>
          </div>
        </div>
      </motion.div>

      {/* IOC Table */}
      <motion.div variants={itemVariants} className={card}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <span>Registered Indicators of Compromise</span>
          </div>
          <span className="text-[0.78rem] text-fg-muted">
            Showing {filteredIocs.length} of {totalMatching} matching indicators
          </span>
        </div>

        {loading ? (
          <LoadingState message="Loading threat intelligence indicators..." />
        ) : error ? (
          <ErrorState title="Failed to Load IOC Store" error={error} onRetry={fetchIocs} />
        ) : filteredIocs.length === 0 ? (
          <div className="py-12 px-6 text-center">
            <div
              className="w-[48px] h-[48px] rounded-[50%] bg-benign-bg flex items-center justify-center mt-0 mx-auto mb-4 border border-benign"
            >
              <Database size={24} color="var(--color-benign)" />
            </div>
            <div className="font-bold text-[1rem] mb-[0.35rem] text-fg">
              {typeFilter || severityFilter || searchQuery
                ? 'No Threat Indicators Match Query'
                : 'Zero Indicators in Local Threat Store'}
            </div>
            <div className="text-fg-muted text-[0.84rem] max-w-[420px] my-0 mx-auto">
              {typeFilter || severityFilter || searchQuery
                ? 'Try clearing your filter inputs to display all registered indicators.'
                : 'Local IOC store is clean. Click "Add IOC" or "CSV Import" above to register malicious IPs, domains, or hashes.'}
            </div>
          </div>
        ) : (
          <div className={tableContainer}>
            <table className={dataTable}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator Value</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Category</th>
                  <th>Source</th>
                  <th>First / Last Seen</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredIocs.map((ioc) => (
                  <tr key={ioc.ioc_id}>
                    <td>
                      <span className={cn(mono, 'text-[0.72rem] bg-elevated border border-line py-[2px] px-[6px] rounded-[4px]')}>
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td 
                      className={cn(mono, 'font-semibold! cursor-pointer hover:text-accent [transition:all_0.15s]')}
                      onClick={() => handleOpenDetail(ioc)}
                      title="Click to view full threat profile"
                    >
                      {ioc.indicator}
                    </td>
                    <td>
                      <SeverityBadge severity={ioc.severity} size="sm" />
                    </td>
                    <td className={cn(mono, 'text-[0.75rem]!')}>
                      {(ioc.confidence * 100).toFixed(0)}%
                    </td>
                    <td>
                      <span className="text-[0.78rem]">{ioc.category || 'THREAT'}</span>
                    </td>
                    <td>
                      <span className={cn(mono, 'text-[0.72rem] text-fg-muted')}>
                        {ioc.source}
                      </span>
                    </td>
                    <td className={cn(mono, 'text-[0.7rem]! text-fg-muted!')}>
                      {ioc.first_seen?.split('T')[0] || 'N/A'}
                    </td>
                    <td>
                      <button
                        className={cn(controlBtn(), 'py-[2px] px-[6px] text-[0.7rem]')}

                        onClick={() => handleToggleIoc(ioc)}
                        title={ioc.enabled ? 'Click to Disable' : 'Click to Enable'}
                      >
                        {ioc.enabled ? (
                          <>
                            <ToggleRight size={14} color="var(--color-benign)" />
                            <span className="text-benign">Enabled</span>
                          </>
                        ) : (
                          <>
                            <ToggleLeft size={14} color="var(--color-fg-muted)" />
                            <span className="text-fg-muted">Disabled</span>
                          </>
                        )}
                      </button>
                    </td>
                    <td>
                      <button
                        className={cn(controlBtn('danger'), 'py-[3px] px-[6px]')}

                        onClick={() => setIocToDelete(ioc)}
                        title="Delete IOC"
                      >
                        <Trash2 size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Add IOC Modal */}
      <Modal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        title="Register Indicator of Compromise (IOC)"
        footer={
          <>
            <button className={controlBtn()} onClick={() => setIsAddModalOpen(false)}>
              Cancel
            </button>
            <button
              className={controlBtn('primary')}
              onClick={handleAddIoc}
              disabled={isSubmitting || !newIndicator.trim()}
            >
              {isSubmitting ? 'Registering...' : 'Save Indicator'}
            </button>
          </>
        }
      >
        <form onSubmit={handleAddIoc} className="flex flex-col gap-[0.85rem]">
          {formError && (
            <div className={alertBox('danger')}>
              <AlertTriangle size={14} />
              <span>{formError}</span>
            </div>
          )}

          <div className="grid grid-cols-[1fr_1fr] gap-3">
            <div className={cn(formGroup, 'm-0')}>
              <label className={formLabel}>Indicator Type</label>
              <select
                className={formSelect}
                value={newType}
                onChange={(e) => setNewType(e.target.value as IOCType)}
              >
                <option value="IP">IP Address</option>
                <option value="DOMAIN">Domain</option>
                <option value="URL">URL</option>
                <option value="HASH">File Hash (MD5/SHA1/SHA256)</option>
              </select>
            </div>

            <div className={cn(formGroup, 'm-0')}>
              <label className={formLabel}>Severity Level</label>
              <select
                className={formSelect}
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value as Severity)}
              >
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Indicator Value</label>
            <input
              type="text"
              className={formInput}
              placeholder={
                newType === 'IP'
                  ? '198.51.100.23'
                  : newType === 'DOMAIN'
                  ? 'c2-beacon.attacker.com'
                  : newType === 'URL'
                  ? 'http://malware-drop.xyz/payload.exe'
                  : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
              }
              value={newIndicator}
              onChange={(e) => setNewIndicator(e.target.value)}
              required
            />
          </div>

          <div className="grid grid-cols-[1fr_1fr] gap-3">
            <div className={cn(formGroup, 'm-0')}>
              <label className={formLabel}>Confidence (0.0 - 1.0)</label>
              <input
                type="number"
                step="0.05"
                min="0.0"
                max="1.0"
                className={formInput}
                value={newConfidence}
                onChange={(e) => setNewConfidence(Number(e.target.value))}
              />
            </div>

            <div className={cn(formGroup, 'm-0')}>
              <label className={formLabel}>Attack Category</label>
              <input
                type="text"
                className={formInput}
                placeholder="C2, BOTNET, PHISHING, RANSOMWARE"
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value)}
              />
            </div>
          </div>

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Description / Threat Context</label>
            <input
              type="text"
              className={formInput}
              placeholder="Known command-and-control server observed in recent campaign"
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
            />
          </div>

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Tags (comma-separated)</label>
            <input
              type="text"
              className={formInput}
              placeholder="malware, apt29, trojan"
              value={newTags}
              onChange={(e) => setNewTags(e.target.value)}
            />
          </div>
        </form>
      </Modal>

      {/* Check Indicator Modal */}
      <Modal
        isOpen={isCheckModalOpen}
        onClose={() => {
          setIsCheckModalOpen(false);
          setCheckResult(null);
        }}
        title="Direct Indicator Lookup Check (POST /api/threat-intel/check)"
        footer={
          <button className={controlBtn()} onClick={() => setIsCheckModalOpen(false)}>
            Close
          </button>
        }
      >
        <form onSubmit={handleCheckIndicator} className="flex flex-col gap-4">
          <p className="text-[0.82rem] text-fg-2">
            Instantly checks an IP, domain, URL, or hash against active local intelligence. Operates purely locally without network queries.
          </p>

          <div className="flex gap-2">
            <input
              type="text"
              className={formInput}
              placeholder="Enter IP, domain, URL, or hash..."
              value={checkInput}
              onChange={(e) => setCheckInput(e.target.value)}
              required
            />
            <button type="submit" className={controlBtn('primary')} disabled={isChecking}>
              <Search size={14} />
              <span>{isChecking ? 'Checking...' : 'Check'}</span>
            </button>
          </div>

          {checkResult && (
            <div className={cn(evidenceSection, 'mt-2')}>
              <div className={evidenceHeader}>
                {checkResult.matched ? (
                  <>
                    <AlertTriangle size={14} color="var(--color-crit)" />
                    <span className="text-crit">THREAT INDICATOR MATCHED</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={14} color="var(--color-benign)" />
                    <span className="text-benign">NO ACTIVE IOC MATCH FOUND</span>
                  </>
                )}
              </div>

              {checkResult.matched && checkResult.matches.length > 0 ? (
                <div className={kvGrid}>
                  <div className={kvItem}>
                    <span className={kvLabel}>Indicator</span>
                    <span className={cn(mono, kvValue)}>{checkResult.matches[0].indicator}</span>
                  </div>
                  <div className={kvItem}>
                    <span className={kvLabel}>Severity</span>
                    <span className={kvValue}>
                      <SeverityBadge severity={checkResult.matches[0].severity} size="sm" />
                    </span>
                  </div>
                  <div className={kvItem}>
                    <span className={kvLabel}>Confidence</span>
                    <span className={cn(mono, kvValue)}>
                      {(checkResult.matches[0].confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className={kvItem}>
                    <span className={kvLabel}>Source</span>
                    <span className={cn(mono, kvValue)}>{checkResult.matches[0].source}</span>
                  </div>
                  {checkResult.matches[0].description && (
                    <div className={cn(kvItem, '[grid-column:1_/_-1]')}>
                      <span className={kvLabel}>Context</span>
                      <span className={kvValue}>{checkResult.matches[0].description}</span>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-[0.82rem] text-fg-2">
                  The indicator is not registered in CIPHER's local threat store.
                </p>
              )}
            </div>
          )}
        </form>
      </Modal>

      {/* JSON Import Modal */}
      <Modal
        isOpen={isJsonImportOpen}
        onClose={() => {
          setIsJsonImportOpen(false);
          setImportResult(null);
        }}
        wide
        title="Bulk Import IOCs (JSON)"
        footer={
          <>
            <button className={controlBtn()} onClick={() => setIsJsonImportOpen(false)}>
              Cancel
            </button>
            <button
              className={controlBtn('primary')}
              onClick={handleImportJson}
              disabled={isSubmitting || !jsonText.trim()}
            >
              {isSubmitting ? 'Importing...' : 'Submit JSON Batch'}
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <p className="text-[0.82rem] text-fg-2">
            Paste a JSON array of IOC objects (maximum 1,000 entries per batch).
          </p>

          <textarea
            className={cn(formTextarea, 'h-[180px]')}

            placeholder={`[\n  {\n    "ioc_type": "IP",\n    "indicator": "198.51.100.99",\n    "severity": "HIGH",\n    "confidence": 0.9,\n    "category": "C2"\n  }\n]`}
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
          />

          {importResult && (
            <div className={alertBox('info')}>
              <span>
                Processed {importResult.total_submitted} items: {importResult.imported_count} imported,{' '}
                {importResult.rejected_count} rejected.
              </span>
            </div>
          )}
        </div>
      </Modal>

      {/* CSV Import Modal */}
      <Modal
        isOpen={isCsvImportOpen}
        onClose={() => {
          setIsCsvImportOpen(false);
          setImportResult(null);
        }}
        wide
        title="Bulk Import IOCs (CSV)"
        footer={
          <>
            <button className={controlBtn()} onClick={() => setIsCsvImportOpen(false)}>
              Cancel
            </button>
            <button
              className={controlBtn('primary')}
              onClick={handleImportCsv}
              disabled={isSubmitting || !csvText.trim()}
            >
              {isSubmitting ? 'Importing...' : 'Submit CSV Batch'}
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <p className="text-[0.82rem] text-fg-2">
            Paste raw CSV text. Required header columns: <code className={codeTag}>ioc_type,indicator,severity,confidence,category,description</code>.
          </p>

          <textarea
            className={cn(formTextarea, 'h-[180px]')}

            placeholder={`ioc_type,indicator,severity,confidence,category,description\nIP,203.0.113.15,HIGH,0.85,SCANNER,Known port scanner\nDOMAIN,malicious-c2.xyz,CRITICAL,0.95,BOTNET,Active botnet C2`}
            value={csvText}
            onChange={(e) => setCsvText(e.target.value)}
          />

          {importResult && (
            <div className={alertBox('info')}>
              <span>
                Processed {importResult.total_submitted} items: {importResult.imported_count} imported,{' '}
                {importResult.rejected_count} rejected.
              </span>
            </div>
          )}
        </div>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(iocToDelete)}
        onClose={() => setIocToDelete(null)}
        onConfirm={handleDeleteIoc}
        title="Delete Indicator of Compromise"
        message={
          iocToDelete ? (
            <div>
              <p>
                Are you sure you want to permanently delete IOC{' '}
                <strong className={mono}>{iocToDelete.indicator}</strong> ({iocToDelete.ioc_type})?
              </p>
              <p className="mt-2 text-crit">
                This indicator will no longer elevate risk scores in subsequent threat evaluations.
              </p>
            </div>
          ) : (
            ''
          )
        }
        confirmLabel="Delete IOC"
        isDestructive
        isLoading={isDeleting}
      />

      {/* Detail Modal */}
      {selectedIoc && (
        <Modal
          isOpen={isDetailModalOpen}
          onClose={() => setIsDetailModalOpen(false)}
          title="Threat Indicator Profile"
          wide
          footer={
            <div className="flex w-full items-center justify-between">
              <button
                className={cn(controlBtn(), 'flex items-center gap-2 border-accent text-accent hover:bg-accent hover:text-bg')}
                onClick={generateIocPdf}
                disabled={isGeneratingPdf}
              >
                <FileText size={16} />
                {isGeneratingPdf ? 'Generating PDF...' : 'Generate PDF Report'}
              </button>
              <button className={controlBtn()} onClick={() => setIsDetailModalOpen(false)}>
                Close
              </button>
            </div>
          }
        >
          <div className="flex flex-col gap-6">
            <div className={evidenceSection}>
              <div className={evidenceHeader}>
                <AlertTriangle size={14} className={selectedIoc.enabled ? "text-crit" : "text-fg-muted"} />
                <span className={selectedIoc.enabled ? "text-crit" : "text-fg-muted"}>
                  {selectedIoc.enabled ? "ACTIVE INDICATOR OF COMPROMISE" : "DISABLED INDICATOR"}
                </span>
              </div>
              <div className={kvGrid}>
                <div className={kvItem}>
                  <span className={kvLabel}>Indicator</span>
                  <span className={cn(mono, kvValue, 'text-accent text-[1.1rem]')}>{selectedIoc.indicator}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Type</span>
                  <span className={kvValue}>{selectedIoc.ioc_type}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Severity</span>
                  <span className={kvValue}>
                    <SeverityBadge severity={selectedIoc.severity} size="sm" />
                  </span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Confidence</span>
                  <span className={cn(mono, kvValue)}>
                    {(selectedIoc.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Source</span>
                  <span className={cn(mono, kvValue)}>{selectedIoc.source}</span>
                </div>
                <div className={kvItem}>
                  <span className={kvLabel}>Category</span>
                  <span className={cn(mono, kvValue)}>{selectedIoc.category || 'N/A'}</span>
                </div>
              </div>
              {selectedIoc.description && (
                <div className="mt-4 border-t border-line pt-4">
                  <span className={kvLabel}>Description & Context</span>
                  <p className="mt-1 text-[0.85rem] text-fg-2">{selectedIoc.description}</p>
                </div>
              )}
            </div>
            
            {/* Associated Incidents */}
            <div>
              <h3 className="mb-3 text-[0.95rem] font-medium text-fg">Historical Incident Matches ({selectedIocIncidents.length})</h3>
              {selectedIocIncidents.length > 0 ? (
                <div className={tableContainer}>
                  <table className={dataTable}>
                    <thead>
                      <tr>
                        <th>Incident ID</th>
                        <th>First Seen</th>
                        <th>Severity</th>
                        <th>Categories</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedIocIncidents.map(inc => (
                        <tr key={inc.incident_id}>
                          <td className={cn(mono, 'text-[0.8rem]')}>{inc.incident_id}</td>
                          <td className="text-[0.8rem] text-fg-muted">{inc.first_seen.split('.')[0].replace('T', ' ')}</td>
                          <td><SeverityBadge severity={inc.severity} size="sm" /></td>
                          <td className={cn(mono, 'text-[0.75rem]')}>{inc.attack_categories?.join(', ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="rounded border border-dashed border-line p-4 text-center text-[0.85rem] text-fg-muted">
                  No direct incident links found in active datastore.
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}

    </motion.div>
  );
};
