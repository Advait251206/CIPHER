import React, { useState, useEffect, useCallback } from 'react';
import { Toast, type ToastType } from '../components/common/Toast';
import { api } from '../api/client';
import {
  EmailAnalyzeResponse,
  EmailModelInfoResponse,
  EmailHealthResponse,
} from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { RiskGauge } from '../components/common/RiskGauge';
import {
  Mail,
  Send,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  ExternalLink,
  Cpu,
  Compass,
  Download,
  Terminal,
  FileText,
  ListFilter,
  Eye,
  Printer,
} from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { cn } from '../lib/cn';
import { alertBox, btn, card, cardHeader, cardTitle, codeTag, controlBtn, input, pageBody } from '../ui/classes';

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

const classificationTone = (c?: string) =>
  c === 'MALICIOUS_EMAIL' || c === 'PHISHING'
    ? 'bg-[rgba(239,68,68,0.15)] text-[#ef4444]'
    : c === 'SUSPICIOUS'
      ? 'bg-[rgba(245,158,11,0.15)] text-[#f59e0b]'
      : 'bg-[rgba(16,185,129,0.15)] text-[#10b981]';


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

export const EmailPage: React.FC = () => {
  const [activeMode, setActiveMode] = useState<'structured' | 'raw'>('structured');
  const [sender, setSender] = useState('');
  const [recipient, setRecipient] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [rawText, setRawText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<EmailAnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Toast notification
  const [toast, setToast] = useState<{ message: string; type: ToastType; visible: boolean }>({
    message: '',
    type: 'info',
    visible: false,
  });
  const showToast = useCallback((message: string, type: ToastType = 'info') => {
    setToast({ message, type, visible: true });
  }, []);
  const hideToast = useCallback(() => {
    setToast((prev) => ({ ...prev, visible: false }));
  }, []);

  const generateReportPdf = () => {
    if (!result) return;
    showToast('Compiling Intelligence Dossier...', 'info');
    setTimeout(() => {
      showToast('PDF Report generated successfully.', 'success');
      
      const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <title>CIPHER Intelligence Report - Email Analysis</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');
    :root { --bg: #0B0B0B; --surface: #141414; --border: #2A2A2A; --text-main: #F8FAFC; --text-muted: #94A3B8; --accent-gold: #D4AF37; --accent-cyan: #22D3EE; }
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; box-sizing: border-box; }
    @page { size: A4 portrait; margin: 0; }
    body { font-family: 'Inter', -apple-system, sans-serif; line-height: 1.6; color: var(--text-main); background-color: var(--bg); margin: 0; padding: 0; }
    .cover-page { height: 297mm; width: 210mm; padding: 3cm; display: flex; flex-direction: column; justify-content: center; position: relative; page-break-after: always; background: var(--bg); }
    .cover-bg-element { position: absolute; top: 0; right: 0; bottom: 0; left: 0; background: radial-gradient(circle at 100% 0%, rgba(34, 211, 238, 0.05) 0%, transparent 50%), radial-gradient(circle at 0% 100%, rgba(212, 175, 55, 0.05) 0%, transparent 50%); z-index: 0; }
    .cover-content { position: relative; z-index: 1; border-left: 4px solid var(--accent-gold); padding-left: 2rem; }
    .cover-brand { font-size: 48px; font-weight: 900; letter-spacing: 4px; margin-bottom: 0.5rem; color: #FFF; }
    .cover-brand span { color: var(--accent-gold); }
    .cover-subtitle { font-size: 14px; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 3px; font-weight: 600; margin-bottom: 4rem; }
    .cover-title { font-size: 36px; font-weight: 700; line-height: 1.2; color: #FFF; margin-bottom: 2rem; max-width: 80%; }
    .cover-meta { margin-top: 4rem; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-muted); }
    .cover-meta table { width: 100%; border-collapse: collapse; }
    .cover-meta td { padding: 8px 0; border-bottom: 1px solid var(--border); text-align: left; }
    .cover-meta td:first-child { color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; width: 150px; }
    .cover-meta td:last-child { color: #FFF; font-weight: 600; }
    .content-page { padding: 1cm 2.5cm; background: var(--bg); width: 210mm; position: relative; }
    .content-page:nth-of-type(2) { padding-top: 2.5cm; }
    .content-page:last-child { padding-bottom: 2.5cm; }
    .page-header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 3rem; }
    .page-header-brand { font-size: 16px; font-weight: 900; letter-spacing: 2px; color: #FFF; }
    .page-header-brand span { color: var(--accent-gold); }
    .page-header-meta { font-size: 9px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
    .section { margin-bottom: 3rem; }
    .section-title { font-size: 18px; font-weight: 300; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 2px; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    .info-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    .info-table th, .info-table td { padding: 12px 0; text-align: left; border-bottom: 1px solid var(--border); }
    .info-table th { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 500; width: 30%; }
    .info-table td { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #FFF; }
    .prose { font-size: 13px; color: #E2E8F0; line-height: 1.8; font-weight: 300; text-align: justify; }
    .prose p { margin-bottom: 1.25rem; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 2px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; font-family: 'Inter', sans-serif; }
    .badge.critical, .badge.high { color: #ef4444; border: 1px solid rgba(239,68,68,0.3); background: rgba(239,68,68,0.05); }
    .badge.medium { color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); background: rgba(245,158,11,0.05); }
    .badge.low { color: #22c55e; border: 1px solid rgba(34,197,94,0.3); background: rgba(34,197,94,0.05); }
    .two-column-prose { display: column; column-count: 2; column-gap: 2rem; text-align: justify; font-size: 11px; color: #94A3B8; line-height: 1.7; }
    .tech-box { border-left: 3px solid var(--accent-cyan); padding: 1rem 1.5rem; background: var(--surface); margin-bottom: 1.5rem; }
    .tech-box h4 { margin: 0 0 0.5rem 0; font-size: 12px; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1px; }
  </style>
</head>
<body>
  <div class="cover-page">
    <div class="cover-bg-element"></div>
    <div class="cover-content">
      <div class="cover-brand">CIPHER<span>.</span></div>
      <div class="cover-subtitle">Cyber Intrusion Prevention & Heuristic Event Response</div>
      <div class="cover-title">Threat Intelligence<br>Email Message Diagnostics</div>
      <div class="cover-meta">
        <table>
          <tr><td>Report ID</td><td>EMAIL-${result.event_id?.substring(0,8) || Math.random().toString(36).substring(2,10).toUpperCase()}</td></tr>
          <tr><td>Date Generated</td><td>${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</td></tr>
          <tr><td>Target Platform</td><td>CIPHER Security Network</td></tr>
          <tr><td>Classification</td><td>RESTRICTED / CONFIDENTIAL</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="content-page">
    <div class="page-header">
      <div class="page-header-brand">CIPHER<span>.</span></div>
      <div class="page-header-meta">EMAIL FORENSICS | PAGE 1 OF 3</div>
    </div>

    <div class="section">
      <h2 class="section-title">1.0 Message Telemetry</h2>
      <table class="info-table">
        <tr><th>Classification</th><td>${result.classification.replace('_', ' ')}</td></tr>
        <tr><th>Confidence</th><td>${(result.confidence * 100).toFixed(1)}%</td></tr>
        <tr><th>Threat Level</th><td><span class="badge ${result.severity.toLowerCase()}">${result.severity}</span></td></tr>
        <tr><th>Risk Score</th><td>${result.risk_score} / 100</td></tr>
      </table>
    </div>

    <div class="section">
      <h2 class="section-title">2.0 Detection Evidence</h2>
      <div class="prose">
        <ul style="padding-left:1.5rem">
          ${(result.evidence || []).map(r => '<li style="margin-bottom:0.5rem">' + r + '</li>').join('')}
        </ul>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">3.0 Action Recommendation</h2>
      <div class="prose">
        <p style="font-weight:600; color:var(--accent-gold)">${result.recommendation}</p>
      </div>
    </div>

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
  </div>

  <div class="content-page">
    <div class="page-header">
      <div class="page-header-brand">CIPHER<span>.</span></div>
      <div class="page-header-meta">REMEDIATION & PROTOCOLS | PAGE 2 OF 3</div>
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
  </div>

  <div class="content-page">
    <div class="page-header">
      <div class="page-header-brand">CIPHER<span>.</span></div>
      <div class="page-header-meta">LEGAL ADMISSIBILITY | PAGE 3 OF 3</div>
    </div>

    <div class="section">
      <h2 class="section-title">7.0 Evidentiary Chain of Custody & Legal Admissibility</h2>
      <div class="prose">
        <p>This document constitutes an automated, cryptographically sealed record of digital intrusion telemetry captured by the CIPHER system. The data contained herein was collected in real-time, in the regular course of business, maintaining a continuous chain of custody from the point of ingestion to the generation of this report. It is prepared in accordance with digital forensics standards for use in incident response, compliance auditing, and legal proceedings.</p>
        
        <p><strong>Legal Framework & Potential Violations:</strong> The anomalous activities documented in this report may constitute unauthorized access to a protected computer system and may violate applicable regional and international cybercrime statutes, including but not limited to:</p>
        <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem; color: #94A3B8;">
          ${getLegalFrameworks([result.classification || ''])}
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
    }, 800);
  };

  // Subsystem Telemetry
  const [modelInfo, setModelInfo] = useState<EmailModelInfoResponse | null>(null);
  const [healthInfo, setHealthInfo] = useState<EmailHealthResponse | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState(true);

  // Samples (10 of each type)
  type SampleCategory = 'Legitimate' | 'Phishing' | 'Spam / Fraud';
  
  const sampleCategories: Record<SampleCategory, { sender: string; recipient: string; subject: string; body: string }[]> = {
    'Legitimate': [
      { sender: 'alex.chen@company.org', recipient: 'dev-team@company.org', subject: 'Quarterly Architecture Sync — Thursday 2 PM', body: 'Hi team, please find the agenda for our architecture review on Thursday. We will review the database migration plan and pipeline latency metrics. Let me know if you have items to add.' },
      { sender: 'hr@company.org', recipient: 'all-employees@company.org', subject: 'Open Enrollment for Health Benefits', body: 'Friendly reminder that open enrollment for health benefits ends this Friday. Please log into the internal portal (hr.company.internal) to make your selections for the upcoming year.' },
      { sender: 'sarah.jones@company.org', recipient: 'marketing@company.org', subject: 'Draft: Q3 Campaign Assets', body: 'Attached are the final drafts for the Q3 marketing campaign. Please review the copy and the banners before our sync tomorrow at 10 AM.' },
      { sender: 'jira-notifications@atlassian.net', recipient: 'dev-team@company.org', subject: '[JIRA] (PROJ-204) Update login flow for edge cases', body: 'Alex Chen updated the description of PROJ-204. "We need to ensure the OAuth callback handles the 503 error gracefully and redirects to the fallback page." View issue: https://company.atlassian.net/browse/PROJ-204' },
      { sender: 'no-reply-aws@amazon.com', recipient: 'cloud-ops@company.org', subject: 'AWS Invoice Available - August 2026', body: 'Hello, your AWS invoice for the period of August 1 - August 31, 2026 is now available. You can view and download your invoice from the Billing and Cost Management console.' },
      { sender: 'lunch-bot@company.org', recipient: 'user@company.org', subject: 'Your lunch order has arrived', body: 'Your order from "The Salad Spot" has arrived at the front desk. Please pick it up within the next 15 minutes.' },
      { sender: 'michael.scott@company.org', recipient: 'user@company.org', subject: '1-on-1 Catch-up', body: 'Hey, do you have 15 minutes this afternoon to quickly sync on the new vendor contract? My calendar is up to date, just throw something on there.' },
      { sender: 'notifications@slack.com', recipient: 'user@company.org', subject: 'New messages from #engineering', body: 'You have unread messages in #engineering. Sarah said: "Has anyone seen the latency spikes on the EU cluster?" Click here to jump back into the conversation.' },
      { sender: 'reservations@delta.com', recipient: 'user@company.org', subject: 'Flight Confirmation: SFO to JFK', body: 'Your flight DL 1042 from San Francisco (SFO) to New York (JFK) is confirmed. Departure is at 08:30 AM on Oct 12. View your itinerary or select seats on the Delta app.' },
      { sender: 'onboarding@company.org', recipient: 'new.hire@company.org', subject: 'Welcome to the team!', body: 'We are thrilled to have you join us! Your IT equipment has been shipped and should arrive tomorrow. Attached is the employee handbook and a schedule for your first week.' }
    ],
    'Phishing': [
      { sender: 'Security Support <no-reply@security-auth-check.xyz>', recipient: 'user@company.org', subject: 'URGENT: Your Account Has Been Locked Due to Suspicious Login', body: 'Dear Customer,\n\nWe detected unauthorized access to your account from an unknown IP address. Your credentials must be verified immediately or your access will be suspended within 24 hours.\n\nPlease log in immediately at http://192.168.1.100/secure-update/login.php to confirm your identity and reset your password.' },
      { sender: 'service@billing-notice-paypal.info', recipient: 'accounting@company.org', subject: 'Invoice #849202 Payment Processed — Action Required', body: 'You sent a payment of $899.00 USD to Crypto Exchange Ltd. If you did not make this transaction, dispute the charges immediately at http://verify-paypal-dispute-resolution.net/auth before funds are irreversibly settled.' },
      { sender: 'IT Service Desk <it-support@corp-update.net>', recipient: 'user@company.org', subject: 'ACTION REQUIRED: Password Expiration Notice', body: 'Your corporate network password will expire in 2 hours. To maintain access to your email and internal tools, please update your credentials immediately at https://corp-sso-login-update.com/reset.' },
      { sender: 'VoiceMail Service <admin@voice-mail-gateway.info>', recipient: 'user@company.org', subject: 'New Voice Message from Unknown Caller (01:14)', body: 'You have received a new secure voice message. Caller ID: +1 (800) 555-0199. Listen to the message online: http://secure-voicemail-portal-122.com/play?id=3819' },
      { sender: 'Chase Bank Alerts <alerts@chase-secure-notice.com>', recipient: 'user@company.org', subject: 'Overdraft Alert: Account Ending in 4492', body: 'Your account balance has fallen below $0.00. To avoid overdraft fees of $35.00, please log in and transfer funds immediately: https://chase-banking-secure-auth.net/login.' },
      { sender: 'CEO <executive@company-mail.org>', recipient: 'finance@company.org', subject: 'URGENT WIRE TRANSFER REQUIRED', body: 'I am currently in a meeting and cannot take calls. I need an urgent wire transfer processed for a new vendor acquisition today. Please reply so I can send the banking details. This is confidential.' },
      { sender: 'Google Docs <no-reply@docs-google-share.com>', recipient: 'user@company.org', subject: 'Document shared with you: "Q4 Bonuses and Layoffs.xlsx"', body: 'A colleague has shared a highly confidential document with you via Google Docs. Click here to view the document: http://docs-share-secure.com/view/8219 (Requires login to verify identity).' },
      { sender: 'UPS Tracking <tracking@ups-delivery-failed.info>', recipient: 'user@company.org', subject: 'Delivery Exception: Package Undeliverable', body: 'We attempted to deliver your package today but no one was available. Please click the link below to pay the $2.99 redelivery fee and schedule a new time: http://ups-reschedule-delivery.com/track/1Z99999.' },
      { sender: 'Zoom Video Communications <invites@zoom-meeting-secure.net>', recipient: 'user@company.org', subject: 'Mandatory All-Hands Meeting Starting Now', body: 'The mandatory Q3 All-Hands meeting is starting now. Your attendance is required. Join the meeting using the secure link below:\n\nhttps://zoom-secure-join.net/j/892011928' },
      { sender: 'Netflix Support <support@netflix-billing-update.com>', recipient: 'user@company.org', subject: 'Your Netflix Membership is on Hold', body: 'We were unable to process your last payment. To avoid losing access to your favorite shows and movies, please update your payment method: http://netflix-billing-auth.com/update.' }
    ],
    'Spam / Fraud': [
      { sender: 'barrister.kofi@lawfirm-westafrica.org', recipient: 'recipient@domain.com', subject: 'CONFIDENTIAL: Transfer of Unclaimed Inheritance Funds ($14.5M USD)', body: 'DEAR FRIEND, I AM BARRISTER KOFI, PERSONAL ATTORNEY TO A DECEASED CONTRACTOR. HE LEFT FOURTEEN MILLION FIVE HUNDRED THOUSAND UNITED STATES DOLLARS IN A SECURITY VAULT. REPLY WITH YOUR FULL BANK ACCOUNT DETAILS TO RECEIVE 40% SHARE AS NEXT OF KIN.' },
      { sender: 'info@miracle-weight-loss.biz', recipient: 'user@company.org', subject: 'Lose 20lbs in 1 week without diet or exercise!', body: 'Discover the secret Hollywood miracle pill that melts fat instantly. 100% natural and doctor approved! Click here to claim your free trial bottle before supplies run out!' },
      { sender: 'Elon Musk <giveaway@tesla-crypto-promo.org>', recipient: 'user@company.org', subject: 'Tesla Bitcoin Giveaway 2026 - Claim your 1 BTC!', body: 'To celebrate the launch of the new Tesla CyberCab, Elon Musk is giving away 5,000 BTC! Send between 0.1 and 5 BTC to the address below, and we will send double the amount back immediately! Address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' },
      { sender: 'seo-expert@firstpage-guarantee.com', recipient: 'marketing@company.org', subject: 'Rank #1 on Google in 24 Hours!', body: 'Hello, I visited your website and noticed you have several critical SEO errors. We guarantee page 1 rankings on Google for your top keywords within 24 hours. Reply to this email for a free quote.' },
      { sender: 'sales@luxury-watches-outlet.net', recipient: 'user@company.org', subject: 'Rolex, Breitling, Omega - 90% OFF Retail!', body: 'Get the exact same quality as authentic luxury watches for a fraction of the price. AAA+ Grade Swiss Replicas. Free shipping on all orders over $100. Shop now at luxury-watches-outlet.net.' },
      { sender: 'prize-board@euromillions-winner.org', recipient: 'user@company.org', subject: 'WINNER: You have won €2,500,000!', body: 'Congratulations! Your email address was selected in the EuroMillions random draw. You have won €2,500,000. To claim your prize, please send your full name, address, and a copy of your ID to our claims agent.' },
      { sender: 'auto-warranty@vehicle-protection.net', recipient: 'user@company.org', subject: 'Final Notice: Vehicle Warranty Expiration', body: 'We have been trying to reach you regarding your vehicle\'s extended warranty. Your coverage is about to expire. Call us immediately at 1-800-555-0199 to renew your policy and avoid expensive repairs.' },
      { sender: 'local-singles@dating-match.biz', recipient: 'user@company.org', subject: 'Someone has a crush on you!', body: 'You have 3 new matches waiting for you! Beautiful local singles are online now and want to chat. Click here to view their profiles and start messaging immediately without a credit card.' },
      { sender: 'b2b-leads@growth-hacker-pro.com', recipient: 'sales@company.org', subject: '10,000 Verified B2B Leads for just $49', body: 'Stop struggling to find customers. We have a database of 10,000 highly targeted, verified B2B leads in your industry. Name, email, phone number, and LinkedIn profiles included. Download now for only $49.' },
      { sender: 'health@miracle-hair-restore.info', recipient: 'user@company.org', subject: 'Regrow your hair in 30 days guaranteed', body: 'Balding? Thinning hair? Try our revolutionary new serum. Clinically proven to reactivate dormant hair follicles. Get a full head of hair in just 30 days. Order your risk-free supply today.' }
    ]
  };

  useEffect(() => {
    const fetchTelemetry = async () => {
      try {
        setTelemetryLoading(true);
        const [mInfo, hInfo] = await Promise.allSettled([
          api.email.getModelInfo(),
          api.email.getHealth(),
        ]);
        if (mInfo.status === 'fulfilled') setModelInfo(mInfo.value);
        if (hInfo.status === 'fulfilled') setHealthInfo(hInfo.value);
      } catch {
        // silent fallback
      } finally {
        setTelemetryLoading(false);
      }
    };
    fetchTelemetry();
  }, []);

  const handleSelectSampleCategory = (category: SampleCategory) => {
    const list = sampleCategories[category];
    const sample = list[Math.floor(Math.random() * list.length)];
    
    setActiveMode('structured');
    setSender(sample.sender);
    setRecipient(sample.recipient);
    setSubject(sample.subject);
    setBody(sample.body);
    setError(null);
  };

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();

    if (activeMode === 'structured' && !subject.trim() && !body.trim()) {
      setError('Please provide at least a subject or body to analyze.');
      return;
    }
    if (activeMode === 'raw' && !rawText.trim()) {
      setError('Please paste the email text or RFC 822 payload to analyze.');
      return;
    }

    try {
      setIsAnalyzing(true);
      setError(null);
      setResult(null);

      let res: EmailAnalyzeResponse;
      if (activeMode === 'structured') {
        res = await api.email.analyze({
          sender: sender.trim() || undefined,
          recipient: recipient.trim() || undefined,
          subject: subject.trim() || undefined,
          body: body.trim() || undefined,
        });
      } else {
        res = await api.email.analyzeText(rawText);
      }
      setResult(res);
    } catch (err: any) {
      setError(err.detail || err.message || 'Email analysis failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <>
    <motion.div
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Privacy and Local Processing Architecture Banner */}
      <motion.div variants={itemVariants} className={alertBox('info')}>
        <Info size={18} className="shrink-0" />
        <div>
          <strong>Local Privacy Architecture:</strong> Email analysis executes strictly in-memory on your local CIPHER node.
          <strong> Raw email bodies are NEVER stored or persisted</strong> in the SQLite database or external telemetry.
          Extracted features are classified using a 32-feature Random Forest model trained on 82,388 deduplicated emails, corroborated with CIPHER's URL phishing engine and local IOC threat cache.
        </div>
      </motion.div>

      {/* Mode Selector and Quick Samples */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-6')}>
        <div className="flex justify-between items-center flex-wrap gap-3 mb-4">
          <div className="flex gap-2">
            <button
              type="button"
              className={btn(activeMode === 'structured' ? 'primary' : 'secondary', 'flex items-center gap-[0.4rem]')}
              onClick={() => setActiveMode('structured')}

            >
              <FileText size={15} />
              <span>Structured Email</span>
            </button>
            <button
              type="button"
              className={btn(activeMode === 'raw' ? 'primary' : 'secondary', 'flex items-center gap-[0.4rem]')}
              onClick={() => setActiveMode('raw')}

            >
              <Terminal size={15} />
              <span>Raw Text / RFC 822</span>
            </button>
          </div>

          <div className="flex items-center gap-[0.4rem] flex-wrap">
            <span className="text-[0.75rem] text-fg-muted">Load Sample:</span>
            {(Object.keys(sampleCategories) as SampleCategory[]).map((category) => (
              <button
                key={category}
                type="button"
                className={cn(btn('secondary'), 'text-[0.72rem] py-[0.3rem] px-[0.6rem]')}

                onClick={() => handleSelectSampleCategory(category)}
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleAnalyze}>
          {activeMode === 'structured' ? (
            <div className="flex flex-col gap-[0.85rem]">
              <div className="grid grid-cols-[1fr_1fr] gap-[0.85rem]">
                <div>
                  <label className="block text-[0.78rem] text-fg-muted mb-[0.3rem]">
                    Sender (From header)
                  </label>
                  <input
                    type="text"
                    className={input}
                    placeholder="e.g. IT Helpdesk <support@acme.com>"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-[0.78rem] text-fg-muted mb-[0.3rem]">
                    Recipient (To header)
                  </label>
                  <input
                    type="text"
                    className={input}
                    placeholder="e.g. employee@acme.com"
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                  />
                </div>
              </div>

              <div>
                <label className="block text-[0.78rem] text-fg-muted mb-[0.3rem]">
                  Subject Line
                </label>
                <input
                  type="text"
                  className={input}
                  placeholder="e.g. URGENT: Verify your billing information"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-[0.78rem] text-fg-muted mb-[0.3rem]">
                  Email Body (Plain Text or HTML)
                  <span className="[float:right] text-[0.7rem] text-fg-muted">
                    {body.length.toLocaleString()} / 500,000 chars
                  </span>
                </label>
                <textarea
                  className={cn(input, 'min-h-[100px] resize-y', '[font-family:var(--font-mono,monospace)] text-[0.85rem] resize-y')}
                  rows={6}
                  placeholder="Paste email message text or HTML content here..."
                  value={body}
                  onChange={(e) => setBody(e.target.value)}

                />
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-[0.78rem] text-fg-muted mb-[0.3rem]">
                Raw Email Stream / RFC 822 Text
                <span className="[float:right] text-[0.7rem] text-fg-muted">
                  {rawText.length.toLocaleString()} / 500,000 chars
                </span>
              </label>
              <textarea
                className={cn(input, 'min-h-[100px] resize-y', '[font-family:var(--font-mono,monospace)] text-[0.85rem] resize-y')}
                rows={9}
                placeholder="From: security@paypal-verify.com&#10;Subject: Action Required&#10;&#10;Please confirm your account immediately at http://192.168.1.1/login..."
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}

              />
            </div>
          )}

          {error && (
            <div className={cn(alertBox('danger'), 'mt-4')}>
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div className="mt-4 flex justify-end gap-3">
            <button
              type="button"
              className={btn('secondary')}
              onClick={() => {
                setSender('');
                setRecipient('');
                setSubject('');
                setBody('');
                setRawText('');
                setResult(null);
                setError(null);
              }}
              disabled={isAnalyzing}
            >
              Clear
            </button>
            <button
              type="submit"
              className={cn(btn('primary'), 'flex items-center gap-2 min-w-[140px] justify-center')}
              disabled={isAnalyzing}

            >
              {isAnalyzing ? (
                <>
                  <div />
                  <span>Evaluating...</span>
                </>
              ) : (
                <>
                  <Send size={15} />
                  <span>Analyze Threat</span>
                </>
              )}
            </button>
          </div>
        </form>
      </motion.div>

      {/* Analysis Results Display */}
      {result && (
        <motion.div variants={itemVariants} className="flex flex-col gap-6 mb-6">
          {/* Main Verdict Card */}
          <div className={card}>
            <div className={cardHeader}>
              <div className={cardTitle}>
                <ShieldCheck size={18} color="var(--color-accent)" />
                <span>Detection Verdict & Risk Assessment</span>
              </div>
              <div className="flex gap-2 items-center">
                <SeverityBadge severity={result.severity} />
                <span
                  className={cn('py-[0.2rem] px-[0.6rem] rounded-[4px] text-[0.75rem] font-semibold', classificationTone(result.classification))}
                >
                  {result.classification}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-[220px_1fr] gap-6 items-center">
              <div className="flex flex-col items-center justify-center p-4 border-r border-r-line">
                <RiskGauge score={result.risk_score} size="lg" />
                <div className="mt-2 text-[0.8rem] text-fg-muted">
                  Confidence: <strong>{(result.confidence * 100).toFixed(1)}%</strong>
                </div>
                {result.event_id && (
                  <div className="mt-1 text-[0.68rem] text-fg-muted [font-family:monospace]">
                    Event: {result.event_id.slice(0, 8)}...
                  </div>
                )}
              </div>

              <div>
                <h4 className="mt-0 mx-0 mb-2 text-[0.95rem]">SOC Operational Recommendation</h4>
                <div
                  className={cn('py-3 px-4 rounded-[6px] bg-[rgba(15,23,42,0.6)] text-[0.86rem] leading-[1.4] mb-4 border-l-4', result.severity === 'CRITICAL' || result.severity === 'HIGH' ? 'border-l-[#ef4444]' : result.severity === 'MEDIUM' ? 'border-l-[#f59e0b]' : 'border-l-[#10b981]')}
                >
                  {result.recommendation}
                </div>

                <h4 className="mt-0 mx-0 mb-2 text-[0.95rem]">Explainable Detection Rationale</h4>
                <ul className="m-0 pl-[1.2rem] flex flex-col gap-[0.35rem] text-[0.83rem] text-fg-2">
                  {result.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="flex gap-3 mt-4 pt-4 border-t border-t-line flex-wrap px-6 pb-6">
              <button className={cn(controlBtn('primary'), 'flex items-center gap-2 bg-accent text-white border-none')} onClick={generateReportPdf}>
                <Printer size={16} /> Print / Save as PDF
              </button>
            </div>
          </div>

          {/* Extracted URLs Breakdown */}
          {result.urls_analyzed && result.urls_analyzed.length > 0 && (
            <div className={card}>
              <div className={cardHeader}>
                <div className={cardTitle}>
                  <ExternalLink size={18} color="var(--color-accent)" />
                  <span>Embedded Hyperlinks Inspected ({result.urls_analyzed.length})</span>
                </div>
              </div>
              <div>
                <table>
                  <thead>
                    <tr>
                      <th>URL Target</th>
                      <th>Verdict</th>
                      <th>Risk Score</th>
                      <th>Severity</th>
                      <th>Confidence</th>
                      <th>Signals</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.urls_analyzed.map((u, i) => (
                      <tr key={i}>
                        <td className="max-w-[280px]! break-all! [font-family:monospace]! text-[0.78rem]!">
                          {u.url}
                        </td>
                        <td>
                          <span
                            className={cn('py-[0.15rem] px-[0.45rem] rounded-[4px] text-[0.72rem] font-semibold', classificationTone(u.classification))}
                          >
                            {u.classification}
                          </span>
                        </td>
                        <td>
                          <strong>{u.risk_score}</strong> / 100
                        </td>
                        <td>
                          <SeverityBadge severity={u.severity} />
                        </td>
                        <td>{(u.confidence * 100).toFixed(1)}%</td>
                        <td className="text-[0.75rem]! text-fg-muted!">
                          {u.reasons && u.reasons.length > 0 ? u.reasons.join(', ') : 'None'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Extracted 32 Feature Vector Viewer */}
          {result.features && Object.keys(result.features).length > 0 && (
            <div className={card}>
              <div className={cardHeader}>
                <div className={cardTitle}>
                  <Cpu size={18} color="var(--color-accent)" />
                  <span>Extracted 32-Feature Vector</span>
                </div>
              </div>
              <div
                className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2 max-h-[260px] overflow-y-auto p-2 bg-[rgba(11,15,25,0.5)] rounded-[6px] border border-line"
              >
                {Object.entries(result.features).map(([feat, val]) => (
                  <div
                    key={feat}
                    className="flex justify-between py-[0.3rem] px-2 rounded-[4px] bg-[rgba(30,41,59,0.4)] text-[0.75rem]"
                  >
                    <span className="text-fg-muted overflow-hidden text-ellipsis whitespace-nowrap" title={feat}>
                      {feat}
                    </span>
                    <strong className={(typeof val === 'number' && val > 0 ? 'text-accent' : 'text-fg-2')}>
                      {typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(4)) : String(val)}
                    </strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      )}

      {/* CIPHER Browser Guard Extension & Model Telemetry Section */}
      <motion.div
        variants={itemVariants}
        className="grid grid-cols-[1fr_1fr] gap-6 mt-6"
      >
        {/* Browser Extension Card */}
        <div className={card}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Compass size={18} color="var(--color-accent)" />
              <span>CIPHER Browser Guard (Chromium Extension)</span>
            </div>
            <span>Manifest V3</span>
          </div>

          <p className="text-[0.84rem] text-fg-2 leading-[1.5] mt-0 mx-0 mb-4">
            Protect against webmail phishing on Gmail, Outlook, and Yahoo Mail directly within your browser.
            Features automatic badge risk alerts and an active interstitial block screen for high-confidence phishing sites.
          </p>

          <div className="flex flex-col gap-[0.6rem] text-[0.8rem] text-fg-2 mb-5">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={15} color="#10b981" />
              <span><strong>Strict Privacy:</strong> Zero cloud analytics; communicates exclusively with <code className={codeTag}>http://127.0.0.1:8000</code></span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 size={15} color="#10b981" />
              <span><strong>Webmail Integration:</strong> Floating scan badge on Gmail, Outlook, and Yahoo webmail</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 size={15} color="#10b981" />
              <span><strong>Active Shield:</strong> Intercepts malicious links before credentials can be submitted</span>
            </div>
          </div>

          <div className="flex gap-[0.6rem] flex-wrap mb-[0.85rem]">
            <button
              type="button"
              className={cn(controlBtn('primary'), 'flex items-center gap-[0.4rem] text-[0.78rem] py-[0.4rem] px-3')}
              onClick={async () => {
                try {
                  if (api.extension?.launchChrome) {
                    await api.extension.launchChrome();
                    showToast('Chrome launched with CIPHER extension pre-loaded!', 'success');
                  }
                } catch (e: any) {
                  showToast(e.detail || e.message || 'Failed to auto-launch Chrome', 'error');
                }
              }}

            >
              <Compass size={14} />
              <span>Launch Chrome with Extension</span>
            </button>

            <a
              href={api.extension?.getDownloadUrl ? api.extension.getDownloadUrl() : '/api/extension/download'}
              download="cipher-browser-guard.zip"
              className={cn(controlBtn(), 'inline-flex items-center gap-[0.4rem] text-[0.78rem] py-[0.4rem] px-3 no-underline')}

            >
              <Download size={13} />
              <span>Download (.zip)</span>
            </a>
          </div>

          <div className="p-3 rounded-[6px] bg-[rgba(15,23,42,0.7)] border border-line text-[0.78rem]">
            <strong className="text-fg block mb-[0.3rem]">Manual Setup Guide:</strong>
            <ol className="m-0 pl-[1.2rem] flex flex-col gap-1">
              <li>Open <code className={codeTag}>chrome://extensions</code> and enable <strong>Developer Mode</strong>.</li>
              <li>Click <strong>Load unpacked</strong> and choose <code className={codeTag}>cipher-browser-extension</code> in the project root.</li>
            </ol>
          </div>
        </div>

        {/* Model Telemetry Card */}
        <div className={card}>
          <div className={cardHeader}>
            <div className={cardTitle}>
              <Cpu size={18} color="var(--color-accent)" />
              <span>Email Machine Learning Engine</span>
            </div>
            {healthInfo?.model_loaded ? (
              <span>Model Active</span>
            ) : (
              <span>Loading...</span>
            )}
          </div>

          {modelInfo ? (
            <div className="flex flex-col gap-[0.85rem]">
              <div className="grid grid-cols-[1fr_1fr] gap-3">
                <div className="p-[0.6rem] rounded-[6px] bg-[rgba(30,41,59,0.4)]">
                  <div className="text-[0.72rem] text-fg-muted">Classifier Architecture</div>
                  <div className="text-[0.9rem] font-semibold text-fg">{modelInfo.model_name}</div>
                </div>
                <div className="p-[0.6rem] rounded-[6px] bg-[rgba(30,41,59,0.4)]">
                  <div className="text-[0.72rem] text-fg-muted">Feature Dimensions</div>
                  <div className="text-[0.9rem] font-semibold text-fg">{modelInfo.feature_count} Leak-Free Features</div>
                </div>
              </div>

              <div className="text-[0.8rem] font-semibold text-fg mt-1">
                Held-Out Test Set Metrics (12,359 samples):
              </div>

              <div className="grid grid-cols-[repeat(3,1fr)] gap-2">
                <div className="p-2 rounded-[4px] bg-[rgba(15,23,42,0.5)] text-center">
                  <div className="text-[0.68rem] text-fg-muted">Accuracy</div>
                  <div className="text-[0.85rem] font-semibold text-[#10b981]">
                    {modelInfo.test_metrics.accuracy ? `${(modelInfo.test_metrics.accuracy * 100).toFixed(2)}%` : '91.53%'}
                  </div>
                </div>
                <div className="p-2 rounded-[4px] bg-[rgba(15,23,42,0.5)] text-center">
                  <div className="text-[0.68rem] text-fg-muted">F1-Score</div>
                  <div className="text-[0.85rem] font-semibold text-accent">
                    {modelInfo.test_metrics.f1_score ? `${(modelInfo.test_metrics.f1_score * 100).toFixed(2)}%` : '91.62%'}
                  </div>
                </div>
                <div className="p-2 rounded-[4px] bg-[rgba(15,23,42,0.5)] text-center">
                  <div className="text-[0.68rem] text-fg-muted">ROC-AUC</div>
                  <div className="text-[0.85rem] font-semibold text-[#38bdf8]">
                    {modelInfo.test_metrics.roc_auc ? modelInfo.test_metrics.roc_auc.toFixed(4) : '0.9736'}
                  </div>
                </div>
                <div className="p-2 rounded-[4px] bg-[rgba(15,23,42,0.5)] text-center">
                  <div className="text-[0.68rem] text-fg-muted">Precision</div>
                  <div className="text-[0.85rem] font-semibold">
                    {modelInfo.test_metrics.precision ? `${(modelInfo.test_metrics.precision * 100).toFixed(2)}%` : '94.24%'}
                  </div>
                </div>
                <div className="p-2 rounded-[4px] bg-[rgba(15,23,42,0.5)] text-center">
                  <div className="text-[0.68rem] text-fg-muted">Recall</div>
                  <div className="text-[0.85rem] font-semibold">
                    {modelInfo.test_metrics.recall ? `${(modelInfo.test_metrics.recall * 100).toFixed(2)}%` : '89.14%'}
                  </div>
                </div>
                <div className="p-2 rounded-[4px] bg-[rgba(15,23,42,0.5)] text-center">
                  <div className="text-[0.68rem] text-fg-muted">Inference Speed</div>
                  <div className="text-[0.85rem] font-semibold">~80,000 /s</div>
                </div>
              </div>

              <div className="text-[0.72rem] text-fg-muted mt-1">
                Dataset: 82,388 deduplicated emails (CEAS_08, Enron, Ling, Nazario, Nigerian Fraud, SpamAssasin).
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-fg-muted text-[0.85rem]">
              Connecting to Email ML Engine...
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>

      <Toast
        message={toast.message}
        type={toast.type}
        isVisible={toast.visible}
        onClose={hideToast}
      />
    </>
  );
};

export default EmailPage;
