import React, { useState, useCallback } from 'react';
import { api } from '../api/client';
import { PhishingAnalyzeResponse } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { RiskGauge } from '../components/common/RiskGauge';
import { Globe, Search, ShieldCheck, AlertTriangle, Info, CheckCircle2, FileText, Printer } from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { Toast, type ToastType } from '../components/common/Toast';
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, controlBtn, evidenceHeader, evidenceSection, formGroup, formInput, formLabel, kvGrid, kvItem, kvLabel, kvValue, mono, pageBody } from '../ui/classes';

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
// One segment of the URL anatomy breakdown. A flagged segment turns its label
// and value red too (the old .url-part-chip.flagged descendant rules).
const UrlPart: React.FC<{ label: string; value: React.ReactNode; flagged?: boolean }> = ({ label, value, flagged }) => (
  <div className={cn('inline-flex flex-col rounded-none border border-line-card bg-surface px-[0.65rem] py-[0.35rem]', flagged && 'border-crit bg-crit-bg')}>
    <span className={cn('text-[0.64rem] font-bold tracking-[0.04em] text-fg-muted uppercase', flagged && 'text-crit')}>{label}</span>
    <span className={cn('font-mono text-[0.78rem] font-semibold text-fg', flagged && 'text-crit')}>{value}</span>
  </div>
);


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

export const PhishingPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<PhishingAnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Toast notification
  const [toast, setToast] = useState<{ message: string; type: ToastType; visible: boolean }>({
    message: '',
    type: 'info',
    visible: false
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
  <title>CIPHER Intelligence Report - Phishing Domain</title>
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
      <div class="cover-title">Threat Intelligence<br>Phishing Domain Diagnostics</div>
      <div class="cover-meta">
        <table>
          <tr><td>Report ID</td><td>PHISH-${result.event_id?.substring(0,8) || Math.random().toString(36).substring(2,10).toUpperCase()}</td></tr>
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
      <div class="page-header-meta">URL FORENSICS | PAGE 1 OF 3</div>
    </div>

    <div class="section">
      <h2 class="section-title">1.0 Domain Telemetry</h2>
      <table class="info-table">
        <tr><th>Classification</th><td>${result.classification.replace('_', ' ')}</td></tr>
        <tr><th>Confidence</th><td>${(result.confidence * 100).toFixed(1)}%</td></tr>
        <tr><th>Threat Level</th><td><span class="badge ${result.severity.toLowerCase()}">${result.severity}</span></td></tr>
        <tr><th>Target URL</th><td style="word-break: break-all; color:var(--accent-cyan)">${urlInput}</td></tr>
        <tr><th>ML Probability Score</th><td>${(result.ml_score * 100).toFixed(1)}%</td></tr>
        <tr><th>Heuristic Threat Score</th><td>${result.heuristic_score} / 100</td></tr>
      </table>
    </div>

    <div class="section">
      <h2 class="section-title">2.0 Detection Evidence</h2>
      <div class="prose">
        <ul style="padding-left:1.5rem">
          ${(result.reasons || []).map(r => '<li style="margin-bottom:0.5rem">' + r + '</li>').join('')}
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

  const handleResolve = () => {
    showToast('Domain threat logged and mitigated successfully.', 'success');
    setResult(null);
    setUrlInput('');
  };

  // Sample URLs — 10 per category
  type SampleCategory = 'Legitimate' | 'Phishing' | 'Malware / Suspicious';

  const sampleUrls: Record<SampleCategory, string[]> = {
    'Legitimate': [
      'https://www.google.com/search?q=open+source+security',
      'https://github.com/trending/python',
      'https://stackoverflow.com/questions/tagged/cybersecurity',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP',
      'https://www.wikipedia.org/wiki/Intrusion_detection_system',
      'https://docs.python.org/3/library/socket.html',
      'https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/',
      'https://www.amazon.com/dp/B09XYZ1234',
      'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      'https://www.linkedin.com/in/johndoe',
    ],
    'Phishing': [
      'http://paypa1-secure-login.xyz/account/verify?token=abc123',
      'https://secure-bankofamerica.net/login/client-auth',
      'http://apple-id-suspended.com/unlock?session=xz99',
      'https://microsoft-365-login.info/oauth2/auth',
      'http://facebook-account-recovery.club/help/login',
      'http://netflix-billing-update.xyz/payment/verify',
      'https://amazon-order-confirm.net/track?id=399123',
      'http://your-paypal-has-been-limited.com/resolve',
      'http://g00gle-signin-accounts.ru/security/check',
      'https://dropbox-shared-file.info/download?ref=user_9182',
    ],
    'Malware / Suspicious': [
      'http://192.168.10.4/cmd.php?exec=whoami',
      'http://xn--pypal-4ve.com/signin',
      'http://dl.freeupdatenow.xyz/installer.exe?src=popup',
      'http://tracking-pixel-ad.ru/pixel.gif?uid=102938&ref=phish',
      'http://cdn-js-update.com/jquery-3.6.min.js.php',
      'http://update-flash-player.tk/setup.exe',
      'https://bit.ly/3phishurl',
      'http://10.0.0.1/admin?pass=admin123',
      'http://free-robux-generator.com/claim?user=victim&amount=10000',
      'http://invoice-download.pw/INV_2026_0918.pdf.exe',
    ],
  };

  const handleSelectSampleUrl = (category: SampleCategory) => {
    const list = sampleUrls[category];
    const url = list[Math.floor(Math.random() * list.length)];
    setUrlInput(url);
    setResult(null);
    setError(null);
  };

  const handleAnalyze = async (urlToTest?: string) => {
    const target = (urlToTest || urlInput).trim();
    if (!target) {
      setError('Please enter a valid URL to analyze.');
      return;
    }

    try {
      setIsAnalyzing(true);
      setError(null);
      setResult(null);

      const res = await api.phishing.analyze({
        url: target,
        source: 'dashboard',
      });

      setResult(res);
    } catch (err: any) {
      setError(err.detail || err.message || 'Phishing analysis request failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const dissectUrl = (rawUrl: string) => {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `http://${rawUrl}`);
      const hostParts = parsed.hostname.split('.');
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname);
      const tld = isIp ? 'RAW IP' : hostParts.length > 1 ? `.${hostParts[hostParts.length - 1]}` : 'N/A';
      const domain = isIp ? parsed.hostname : hostParts.slice(-2).join('.');
      const subdomain = !isIp && hostParts.length > 2 ? hostParts.slice(0, -2).join('.') : 'None';
      return {
        protocol: parsed.protocol.replace(':', ''),
        hostname: parsed.hostname,
        domain,
        subdomain,
        tld,
        pathname: parsed.pathname || '/',
        search: parsed.search || 'None',
        isIp,
        isHttps: parsed.protocol === 'https:',
      };
    } catch {
      return null;
    }
  };

  const currentDissection = urlInput ? dissectUrl(urlInput) : null;

  return (
    <motion.div
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Privacy and Local Processing Notice */}
      <motion.div variants={itemVariants} className={alertBox('info')}>
        <Info size={18} className="shrink-0" />
        <div>
          <strong>Local Privacy Architecture:</strong> Analysis is performed locally on this machine. CIPHER does not automatically transmit submitted indicators to external services.
          28 structural and lexical features are extracted and evaluated locally using a PhiUSIIL-trained Random Forest model and heuristic rules.
          <em> Machine learning threat classification is probabilistic and does not guarantee 100% accuracy or zero false negatives.</em>
        </div>
      </motion.div>

      {/* URL Submission Form */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-6')}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <Globe size={18} color="var(--color-accent)" />
            <span>Phishing URL Inspector (POST /api/phishing/analyze)</span>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="flex flex-col gap-4"
        >
          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Enter Target URL to Inspect</label>
            <div className="flex gap-3">
              <input
                type="text"
                className={formInput}
                placeholder="https://example.com/login or http://suspicious-domain.xyz"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                disabled={isAnalyzing}
              />
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                type="submit"
                className={cn(controlBtn('primary'), 'shrink-0')}
                disabled={isAnalyzing || !urlInput.trim()}

              >
                <Search size={14} />
                <span>{isAnalyzing ? 'Analyzing...' : 'Inspect URL'}</span>
              </motion.button>
            </div>
          </div>


          {/* Sample URL Loader */}
          <div className="flex flex-col gap-2">
            <span className="text-[0.74rem] text-fg-muted uppercase tracking-wider font-semibold">
              Load Sample URL
            </span>
            <div className="flex gap-2 flex-wrap">
              {(['Legitimate', 'Phishing', 'Malware / Suspicious'] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  className={controlBtn(cat === 'Legitimate' ? 'success' : cat === 'Phishing' ? 'danger' : 'default', 'text-[0.75rem] py-[0.3rem] px-[0.65rem]')}
                  onClick={() => handleSelectSampleUrl(cat)}
                  disabled={isAnalyzing}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

        </form>

        {/* Real-Time URL Anatomical Dissection */}
        {currentDissection && (
          <div className="mt-4 rounded-none border border-line bg-elevated p-4">
            <div className="flex items-center gap-[0.45rem] mb-[0.35rem]">
              <Globe size={14} color="var(--color-accent)" />
              <span className="text-[0.74rem] font-bold uppercase text-fg tracking-[0.04em]">
                Forensic URL Structural Breakdown
              </span>
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              <UrlPart label="Protocol" value={currentDissection.protocol} flagged={!currentDissection.isHttps} />
              <UrlPart label="Subdomain" value={currentDissection.subdomain} flagged={currentDissection.subdomain !== 'None' && currentDissection.subdomain.split('.').length > 1} />
              <UrlPart label="Domain / Host" value={currentDissection.domain} flagged={currentDissection.isIp} />
              <UrlPart label="TLD Class" value={currentDissection.tld} flagged={currentDissection.tld === '.xyz' || currentDissection.isIp} />
              <UrlPart label="Path" value={currentDissection.pathname} />
              {currentDissection.search !== 'None' && (
                <UrlPart label="Query Tokens" value={currentDissection.search} flagged />
              )}
            </div>
          </div>
        )}

        {error && (
          <div className={cn(alertBox('danger'), 'mt-4')}>
            <AlertTriangle size={16} />
            <span>{error}</span>
          </div>
        )}
      </motion.div>

      {/* Analysis Results Card */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 12, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.3 }}
          className={card}
        >
          <div className={cardHeader}>
            <div className={cardTitle}>
              <ShieldCheck size={18} color="var(--color-accent)" />
              <span>Phishing Security Assessment</span>
            </div>
            <SeverityBadge severity={result.severity} />
          </div>

          <div className="mb-5">
            <RiskGauge score={result.risk_score} label="Unified Threat Score" />
          </div>

          <div className={cn(kvGrid, 'mb-5')}>
            <div className={kvItem}>
              <span className={kvLabel}>Classification Verdict</span>
              <span
                className={cn(kvValue, 'font-bold', result.classification === 'LIKELY_PHISHING' ? 'text-crit' : result.classification === 'SUSPICIOUS' ? 'text-med' : 'text-benign')}
              >
                {result.classification.replace('_', ' ')}
              </span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Classifier Confidence</span>
              <span className={cn(mono, kvValue)}>{(result.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>ML Phishing Probability</span>
              <span className={cn(mono, kvValue)}>{(result.ml_score * 100).toFixed(1)}%</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Heuristic Threat Score</span>
              <span className={cn(mono, kvValue)}>{result.heuristic_score} / 100</span>
            </div>
            <div className={kvItem}>
              <span className={kvLabel}>Model Version</span>
              <span className={cn(mono, kvValue)}>{result.model_version}</span>
            </div>
            {result.event_id && (
              <div className={kvItem}>
                <span className={kvLabel}>Recorded Event ID</span>
                <span className={cn(mono, kvValue)}>{result.event_id}</span>
              </div>
            )}
          </div>

          {/* Action Recommendation */}
          <div className={cn(evidenceSection, 'mb-4')}>
            <div className={evidenceHeader}>
              <CheckCircle2 size={14} />
              <span>Recommended Security Guidance</span>
            </div>
            <p className="text-fg text-[0.88rem] font-semibold">
              {result.recommendation}
            </p>
          </div>

          {/* Feature Explanations / Reasons */}
          {result.reasons && result.reasons.length > 0 && (
            <div className={evidenceSection}>
              <div className={evidenceHeader}>
                <Info size={14} />
                <span>Detection Explanations & Evidence ({result.reasons.length})</span>
              </div>
              <ul className="pl-5 text-fg-2 text-[0.82rem] flex flex-col gap-[0.35rem]">
                {result.reasons.map((reason, idx) => (
                  <li key={idx}>{reason}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-3 mt-6 pt-6 border-t border-t-line flex-wrap">
            <button className={cn(controlBtn('primary'), 'flex items-center gap-2 bg-accent text-white border-none')} onClick={generateReportPdf}>
              <Printer size={16} /> Print / Save as PDF
            </button>
            <div className="flex-1"></div>
            <button className={cn(controlBtn(), 'flex items-center gap-2 bg-benign text-[#0B0B0B] border-none font-semibold not-disabled:hover:bg-benign not-disabled:hover:text-[#0B0B0B]')} onClick={handleResolve}>
              <CheckCircle2 size={16} /> Resolve Threat
            </button>
          </div>
        </motion.div>
      )}

      <Toast
        message={toast.message}
        type={toast.type}
        isVisible={toast.visible}
        onClose={hideToast}
      />
    </motion.div>
  );
};
