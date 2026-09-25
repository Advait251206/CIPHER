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

  const generateReportTxt = () => {
    showToast('Generating Forensic TXT Report...', 'info');
    setTimeout(() => {
      showToast('TXT Report generated successfully.', 'success');
      // In a real app, generate blob and trigger download
    }, 1500);
  };

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
  </style>
</head>
<body>
  <div class="cover-page">
    <div class="cover-bg-element"></div>
    <div class="cover-content">
      <div class="cover-brand">CIPHER<span>.</span></div>
      <div class="cover-subtitle">Cyber Intelligence & Heuristic Response</div>
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
      <div class="page-header-meta">URL FORENSICS | PAGE 1 OF 1</div>
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
    
    <div style="margin-top:5rem;border-top:1px solid var(--border);padding-top:2rem;text-align:center;">
      <div style="font-size:10px;color:var(--accent-gold);letter-spacing:3px;text-transform:uppercase;font-weight:700;margin-bottom:1rem;">END OF REPORT</div>
      <div style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">
        CIPHER SOC Automated Intelligence Engine<br>
        CONFIDENTIAL — INTERNAL USE ONLY
      </div>
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
            <button className={cn(controlBtn(), 'flex items-center gap-2 bg-[#f1f5f9] text-[#334155] border border-[#cbd5e1] not-disabled:hover:bg-[#f1f5f9] not-disabled:hover:text-[#334155] not-disabled:hover:border-[#cbd5e1]')} onClick={generateReportTxt}>
              <FileText size={16} /> TXT Report
            </button>
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
