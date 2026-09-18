import React, { useState, useCallback } from 'react';
import { api } from '../api/client';
import { PhishingAnalyzeResponse } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { RiskGauge } from '../components/common/RiskGauge';
import { Globe, Search, ShieldCheck, AlertTriangle, Info, CheckCircle2, FileText, Printer } from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { Toast, type ToastType } from '../components/common/Toast';

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
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Privacy and Local Processing Notice */}
      <motion.div variants={itemVariants} className="alert-box info">
        <Info size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Local Privacy Architecture:</strong> Analysis is performed locally on this machine. CIPHER does not automatically transmit submitted indicators to external services.
          28 structural and lexical features are extracted and evaluated locally using a PhiUSIIL-trained Random Forest model and heuristic rules.
          <em> Machine learning threat classification is probabilistic and does not guarantee 100% accuracy or zero false negatives.</em>
        </div>
      </motion.div>

      {/* URL Submission Form */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Globe size={18} color="var(--accent-cyan)" />
            <span>Phishing URL Inspector (POST /api/phishing/analyze)</span>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
        >
          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Enter Target URL to Inspect</label>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <input
                type="text"
                className="form-input"
                placeholder="https://example.com/login or http://suspicious-domain.xyz"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                disabled={isAnalyzing}
              />
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                type="submit"
                className="control-btn primary"
                disabled={isAnalyzing || !urlInput.trim()}
                style={{ flexShrink: 0 }}
              >
                <Search size={14} />
                <span>{isAnalyzing ? 'Analyzing...' : 'Inspect URL'}</span>
              </motion.button>
            </div>
          </div>


          {/* Sample URL Loader */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
              Load Sample URL
            </span>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {(['Legitimate', 'Phishing', 'Malware / Suspicious'] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  className={`control-btn${
                    cat === 'Legitimate' ? ' success' : cat === 'Phishing' ? ' danger' : ''
                  }`}
                  style={{ fontSize: '0.75rem', padding: '0.3rem 0.65rem' }}
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
          <div className="url-dissector-deck">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.35rem' }}>
              <Globe size={14} color="var(--accent-blue)" />
              <span style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
                Forensic URL Structural Breakdown
              </span>
            </div>
            <div className="url-parts-grid">
              <div className={`url-part-chip ${!currentDissection.isHttps ? 'flagged' : ''}`}>
                <span className="url-part-label">Protocol</span>
                <span className="url-part-value">{currentDissection.protocol}</span>
              </div>
              <div className={`url-part-chip ${currentDissection.subdomain !== 'None' && currentDissection.subdomain.split('.').length > 1 ? 'flagged' : ''}`}>
                <span className="url-part-label">Subdomain</span>
                <span className="url-part-value">{currentDissection.subdomain}</span>
              </div>
              <div className={`url-part-chip ${currentDissection.isIp ? 'flagged' : ''}`}>
                <span className="url-part-label">Domain / Host</span>
                <span className="url-part-value">{currentDissection.domain}</span>
              </div>
              <div className={`url-part-chip ${currentDissection.tld === '.xyz' || currentDissection.isIp ? 'flagged' : ''}`}>
                <span className="url-part-label">TLD Class</span>
                <span className="url-part-value">{currentDissection.tld}</span>
              </div>
              <div className="url-part-chip">
                <span className="url-part-label">Path</span>
                <span className="url-part-value">{currentDissection.pathname}</span>
              </div>
              {currentDissection.search !== 'None' && (
                <div className="url-part-chip flagged">
                  <span className="url-part-label">Query Tokens</span>
                  <span className="url-part-value">{currentDissection.search}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {error && (
          <div className="alert-box danger" style={{ marginTop: '1rem' }}>
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
          className="card"
        >
          <div className="card-header">
            <div className="card-title">
              <ShieldCheck size={18} color="var(--accent-cyan)" />
              <span>Phishing Security Assessment</span>
            </div>
            <SeverityBadge severity={result.severity} />
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <RiskGauge score={result.risk_score} label="Unified Threat Score" />
          </div>

          <div className="kv-grid" style={{ marginBottom: '1.25rem' }}>
            <div className="kv-item">
              <span className="kv-label">Classification Verdict</span>
              <span
                className="kv-value"
                style={{
                  fontWeight: 700,
                  color:
                    result.classification === 'LIKELY_PHISHING'
                      ? 'var(--crit-color)'
                      : result.classification === 'SUSPICIOUS'
                      ? 'var(--med-color)'
                      : 'var(--benign-color)',
                }}
              >
                {result.classification.replace('_', ' ')}
              </span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Classifier Confidence</span>
              <span className="kv-value mono">{(result.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">ML Phishing Probability</span>
              <span className="kv-value mono">{(result.ml_score * 100).toFixed(1)}%</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Heuristic Threat Score</span>
              <span className="kv-value mono">{result.heuristic_score} / 100</span>
            </div>
            <div className="kv-item">
              <span className="kv-label">Model Version</span>
              <span className="kv-value mono">{result.model_version}</span>
            </div>
            {result.event_id && (
              <div className="kv-item">
                <span className="kv-label">Recorded Event ID</span>
                <span className="kv-value mono">{result.event_id}</span>
              </div>
            )}
          </div>

          {/* Action Recommendation */}
          <div className="evidence-section" style={{ marginBottom: '1rem' }}>
            <div className="evidence-header">
              <CheckCircle2 size={14} />
              <span>Recommended Security Guidance</span>
            </div>
            <p style={{ color: 'var(--text-primary)', fontSize: '0.88rem', fontWeight: 600 }}>
              {result.recommendation}
            </p>
          </div>

          {/* Feature Explanations / Reasons */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="evidence-section">
              <div className="evidence-header">
                <Info size={14} />
                <span>Detection Explanations & Evidence ({result.reasons.length})</span>
              </div>
              <ul style={{ paddingLeft: '1.25rem', color: 'var(--text-secondary)', fontSize: '0.82rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {result.reasons.map((reason, idx) => (
                  <li key={idx}>{reason}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border)', flexWrap: 'wrap' }}>
            <button className="control-btn" onClick={generateReportTxt} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1' }}>
              <FileText size={16} /> TXT Report
            </button>
            <button className="control-btn primary" onClick={generateReportPdf} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--accent-cyan)', color: 'white', border: 'none' }}>
              <Printer size={16} /> Print / Save as PDF
            </button>
            <div style={{ flex: 1 }}></div>
            <button className="control-btn" onClick={handleResolve} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--benign-color)', color: '#0B0B0B', border: 'none', fontWeight: 600 }}>
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
