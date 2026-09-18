import React, { useState, useEffect } from 'react';
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
} from 'lucide-react';
import { motion, type Variants } from 'framer-motion';

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

  // Subsystem Telemetry
  const [modelInfo, setModelInfo] = useState<EmailModelInfoResponse | null>(null);
  const [healthInfo, setHealthInfo] = useState<EmailHealthResponse | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState(true);

  // Samples
  const samples = [
    {
      label: 'Legitimate: IT Meeting Invite',
      sender: 'alex.chen@company.org',
      recipient: 'dev-team@company.org',
      subject: 'Quarterly Architecture Sync — Thursday 2 PM',
      body: 'Hi team, please find the agenda for our architecture review on Thursday. We will review the database migration plan and pipeline latency metrics. Let me know if you have items to add.',
    },
    {
      label: 'Phishing: Security Alert / Account Suspension',
      sender: 'Security Support <no-reply@security-auth-check.xyz>',
      recipient: 'user@company.org',
      subject: 'URGENT: Your Account Has Been Locked Due to Suspicious Login',
      body: 'Dear Customer,\n\nWe detected unauthorized access to your account from an unknown IP address. Your credentials must be verified immediately or your access will be suspended within 24 hours.\n\nPlease log in immediately at http://192.168.1.100/secure-update/login.php to confirm your identity and reset your password.',
    },
    {
      label: 'Phishing: Fake PayPal Invoice / Billing Scam',
      sender: 'service@billing-notice-paypal.info',
      recipient: 'accounting@company.org',
      subject: 'Invoice #849202 Payment Processed — Action Required',
      body: 'You sent a payment of $899.00 USD to Crypto Exchange Ltd. If you did not make this transaction, dispute the charges immediately at http://verify-paypal-dispute-resolution.net/auth before funds are irreversibly settled.',
    },
    {
      label: 'Spam / Fraud: Nigerian Advance Fee Lure',
      sender: 'barrister.kofi@lawfirm-westafrica.org',
      recipient: 'recipient@domain.com',
      subject: 'CONFIDENTIAL: Transfer of Unclaimed Inheritance Funds ($14.5M USD)',
      body: 'DEAR FRIEND, I AM BARRISTER KOFI, PERSONAL ATTORNEY TO A DECEASED CONTRACTOR. HE LEFT FOURTEEN MILLION FIVE HUNDRED THOUSAND UNITED STATES DOLLARS IN A SECURITY VAULT. REPLY WITH YOUR FULL BANK ACCOUNT DETAILS TO RECEIVE 40% SHARE AS NEXT OF KIN.',
    },
  ];

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

  const handleSelectSample = (sample: (typeof samples)[0]) => {
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
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Privacy and Local Processing Architecture Banner */}
      <motion.div variants={itemVariants} className="alert-box info">
        <Info size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Local Privacy Architecture:</strong> Email analysis executes strictly in-memory on your local CIPHER node.
          <strong> Raw email bodies are NEVER stored or persisted</strong> in the SQLite database or external telemetry.
          Extracted features are classified using a 32-feature Random Forest model trained on 82,388 deduplicated emails, corroborated with CIPHER's URL phishing engine and local IOC threat cache.
        </div>
      </motion.div>

      {/* Mode Selector and Quick Samples */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className={`btn ${activeMode === 'structured' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveMode('structured')}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <FileText size={15} />
              <span>Structured Email</span>
            </button>
            <button
              type="button"
              className={`btn ${activeMode === 'raw' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveMode('raw')}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <Terminal size={15} />
              <span>Raw Text / RFC 822</span>
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Load Sample:</span>
            {samples.map((s, idx) => (
              <button
                key={idx}
                type="button"
                className="btn btn-secondary"
                style={{ fontSize: '0.72rem', padding: '0.3rem 0.6rem' }}
                onClick={() => handleSelectSample(s)}
              >
                {s.label.split(':')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleAnalyze}>
          {activeMode === 'structured' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
                    Sender (From header)
                  </label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g. IT Helpdesk <support@acme.com>"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
                    Recipient (To header)
                  </label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g. employee@acme.com"
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
                  Subject Line
                </label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. URGENT: Verify your billing information"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
                  Email Body (Plain Text or HTML)
                  <span style={{ float: 'right', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {body.length.toLocaleString()} / 500,000 chars
                  </span>
                </label>
                <textarea
                  className="input"
                  rows={6}
                  placeholder="Paste email message text or HTML content here..."
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.85rem', resize: 'vertical' }}
                />
              </div>
            </div>
          ) : (
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
                Raw Email Stream / RFC 822 Text
                <span style={{ float: 'right', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  {rawText.length.toLocaleString()} / 500,000 chars
                </span>
              </label>
              <textarea
                className="input"
                rows={9}
                placeholder="From: security@paypal-verify.com&#10;Subject: Action Required&#10;&#10;Please confirm your account immediately at http://192.168.1.1/login..."
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.85rem', resize: 'vertical' }}
              />
            </div>
          )}

          {error && (
            <div className="alert-box danger" style={{ marginTop: '1rem' }}>
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button
              type="button"
              className="btn btn-secondary"
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
              className="btn btn-primary"
              disabled={isAnalyzing}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: '140px', justifyContent: 'center' }}
            >
              {isAnalyzing ? (
                <>
                  <div className="spinner-border spinner-border-sm" />
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
        <motion.div variants={itemVariants} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginBottom: '1.5rem' }}>
          {/* Main Verdict Card */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <ShieldCheck size={18} color="var(--accent-cyan)" />
                <span>Detection Verdict & Risk Assessment</span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <SeverityBadge severity={result.severity} />
                <span
                  style={{
                    padding: '0.2rem 0.6rem',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    backgroundColor:
                      result.classification === 'MALICIOUS_EMAIL'
                        ? 'rgba(239, 68, 68, 0.15)'
                        : result.classification === 'SUSPICIOUS'
                        ? 'rgba(245, 158, 11, 0.15)'
                        : 'rgba(16, 185, 129, 0.15)',
                    color:
                      result.classification === 'MALICIOUS_EMAIL'
                        ? '#ef4444'
                        : result.classification === 'SUSPICIOUS'
                        ? '#f59e0b'
                        : '#10b981',
                  }}
                >
                  {result.classification}
                </span>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: '1.5rem', alignItems: 'center' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '1rem', borderRight: '1px solid var(--border-color)' }}>
                <RiskGauge score={result.risk_score} size="lg" />
                <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Confidence: <strong>{(result.confidence * 100).toFixed(1)}%</strong>
                </div>
                {result.event_id && (
                  <div style={{ marginTop: '0.25rem', fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    Event: {result.event_id.slice(0, 8)}...
                  </div>
                )}
              </div>

              <div>
                <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.95rem' }}>SOC Operational Recommendation</h4>
                <div
                  style={{
                    padding: '0.75rem 1rem',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(15, 23, 42, 0.6)',
                    borderLeft: `4px solid ${
                      result.severity === 'CRITICAL' || result.severity === 'HIGH'
                        ? '#ef4444'
                        : result.severity === 'MEDIUM'
                        ? '#f59e0b'
                        : '#10b981'
                    }`,
                    fontSize: '0.86rem',
                    lineHeight: '1.4',
                    marginBottom: '1rem',
                  }}
                >
                  {result.recommendation}
                </div>

                <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.95rem' }}>Explainable Detection Rationale</h4>
                <ul style={{ margin: 0, paddingLeft: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.83rem', color: 'var(--text-secondary)' }}>
                  {result.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Extracted URLs Breakdown */}
          {result.urls_analyzed && result.urls_analyzed.length > 0 && (
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <ExternalLink size={18} color="var(--accent-cyan)" />
                  <span>Embedded Hyperlinks Inspected ({result.urls_analyzed.length})</span>
                </div>
              </div>
              <div className="table-responsive">
                <table className="table">
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
                        <td style={{ maxWidth: '280px', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.78rem' }}>
                          {u.url}
                        </td>
                        <td>
                          <span
                            style={{
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              fontSize: '0.72rem',
                              fontWeight: 600,
                              backgroundColor:
                                u.classification === 'PHISHING'
                                  ? 'rgba(239, 68, 68, 0.15)'
                                  : u.classification === 'SUSPICIOUS'
                                  ? 'rgba(245, 158, 11, 0.15)'
                                  : 'rgba(16, 185, 129, 0.15)',
                              color:
                                u.classification === 'PHISHING'
                                  ? '#ef4444'
                                  : u.classification === 'SUSPICIOUS'
                                  ? '#f59e0b'
                                  : '#10b981',
                            }}
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
                        <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
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
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <Cpu size={18} color="var(--accent-cyan)" />
                  <span>Extracted 32-Feature Vector</span>
                </div>
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                  gap: '0.5rem',
                  maxHeight: '260px',
                  overflowY: 'auto',
                  padding: '0.5rem',
                  backgroundColor: 'rgba(11, 15, 25, 0.5)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-color)',
                }}
              >
                {Object.entries(result.features).map(([feat, val]) => (
                  <div
                    key={feat}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      padding: '0.3rem 0.5rem',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(30, 41, 59, 0.4)',
                      fontSize: '0.75rem',
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={feat}>
                      {feat}
                    </span>
                    <strong style={{ color: typeof val === 'number' && val > 0 ? 'var(--accent-cyan)' : 'var(--text-secondary)' }}>
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
        style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginTop: '1.5rem' }}
      >
        {/* Browser Extension Card */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Compass size={18} color="var(--accent-cyan)" />
              <span>CIPHER Browser Guard (Chromium Extension)</span>
            </div>
            <span className="badge badge-primary">Manifest V3</span>
          </div>

          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: '0 0 1rem 0' }}>
            Protect against webmail phishing on Gmail, Outlook, and Yahoo Mail directly within your browser.
            Features automatic badge risk alerts and an active interstitial block screen for high-confidence phishing sites.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={15} color="#10b981" />
              <span><strong>Strict Privacy:</strong> Zero cloud analytics; communicates exclusively with <code>http://127.0.0.1:8000</code></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={15} color="#10b981" />
              <span><strong>Webmail Integration:</strong> Floating scan badge on Gmail, Outlook, and Yahoo webmail</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={15} color="#10b981" />
              <span><strong>Active Shield:</strong> Intercepts malicious links before credentials can be submitted</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', marginBottom: '0.85rem' }}>
            <button
              type="button"
              className="control-btn primary"
              onClick={async () => {
                try {
                  if (api.extension?.launchChrome) {
                    await api.extension.launchChrome();
                    alert('Chrome launched with CIPHER extension pre-loaded!');
                  }
                } catch (e: any) {
                  alert(e.detail || e.message || 'Failed to auto-launch Chrome');
                }
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.78rem',
                padding: '0.4rem 0.75rem',
              }}
            >
              <Compass size={14} />
              <span>Launch Chrome with Extension</span>
            </button>

            <a
              href={api.extension?.getDownloadUrl ? api.extension.getDownloadUrl() : '/api/extension/download'}
              download="cipher-browser-guard.zip"
              className="control-btn"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.78rem',
                padding: '0.4rem 0.75rem',
                textDecoration: 'none',
              }}
            >
              <Download size={13} />
              <span>Download (.zip)</span>
            </a>
          </div>

          <div style={{ padding: '0.75rem', borderRadius: '6px', backgroundColor: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-color)', fontSize: '0.78rem' }}>
            <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '0.3rem' }}>Manual Setup Guide:</strong>
            <ol style={{ margin: 0, paddingLeft: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <li>Open <code>chrome://extensions</code> and enable <strong>Developer Mode</strong>.</li>
              <li>Click <strong>Load unpacked</strong> and choose <code>cipher-browser-extension</code> in the project root.</li>
            </ol>
          </div>
        </div>

        {/* Model Telemetry Card */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={18} color="var(--accent-cyan)" />
              <span>Email Machine Learning Engine</span>
            </div>
            {healthInfo?.model_loaded ? (
              <span className="badge badge-success">Model Active</span>
            ) : (
              <span className="badge badge-warning">Loading...</span>
            )}
          </div>

          {modelInfo ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div style={{ padding: '0.6rem', borderRadius: '6px', backgroundColor: 'rgba(30, 41, 59, 0.4)' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Classifier Architecture</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>{modelInfo.model_name}</div>
                </div>
                <div style={{ padding: '0.6rem', borderRadius: '6px', backgroundColor: 'rgba(30, 41, 59, 0.4)' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Feature Dimensions</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>{modelInfo.feature_count} Leak-Free Features</div>
                </div>
              </div>

              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                Held-Out Test Set Metrics (12,359 samples):
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem' }}>
                <div style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'rgba(15, 23, 42, 0.5)', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Accuracy</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#10b981' }}>
                    {modelInfo.test_metrics.accuracy ? `${(modelInfo.test_metrics.accuracy * 100).toFixed(2)}%` : '91.53%'}
                  </div>
                </div>
                <div style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'rgba(15, 23, 42, 0.5)', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>F1-Score</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    {modelInfo.test_metrics.f1_score ? `${(modelInfo.test_metrics.f1_score * 100).toFixed(2)}%` : '91.62%'}
                  </div>
                </div>
                <div style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'rgba(15, 23, 42, 0.5)', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>ROC-AUC</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8' }}>
                    {modelInfo.test_metrics.roc_auc ? modelInfo.test_metrics.roc_auc.toFixed(4) : '0.9736'}
                  </div>
                </div>
                <div style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'rgba(15, 23, 42, 0.5)', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Precision</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                    {modelInfo.test_metrics.precision ? `${(modelInfo.test_metrics.precision * 100).toFixed(2)}%` : '94.24%'}
                  </div>
                </div>
                <div style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'rgba(15, 23, 42, 0.5)', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Recall</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                    {modelInfo.test_metrics.recall ? `${(modelInfo.test_metrics.recall * 100).toFixed(2)}%` : '89.14%'}
                  </div>
                </div>
                <div style={{ padding: '0.5rem', borderRadius: '4px', backgroundColor: 'rgba(15, 23, 42, 0.5)', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Inference Speed</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>~80,000 /s</div>
                </div>
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Dataset: 82,388 deduplicated emails (CEAS_08, Enron, Ling, Nazario, Nigerian Fraud, SpamAssasin).
              </div>
            </div>
          ) : (
            <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              Connecting to Email ML Engine...
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
};

export default EmailPage;
