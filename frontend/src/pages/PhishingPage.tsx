import React, { useState } from 'react';
import { api } from '../api/client';
import { PhishingAnalyzeResponse } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { RiskGauge } from '../components/common/RiskGauge';
import { Globe, Search, ShieldCheck, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';
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

export const PhishingPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<PhishingAnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);


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
        </motion.div>
      )}
    </motion.div>
  );
};
