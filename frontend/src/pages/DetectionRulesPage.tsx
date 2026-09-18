import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { RuleItem, RuleDetailResponse, RuleEvaluateResponse } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { Modal } from '../components/common/Modal';
import { Sliders, ToggleLeft, ToggleRight, Info, Eye, Play, CheckCircle, ShieldAlert } from 'lucide-react';
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
    transition: { duration: 0.32, ease: [0.25, 0.1, 0.25, 1] as const },
  },
};

export const DetectionRulesPage: React.FC = () => {
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [enabledCount, setEnabledCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [enabledOnly, setEnabledOnly] = useState<boolean>(false);

  // Detail Modal
  const [selectedRuleDetail, setSelectedRuleDetail] = useState<RuleDetailResponse | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Evaluation Sandbox
  const [isSandboxOpen, setIsSandboxOpen] = useState(false);
  const [evalPayloadText, setEvalPayloadText] = useState(
    JSON.stringify(
      {
        source_ip: '192.168.1.50',
        destination_ip: '10.0.0.5',
        destination_port: 22,
        protocol: 'TCP',
        flow_duration: 100,
        'SYN Flag Count': 1,
        'ACK Flag Count': 0,
        'Fwd Packets/s': 15000,
      },
      null,
      2
    )
  );
  const [evalResult, setEvalResult] = useState<RuleEvaluateResponse | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [sandboxError, setSandboxError] = useState<string | null>(null);

  // Toggle feedback
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const fetchRules = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.rules.list({
        category: categoryFilter || undefined,
        severity: severityFilter || undefined,
        enabled_only: enabledOnly ? true : undefined,
      });
      setRules(res.rules);
      setEnabledCount(res.enabled_count);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve detection rules.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, [categoryFilter, severityFilter, enabledOnly]);

  const handleToggleRule = async (rule: RuleItem) => {
    try {
      if (rule.enabled) {
        await api.rules.disable(rule.rule_id);
        setActionNotice(`Rule ${rule.rule_id} disabled.`);
      } else {
        await api.rules.enable(rule.rule_id);
        setActionNotice(`Rule ${rule.rule_id} enabled.`);
      }
      fetchRules();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule.');
    }
  };

  const handleInspectRule = async (ruleId: string) => {
    try {
      setLoadingDetail(true);
      const detail = await api.rules.get(ruleId);
      setSelectedRuleDetail(detail);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch rule details.');
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleRunEvaluation = async () => {
    try {
      setEvaluating(true);
      setSandboxError(null);
      const parsed = JSON.parse(evalPayloadText);
      const res = await api.rules.evaluate(parsed);
      setEvalResult(res);
    } catch (err: any) {
      setSandboxError(err.message || 'Rule evaluation failed.');
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <motion.div
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Authoritative Scoring Notice */}
      <div className="alert-box info">
        <Info size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Deterministic Detection Authority:</strong> Rule evaluations produce structured evidence and confidence weights.
          <em> The frontend does not calculate or override threat scores. Backend ThreatScorer remains the sole scoring authority.</em>
        </div>
      </div>

      {actionNotice && (
        <div className="alert-box success">
          <CheckCircle size={16} />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Header Tools */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sliders size={18} color="var(--accent-cyan)" />
              <span>Deterministic Rule Registry</span>
            </h2>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              10 Network Heuristics & 4 Signatures configured for zero-delay deterministic attack identification.
            </p>
          </div>

          <button className="control-btn primary" onClick={() => setIsSandboxOpen(true)}>
            <Play size={14} />
            <span>Rule Evaluation Sandbox</span>
          </button>
        </div>
      </motion.div>

      {/* Filter Bar */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.25rem' }}>
        {/* Quick Category Filter Pills */}
        <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', marginBottom: '0.85rem' }}>
          {[
            { label: 'All Rules', val: '' },
            { label: 'Port Scan', val: 'PORT_SCAN' },
            { label: 'DoS Flood', val: 'DOS' },
            { label: 'DDoS Aggregation', val: 'DDOS' },
            { label: 'Brute Force', val: 'BRUTE_FORCE' },
            { label: 'Botnet Beacon', val: 'BOTNET' },
            { label: 'Web Attack', val: 'WEB_ATTACK' },
          ].map((cat) => (
            <button
              key={cat.val}
              type="button"
              className={`control-btn ${categoryFilter === cat.val ? 'primary' : ''}`}
              style={{ fontSize: '0.74rem', padding: '0.25rem 0.65rem' }}
              onClick={() => setCategoryFilter(cat.val)}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-end', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
          <div className="form-group" style={{ width: '180px', margin: 0 }}>
            <label className="form-label">Attack Category</label>
            <select
              className="form-select"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              <option value="">All Categories</option>
              <option value="PORT_SCAN">Port Scan</option>
              <option value="DOS">DoS Flood</option>
              <option value="DDOS">DDoS Aggregation</option>
              <option value="BRUTE_FORCE">Brute Force</option>
              <option value="BOTNET">Botnet / Beaconing</option>
              <option value="WEB_ATTACK">Web Attack</option>
            </select>
          </div>

          <div className="form-group" style={{ width: '160px', margin: 0 }}>
            <label className="form-label">Severity</label>
            <select
              className="form-select"
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

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', paddingBottom: '0.5rem' }}>
            <input
              type="checkbox"
              id="enabledOnlyRules"
              checked={enabledOnly}
              onChange={(e) => setEnabledOnly(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <label htmlFor="enabledOnlyRules" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              Enabled Only ({enabledCount} active)
            </label>
          </div>
        </div>
      </motion.div>

      {/* Rules Table */}
      <motion.div variants={itemVariants} className="card">
        <div className="card-header">
          <div className="card-title">
            <span>Registered Rules ({rules.length})</span>
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            {enabledCount} of {rules.length} rules active
          </span>
        </div>

        {loading ? (
          <LoadingState message="Loading detection rules..." />
        ) : error ? (
          <ErrorState title="Failed to Load Rules" error={error} onRetry={fetchRules} />
        ) : rules.length === 0 ? (
          <EmptyState title="No rules found." description="No registered rules match the selected filter." />
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Scope</th>
                  <th>State</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                      {rule.rule_id}
                    </td>
                    <td style={{ fontWeight: 600 }}>{rule.name}</td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.72rem', background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', padding: '2px 6px', borderRadius: '4px' }}>
                        {rule.rule_type || (rule.rule_id?.startsWith('SIG') ? 'SIGNATURE' : 'HEURISTIC')}
                      </span>
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.75rem' }}>{rule.category}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} size="sm" />
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {(rule.confidence * 100).toFixed(0)}%
                    </td>
                    <td>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {rule.scope || (rule as any).target_event_type || 'flow'}
                      </span>
                    </td>
                    <td>
                      <button
                        className="control-btn"
                        style={{ padding: '2px 6px', fontSize: '0.7rem' }}
                        onClick={() => handleToggleRule(rule)}
                        title={rule.enabled ? 'Click to Disable' : 'Click to Enable'}
                      >
                        {rule.enabled ? (
                          <>
                            <ToggleRight size={14} color="var(--benign-color)" />
                            <span style={{ color: 'var(--benign-color)' }}>Enabled</span>
                          </>
                        ) : (
                          <>
                            <ToggleLeft size={14} color="var(--text-muted)" />
                            <span style={{ color: 'var(--text-muted)' }}>Disabled</span>
                          </>
                        )}
                      </button>
                    </td>
                    <td>
                      <button
                        className="control-btn"
                        style={{ padding: '2px 6px' }}
                        onClick={() => handleInspectRule(rule.rule_id)}
                        title="View Rule Thresholds & Description"
                      >
                        <Eye size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Rule Detail & Thresholds Modal */}
      {selectedRuleDetail && (
        <Modal
          isOpen={Boolean(selectedRuleDetail)}
          onClose={() => setSelectedRuleDetail(null)}
          title={`Rule Detail: ${selectedRuleDetail.rule.rule_id}`}
          footer={
            <button className="control-btn" onClick={() => setSelectedRuleDetail(null)}>
              Close
            </button>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="evidence-section">
              <div className="evidence-header">
                <Info size={14} />
                <span>Description & Detection Logic</span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                {selectedRuleDetail.rule.description}
              </p>
            </div>

            <div className="evidence-section">
              <div className="evidence-header">
                <Sliders size={14} />
                <span>Configured System Thresholds</span>
              </div>
              <div className="kv-grid">
                {Object.entries(selectedRuleDetail.thresholds).map(([k, v]) => (
                  <div key={k} className="kv-item">
                    <span className="kv-label">{k}</span>
                    <span className="kv-value mono">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Modal>
      )}

      {/* Rule Evaluation Sandbox Modal */}
      <Modal
        isOpen={isSandboxOpen}
        onClose={() => {
          setIsSandboxOpen(false);
          setEvalResult(null);
        }}
        wide
        title="Direct Rule Evaluation Sandbox (POST /api/rules/evaluate)"
        footer={
          <>
            <button className="control-btn" onClick={() => setIsSandboxOpen(false)}>
              Close
            </button>
            <button
              className="control-btn primary"
              onClick={handleRunEvaluation}
              disabled={evaluating}
            >
              <Play size={14} />
              <span>{evaluating ? 'Evaluating...' : 'Evaluate Against Rules'}</span>
            </button>
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Test a sample security event payload against all enabled rules to verify match triggers and evidence extraction.
          </p>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Event / Flow JSON Payload</label>
            <textarea
              className="form-textarea"
              style={{ height: '140px' }}
              value={evalPayloadText}
              onChange={(e) => setEvalPayloadText(e.target.value)}
            />
          </div>

          {sandboxError && (
            <div className="alert-box danger">
              <ShieldAlert size={16} />
              <span>{sandboxError}</span>
            </div>
          )}

          {evalResult && (
            <div className="evidence-section">
              <div className="evidence-header">
                <CheckCircle size={14} color="var(--benign-color)" />
                <span>Evaluation Results</span>
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                Evaluated against {evalResult.total_evaluated} enabled rules. Triggered {evalResult.total_matched} matches.
              </p>

              {evalResult.matches.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                  No rules matched this payload.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {evalResult.matches.map((m, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--crit-bg)',
                        border: '1px solid var(--crit-border)',
                        padding: '0.5rem 0.75rem',
                        borderRadius: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="mono" style={{ fontWeight: 700, color: 'var(--crit-color)' }}>
                          {m.rule_id}: {m.rule_name}
                        </span>
                        <SeverityBadge severity={m.severity} size="sm" />
                      </div>
                      <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        {m.evidence}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </Modal>
    </motion.div>
  );
};
