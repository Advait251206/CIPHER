import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { RuleItem, RuleDetailResponse, RuleEvaluateResponse } from '../api/types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { Modal } from '../components/common/Modal';
import { WafControlPanel } from '../components/common/WafControlPanel';
import { Sliders, ToggleLeft, ToggleRight, Info, Eye, Play, CheckCircle, ShieldAlert } from 'lucide-react';
import { motion, type Variants } from 'framer-motion';
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, controlBtn, dataTable, evidenceHeader, evidenceSection, formGroup, formLabel, formSelect, formTextarea, kvGrid, kvItem, kvLabel, kvValue, mono, pageBody, tableContainer } from '../ui/classes';

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
      className={pageBody}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Authoritative Scoring Notice */}
      <div className={alertBox('info')}>
        <Info size={18} className="shrink-0" />
        <div>
          <strong>Deterministic Detection Authority:</strong> Rule evaluations produce structured evidence and confidence weights.
          <em> The frontend does not calculate or override threat scores. Backend ThreatScorer remains the sole scoring authority.</em>
        </div>
      </div>

      {actionNotice && (
        <div className={alertBox('success')}>
          <CheckCircle size={16} />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Header Tools */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-5')}>
        <div className="flex justify-between items-center flex-wrap gap-4">
          <div>
            <h2 className="text-[1.1rem] font-bold text-fg flex items-center gap-2">
              <Sliders size={18} color="var(--color-accent)" />
              <span>Deterministic Rule Registry</span>
            </h2>
            <p className="text-[0.78rem] text-fg-muted">
              10 Network Heuristics & 4 Signatures configured for zero-delay deterministic attack identification.
            </p>
          </div>

          <button className={controlBtn('primary')} onClick={() => setIsSandboxOpen(true)}>
            <Play size={14} />
            <span>Rule Evaluation Sandbox</span>
          </button>
        </div>
      </motion.div>

      {/* WAF Global Protection Panel */}
      <motion.div variants={itemVariants} className="mb-5">
        <WafControlPanel />
      </motion.div>

      {/* Filter Bar */}
      <motion.div variants={itemVariants} className={cn(card, 'mb-5')}>
        {/* Quick Category Filter Pills */}
        <div className="flex gap-[0.45rem] flex-wrap mb-[0.85rem]">
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
              className={controlBtn(categoryFilter === cat.val ? 'primary' : 'default', 'text-[0.74rem] py-1 px-[0.65rem]')}

              onClick={() => setCategoryFilter(cat.val)}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-4 items-end pt-2 border-t border-t-line">
          <div className={cn(formGroup, 'w-[180px] m-0')}>
            <label className={formLabel}>Attack Category</label>
            <select
              className={formSelect}
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

          <div className={cn(formGroup, 'w-[160px] m-0')}>
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
              id="enabledOnlyRules"
              checked={enabledOnly}
              onChange={(e) => setEnabledOnly(e.target.checked)}
              className="cursor-pointer"
            />
            <label htmlFor="enabledOnlyRules" className="text-[0.8rem] text-fg-2 cursor-pointer">
              Enabled Only ({enabledCount} active)
            </label>
          </div>
        </div>
      </motion.div>

      {/* Rules Table */}
      <motion.div variants={itemVariants} className={card}>
        <div className={cardHeader}>
          <div className={cardTitle}>
            <span>Registered Rules ({rules.length})</span>
          </div>
          <span className="text-[0.78rem] text-fg-muted">
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
          <div className={tableContainer}>
            <table className={dataTable}>
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
                    <td className={cn(mono, 'font-bold! text-accent!')}>
                      {rule.rule_id}
                    </td>
                    <td className="font-semibold!">{rule.name}</td>
                    <td>
                      <span className={cn(mono, 'text-[0.72rem] bg-elevated border border-line py-[2px] px-[6px] rounded-[4px]')}>
                        {rule.rule_type || (rule.rule_id?.startsWith('SIG') ? 'SIGNATURE' : 'HEURISTIC')}
                      </span>
                    </td>
                    <td>
                      <span className={cn(mono, 'text-[0.75rem]')}>{rule.category}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} size="sm" />
                    </td>
                    <td className={cn(mono, 'text-[0.75rem]!')}>
                      {(rule.confidence * 100).toFixed(0)}%
                    </td>
                    <td>
                      <span className="text-[0.75rem] text-fg-muted">
                        {rule.scope || (rule as any).target_event_type || 'flow'}
                      </span>
                    </td>
                    <td>
                      <button
                        className={cn(controlBtn(), 'py-[2px] px-[6px] text-[0.7rem]')}

                        onClick={() => handleToggleRule(rule)}
                        title={rule.enabled ? 'Click to Disable' : 'Click to Enable'}
                      >
                        {rule.enabled ? (
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
                        className={cn(controlBtn(), 'py-[2px] px-[6px]')}

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
            <button className={controlBtn()} onClick={() => setSelectedRuleDetail(null)}>
              Close
            </button>
          }
        >
          <div className="flex flex-col gap-4">
            <div className={evidenceSection}>
              <div className={evidenceHeader}>
                <Info size={14} />
                <span>Description & Detection Logic</span>
              </div>
              <p className="text-[0.85rem] text-fg-2">
                {selectedRuleDetail.rule.description}
              </p>
            </div>

            <div className={evidenceSection}>
              <div className={evidenceHeader}>
                <Sliders size={14} />
                <span>Configured System Thresholds</span>
              </div>
              <div className={kvGrid}>
                {Object.entries(selectedRuleDetail.thresholds).map(([k, v]) => (
                  <div key={k} className={kvItem}>
                    <span className={kvLabel}>{k}</span>
                    <span className={cn(mono, kvValue)}>{String(v)}</span>
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
            <button className={controlBtn()} onClick={() => setIsSandboxOpen(false)}>
              Close
            </button>
            <button
              className={controlBtn('primary')}
              onClick={handleRunEvaluation}
              disabled={evaluating}
            >
              <Play size={14} />
              <span>{evaluating ? 'Evaluating...' : 'Evaluate Against Rules'}</span>
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <p className="text-[0.82rem] text-fg-2">
            Test a sample security event payload against all enabled rules to verify match triggers and evidence extraction.
          </p>

          <div className={cn(formGroup, 'm-0')}>
            <label className={formLabel}>Event / Flow JSON Payload</label>
            <textarea
              className={cn(formTextarea, 'h-[140px]')}

              value={evalPayloadText}
              onChange={(e) => setEvalPayloadText(e.target.value)}
            />
          </div>

          {sandboxError && (
            <div className={alertBox('danger')}>
              <ShieldAlert size={16} />
              <span>{sandboxError}</span>
            </div>
          )}

          {evalResult && (
            <div className={evidenceSection}>
              <div className={evidenceHeader}>
                <CheckCircle size={14} color="var(--color-benign)" />
                <span>Evaluation Results</span>
              </div>
              <p className="text-[0.82rem] text-fg-2 mb-2">
                Evaluated against {evalResult.total_evaluated} enabled rules. Triggered {evalResult.total_matched} matches.
              </p>

              {evalResult.matches.length === 0 ? (
                <div className="text-fg-muted text-[0.82rem]">
                  No rules matched this payload.
                </div>
              ) : (
                <div className="flex flex-col gap-2">
                  {evalResult.matches.map((m, idx) => (
                    <div
                      key={idx}
                      className="bg-crit-bg border border-crit py-2 px-3 rounded-[6px]"
                    >
                      <div className="flex justify-between items-center">
                        <span className={cn(mono, 'font-bold text-crit')}>
                          {m.rule_id}: {m.rule_name}
                        </span>
                        <SeverityBadge severity={m.severity} size="sm" />
                      </div>
                      <p className="text-[0.78rem] text-fg-2 mt-1">
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
