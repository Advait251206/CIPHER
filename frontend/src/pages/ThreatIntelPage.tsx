import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import {
  IOCItem,
  IOCType,
  Severity,
  IOCCheckResponse,
  IOCImportResponse,
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
      className="page-body"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {actionSuccess && (
        <div className="alert-box success">
          <CheckCircle2 size={16} />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Action Header & Tools */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Database size={18} color="var(--accent-cyan)" />
              <span>Local Threat Intelligence / IOC Store</span>
            </h2>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              All IOCs are stored locally in SQLite. CIPHER does not automatically transmit indicators to external threat feeds.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button className="control-btn" onClick={() => setIsCheckModalOpen(true)}>
              <Search size={14} />
              <span>Check Indicator</span>
            </button>
            <button className="control-btn" onClick={() => setIsJsonImportOpen(true)}>
              <FileCode size={14} />
              <span>JSON Import</span>
            </button>
            <button className="control-btn" onClick={() => setIsCsvImportOpen(true)}>
              <FileSpreadsheet size={14} />
              <span>CSV Import</span>
            </button>
            <button className="control-btn primary" onClick={() => setIsAddModalOpen(true)}>
              <Plus size={14} />
              <span>Add IOC</span>
            </button>
          </div>
        </div>
      </motion.div>

      {/* IOC Intelligence Metric Strip */}
      <motion.div variants={itemVariants} className="ioc-metric-strip">
        <div className="ioc-metric-tile">
          <div className="ioc-metric-num">{totalMatching}</div>
          <div className="ioc-metric-label">Total Indicators</div>
        </div>
        <div className="ioc-metric-tile">
          <div className="ioc-metric-num" style={{ color: 'var(--accent-blue)' }}>
            {iocs.filter((i) => i.ioc_type === 'IP').length}
          </div>
          <div className="ioc-metric-label">IP Addresses</div>
        </div>
        <div className="ioc-metric-tile">
          <div className="ioc-metric-num" style={{ color: 'var(--accent-cyan)' }}>
            {iocs.filter((i) => i.ioc_type === 'DOMAIN').length}
          </div>
          <div className="ioc-metric-label">Malicious Domains</div>
        </div>
        <div className="ioc-metric-tile">
          <div className="ioc-metric-num" style={{ color: 'var(--high-color)' }}>
            {iocs.filter((i) => i.ioc_type === 'URL').length}
          </div>
          <div className="ioc-metric-label">Phishing URLs</div>
        </div>
        <div className="ioc-metric-tile">
          <div className="ioc-metric-num" style={{ color: 'var(--accent-purple)' }}>
            {iocs.filter((i) => i.ioc_type === 'HASH').length}
          </div>
          <div className="ioc-metric-label">File Hashes</div>
        </div>
        <div className="ioc-metric-tile">
          <div className="ioc-metric-num" style={{ color: 'var(--benign-color)' }}>
            {iocs.filter((i) => i.enabled).length}
          </div>
          <div className="ioc-metric-label">Active & Enforcing</div>
        </div>
      </motion.div>

      {/* Filter Controls */}
      <motion.div variants={itemVariants} className="card" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: '1 1 200px', margin: 0 }}>
            <label className="form-label">Search Indicator</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g. 198.51.100.24 or evil-domain.com"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="form-group" style={{ width: '140px', margin: 0 }}>
            <label className="form-label">IOC Type</label>
            <select
              className="form-select"
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

          <div className="form-group" style={{ width: '140px', margin: 0 }}>
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
              id="enabledOnly"
              checked={enabledOnly}
              onChange={(e) => setEnabledOnly(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <label htmlFor="enabledOnly" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              Active Only
            </label>
          </div>
        </div>
      </motion.div>

      {/* IOC Table */}
      <motion.div variants={itemVariants} className="card">
        <div className="card-header">
          <div className="card-title">
            <span>Registered Indicators of Compromise</span>
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Showing {filteredIocs.length} of {totalMatching} matching indicators
          </span>
        </div>

        {loading ? (
          <LoadingState message="Loading threat intelligence indicators..." />
        ) : error ? (
          <ErrorState title="Failed to Load IOC Store" error={error} onRetry={fetchIocs} />
        ) : filteredIocs.length === 0 ? (
          <div style={{ padding: '3rem 1.5rem', textAlign: 'center' }}>
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '50%',
                background: 'var(--benign-bg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem auto',
                border: '1px solid var(--benign-border)',
              }}
            >
              <Database size={24} color="var(--benign-color)" />
            </div>
            <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
              {typeFilter || severityFilter || searchQuery
                ? 'No Threat Indicators Match Query'
                : 'Zero Indicators in Local Threat Store'}
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.84rem', maxWidth: '420px', margin: '0 auto' }}>
              {typeFilter || severityFilter || searchQuery
                ? 'Try clearing your filter inputs to display all registered indicators.'
                : 'Local IOC store is clean. Click "Add IOC" or "CSV Import" above to register malicious IPs, domains, or hashes.'}
            </div>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
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
                      <span className="mono" style={{ fontSize: '0.72rem', background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', padding: '2px 6px', borderRadius: '4px' }}>
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="mono" style={{ fontWeight: 600 }}>
                      {ioc.indicator}
                    </td>
                    <td>
                      <SeverityBadge severity={ioc.severity} size="sm" />
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {(ioc.confidence * 100).toFixed(0)}%
                    </td>
                    <td>
                      <span style={{ fontSize: '0.78rem' }}>{ioc.category || 'THREAT'}</span>
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {ioc.source}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {ioc.first_seen?.split('T')[0] || 'N/A'}
                    </td>
                    <td>
                      <button
                        className="control-btn"
                        style={{ padding: '2px 6px', fontSize: '0.7rem' }}
                        onClick={() => handleToggleIoc(ioc)}
                        title={ioc.enabled ? 'Click to Disable' : 'Click to Enable'}
                      >
                        {ioc.enabled ? (
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
                        className="control-btn danger"
                        style={{ padding: '3px 6px' }}
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
            <button className="control-btn" onClick={() => setIsAddModalOpen(false)}>
              Cancel
            </button>
            <button
              className="control-btn primary"
              onClick={handleAddIoc}
              disabled={isSubmitting || !newIndicator.trim()}
            >
              {isSubmitting ? 'Registering...' : 'Save Indicator'}
            </button>
          </>
        }
      >
        <form onSubmit={handleAddIoc} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {formError && (
            <div className="alert-box danger">
              <AlertTriangle size={14} />
              <span>{formError}</span>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Indicator Type</label>
              <select
                className="form-select"
                value={newType}
                onChange={(e) => setNewType(e.target.value as IOCType)}
              >
                <option value="IP">IP Address</option>
                <option value="DOMAIN">Domain</option>
                <option value="URL">URL</option>
                <option value="HASH">File Hash (MD5/SHA1/SHA256)</option>
              </select>
            </div>

            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Severity Level</label>
              <select
                className="form-select"
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

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Indicator Value</label>
            <input
              type="text"
              className="form-input"
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

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Confidence (0.0 - 1.0)</label>
              <input
                type="number"
                step="0.05"
                min="0.0"
                max="1.0"
                className="form-input"
                value={newConfidence}
                onChange={(e) => setNewConfidence(Number(e.target.value))}
              />
            </div>

            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Attack Category</label>
              <input
                type="text"
                className="form-input"
                placeholder="C2, BOTNET, PHISHING, RANSOMWARE"
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value)}
              />
            </div>
          </div>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Description / Threat Context</label>
            <input
              type="text"
              className="form-input"
              placeholder="Known command-and-control server observed in recent campaign"
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
            />
          </div>

          <div className="form-group" style={{ margin: 0 }}>
            <label className="form-label">Tags (comma-separated)</label>
            <input
              type="text"
              className="form-input"
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
          <button className="control-btn" onClick={() => setIsCheckModalOpen(false)}>
            Close
          </button>
        }
      >
        <form onSubmit={handleCheckIndicator} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Instantly checks an IP, domain, URL, or hash against active local intelligence. Operates purely locally without network queries.
          </p>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Enter IP, domain, URL, or hash..."
              value={checkInput}
              onChange={(e) => setCheckInput(e.target.value)}
              required
            />
            <button type="submit" className="control-btn primary" disabled={isChecking}>
              <Search size={14} />
              <span>{isChecking ? 'Checking...' : 'Check'}</span>
            </button>
          </div>

          {checkResult && (
            <div className="evidence-section" style={{ marginTop: '0.5rem' }}>
              <div className="evidence-header">
                {checkResult.matched ? (
                  <>
                    <AlertTriangle size={14} color="var(--crit-color)" />
                    <span style={{ color: 'var(--crit-color)' }}>THREAT INDICATOR MATCHED</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={14} color="var(--benign-color)" />
                    <span style={{ color: 'var(--benign-color)' }}>NO ACTIVE IOC MATCH FOUND</span>
                  </>
                )}
              </div>

              {checkResult.matched && checkResult.matches.length > 0 ? (
                <div className="kv-grid">
                  <div className="kv-item">
                    <span className="kv-label">Indicator</span>
                    <span className="kv-value mono">{checkResult.matches[0].indicator}</span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Severity</span>
                    <span className="kv-value">
                      <SeverityBadge severity={checkResult.matches[0].severity} size="sm" />
                    </span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Confidence</span>
                    <span className="kv-value mono">
                      {(checkResult.matches[0].confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Source</span>
                    <span className="kv-value mono">{checkResult.matches[0].source}</span>
                  </div>
                  {checkResult.matches[0].description && (
                    <div className="kv-item" style={{ gridColumn: '1 / -1' }}>
                      <span className="kv-label">Context</span>
                      <span className="kv-value">{checkResult.matches[0].description}</span>
                    </div>
                  )}
                </div>
              ) : (
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
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
            <button className="control-btn" onClick={() => setIsJsonImportOpen(false)}>
              Cancel
            </button>
            <button
              className="control-btn primary"
              onClick={handleImportJson}
              disabled={isSubmitting || !jsonText.trim()}
            >
              {isSubmitting ? 'Importing...' : 'Submit JSON Batch'}
            </button>
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Paste a JSON array of IOC objects (maximum 1,000 entries per batch).
          </p>

          <textarea
            className="form-textarea"
            style={{ height: '180px' }}
            placeholder={`[\n  {\n    "ioc_type": "IP",\n    "indicator": "198.51.100.99",\n    "severity": "HIGH",\n    "confidence": 0.9,\n    "category": "C2"\n  }\n]`}
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
          />

          {importResult && (
            <div className="alert-box info">
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
            <button className="control-btn" onClick={() => setIsCsvImportOpen(false)}>
              Cancel
            </button>
            <button
              className="control-btn primary"
              onClick={handleImportCsv}
              disabled={isSubmitting || !csvText.trim()}
            >
              {isSubmitting ? 'Importing...' : 'Submit CSV Batch'}
            </button>
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Paste raw CSV text. Required header columns: <code>ioc_type,indicator,severity,confidence,category,description</code>.
          </p>

          <textarea
            className="form-textarea"
            style={{ height: '180px' }}
            placeholder={`ioc_type,indicator,severity,confidence,category,description\nIP,203.0.113.15,HIGH,0.85,SCANNER,Known port scanner\nDOMAIN,malicious-c2.xyz,CRITICAL,0.95,BOTNET,Active botnet C2`}
            value={csvText}
            onChange={(e) => setCsvText(e.target.value)}
          />

          {importResult && (
            <div className="alert-box info">
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
                <strong className="mono">{iocToDelete.indicator}</strong> ({iocToDelete.ioc_type})?
              </p>
              <p style={{ marginTop: '0.5rem', color: 'var(--crit-color)' }}>
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
    </motion.div>
  );
};
