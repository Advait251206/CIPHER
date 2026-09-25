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
import { cn } from '../lib/cn';
import { alertBox, card, cardHeader, cardTitle, codeTag, controlBtn, dataTable, evidenceHeader, evidenceSection, formGroup, formInput, formLabel, formSelect, formTextarea, kvGrid, kvItem, kvLabel, kvValue, mono, pageBody, tableContainer } from '../ui/classes';

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
                    <td className={cn(mono, 'font-semibold!')}>
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
    </motion.div>
  );
};
