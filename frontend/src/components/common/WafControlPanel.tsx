import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import { ShieldCheck, ShieldAlert, Power } from 'lucide-react';
import { cn } from '../../lib/cn';

// The backend exposes GET/POST /api/waf/config with one mode per feature:
// { sql_protection: 'off' | 'detect' | 'enforce', xss_protection: ..., brute_force_protection: ... }
type WafMode = 'off' | 'detect' | 'enforce';
type WafConfig = Record<string, WafMode>;

const FEATURES: Array<{ key: string; title: string }> = [
  { key: 'sql_protection', title: 'SQL Injection (SQLi)' },
  { key: 'xss_protection', title: 'Cross-Site Scripting (XSS)' },
  { key: 'brute_force_protection', title: 'Brute Force' },
];

export const WafControlPanel: React.FC = () => {
  const [config, setConfig] = useState<WafConfig | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchConfig = async () => {
    try {
      setConfig(await api.waf.getConfig());
    } catch (err) {
      console.error('Failed to fetch WAF config', err);
    }
  };

  useEffect(() => {
    fetchConfig();
    const interval = setInterval(fetchConfig, 5000);
    return () => clearInterval(interval);
  }, []);

  // Clicking the active mode turns that protection off again.
  const setMode = async (feature: string, mode: WafMode) => {
    if (!config) return;
    setLoading(true);
    try {
      const next: WafMode = config[feature] === mode ? 'off' : mode;
      setConfig(await api.waf.setMode(feature, next));
    } catch (err) {
      console.error('Failed to update WAF config', err);
    } finally {
      setLoading(false);
    }
  };

  if (!config) return null;

  const renderToggle = (title: string, feature: string) => {
    const mode = config[feature] ?? 'off';
    return (
      <div key={feature} className="flex items-center justify-between p-3 bg-sidebar rounded-[6px] border border-line">
        <div className="flex items-center gap-3">
          {mode === 'enforce' ? (
            <ShieldCheck size={20} color="var(--color-crit)" />
          ) : mode === 'detect' ? (
            <ShieldAlert size={20} color="var(--color-high)" />
          ) : (
            <Power size={20} color="var(--color-fg-muted)" />
          )}
          <span className="text-fg font-medium text-[0.9rem]">{title}</span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setMode(feature, 'detect')}
            disabled={loading}
            className={cn(
              'py-[0.3rem] px-[0.6rem] text-[0.8rem] rounded-[4px] border-none cursor-pointer',
              mode !== 'off' ? 'bg-high text-black' : 'bg-surface text-fg'
            )}
          >
            Detect
          </button>
          <button
            onClick={() => setMode(feature, 'enforce')}
            disabled={loading}
            className={cn(
              'py-[0.3rem] px-[0.6rem] text-[0.8rem] rounded-[4px] border-none cursor-pointer',
              mode === 'enforce' ? 'bg-crit text-white' : 'bg-surface text-fg'
            )}
          >
            Enforce (Block)
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col gap-3">
      <h3 className="text-[0.9rem] text-fg flex items-center gap-2">
        <ShieldCheck size={18} /> Active WAF Protection
      </h3>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(300px,1fr))] gap-4 bg-surface border border-line rounded-[6px] p-4">
        {FEATURES.map((f) => renderToggle(f.title, f.key))}
      </div>
    </div>
  );
};
