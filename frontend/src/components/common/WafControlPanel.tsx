import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import { ShieldCheck, ShieldAlert, Power } from 'lucide-react';

interface WafState {
  sql_injection: { enabled: boolean; enforce: boolean };
  xss: { enabled: boolean; enforce: boolean };
  brute_force: { enabled: boolean; enforce: boolean };
}

export const WafControlPanel: React.FC = () => {
  const [wafState, setWafState] = useState<WafState | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchWafState = async () => {
    try {
      // Temporary fetch to our new endpoint
      const res = await fetch('http://localhost:8000/api/v1/waf/status');
      if (res.ok) {
        const data = await res.json();
        setWafState(data.config);
      }
    } catch (err) {
      console.error('Failed to fetch WAF state', err);
    }
  };

  useEffect(() => {
    fetchWafState();
    const interval = setInterval(fetchWafState, 5000);
    return () => clearInterval(interval);
  }, []);

  const toggleWaf = async (attackType: string, field: 'enabled' | 'enforce') => {
    if (!wafState) return;
    setLoading(true);
    try {
      const currentState = wafState[attackType as keyof WafState][field];
      const res = await fetch(`http://localhost:8000/api/v1/waf/toggle/${attackType}?${field}=${!currentState}`, {
        method: 'POST'
      });
      if (res.ok) {
        await fetchWafState();
      }
    } catch (err) {
      console.error('Failed to toggle WAF', err);
    } finally {
      setLoading(false);
    }
  };

  if (!wafState) return null;

  const renderToggle = (title: string, type: string) => {
    const config = wafState[type as keyof WafState];
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem', background: 'var(--bg-sidebar)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {config.enforce ? <ShieldCheck size={20} color="var(--crit-color)" /> : (config.enabled ? <ShieldAlert size={20} color="var(--high-color)" /> : <Power size={20} color="var(--text-muted)" />)}
          <span style={{ color: 'var(--text-primary)', fontWeight: 500, fontSize: '0.9rem' }}>{title}</span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button 
            onClick={() => toggleWaf(type, 'enabled')}
            disabled={loading}
            style={{ 
              padding: '0.3rem 0.6rem', 
              fontSize: '0.8rem', 
              borderRadius: '4px',
              border: 'none',
              cursor: 'pointer',
              background: config.enabled ? 'var(--high-color)' : 'var(--bg-surface)',
              color: config.enabled ? '#000' : 'var(--text-primary)'
            }}
          >
            Detect
          </button>
          <button 
            onClick={() => toggleWaf(type, 'enforce')}
            disabled={loading || !config.enabled}
            style={{ 
              padding: '0.3rem 0.6rem', 
              fontSize: '0.8rem', 
              borderRadius: '4px',
              border: 'none',
              cursor: config.enabled ? 'pointer' : 'not-allowed',
              background: config.enforce ? 'var(--crit-color)' : 'var(--bg-surface)',
              color: config.enforce ? '#fff' : 'var(--text-primary)',
              opacity: config.enabled ? 1 : 0.5
            }}
          >
            Enforce (Block)
          </button>
        </div>
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <h3 style={{ fontSize: '0.9rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <ShieldCheck size={18} /> Active WAF Protection
      </h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem', background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1rem' }}>
        {renderToggle('SQL Injection (SQLi)', 'sql_injection')}
        {renderToggle('Cross-Site Scripting (XSS)', 'xss')}
        {renderToggle('Brute Force', 'brute_force')}
      </div>
    </div>
  );
};
