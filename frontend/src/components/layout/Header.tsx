import React, { useState } from 'react';
import { Shield, ShieldAlert } from 'lucide-react';
import { Severity } from '../../api/types';
import { SeverityBadge } from '../common/SeverityBadge';

interface HeaderProps {
  title: string;
  subtitle: string;
  threatLevel?: Severity;
  preventionMode?: 'detect_only' | 'enforce';
  onModeToggle?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  threatLevel = 'LOW',
  preventionMode = 'detect_only',
  onModeToggle,
}) => {
  const [isToggling, setIsToggling] = useState(false);

  const handleToggle = async () => {
    if (onModeToggle) {
      setIsToggling(true);
      await onModeToggle();
      setIsToggling(false);
    }
  };

  return (
    <header className="header">
      <div className="header-left">
        <div>
          <h1 className="header-title">{title}</h1>
          <div className="header-subtitle">{subtitle}</div>
        </div>
      </div>

      <div className="header-right">
        {/* Prevention Mode Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', paddingRight: '0.75rem', borderRight: '1px solid var(--border-subtle)' }}>
          <button 
            onClick={handleToggle}
            disabled={isToggling}
            className={`control-btn ${preventionMode === 'enforce' ? 'danger' : 'success'}`}
            style={{ padding: '0.35rem 0.6rem', fontSize: '0.7rem' }}
            title="Toggle Prevention Mode"
          >
            {preventionMode === 'enforce' ? (
              <><ShieldAlert size={14} /> PREVENT TOO</>
            ) : (
              <><Shield size={14} /> DETECT ONLY</>
            )}
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', paddingRight: '0.75rem', borderRight: '1px solid var(--border-subtle)' }}>
          <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
            Perimeter Threat:
          </span>
          <SeverityBadge severity={threatLevel} size="sm" />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <span className="live-indicator"></span>
            Live Data
          </span>
        </div>

      </div>
    </header>
  );
};
