import React from 'react';
import { Compass } from 'lucide-react';
import { Severity } from '../../api/types';
import { SeverityBadge } from '../common/SeverityBadge';

interface HeaderProps {
  title: string;
  subtitle: string;
  threatLevel?: Severity;
  onOpenExtensionModal?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  threatLevel = 'LOW',
  onOpenExtensionModal,
}) => {
  return (
    <header className="header">
      <div className="header-left">
        <div>
          <h1 className="header-title">{title}</h1>
          <div className="header-subtitle">{subtitle}</div>
        </div>
      </div>

      <div className="header-right">
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

        {onOpenExtensionModal && (
          <button
            className="control-btn primary"
            onClick={onOpenExtensionModal}
            title="Add CIPHER Browser Guard Extension"
            style={{
              fontSize: '0.75rem',
              padding: '0.35rem 0.75rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(59, 130, 246, 0.2))',
              borderColor: 'var(--accent-cyan)',
              color: 'var(--text-primary)',
            }}
          >
            <Compass size={13} color="var(--accent-cyan)" />
            <span>Add Extension</span>
          </button>
        )}
      </div>
    </header>
  );
};
