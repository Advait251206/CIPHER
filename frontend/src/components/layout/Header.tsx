import React, { useState } from 'react';
import { Shield, ShieldAlert } from 'lucide-react';
import { Severity } from '../../api/types';
import { SeverityBadge } from '../common/SeverityBadge';
import { controlBtn, liveIndicator } from '../../ui/classes';

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
    <header className="sticky top-0 z-5 flex items-center justify-between border-b border-b-line bg-surface px-9 py-[0.85rem] lte-768:flex-col lte-768:items-start lte-768:gap-3">
      <div className="flex items-center gap-6">
        <div>
          <h1 className="text-[1.3rem] leading-[1.2] font-extrabold tracking-[-0.015em] text-fg">{title}</h1>
          <div className="text-[0.8rem] text-fg-muted">{subtitle}</div>
        </div>
      </div>

      <div className="flex items-center gap-[0.85rem]">
        {/* Prevention Mode Toggle */}
        <div className="flex items-center gap-2 border-r border-r-line pr-3">
          <button
            onClick={handleToggle}
            disabled={isToggling}
            className={controlBtn(preventionMode === 'enforce' ? 'danger' : 'success', 'px-[0.6rem] py-[0.35rem] text-[0.7rem]')}
            title="Toggle Prevention Mode"
          >
            {preventionMode === 'enforce' ? (
              <><ShieldAlert size={14} /> PREVENT TOO</>
            ) : (
              <><Shield size={14} /> DETECT ONLY</>
            )}
          </button>
        </div>

        <div className="flex items-center gap-[0.45rem] border-r border-r-line pr-3">
          <span className="text-[0.72rem] font-semibold text-fg-muted uppercase">
            Perimeter Threat:
          </span>
          <SeverityBadge severity={threatLevel} size="sm" />
        </div>

        <div className="flex items-center gap-[0.4rem]">
          <span className="flex items-center gap-[0.3rem] text-[0.75rem] font-medium text-fg-muted">
            <span className={liveIndicator}></span>
            Live Data
          </span>
        </div>

      </div>
    </header>
  );
};
