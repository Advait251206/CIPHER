import React, { ReactNode } from 'react';
import { ShieldCheck } from 'lucide-react';

interface EmptyStateProps {
  title?: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No security events detected.',
  description = 'Local traffic flows and monitored indicators are currently within normal baseline thresholds.',
  action,
  icon,
}) => {
  return (
    <div className="state-container" data-testid="empty-state">
      <div className="state-icon" style={{ background: 'var(--benign-bg)', color: 'var(--benign-color)' }}>
        {icon || <ShieldCheck size={28} />}
      </div>
      <div className="state-title">{title}</div>
      <div className="state-desc">{description}</div>
      {action && <div style={{ marginTop: '0.75rem' }}>{action}</div>}
    </div>
  );
};
