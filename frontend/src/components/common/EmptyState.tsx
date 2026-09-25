import React, { ReactNode } from 'react';
import { ShieldCheck } from 'lucide-react';
import { cn } from '../../lib/cn';
import { stateContainer, stateDesc, stateIcon, stateTitle } from '../../ui/classes';

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
    <div className={stateContainer} data-testid="empty-state">
      <div className={cn(stateIcon, 'bg-benign-bg text-benign')}>
        {icon || <ShieldCheck size={28} />}
      </div>
      <div className={stateTitle}>{title}</div>
      <div className={stateDesc}>{description}</div>
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
};
