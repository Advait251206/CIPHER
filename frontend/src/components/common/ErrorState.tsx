import React from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';
import { cn } from '../../lib/cn';
import { controlBtn, stateContainer, stateDesc, stateIcon, stateTitle } from '../../ui/classes';

interface ErrorStateProps {
  title?: string;
  error?: string | Error | null;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Unable to reach CIPHER API.',
  error,
  onRetry,
}) => {
  const errorMessage =
    typeof error === 'string'
      ? error
      : error instanceof Error
      ? error.message
      : 'Network connection failed or backend server is not running on http://127.0.0.1:8000.';

  return (
    <div className={stateContainer} data-testid="error-state">
      <div className={cn(stateIcon, 'bg-crit-bg text-crit')}>
        <AlertOctagon size={28} />
      </div>
      <div className={cn(stateTitle, 'text-crit')}>
        {title}
      </div>
      <div className={cn(stateDesc, 'font-mono text-[0.78rem]')}>
        {errorMessage}
      </div>
      {onRetry && (
        <button
          className={controlBtn('primary', 'mt-3')}
          onClick={onRetry}
        >
          <RefreshCw size={14} />
          <span>Retry Connection</span>
        </button>
      )}
    </div>
  );
};
