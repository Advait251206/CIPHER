import React from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

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
    <div className="state-container" data-testid="error-state">
      <div className="state-icon" style={{ background: 'var(--crit-bg)', color: 'var(--crit-color)' }}>
        <AlertOctagon size={28} />
      </div>
      <div className="state-title" style={{ color: 'var(--crit-color)' }}>
        {title}
      </div>
      <div className="state-desc" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
        {errorMessage}
      </div>
      {onRetry && (
        <button
          className="control-btn primary"
          onClick={onRetry}
          style={{ marginTop: '0.75rem' }}
        >
          <RefreshCw size={14} />
          <span>Retry Connection</span>
        </button>
      )}
    </div>
  );
};
