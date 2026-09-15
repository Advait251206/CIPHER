import React from 'react';

interface LoadingStateProps {
  message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Loading security data...',
}) => {
  return (
    <div className="state-container" data-testid="loading-state">
      <div className="spinner" />
      <div className="state-title">{message}</div>
      <div className="state-desc" style={{ fontSize: '0.78rem' }}>
        Querying local CIPHER threat intelligence & detection subsystem...
      </div>
    </div>
  );
};
