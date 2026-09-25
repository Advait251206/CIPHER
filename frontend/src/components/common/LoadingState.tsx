import React from 'react';
import { cn } from '../../lib/cn';
import { spinner, stateContainer, stateDesc, stateTitle } from '../../ui/classes';

interface LoadingStateProps {
  message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Loading security data...',
}) => {
  return (
    <div className={stateContainer} data-testid="loading-state">
      <div className={spinner} />
      <div className={stateTitle}>{message}</div>
      <div className={cn(stateDesc, 'text-[0.78rem]')}>
        Querying local CIPHER threat intelligence & detection subsystem...
      </div>
    </div>
  );
};
