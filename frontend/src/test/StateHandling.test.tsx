import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';

describe('State Handling Components', () => {
  it('renders LoadingState with default and custom message', () => {
    const { rerender } = render(<LoadingState />);
    expect(screen.getByTestId('loading-state')).toBeInTheDocument();
    expect(screen.getByText('Loading security data...')).toBeInTheDocument();

    rerender(<LoadingState message="Connecting to sensor..." />);
    expect(screen.getByText('Connecting to sensor...')).toBeInTheDocument();
  });

  it('renders EmptyState without confusing it with an error', () => {
    render(<EmptyState title="No security events detected." description="Normal traffic baseline." />);
    expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    expect(screen.getByText('No security events detected.')).toBeInTheDocument();
    expect(screen.getByText('Normal traffic baseline.')).toBeInTheDocument();
  });

  it('renders ErrorState with detailed error and triggers retry', () => {
    const retryFn = vi.fn();
    render(
      <ErrorState
        title="Unable to reach CIPHER API."
        error="Backend connection refused on http://127.0.0.1:8000"
        onRetry={retryFn}
      />
    );
    expect(screen.getByTestId('error-state')).toBeInTheDocument();
    expect(screen.getByText('Unable to reach CIPHER API.')).toBeInTheDocument();
    expect(screen.getByText('Backend connection refused on http://127.0.0.1:8000')).toBeInTheDocument();

    const retryBtn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(retryBtn);
    expect(retryFn).toHaveBeenCalledTimes(1);
  });
});
