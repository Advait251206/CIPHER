import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { SeverityBadge } from '../components/common/SeverityBadge';

describe('SeverityBadge Component', () => {
  it('renders CRITICAL severity with text and icon', () => {
    render(<SeverityBadge severity="CRITICAL" />);
    const badge = screen.getByTestId('severity-badge');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent('CRITICAL');
    expect(badge).toHaveAttribute('data-severity', 'CRITICAL');
    expect(badge).toHaveClass('critical');
  });

  it('renders HIGH severity correctly', () => {
    render(<SeverityBadge severity="HIGH" />);
    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('HIGH');
    expect(badge).toHaveClass('high');
  });

  it('renders MEDIUM severity correctly', () => {
    render(<SeverityBadge severity="MEDIUM" />);
    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('MEDIUM');
    expect(badge).toHaveClass('medium');
  });

  it('renders LOW severity correctly', () => {
    render(<SeverityBadge severity="LOW" />);
    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('LOW');
    expect(badge).toHaveClass('low');
  });

  it('renders BENIGN / LEGITIMATE severity correctly', () => {
    render(<SeverityBadge severity="BENIGN" />);
    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('BENIGN');
    expect(badge).toHaveClass('benign');
  });
});
