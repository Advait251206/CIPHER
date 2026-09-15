import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { EventDetailModal } from '../components/events/EventDetailModal';
import { SecurityEventItem } from '../api/types';

describe('EventDetailModal Component', () => {
  const sampleEvent: SecurityEventItem = {
    event_id: 'ev-test-uuid-1234',
    timestamp: '2026-09-15T02:00:00Z',
    classification: 'PORT_SCAN',
    attack_type: 'PORT_SCAN',
    severity: 'HIGH',
    risk_score: 75,
    confidence: 0.92,
    ml_score: 0.88,
    heuristic_score: 65,
    domain: '',
    source_ip: '192.168.1.55',
    destination_ip: '10.0.0.1',
    source_port: 54321,
    destination_port: 22,
    protocol: 'TCP',
    reasons: ['Half-open SYN probe detected', 'Multiple destination ports probed'],
    recommendation: 'Block source IP address immediately.',
    model_version: 'cicids2017-dual-rf-v1',
    source: 'Network IDPS',
    detection_method: 'ML + Heuristic',
    action: 'ALERT',
    metadata: {
      rule_id: 'NET-PSCAN-01',
      rule_name: 'Half-Open SYN Scan',
      incident_id: 'INC-2026-001',
      escalation_detected: true,
      ioc_match: {
        indicator: '192.168.1.55',
        ioc_type: 'IP',
        severity: 'HIGH',
        confidence: 0.9,
        source: 'local_database',
        description: 'Known scanner IP in local IOC database',
      },
    },
  };

  it('renders all evidence sections accurately', () => {
    const handleClose = vi.fn();
    const handleNavIncident = vi.fn();

    render(
      <EventDetailModal
        isOpen={true}
        onClose={handleClose}
        event={sampleEvent}
        onNavigateToIncident={handleNavIncident}
      />
    );

    // Event metadata
    expect(screen.getByText('ev-test-uuid-1234')).toBeInTheDocument();
    expect(screen.getAllByText('192.168.1.55').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();

    // Threat & Rule Evidence
    expect(screen.getByText(/NET-PSCAN-01/i)).toBeInTheDocument();
    expect(screen.getByText('Half-open SYN probe detected')).toBeInTheDocument();

    // IOC Match
    expect(screen.getByText('Known scanner IP in local IOC database')).toBeInTheDocument();

    // Incident Correlation link
    expect(screen.getByText('INC-2026-001')).toBeInTheDocument();
    const viewIncBtn = screen.getByRole('button', { name: /view correlated incident/i });
    expect(viewIncBtn).toBeInTheDocument();

    fireEvent.click(viewIncBtn);
    expect(handleNavIncident).toHaveBeenCalledWith('INC-2026-001');
  });

  it('does not render when isOpen is false', () => {
    render(<EventDetailModal isOpen={false} onClose={vi.fn()} event={sampleEvent} />);
    expect(screen.queryByText('ev-test-uuid-1234')).not.toBeInTheDocument();
  });
});
