import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ConfirmDialog } from '../components/common/ConfirmDialog';

describe('ConfirmDialog Component', () => {
  it('calls onConfirm when confirm button is clicked', () => {
    const handleConfirm = vi.fn();
    const handleClose = vi.fn();

    render(
      <ConfirmDialog
        isOpen={true}
        onClose={handleClose}
        onConfirm={handleConfirm}
        title="Resolve Security Incident"
        message="Are you sure you want to resolve incident INC-001?"
        confirmLabel="Resolve"
      />
    );

    expect(screen.getByText('Resolve Security Incident')).toBeInTheDocument();
    expect(screen.getByText('Are you sure you want to resolve incident INC-001?')).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: 'Resolve' });
    fireEvent.click(confirmBtn);
    expect(handleConfirm).toHaveBeenCalledTimes(1);

    const cancelBtn = screen.getByRole('button', { name: 'Cancel' });
    fireEvent.click(cancelBtn);
    expect(handleClose).toHaveBeenCalledTimes(1);
  });
});
