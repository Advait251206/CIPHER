import React from 'react';
import { render, screen, act } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { EmailPage } from '../pages/EmailPage';

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    email: {
      analyze: vi.fn(),
      analyzeText: vi.fn(),
      getModelInfo: vi.fn().mockResolvedValue({
        model_name: 'Random Forest Classifier',
        model_version: 'cipher-email-rf-v1',
        feature_count: 32,
        feature_names: ['char_count', 'word_count'],
        test_metrics: {
          accuracy: 0.9153,
          f1_score: 0.9162,
          roc_auc: 0.9736,
          precision: 0.9424,
          recall: 0.8914,
        },
        training_timestamp: '2026-09-15',
      }),
      getHealth: vi.fn().mockResolvedValue({
        status: 'ok',
        model_loaded: true,
        feature_count: 32,
        version: '1.0.0',
      }),
    },
    extension: {
      getStatus: vi.fn().mockResolvedValue({
        available: true,
        path: '/mock/path',
        manifest_name: 'CIPHER Browser Guard',
        version: '1.0.0',
        browser_detected: true,
      }),
      launchChrome: vi.fn().mockResolvedValue({
        success: true,
        message: 'Chrome launched',
        extension_path: '/mock/path',
      }),
      getDownloadUrl: vi.fn().mockReturnValue('/api/extension/download'),
    },
  },
}));

describe('EmailPage Component', () => {
  it('renders privacy architecture notice and structured form', async () => {
    await act(async () => {
      render(<EmailPage />);
    });

    expect(screen.getByText(/Local Privacy Architecture:/i)).toBeInTheDocument();
    expect(screen.getByText(/Structured Email/i)).toBeInTheDocument();
    expect(screen.getByText(/Raw Text \/ RFC 822/i)).toBeInTheDocument();
    expect(screen.getByText(/Analyze Threat/i)).toBeInTheDocument();
  });

  it('renders quick sample buttons and browser extension card', async () => {
    await act(async () => {
      render(<EmailPage />);
    });

    expect(screen.getByText(/Legitimate/i)).toBeInTheDocument();
    expect(screen.getByText(/CIPHER Browser Guard \(Chromium Extension\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Email Machine Learning Engine/i)).toBeInTheDocument();
  });
});
