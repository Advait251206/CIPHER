import React, { useState, useEffect } from 'react';
import { Modal } from './Modal';
import { api } from '../../api/client';
import { ExtensionStatusResponse } from '../../api/types';
import { Compass, Download, ShieldCheck } from 'lucide-react';

interface ExtensionModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ExtensionModal: React.FC<ExtensionModalProps> = ({ isOpen, onClose }) => {
  const [status, setStatus] = useState<ExtensionStatusResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      api.extension
        .getStatus()
        .then((res) => setStatus(res))
        .catch(() => {})
        .finally(() => setLoading(false));
    }
  }, [isOpen]);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      wide={true}
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Compass size={20} color="var(--accent-cyan)" />
          <span style={{ fontWeight: 700 }}>Add CIPHER Browser Guard Extension</span>
        </div>
      }
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Manifest V3 &bull; Privacy-first &bull; Local 127.0.0.1
          </span>
          <button className="control-btn" onClick={onClose}>
            Close
          </button>
        </div>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Intro */}
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
          <strong>CIPHER Browser Guard</strong> inspects emails on Gmail, Outlook, and Yahoo Mail in real-time,
          evaluates hyperlinks against our 28-feature and 32-feature Random Forest models, and alerts you before credential theft occurs.
        </p>

        {/* Download Option */}
        <div
          style={{
            padding: '1.1rem',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.12) 0%, rgba(59, 130, 246, 0.12) 100%)',
            border: '1px solid rgba(6, 182, 212, 0.35)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.85rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
            <Download size={18} color="var(--accent-cyan)" />
            <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>Download Extension Package</strong>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.4, margin: '0 0 0.5rem 0' }}>
            Download the complete Manifest V3 package (.zip) for manually loading into Chromium browsers via the Extensions page (developer mode).
          </p>
          <div>
            <a
              href={api.extension.getDownloadUrl()}
              download="cipher-browser-guard.zip"
              className="control-btn primary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 1.25rem',
                fontSize: '0.85rem',
                fontWeight: 600,
                textDecoration: 'none',
                boxShadow: '0 0 15px rgba(6, 182, 212, 0.3)',
              }}
            >
              <Download size={16} />
              <span>Download cipher-browser-guard.zip</span>
            </a>
          </div>
        </div>
      </div>
    </Modal>
  );
};
