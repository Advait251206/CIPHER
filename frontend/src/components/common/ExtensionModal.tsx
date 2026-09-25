import React, { useState, useEffect } from 'react';
import { Modal } from './Modal';
import { api } from '../../api/client';
import { ExtensionStatusResponse } from '../../api/types';
import { Compass, Download, ShieldCheck } from 'lucide-react';
import { controlBtn } from '../../ui/classes';

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
        <div className="flex items-center gap-[0.6rem]">
          <Compass size={20} color="var(--color-accent)" />
          <span className="font-bold">Add CIPHER Browser Guard Extension</span>
        </div>
      }
      footer={
        <div className="flex w-full items-center justify-between">
          <span className="text-[0.75rem] text-fg-muted">
            Manifest V3 &bull; Privacy-first &bull; Local 127.0.0.1
          </span>
          <button className={controlBtn()} onClick={onClose}>
            Close
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-5">
        {/* Intro */}
        <p className="text-[0.85rem] leading-[1.5] text-fg-2">
          <strong>CIPHER Browser Guard</strong> inspects emails on Gmail, Outlook, and Yahoo Mail in real-time,
          evaluates hyperlinks against our 15-feature and 32-feature Random Forest models, and alerts you before credential theft occurs.
        </p>

        {/* Download Option */}
        <div className="flex flex-col gap-[0.85rem] rounded-[8px] border border-[rgba(6,182,212,0.35)] bg-[linear-gradient(135deg,rgba(6,182,212,0.12)_0%,rgba(59,130,246,0.12)_100%)] p-[1.1rem]">
          <div className="mb-[0.2rem] flex items-center gap-2">
            <Download size={18} color="var(--color-accent)" />
            <strong className="text-[0.95rem] text-fg">Download Extension Package</strong>
          </div>
          <p className="mb-2 text-[0.82rem] leading-[1.4] text-fg-2">
            Download the complete Manifest V3 package (.zip) for manually loading into Chromium browsers via the Extensions page (developer mode).
          </p>
          <div>
            <a
              href={api.extension.getDownloadUrl()}
              download="cipher-browser-guard.zip"
              className={controlBtn(
                'primary',
                'inline-flex items-center gap-2 px-5 py-2 text-[0.85rem] font-semibold no-underline [box-shadow:0_0_15px_rgba(6,182,212,0.3)]'
              )}
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
