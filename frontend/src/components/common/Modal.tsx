import React, { ReactNode, useEffect } from 'react';
import { X } from 'lucide-react';
import { cn } from '../../lib/cn';
import { closeBtn, modalBody, modalFooter, modalHeader, modalPanel, modalTitle } from '../../ui/classes';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string | ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  footer,
  wide = false,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed top-0 left-0 z-50 flex h-screen w-screen items-center justify-center bg-[rgba(15,23,42,0.45)] p-4" onClick={onClose} role="dialog" aria-modal="true">
      <div
        className={cn(modalPanel, wide && 'max-w-[880px]')}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={modalHeader}>
          <div className={modalTitle}>{title}</div>
          <button className={closeBtn} onClick={onClose} aria-label="Close modal">
            <X size={18} />
          </button>
        </div>
        <div className={modalBody}>{children}</div>
        {footer && <div className={modalFooter}>{footer}</div>}
      </div>
    </div>
  );
};
