import React, { ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';
import { Modal } from './Modal';
import { controlBtn } from '../../ui/classes';

interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string | ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  isDestructive?: boolean;
  isLoading?: boolean;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  isDestructive = false,
  isLoading = false,
}) => {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={
        <div className="flex items-center gap-2">
          <AlertTriangle size={20} color={isDestructive ? 'var(--color-crit)' : 'var(--color-med)'} />
          <span>{title}</span>
        </div>
      }
      footer={
        <>
          <button className={controlBtn()} onClick={onClose} disabled={isLoading}>
            {cancelLabel}
          </button>
          <button
            className={controlBtn(isDestructive ? 'danger' : 'primary')}
            onClick={onConfirm}
            disabled={isLoading}
          >
            {isLoading ? 'Processing...' : confirmLabel}
          </button>
        </>
      }
    >
      <div className="text-[0.88rem] leading-[1.6] text-fg-2">
        {message}
      </div>
    </Modal>
  );
};
