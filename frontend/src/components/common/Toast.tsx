import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, AlertOctagon, Info } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'info';

interface ToastProps {
  message: string;
  type?: ToastType;
  isVisible: boolean;
  onClose: () => void;
  duration?: number;
}

export const Toast: React.FC<ToastProps> = ({
  message,
  type = 'info',
  isVisible,
  onClose,
  duration = 4000,
}) => {
  useEffect(() => {
    if (isVisible) {
      const timer = setTimeout(() => {
        onClose();
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [isVisible, duration, onClose]);

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle2 size={18} color="var(--color-benign)" />;
      case 'error':
        return <AlertOctagon size={18} color="var(--color-crit)" />;
      case 'info':
      default:
        return <Info size={18} color="var(--color-accent)" />;
    }
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, y: 50, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 20, scale: 0.95 }}
          transition={{ duration: 0.2 }}
          className="fixed right-[24px] bottom-[24px] z-[10000] flex max-w-[400px] items-center gap-[12px] rounded-[8px] border border-line bg-elevated px-[16px] py-[12px] [box-shadow:0_8px_24px_rgba(0,0,0,0.4)]"
          role="alert"
        >
          {getIcon()}
          <span className="text-[0.875rem] leading-[1.4] text-fg">
            {message}
          </span>
          <button
            onClick={onClose}
            className="ml-[8px] flex cursor-pointer items-center justify-center border-none bg-transparent p-[4px] text-fg-muted"
          >
            &times;
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
