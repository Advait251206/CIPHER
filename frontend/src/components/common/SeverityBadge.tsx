import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, Shield, CheckCircle2 } from 'lucide-react';
import { Severity } from '../../api/types';
import { cn } from '../../lib/cn';

type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'benign';

const variantClass: Record<BadgeVariant, string> = {
  critical: 'border-crit bg-crit-bg text-crit',
  high: 'border-high bg-high-bg text-high',
  medium: 'border-med bg-med-bg text-med',
  low: 'border-low bg-low-bg text-low',
  benign: 'border-benign bg-benign-bg text-benign',
};

interface SeverityBadgeProps {
  severity?: string | Severity | null;
  className?: string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity = 'LOW',
  className = '',
  size = 'md',
}) => {
  const norm = (severity || 'LOW').toUpperCase();

  const getIcon = () => {
    const iconSize = size === 'sm' ? 12 : 14;
    switch (norm) {
      case 'CRITICAL':
        return <ShieldAlert size={iconSize} />;
      case 'HIGH':
        return <AlertTriangle size={iconSize} />;
      case 'MEDIUM':
        return <AlertCircle size={iconSize} />;
      case 'BENIGN':
      case 'CLEAN':
      case 'LEGITIMATE':
        return <CheckCircle2 size={iconSize} />;
      case 'LOW':
      default:
        return <Shield size={iconSize} />;
    }
  };

  const getVariant = (): BadgeVariant => {
    switch (norm) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'BENIGN':
      case 'CLEAN':
      case 'LEGITIMATE':
        return 'benign';
      case 'LOW':
      default:
        return 'low';
    }
  };

  const variant = getVariant();

  return (
    <span
      className={cn(
        'inline-flex items-center gap-[0.35rem] rounded-none border border-transparent px-[0.6rem] py-[0.22rem] font-mono text-[0.72rem] font-bold tracking-[0.04em] whitespace-nowrap uppercase',
        variantClass[variant],
        size === 'sm' && 'px-[0.4rem] py-[0.15rem] text-[0.68rem]',
        className
      )}
      data-testid="severity-badge"
      data-severity={norm}
      data-variant={variant}
    >
      {getIcon()}
      <span>{norm}</span>
    </span>
  );
};
