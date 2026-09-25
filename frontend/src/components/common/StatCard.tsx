import React, { ReactNode } from 'react';
import { cn } from '../../lib/cn';

const tone = {
  critical: { border: 'border-crit', value: 'text-crit', icon: 'border-crit bg-crit-bg text-crit' },
  high: { border: 'border-high', value: 'text-high', icon: 'border-high bg-high-bg text-high' },
  medium: { border: 'border-med', value: 'text-med', icon: 'border-med bg-med-bg text-med' },
  low: { border: 'border-low', value: 'text-low', icon: 'border-low bg-low-bg text-low' },
};

interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon?: ReactNode;
  variant?: 'normal' | 'critical' | 'high' | 'medium' | 'low';
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subValue,
  icon,
  variant = 'normal',
  onClick,
}) => {
  return (
    <div
      className={cn(
        'group relative flex flex-col justify-between gap-2 overflow-hidden rounded-none border border-line-card bg-card p-5',
        '[transition:all_0.2s_cubic-bezier(0.4,0,0.2,1)] hover:transform-[translateY(-2px)]',
        // .stat-card.<variant> follows .stat-card:hover in the old stylesheet, so
        // coloured cards keep their border on hover; only 'normal' changes it.
        variant === 'normal' ? 'hover:border-elevated' : cn('bg-app', tone[variant].border),
        onClick && 'cursor-pointer'
      )}
      onClick={onClick}
      data-testid={`stat-card-${label.toLowerCase().replace(/\s+/g, '-')}`}
    >
      <div className="flex items-center justify-between text-fg-muted">
        <span className="text-[0.74rem] font-bold tracking-[0.05em] text-fg-muted uppercase">{label}</span>
        {icon && (
          <div
            className={cn(
              'flex size-[32px] items-center justify-center rounded-none border border-line bg-elevated text-fg-2 [transition:all_0.15s_ease] group-hover:transform-[scale(1.08)]',
              variant !== 'normal' && tone[variant].icon
            )}
          >
            {icon}
          </div>
        )}
      </div>
      <div className={cn('font-mono text-[1.9rem] leading-[1.1] font-extrabold tracking-[-0.02em] text-fg', variant !== 'normal' && tone[variant].value)}>{value}</div>
      {subValue && <div className="text-[0.75rem] text-fg-muted">{subValue}</div>}
    </div>
  );
};
