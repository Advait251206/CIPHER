import React from 'react';
import { cn } from '../../lib/cn';

interface MetricCardProps {
  title: string;
  value: string | number;
  icon?: React.ReactNode;
  subtitle?: string;
  trend?: {
    value: number;
    label: string;
    isPositive: boolean;
  };
  highlight?: boolean;
}

export const MetricCard: React.FC<MetricCardProps> = ({ title, value, icon, subtitle, trend, highlight }) => {
  return (
    <div
      className={cn(
        'relative flex flex-col gap-3 overflow-hidden rounded-[6px] border border-t-[3px] border-line bg-surface p-6',
        '[transition:transform_0.15s_ease,border-color_0.15s_ease] hover:transform-[translateY(-2px)]',
        highlight ? 'border-t-accent' : 'hover:border-t-[#666]'
      )}
    >
      <div className="flex items-center justify-between text-fg-2">
        <h4 className="text-[0.85rem] font-semibold tracking-wider uppercase">
          {title}
        </h4>
        {icon && <div className={highlight ? 'text-accent' : 'text-fg-muted'}>{icon}</div>}
      </div>

      <div className="mt-1 flex items-end gap-3">
        <span className="text-[2.5rem] leading-none font-bold tracking-[-0.02em] text-fg">
          {value}
        </span>
        {trend && (
          <span className={cn('mb-[6px] text-[0.8rem] font-semibold', trend.isPositive ? 'text-benign' : 'text-crit')}>
            {trend.isPositive ? '▲' : '▼'} {trend.value}% {trend.label}
          </span>
        )}
      </div>

      {subtitle && (
        <div className="mt-auto text-[0.75rem] text-fg-muted">
          {subtitle}
        </div>
      )}
    </div>
  );
};
