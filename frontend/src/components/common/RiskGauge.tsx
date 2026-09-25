import React from 'react';
import { cn } from '../../lib/cn';

interface RiskGaugeProps {
  score: number;
  maxScore?: number;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
}

const tone = {
  CRITICAL: { text: 'text-crit', bar: 'bg-crit' },
  HIGH: { text: 'text-high', bar: 'bg-high' },
  MEDIUM: { text: 'text-med', bar: 'bg-med' },
  LOW: { text: 'text-low', bar: 'bg-low' },
  BENIGN: { text: 'text-benign', bar: 'bg-benign' },
};

const trackHeight = { sm: 'h-[6px]', md: 'h-[8px]', lg: 'h-[12px]' };

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  maxScore = 100,
  label = 'Risk',
  size = 'md',
}) => {
  const clamped = Math.max(0, Math.min(maxScore, score));
  const percent = Math.round((clamped / maxScore) * 100);

  const getSeverityLabel = (): keyof typeof tone => {
    if (clamped >= 85) return 'CRITICAL';
    if (clamped >= 60) return 'HIGH';
    if (clamped >= 35) return 'MEDIUM';
    if (clamped > 0) return 'LOW';
    return 'BENIGN';
  };

  const severity = getSeverityLabel();

  return (
    <div className="flex w-full flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-[0.72rem] text-fg-muted uppercase">
          {label}
        </span>
        <span className={cn('font-mono text-[0.85rem] font-bold', tone[severity].text)}>
          {clamped} / {maxScore} ({severity})
        </span>
      </div>
      <div
        className={cn(
          'relative w-full overflow-hidden rounded-[9999px] border border-line bg-elevated',
          trackHeight[size]
        )}
      >
        <div
          className={cn('h-full rounded-[9999px] [transition:width_0.3s_ease]', tone[severity].bar)}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
};
