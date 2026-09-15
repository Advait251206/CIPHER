import React from 'react';

interface RiskGaugeProps {
  score: number;
  maxScore?: number;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  maxScore = 100,
  label = 'Risk',
  size = 'md',
}) => {
  const clamped = Math.max(0, Math.min(maxScore, score));
  const percent = Math.round((clamped / maxScore) * 100);

  const getColor = () => {
    if (clamped >= 85) return 'var(--crit-color)';
    if (clamped >= 60) return 'var(--high-color)';
    if (clamped >= 35) return 'var(--med-color)';
    if (clamped > 0) return 'var(--low-color)';
    return 'var(--benign-color)';
  };

  const getSeverityLabel = () => {
    if (clamped >= 85) return 'CRITICAL';
    if (clamped >= 60) return 'HIGH';
    if (clamped >= 35) return 'MEDIUM';
    if (clamped > 0) return 'LOW';
    return 'BENIGN';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
          {label}
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.85rem', color: getColor() }}>
          {clamped} / {maxScore} ({getSeverityLabel()})
        </span>
      </div>
      <div
        style={{
          width: '100%',
          height: size === 'sm' ? '6px' : size === 'lg' ? '12px' : '8px',
          background: 'var(--bg-surface-elevated)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '9999px',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        <div
          style={{
            height: '100%',
            width: `${percent}%`,
            background: getColor(),
            borderRadius: '9999px',
            transition: 'width 0.3s ease',
          }}
        />
      </div>
    </div>
  );
};
