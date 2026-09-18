import React from 'react';

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
    <div style={{
      background: 'var(--bg-surface)',
      border: `1px solid ${highlight ? 'var(--border-accent)' : 'var(--border-subtle)'}`,
      borderRadius: '6px',
      padding: '1.25rem',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.5rem',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {highlight && (
        <div style={{ position: 'absolute', top: 0, left: 0, width: '4px', height: '100%', background: 'var(--border-accent)' }} />
      )}
      
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
        <h4 style={{ margin: 0, fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {title}
        </h4>
        {icon && <div style={{ opacity: 0.7 }}>{icon}</div>}
      </div>

      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '0.75rem' }}>
        <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
          {value}
        </span>
        {trend && (
          <span style={{ 
            fontSize: '0.75rem', 
            fontWeight: 600, 
            color: trend.isPositive ? 'var(--benign-color)' : 'var(--crit-color)',
            marginBottom: '4px'
          }}>
            {trend.isPositive ? '↑' : '↓'} {trend.value}% {trend.label}
          </span>
        )}
      </div>

      {subtitle && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {subtitle}
        </div>
      )}
    </div>
  );
};
