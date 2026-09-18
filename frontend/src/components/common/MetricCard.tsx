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
    <div 
      style={{
        background: 'var(--bg-surface)',
        border: `1px solid var(--border-subtle)`,
        borderTop: highlight ? '3px solid var(--border-accent)' : '3px solid var(--border-subtle)',
        borderRadius: '6px',
        padding: '1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.75rem',
        position: 'relative',
        overflow: 'hidden',
        transition: 'transform 0.15s ease, border-color 0.15s ease'
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'translateY(-2px)';
        if (!highlight) e.currentTarget.style.borderTopColor = '#666';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'translateY(0)';
        if (!highlight) e.currentTarget.style.borderTopColor = 'var(--border-subtle)';
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
        <h4 style={{ margin: 0, fontSize: '0.85rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {title}
        </h4>
        {icon && <div style={{ color: highlight ? 'var(--border-accent)' : 'var(--text-muted)' }}>{icon}</div>}
      </div>

      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '0.75rem', marginTop: '0.25rem' }}>
        <span style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1, letterSpacing: '-0.02em' }}>
          {value}
        </span>
        {trend && (
          <span style={{ 
            fontSize: '0.8rem', 
            fontWeight: 600, 
            color: trend.isPositive ? 'var(--benign-color)' : 'var(--crit-color)',
            marginBottom: '6px'
          }}>
            {trend.isPositive ? '▲' : '▼'} {trend.value}% {trend.label}
          </span>
        )}
      </div>

      {subtitle && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 'auto' }}>
          {subtitle}
        </div>
      )}
    </div>
  );
};
