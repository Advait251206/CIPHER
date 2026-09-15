import React, { ReactNode } from 'react';

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
      className={`stat-card ${variant}`}
      onClick={onClick}
      style={onClick ? { cursor: 'pointer' } : undefined}
      data-testid={`stat-card-${label.toLowerCase().replace(/\s+/g, '-')}`}
    >
      <div className="stat-card-top">
        <span className="stat-card-label">{label}</span>
        {icon && <div className="stat-card-icon">{icon}</div>}
      </div>
      <div className="stat-card-value">{value}</div>
      {subValue && <div className="stat-card-sub">{subValue}</div>}
    </div>
  );
};
