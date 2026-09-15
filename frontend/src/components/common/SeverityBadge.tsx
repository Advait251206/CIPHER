import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, Shield, CheckCircle2 } from 'lucide-react';
import { Severity } from '../../api/types';

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

  const getStyleClass = () => {
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

  return (
    <span
      className={`severity-badge ${getStyleClass()} ${className}`}
      data-testid="severity-badge"
      data-severity={norm}
      style={size === 'sm' ? { fontSize: '0.68rem', padding: '0.15rem 0.4rem' } : undefined}
    >
      {getIcon()}
      <span>{norm}</span>
    </span>
  );
};
