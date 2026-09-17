import React from 'react';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Activity,
  Flame,
  Network,
  Globe,
  Database,
  Sliders,
  ShieldAlert,
  Radio,
  HeartPulse,
  Shield,
  Mail,
} from 'lucide-react';
import { PreventionMode } from '../../api/types';

export type NavigationTab =
  | 'overview'
  | 'events'
  | 'incidents'
  | 'network'
  | 'phishing'
  | 'email'
  | 'threat-intel'
  | 'rules'
  | 'prevention'
  | 'sensor'
  | 'health';

interface SidebarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  openIncidentsCount?: number;
  sensorRunning?: boolean;
  preventionMode?: PreventionMode;
  backendConnected?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  openIncidentsCount = 0,
  sensorRunning = false,
  preventionMode = 'detect_only',
  backendConnected = true,
}) => {
  const navItems: Array<{
    id: NavigationTab;
    label: string;
    icon: React.ReactNode;
    badge?: React.ReactNode;
  }> = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <LayoutDashboard size={17} />,
    },
    {
      id: 'events',
      label: 'Live Events',
      icon: <Activity size={17} />,
    },
    {
      id: 'incidents',
      label: 'Incidents',
      icon: <Flame size={17} />,
      badge:
        openIncidentsCount > 0 ? (
          <span className="nav-badge danger">{openIncidentsCount}</span>
        ) : undefined,
    },

    {
      id: 'phishing',
      label: 'Phishing Detection',
      icon: <Globe size={17} />,
    },
    {
      id: 'email',
      label: 'Email Phishing',
      icon: <Mail size={17} />,
    },
    {
      id: 'threat-intel',
      label: 'Threat Intel / IOCs',
      icon: <Database size={17} />,
    },
    {
      id: 'rules',
      label: 'Detection Rules',
      icon: <Sliders size={17} />,
    },
    {
      id: 'prevention',
      label: 'Prevention / IPS',
      icon: <ShieldAlert size={17} />,
      badge: (
        <span className="nav-badge" style={{ fontSize: '0.65rem' }}>
          {preventionMode.replace('_', ' ')}
        </span>
      ),
    },
    {
      id: 'sensor',
      label: 'Network IDS (Live Sensor)',
      icon: <Radio size={17} />,
      badge: sensorRunning ? (
        <span className="nav-badge active" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
          <span className="pulse-dot" />
          LIVE
        </span>
      ) : undefined,
    },
    {
      id: 'health',
      label: 'System Health',
      icon: <HeartPulse size={17} />,
      badge: !backendConnected ? (
        <span className="nav-badge danger">OFFLINE</span>
      ) : undefined,
    },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">
          <Shield size={22} />
        </div>
        <div>
          <div className="brand-title">CIPHER</div>
          <div className="brand-sub">Unified Local IDPS Engine</div>
        </div>
      </div>

      <div style={{ padding: '0 1rem 0.5rem 1rem' }}>
        <div
          style={{
            background: 'var(--bg-surface-elevated)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '0.4rem 0.65rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.72rem',
            color: 'var(--text-secondary)',
          }}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
            <span className="pulse-dot" />
            Air-Gapped SOC
          </span>
          <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>v1.1.0019</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-title">Operations & Monitoring</div>
        {navItems.slice(0, 3).map((item) => (
          <motion.div
            key={item.id}
            whileHover={{ x: 3 }}
            whileTap={{ scale: 0.98 }}
            className={`nav-item ${currentTab === item.id ? 'active' : ''}`}
            onClick={() => onSelectTab(item.id)}
            role="button"
            tabIndex={0}
          >
            {currentTab === item.id && (
              <motion.div
                layoutId="sidebarActiveIndicator"
                className="sidebar-active-indicator"
                transition={{ type: 'spring', stiffness: 500, damping: 35 }}
              />
            )}
            <div className="nav-item-left">
              {item.icon}
              <span>{item.label}</span>
            </div>
            {item.badge}
          </motion.div>
        ))}

        <div className="nav-section-title">Detection & Intelligence</div>
        {navItems.slice(3, 7).map((item) => (
          <motion.div
            key={item.id}
            whileHover={{ x: 3 }}
            whileTap={{ scale: 0.98 }}
            className={`nav-item ${currentTab === item.id ? 'active' : ''}`}
            onClick={() => onSelectTab(item.id)}
            role="button"
            tabIndex={0}
          >
            {currentTab === item.id && (
              <motion.div
                layoutId="sidebarActiveIndicator"
                className="sidebar-active-indicator"
                transition={{ type: 'spring', stiffness: 500, damping: 35 }}
              />
            )}
            <div className="nav-item-left">
              {item.icon}
              <span>{item.label}</span>
            </div>
            {item.badge}
          </motion.div>
        ))}

        <div className="nav-section-title">Response & Infrastructure</div>
        {navItems.slice(7).map((item) => (
          <motion.div
            key={item.id}
            whileHover={{ x: 3 }}
            whileTap={{ scale: 0.98 }}
            className={`nav-item ${currentTab === item.id ? 'active' : ''}`}
            onClick={() => onSelectTab(item.id)}
            role="button"
            tabIndex={0}
          >
            {currentTab === item.id && (
              <motion.div
                layoutId="sidebarActiveIndicator"
                className="sidebar-active-indicator"
                transition={{ type: 'spring', stiffness: 500, damping: 35 }}
              />
            )}
            <div className="nav-item-left">
              {item.icon}
              <span>{item.label}</span>
            </div>
            {item.badge}
          </motion.div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="footer-status-row">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span
              className={`status-indicator ${backendConnected ? '' : 'offline'}`}
            />
            <span style={{ fontWeight: 500 }}>{backendConnected ? 'Backend Online' : 'Backend Offline'}</span>
          </div>
          <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>127.0.0.1</span>
        </div>
      </div>
    </aside>
  );
};
