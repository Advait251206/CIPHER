import React from 'react';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Activity,
  Flame,
  Network,
  Globe,
  Mail,
  Database,
  Sliders,
  ShieldAlert,
  Radio,
  HeartPulse,
  Shield,
} from 'lucide-react';
import { PreventionMode } from '../../api/types';

export type NavigationTab =
  | 'overview'
  | 'events'
  | 'incidents'
  | 'network_idps'
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
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={16} /> },
    { id: 'events', label: 'Security Events', icon: <Activity size={16} /> },
    { id: 'incidents', label: 'Incident Chains', icon: <Flame size={16} />, badge: openIncidentsCount > 0 ? <span className="nav-badge danger">{openIncidentsCount}</span> : undefined },
    { id: 'network_idps', label: 'Network IDPS', icon: <Network size={16} /> },
    { id: 'phishing', label: 'Phishing Detection', icon: <Globe size={16} /> },
    { id: 'email', label: 'Email Analyzer', icon: <Mail size={16} /> },
    { id: 'threat-intel', label: 'Threat Intel', icon: <Database size={16} /> },
    { id: 'rules', label: 'Detection Rules', icon: <Sliders size={16} /> },
    { id: 'prevention', label: 'Active Prevention', icon: <ShieldAlert size={16} />, badge: <span className="nav-badge" style={{ fontSize: '0.65rem' }}>{preventionMode.replace('_', ' ')}</span> },
    { id: 'sensor', label: 'Network IDS', icon: <Radio size={16} />, badge: sensorRunning ? <span className="nav-badge active" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><span className="pulse-dot" />LIVE</span> : undefined },
    { id: 'health', label: 'System Health', icon: <HeartPulse size={16} />, badge: !backendConnected ? <span className="nav-badge danger">OFFLINE</span> : undefined },
  ];

  return (
    <aside style={{
      width: '260px',
      background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border-subtle)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      flexShrink: 0
    }}>
      <div style={{
        padding: '1.5rem 1.25rem',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        borderBottom: '1px solid var(--border-subtle)'
      }}>
        <div style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield size={24} />
        </div>
        <div>
          <div style={{ fontSize: '1rem', fontWeight: 700, letterSpacing: '0.05em', color: 'var(--text-primary)' }}>CIPHER | SOC</div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Local IDPS Engine</div>
        </div>
      </div>

      <nav style={{ flex: 1, overflowY: 'auto', padding: '1.5rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {navItems.map((item) => {
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.75rem 1rem',
                width: '100%',
                background: isActive ? 'var(--bg-card-hover)' : 'transparent',
                border: 'none',
                borderLeft: isActive ? '3px solid var(--border-accent)' : '3px solid transparent',
                borderRadius: '0 4px 4px 0',
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontSize: '0.8rem',
                fontWeight: isActive ? 600 : 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                textAlign: 'left'
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.color = 'var(--text-primary)';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.color = 'var(--text-secondary)';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span style={{ color: isActive ? 'var(--border-accent)' : 'inherit' }}>{item.icon}</span>
                {item.label}
              </div>
              {item.badge && item.badge}
            </button>
          );
        })}
      </nav>
      
      <div style={{ padding: '1rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'center' }}>
        v1.2.0021
      </div>
    </aside>
  );
};
