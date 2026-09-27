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
import { cn } from '../../lib/cn';
import { navBadge } from '../../ui/classes';


export type NavigationTab =
  | 'overview'
  | 'events'
  | 'incidents'
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
    { id: 'incidents', label: 'Incident Chains', icon: <Flame size={16} />, badge: openIncidentsCount > 0 ? <span className={navBadge('danger')}>{openIncidentsCount}</span> : undefined },
    { id: 'phishing', label: 'Phishing Detection', icon: <Globe size={16} /> },
    { id: 'email', label: 'Email Analyzer', icon: <Mail size={16} /> },
    { id: 'threat-intel', label: 'Threat Intel', icon: <Database size={16} /> },
    { id: 'rules', label: 'Detection Rules', icon: <Sliders size={16} /> },
    { id: 'prevention', label: 'Active Prevention', icon: <ShieldAlert size={16} />, badge: <span className={navBadge('neutral', 'text-[0.65rem]')}>{preventionMode.replace('_', ' ')}</span> },
    { id: 'sensor', label: 'Network IDS', icon: <Radio size={16} />, badge: sensorRunning ? <span className={navBadge('active', 'flex items-center gap-[5px]')}><span className="inline-block size-[8px] animate-pulse-green rounded-[50%] bg-benign" />LIVE</span> : undefined },
    { id: 'health', label: 'System Health', icon: <HeartPulse size={16} />, badge: !backendConnected ? <span className={navBadge('danger')}>OFFLINE</span> : undefined },
  ];

  return (
    <aside className="flex h-screen w-[260px] shrink-0 flex-col border-r border-r-line bg-sidebar">
      <div className="flex items-center gap-3 border-b border-b-line px-5 py-6">
        <div className="flex items-center justify-center text-fg">
          <Shield size={24} />
        </div>
        <div>
          <div className="text-[1rem] font-bold tracking-wider text-fg">CIPHER | SOC</div>
          <div className="text-[0.65rem] text-fg-muted uppercase">Local IDPS Engine</div>
        </div>
      </div>

      <nav className="flex flex-1 flex-col gap-1 overflow-y-auto px-4 py-6">
        {navItems.map((item) => {
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={cn(
                'flex w-full cursor-pointer items-center justify-between rounded-[0_4px_4px_0] border-0 border-l-[3px] border-solid px-4 py-3 text-left text-[0.8rem] [transition:all_0.15s_ease]',
                isActive
                  ? 'border-l-accent bg-card-hover font-semibold text-fg'
                  : 'border-l-transparent bg-transparent font-medium text-fg-2 hover:text-fg'
              )}
            >
              <div className="flex items-center gap-3">
                <span className={isActive ? 'text-accent' : undefined}>{item.icon}</span>
                {item.label}
              </div>
              {item.badge && item.badge}
            </button>
          );
        })}
      </nav>

      <div className="border-t border-t-line p-4 text-center text-[0.7rem] text-fg-muted">
        v1.2.0022
      </div>
    </aside>
  );
};
