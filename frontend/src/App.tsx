import React, { useState, useEffect, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Sidebar, NavigationTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewPage } from './pages/OverviewPage';
import { SecurityEventsPage } from './pages/SecurityEventsPage';
import { IncidentChainsPage } from './pages/IncidentChainsPage';

import { PhishingPage } from './pages/PhishingPage';
import { EmailPage } from './pages/EmailPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { PreventionPage } from './pages/PreventionPage';
import { SensorPage } from './pages/SensorPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { UsersPage } from './pages/UsersPage';
import { ExtensionModal } from './components/common/ExtensionModal';
import { api } from './api/client';
import { Severity, PreventionMode } from './api/types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavigationTab>(() => {
    const saved = localStorage.getItem('cipher_current_tab');
    return (saved as NavigationTab) || 'overview';
  });
  
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(() => {
    return localStorage.getItem('cipher_selected_incident');
  });

  useEffect(() => {
    localStorage.setItem('cipher_current_tab', currentTab);
  }, [currentTab]);

  useEffect(() => {
    if (selectedIncidentId) {
      localStorage.setItem('cipher_selected_incident', selectedIncidentId);
    } else {
      localStorage.removeItem('cipher_selected_incident');
    }
  }, [selectedIncidentId]);

  const [isExtensionModalOpen, setIsExtensionModalOpen] = useState(false);

  // Global telemetry
  const [backendConnected, setBackendConnected] = useState(true);
  const [threatLevel, setThreatLevel] = useState<Severity>('LOW');
  const [openIncidentsCount, setOpenIncidentsCount] = useState(0);
  const [sensorRunning, setSensorRunning] = useState(false);
  const [preventionMode, setPreventionMode] = useState<PreventionMode>('detect_only');

  // Live Refresh
  const [refreshKey, setRefreshKey] = useState(0);

  const fetchGlobalStatus = useCallback(async () => {
    try {
      const [healthRes, corrStatsRes, sensorRes, netHealthRes] = await Promise.allSettled([
        api.health.getHealth(),
        api.incidents.getStats(),
        api.network.getSensorStatus(),
        api.network.getHealth(),
      ]);

      if (healthRes.status === 'fulfilled' || netHealthRes.status === 'fulfilled') {
        setBackendConnected(true);
      } else {
        setBackendConnected(false);
      }

      if (corrStatsRes.status === 'fulfilled') {
        const stats = corrStatsRes.value;
        setOpenIncidentsCount(stats.open_incidents);

        // Derive highest active threat level
        if (stats.incidents_by_severity?.CRITICAL && stats.incidents_by_severity.CRITICAL > 0) {
          setThreatLevel('CRITICAL');
        } else if (stats.incidents_by_severity?.HIGH && stats.incidents_by_severity.HIGH > 0) {
          setThreatLevel('HIGH');
        } else if (stats.incidents_by_severity?.MEDIUM && stats.incidents_by_severity.MEDIUM > 0) {
          setThreatLevel('MEDIUM');
        } else {
          setThreatLevel('LOW');
        }
      }

      if (sensorRes.status === 'fulfilled') {
        setSensorRunning(Boolean(sensorRes.value.running));
      }

      if (netHealthRes.status === 'fulfilled') {
        setPreventionMode(netHealthRes.value.prevention_mode || 'detect_only');
      }

    } catch {
      setBackendConnected(false);
    }
  }, []);

  // Initial fetch and fast LIVE polling
  useEffect(() => {
    fetchGlobalStatus();
    
    // Live update interval: 5 seconds
    const LIVE_POLLING_INTERVAL = 5000;
    const intervalId = setInterval(() => {
      fetchGlobalStatus();
      setRefreshKey((k) => k + 1);
    }, LIVE_POLLING_INTERVAL);
    
    return () => clearInterval(intervalId);
  }, [fetchGlobalStatus]);

  const getPageMeta = (): { title: string; subtitle: string } => {
    switch (currentTab) {
      case 'overview':
        return {
          title: 'Cybersecurity Operations Overview',
          subtitle: 'Real-time telemetry across intrusion prevention, threat scoring, and heuristic correlation',
        };
      case 'events':
        return {
          title: 'Security Events Log',
          subtitle: 'Detailed data table showing raw security events',
        };
      case 'incidents':
        return {
          title: 'Incident Chains',
          subtitle: 'Correlated threats with Risk Score and action resolution',
        };
      case 'phishing':
        return {
          title: 'Phishing Threat Detector',
          subtitle: '15-feature Random Forest ML classification & local URL heuristic inspection',
        };
      case 'email':
        return {
          title: 'Email Phishing & Threat Inspector',
          subtitle: '32-feature Random Forest ML classification, explainable evidence & Browser Guard',
        };
      case 'threat-intel':
        return {
          title: 'Threat Intelligence & IOC Store',
          subtitle: 'Local SQLite repository for IP, domain, URL, and hash indicators',
        };
      case 'rules':
        return {
          title: 'Deterministic Detection Rules',
          subtitle: 'Inspect and configure heuristic & signature rules with threshold controls',
        };
      case 'prevention':
        return {
          title: 'Intrusion Prevention & Blocklist',
          subtitle: 'Active IPS enforcement mode, temporary blocklist, and automated TTL expiration',
        };
      case 'sensor':
        return {
          title: 'Network IDS (Live Sensor)',
          subtitle: 'Real-time flow aggregation into CIC-compatible 67-feature vectors for ML inference',
        };
      case 'health':
        return {
          title: 'System Diagnostics & Engine Health',
          subtitle: 'Component liveness, local model parameters, and database connectivity',
        };
      default:
        return { title: 'CIPHER Security', subtitle: 'Cyber Intrusion Prevention & Heuristic Event Response' };
    }
  };

  const handleSetMode = async (newMode: 'detect_only' | 'enforce') => {
    try {
      await api.network.setPreventionMode(newMode);
      setPreventionMode(newMode);
      // Trigger immediate global refresh
      setRefreshKey((k) => k + 1);
      fetchGlobalStatus();
    } catch (err) {
      console.error('Failed to update prevention mode:', err);
    }
  };

  const { title, subtitle } = getPageMeta();

  return (
    <div className="flex h-full w-full">
      <Sidebar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          setCurrentTab(tab);
          if (tab !== 'incidents') {
            setSelectedIncidentId(null);
          }
        }}
        openIncidentsCount={openIncidentsCount}
        sensorRunning={sensorRunning}
        preventionMode={preventionMode}
        backendConnected={backendConnected}
      />

      <div className="flex h-full flex-1 flex-col overflow-y-auto bg-app">
        <Header
          title={title}
          subtitle={subtitle}
          threatLevel={threatLevel}
          preventionMode={preventionMode}
          onModeToggle={() => handleSetMode(preventionMode === 'detect_only' ? 'enforce' : 'detect_only')}
        />

        <main className="flex-1 flex flex-col">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2, ease: [0.25, 0.1, 0.25, 1] as const }}
              className="flex-1 flex flex-col"
            >
              {currentTab === 'overview' && (
                <OverviewPage
                  onNavigate={(tab) => setCurrentTab(tab)}
                  onSelectIncident={(incId) => {
                    setSelectedIncidentId(incId);
                    setCurrentTab('incidents');
                  }}
                  refreshTrigger={refreshKey}
                  onOpenExtensionModal={() => setIsExtensionModalOpen(true)}
                />
              )}

              {currentTab === 'events' && (
                <SecurityEventsPage
                  onSelectIncident={(incId) => {
                    setSelectedIncidentId(incId);
                    setCurrentTab('incidents');
                  }}
                  refreshTrigger={refreshKey}
                />
              )}

              {currentTab === 'incidents' && (
                <IncidentChainsPage initialIncidentId={selectedIncidentId} refreshTrigger={refreshKey} />
              )}

              {currentTab === 'phishing' && <PhishingPage />}

              {currentTab === 'email' && <EmailPage />}

              {currentTab === 'threat-intel' && <ThreatIntelPage />}

              {currentTab === 'rules' && <DetectionRulesPage />}

              {currentTab === 'prevention' && <PreventionPage refreshTrigger={refreshKey} onSetMode={handleSetMode} />}

              {currentTab === 'sensor' && <SensorPage />}

              {currentTab === 'users' && <UsersPage />}

              {currentTab === 'health' && <SystemHealthPage />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <ExtensionModal
        isOpen={isExtensionModalOpen}
        onClose={() => setIsExtensionModalOpen(false)}
      />
    </div>
  );
};

export default App;
