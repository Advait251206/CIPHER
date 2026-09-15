import React, { useState, useEffect, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Sidebar, NavigationTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewPage } from './pages/OverviewPage';
import { LiveEventsPage } from './pages/LiveEventsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { NetworkIdsPage } from './pages/NetworkIdsPage';
import { PhishingPage } from './pages/PhishingPage';
import { EmailPage } from './pages/EmailPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { PreventionPage } from './pages/PreventionPage';
import { SensorPage } from './pages/SensorPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { ExtensionModal } from './components/common/ExtensionModal';
import { api } from './api/client';
import { Severity, PreventionMode } from './api/types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavigationTab>('overview');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
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
        setSensorRunning(Boolean(sensorRes.value.running ?? sensorRes.value.is_running));
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
    
    // Live update interval: 2 seconds
    const LIVE_POLLING_INTERVAL = 2000;
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
          title: 'Live Security Events Log',
          subtitle: 'Unified detection stream across Network IDS, Phishing analyzer, and deterministic rules',
        };
      case 'incidents':
        return {
          title: 'Incident Correlation Manager',
          subtitle: 'Multi-event correlated attack chains and escalation detection',
        };
      case 'network':
        return {
          title: 'Network Intrusion Detection System',
          subtitle: 'Dual Random Forest ML pipeline (CIC-IDS2017) & flow analysis sandbox',
        };
      case 'phishing':
        return {
          title: 'Phishing Threat Detector',
          subtitle: '28-feature Random Forest ML classification & local URL heuristic inspection',
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
          title: 'Live Network Packet Sensor',
          subtitle: 'Scapy / Npcap flow aggregation into CIC-compatible 67-feature vectors',
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

  const { title, subtitle } = getPageMeta();

  return (
    <div className="app-container">
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

      <div className="main-content">
        <Header
          title={title}
          subtitle={subtitle}
          threatLevel={threatLevel}
          onOpenExtensionModal={() => setIsExtensionModalOpen(true)}
        />

        <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <AnimatePresence mode="wait">
            <motion.div
              key={currentTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2, ease: [0.25, 0.1, 0.25, 1] as const }}
              style={{ flex: 1, display: 'flex', flexDirection: 'column' }}
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
                <LiveEventsPage
                  onSelectIncident={(incId) => {
                    setSelectedIncidentId(incId);
                    setCurrentTab('incidents');
                  }}
                  refreshTrigger={refreshKey}
                />
              )}

              {currentTab === 'incidents' && (
                <IncidentsPage initialIncidentId={selectedIncidentId} refreshTrigger={refreshKey} />
              )}

              {currentTab === 'network' && <NetworkIdsPage />}

              {currentTab === 'phishing' && <PhishingPage />}

              {currentTab === 'email' && <EmailPage />}

              {currentTab === 'threat-intel' && <ThreatIntelPage />}

              {currentTab === 'rules' && <DetectionRulesPage />}

              {currentTab === 'prevention' && <PreventionPage />}

              {currentTab === 'sensor' && <SensorPage refreshTrigger={refreshKey} />}

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
