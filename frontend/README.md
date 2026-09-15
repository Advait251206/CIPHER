# CIPHER SOC Operations Dashboard

The **CIPHER SOC Dashboard** is a modern, responsive single-page application engineered to provide real-time visibility, telemetry analysis, and incident management for the CIPHER (Cyber Intrusion Prevention & Heuristic Event Response) security engine.

---

## Technology Stack
- **Framework**: React 18.3
- **Language**: TypeScript 5.6
- **Build Tool**: Vite 6.4
- **Styling**: Vanilla CSS Design Tokens (Dark Cybersecurity Aesthetic, Glassmorphism, Monospace Metrics)
- **Testing**: Vitest + React Testing Library

---

## Ten Operational Views

1. **Overview** (`OverviewPage.tsx`): 8 KPI counters, active incidents feed, attack distribution charts, and live subsystem status cards.
2. **Live Events** (`LiveEventsPage.tsx`): Unified security event stream, filtering, auto-refresh, and structured evidence modals.
3. **Incidents** (`IncidentsPage.tsx`): Correlated multi-stage attack chains, escalation badges, event timeline, and resolution workflows.
4. **Network IDS** (`NetworkIdsPage.tsx`): Dual Random Forest model metrics, feature importances, and interactive flow evaluation sandbox.
5. **Phishing** (`PhishingPage.tsx`): URL analysis interface with presets, 28-feature lexical inspection, risk gauge, and security guidance.
6. **Threat Intelligence** (`ThreatIntelPage.tsx`): SQLite IOC repository management, instant indicator search, active/disabled toggles, and bulk import.
7. **Detection Rules** (`DetectionRulesPage.tsx`): 14 heuristic and signature rules, live toggle controls, and rule evaluation sandbox.
8. **Prevention** (`PreventionPage.tsx`): Authoritative IPS mode governance (`detect_only`, `simulate`, `enforce`) and active blocklist table.
9. **Live Sensor** (`SensorPage.tsx`): Npcap packet capture telemetry, interface selector, BPF filter input, and start/stop sniffer controls.
10. **System Health** (`SystemHealthPage.tsx`): Operational health checks across all backend subsystems and model artifacts.

---

## Setup & Execution

### Prerequisites
- Node.js 18+ (Node.js 20+ recommended)
- CIPHER backend running on `http://127.0.0.1:8000`

### 1. Install Dependencies
```bash
npm install
```

### 2. Development Server (with API Proxy)
```bash
npm run dev
```
The application will launch on `http://localhost:5173`. Requests to `/api/*` are automatically proxied to the backend at `http://127.0.0.1:8000`.

### 3. Run Automated Tests
```bash
npm run test
```

### 4. Build Production Bundle
```bash
npx tsc --noEmit
npm run build
```
Production assets are compiled into the `dist/` directory.

---

## Local Privacy Guarantee
The dashboard displays the authoritative local-first privacy statement:
> *"Analysis is performed locally on this machine. CIPHER does not automatically transmit submitted indicators to external services."*
