# CIPHER: Cyber Intrusion Prevention & Heuristic Event Response

[![Backend Tests](https://img.shields.io/badge/backend%20tests-152%20passed-success)](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/backend/tests)
[![Frontend Tests](https://img.shields.io/badge/frontend%20tests-11%20passed-success)](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/frontend/src/test)
[![Validation](https://img.shields.io/badge/validation%20(A--H)-8%2F8%20passed-blue)](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/validation.md)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20local--first-green)](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/architecture.md)

---

## Overview

**CIPHER** (*Cyber Intrusion Prevention & Heuristic Event Response*) is an integrated, local-first cybersecurity platform that unites machine learning detection, deterministic heuristic/signature evaluation, local threat intelligence, multi-stage event correlation, calibrated threat scoring, and automated defensive prevention. Designed for host and edge environments, CIPHER operates **100% locally on `127.0.0.1`** with zero external cloud API dependencies, eliminating telemetry leakage and third-party exposure.

The platform provides dual-domain threat visibility: inspecting suspicious web indicators via a static 28-feature Random Forest phishing detector trained on PhiUSIIL, while concurrently ingesting raw network packets through an Npcap live sensor and analyzing flow statistics via a Dual Random Forest network intrusion detection system trained on 2.49 million deduplicated flows from CIC-IDS2017. A modern dark-themed SOC operations dashboard developed in React 18, TypeScript, and Vite provides real-time telemetry, interactive sandboxes, incident lifecycle tracking, and evidence inspection.

---

## Problem Statement

Contemporary enterprise security environments are hindered by three critical structural flaws:
1. **Tool Sprawl & Blind Spots**: Phishing filters, network sensors, and threat feeds operate in isolated silos, requiring analysts to manually correlate disjointed alerts.
2. **Cloud Privacy Hazards**: Many commercial threat analysis tools transmit internal URLs, sensitive IP addresses, and proprietary metadata to cloud APIs, violating regulatory privacy mandates (e.g., GDPR, HIPAA) and revealing internal architecture to external services.
3. **Alert Fatigue & Destructive Prevention**: Single-event alert floods overwhelm SOC teams without kill-chain context, while poorly calibrated automated prevention mechanisms risk business disruption by blocking legitimate traffic during operational bursts.

---

## Objectives

CIPHER fulfills eight core technical objectives:
- **Network Intrusion Detection**: Real-time statistical flow classification across 8 attack categories (DoS, DDoS, PortScan, BruteForce, Botnet, Web Attacks, Infiltration, Heartbleed).
- **Phishing URL Detection**: Sub-millisecond static URL inspection across 28 lexical, structural, and information-theoretic features without active web crawling.
- **Deterministic Heuristic & Signature Detection**: 14 stateful rules operating alongside ML to guarantee deterministic detection of horizontal scans, credential storms, and volumetric floods.
- **Threat Intelligence Correlation**: Local-first SQLite IOC store (`threat_intel_iocs`) with in-memory caching and dominant severity risk floors.
- **Multi-Stage Event Correlation**: Sliding-window (300s) incident correlation linking related events using strict `(source_ip, destination_ip)` identity pairing with automated escalation tracking.
- **Incident Management**: State transitions (`ACTIVE`, `INVESTIGATING`, `RESOLVED`), chronological timeline reconstruction, and official PDF/TXT incident reporting.
- **Defensive Intrusion Prevention**: Multi-mode defense (`detect_only`, `simulate`, `enforce`) with TTL blocklists and flow rate limiting.
- **SOC Visualization**: Comprehensive React 18 / TypeScript single-page dashboard with 10 operational views and structured evidence inspection.

---

## Architecture

```text
Attack / Test Traffic               Suspicious URLs
         │                                 │
  [ Live Sensor / Npcap ]                  │
  (50k Active Flow Table)                  │
         │                                 │
67-Feature Flow Extraction        28-Feature URL Extractor
         │                                 │
┌────────┴────────┐               ┌────────┴────────┐
│  Network ML:    │               │  Phishing ML:   │
│ Dual RF Models  │               │  Random Forest  │
└────────┬────────┘               └────────┬────────┘
         │                                 │
┌────────┴────────┐               ┌────────┴────────┐
│ Deterministic   │               │ Lexical / Brand │
│ Rules (10+4)    │               │ Heuristics      │
└────────┬────────┘               └────────┬────────┘
         │                                 │
         └────────────────┬────────────────┘
                          │
          Local Threat Intelligence (SQLite IOC Store)
                          │
             Calibrated ThreatScorer (0–100)
                          │
          Multi-Stage Event Correlation Engine
                 (300s Sliding Window)
                          │
             Incident Lifecycle Manager
                          │
             Intrusion Prevention Engine
          (detect_only | simulate | enforce)
                          │
             SQLite Unified Security Database
                          │
             FastAPI REST API Gateway (Port 8000)
                          │
             SOC Operations Dashboard (Port 5173)
```

---

## Major Components

| Component | Technology | Primary Function |
|:---|:---|:---|
| **Phishing Detector** | Scikit-Learn Random Forest | 28 static lexical features; 99.66% accuracy on PhiUSIIL test set; hybrid approach with Tranco Top 50,000 domain whitelist to prevent false positives. |
| **Browser Guard** | Chrome/Edge Extension | 100% local, air-gapped browser extension that connects directly to `localhost:8000` to scan active tabs in real-time. |
| **Network IDS** | Dual Random Forest Ensemble | Binary gate + 9-class multiclass classifier; 67 flow features; 99.90% accuracy on CIC-IDS2017. |
| **Live Network Sensor** | Scapy + Npcap Async Sniffer | Captures raw packets; tracks 50,000 flows; 5s idle / 60s active eviction timers. |
| **Rule Engine** | Stateful Heuristics & Signatures | 10 heuristics (PortScan, BruteForce, DoS) + 4 signatures; 10,000-entry sliding-window trackers. |
| **Threat Intelligence** | SQLite + Thread-Safe LRU Cache | In-process matching for IP, Domain, URL, Hash; 5,000-entry cache; dominant severity floor. |
| **Event Correlator** | Sliding-Window Correlator | Identity pairing `(src_ip, dst_ip)`; 300s window; detects reconnaissance $\to$ exploitation escalation. |
| **Prevention Engine** | State Engine + Rate Limiter | Multi-mode (`detect_only`, `simulate`, `enforce`); TTL blocklist with dynamic countdowns. |
| **SOC Dashboard** | React 18 + TypeScript + Vite | 10 operational views; dark cybersecurity design system; same-origin API proxy. |

---

## Technology Stack

### Backend
- **Language**: Python 3.13
- **Framework**: FastAPI 0.115, Pydantic v2, Uvicorn
- **Machine Learning**: Scikit-Learn 1.6, NumPy, Pandas, Joblib
- **Packet Capture**: Scapy 2.6, Npcap
- **Database**: SQLite3 (WAL mode, composite indexing)
- **Testing**: Pytest 9.1

### Frontend
- **Framework**: React 18.3
- **Language**: TypeScript 5.6
- **Build Tool**: Vite 6.4
- **Styling**: Vanilla CSS Design Tokens (Dark SOC Aesthetic, Glassmorphism, Monospace Metrics)
- **Testing**: Vitest 3.2 + React Testing Library

---

## Installation & Setup

### Prerequisites
- Python 3.11+ (Python 3.13 verified)
- Node.js 18+ (Node.js 20+ verified)
- Npcap (required only for live network packet sniffing; all synthetic and API tests run without Npcap)

### 1. Clone & Setup Backend
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
```

### 2. Setup Frontend
```powershell
cd ../frontend
npm install
```

---

## Running the System

### Terminal 1: Backend Server (FastAPI)
```powershell
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
*API documentation will be accessible at `http://127.0.0.1:8000/docs`.*

### Terminal 2: Frontend Dashboard (Vite)
```powershell
cd frontend
npm run dev
```
*SOC Dashboard will launch at `http://localhost:5173`.*

---

## Running Automated Tests

### Backend Test Suite (Pytest)
```powershell
cd backend
pytest tests/ -v
```
**Verified Result**: **152 passed** in ~13 seconds across 13 test modules.

### Frontend Test Suite & Production Build (Vitest & Vite)
```powershell
cd frontend
npm run test
npx tsc --noEmit
npm run build
```
**Verified Result**: **11 passed** in ~1.3 seconds, 0 TypeScript errors, production bundle compiled cleanly in 1.34 seconds.

---

## Phase 10 Controlled Local Validation

CIPHER includes an automated, local-only validation suite that executes 8 comprehensive end-to-end scenarios (A through H):

```powershell
cd backend
python -m scripts.phase10_validation.runner
```

### Scenario Results Matrix
| Scenario | Name | Traffic Classification | Status | Result / Key Evidence |
|:---:|:---|:---|:---:|:---|
| **A** | Benign Localhost Traffic | `REAL LOCAL TRAFFIC` | **PASS** | 5 genuine HTTP flows. Classified as `BENIGN` (score 4/100, `LOW`, ML confidence 86.5%). Zero false critical alerts. |
| **B** | Port Scan Sweep | `REAL LOCAL TRAFFIC` | **PASS** | 12 bounded connection probes across loopback ports 18010–18021. Triggered `HEUR-PORTSCAN-001` & `HEUR-PORTSCAN-002` (score 80/100, `CRITICAL`). |
| **C** | Auth-Storm / Brute-Force | `REAL LOCAL TRAFFIC + METADATA` | **PASS** | 6 bounded connections to port 22. Satisfied existing `HEUR-BRUTEFORCE-001` conditions (score 50/100, `HIGH`). |
| **D** | Controlled Flood Heuristic | `CONTROLLED SYNTHETIC TEST DATA` | **PASS** | Evaluated flow exceeding production thresholds (60,000 pkts/s, 8 MB/s). Triggered `HEUR-DOS-001` & `HEUR-DOS-002`. Zero host packet flooding. |
| **E** | Threat Intelligence Match | `CONTROLLED SYNTHETIC TEST DATA` | **PASS** | Synthetic test indicator `203.0.113.199` registered. ThreatScorer elevated score to 98/100 (`CRITICAL`). Verified disabled isolation and safe cleanup. |
| **F** | Multi-Stage Correlation | `CONTROLLED SEQUENTIAL EVENTS` | **PASS** | Sequential attack chain (`PORT_SCAN` $\to$ `BRUTE_FORCE`) merged into single incident with escalation flag (score 100/100). Distinct destination created separate incident. |
| **G** | Prevention Simulation | `CONTROLLED ENGINE VERIFICATION` | **PASS** | `simulate` mode returned `SIMULATED_TEMPORARY_BLOCK` without host firewall modifications. `detect_only` mode returned `MONITORED_ONLY`. |
| **H** | Full Pipeline Provenance | `INTEGRATED DEMONSTRATION` | **PASS** | Complete 6-stage provenance chain recorded with exact entity IDs. |

**Audit Artifacts Generated**:
- Machine-readable JSON: `backend/artifacts/phase10/validation_report.json`
- Human-readable Markdown: `backend/artifacts/phase10/validation_summary.md`

---

## Measured Benchmark Results

| Model / Subsystem | Accuracy | Precision | Recall | F1-Score | Evaluation Test Set |
|:---|:---:|:---:|:---:|:---:|:---|
| **Phishing Detector** | **99.66%** | **99.91%** | **99.29%** | **0.9960** | PhiUSIIL Held-Out Test (35,306 URLs) |
| **Network IDS (Binary Gate)** | **99.903%** | **99.520%** | **99.914%** | **0.99716**| CIC-IDS2017 Held-Out Test (374,833 flows) |
| **Network IDS (Multiclass)** | **99.900%** | Macro: 96.3% | Macro: 96.1%| Macro: 0.961| CIC-IDS2017 Held-Out Test (374,833 flows) |

> [!NOTE]
> Detailed per-class metrics, confusion matrices, and minority class analyses (e.g., Botnet precision at 69.39%, Infiltration support) are documented in [docs/model_results.md](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/model_results.md).

---

## Technical Limitations

1. **Historical Dataset Bounds**: CIC-IDS2017 was captured in 2017. Real-world networks experience protocol drift (QUIC, HTTP/3, TLS 1.3) and evolving attack tools.
2. **Encrypted Payloads**: The live sensor inspects Layer 3/4 flow metadata (packet lengths, inter-arrival times) and does not perform TLS decryption.
3. **Lexical Phishing Bounds**: Phishing analysis inspects static URL properties; it does not execute client-side JavaScript or render dynamic DOM trees.
4. **No Universal Detection Claim**: No intrusion detection system achieves zero false positives or zero false negatives in open, complex network environments.

---

## Security & Safety Guarantees

- **Confined Loopback Target**: All validation sockets strictly target `127.0.0.1` / `::1`. Remote and public IPs raise immediate exceptions.
- **Zero Host Tampering**: CIPHER never alters Windows Defender, host firewall rules (`netsh`), or registry entries.
- **Safe Prevention Defaults**: Default operating mode is `detect_only`, ensuring non-destructive execution during evaluation and demonstration.
- **Data Isolation**: Test IOCs tagged `CIPHER_PHASE10_TEST` are automatically purged post-validation.

---

## Project Documentation Index

All detailed technical documentation is organized in the [`docs/`](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/) directory:
- [Architecture & Diagrams](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/architecture.md)
- [Methodology Across Phases 1–10](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/methodology.md)
- [Machine Learning Results & Disclaimers](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/model_results.md)
- [Dataset Documentation & Splits](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/dataset_documentation.md)
- [Validation Report & Scenarios (A–H)](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/validation.md)
- [Technical Limitations](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/limitations.md)
- [REST API Reference](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/api_reference.md)
- [Demonstration Runbook (8–12 Minutes)](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/demonstration.md)
- [Evidence Index & Claim Mapping](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/evidence_index.md)
- [Verified Project Statistics](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/project_statistics.md)
- [Final Presentation Slide Deck Outline](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/presentation_outline.md)
- [Defensible Claims & Evaluation Boundaries](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/defensible_claims.md)
- [Final Comprehensive Project Report](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/final_project_report.md)
