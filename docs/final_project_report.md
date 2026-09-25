# CIPHER — Final Project Technical Report

**CIPHER: Cyber Intrusion Prevention & Heuristic Event Response**  
*A Local-First, Unified Cyber Defense Platform Integrating Machine Learning, Deterministic Heuristics, Threat Intelligence, Multi-Stage Correlation, and SOC Operations*

---

## 1. Executive Summary

**CIPHER** is an end-to-end, host-level intrusion detection and prevention system (IDPS) engineered to overcome the operational fragmentation, alert fatigue, and cloud privacy hazards inherent in modern cybersecurity workflows. Executing entirely on local infrastructure (`127.0.0.1`), CIPHER combines:
1. **Phishing URL Detection**: Static 15-feature Random Forest model trained on the PhiUSIIL dataset, operating alongside lexical heuristic rules.
2. **Network Intrusion Detection**: Dual Random Forest model (Binary Gate + 9-Class Multiclass) trained on 2.49M deduplicated flows from the CIC-IDS2017 benchmark across 67 features.
3. **Live Packet Sensor**: Npcap/Scapy flow aggregation engine tracking up to 50,000 active bidirectional flows with automated feature calculation.
4. **Deterministic Heuristic & Signature Engine**: 14 stateful rules for reconnaissance, brute-force storms, volumetric floods, and anomalies.
5. **Local Threat Intelligence**: High-speed, privacy-preserving SQLite IOC store with non-additive dominant severity risk floor synthesis.
6. **Multi-Stage Event Correlation**: 300-second sliding-window correlator linking related security events into unified incident chains based on strict `(source_ip, destination_ip)` identity pairing.
7. **Intrusion Prevention Engine**: Multi-mode defense (`detect_only`, `simulate`, `enforce`) featuring TTL-managed blocklists and rate-limiting.
8. **Modern SOC Operations Dashboard**: React 18, TypeScript, and Vite single-page application delivering 10 operational views.

On held-out test partitions, CIPHER achieved **99.66% accuracy** for Phishing URL classification and **99.90% accuracy** for Network Intrusion Detection. Phase 10 controlled local validation demonstrated 100% pass rates across eight comprehensive test scenarios (A through H) with complete 6-stage provenance tracing.

---

## 2. Problem Statement

Contemporary Security Operations Centers (SOCs) and enterprise environments face critical structural challenges:
- **Tool Sprawl & Disjointed Visibility**: Web-filtering gateways, network intrusion sensors, and threat feeds operate in isolation, leaving analysts to manually correlate fragmented alerts.
- **Privacy & Telemetry Leakage**: Many contemporary threat intelligence and detection tools transmit internal URLs, IP addresses, and customer metadata to cloud-hosted APIs for evaluation, violating compliance mandates (e.g., GDPR, HIPAA) and exposing reconnaissance activities to external third parties.
- **Alert Fatigue & Correlation Deficits**: Raw alert streams overwhelm security teams with unprioritized single-event notifications lacking attack lifecycle context.
- **Destructive Prevention Risks**: Aggressive IPS solutions frequently misclassify legitimate traffic bursts as attacks, leading to operational downtime and self-lockout.

---

## 3. Objectives

The primary engineering objectives accomplished in CIPHER are:
- **Dual-Domain Detection**: Integrate both Web Phishing URL inspection and Network Flow intrusion detection into a unified platform.
- **Local-First Processing**: Ensure 100% of feature extraction, inference, threat intelligence matching, and correlation runs locally with zero external API dependencies.
- **Defense-in-Depth Synergy**: Combine statistical machine learning with deterministic heuristics and signatures, preventing single-point detection failures.
- **Calibrated Threat Scoring**: Unify diverse detection signals into a calibrated 0–100 risk score and standardized severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Identity-Safe Correlation**: Group related attack events into incident chains using strict destination-aware identities and temporal sliding windows.
- **Safe, Multi-Mode Prevention**: Implement automated defensive responses with safe defaults (`detect_only`, `simulate`) to eliminate accidental network disruption.
- **Actionable Visualization**: Provide a dark-mode SOC dashboard with interactive sandboxes, telemetry feeds, and structured evidence modals.

---

## 4. System Architecture

CIPHER follows a layered pipeline architecture:

```text
[ Raw Network Packets / Npcap ]       [ URL Submissions / REST API ]
               │                                     │
     Live Network Sensor                   URL Feature Extractor
    (50k Active Flow Table)                 (15 Lexical Features)
               │                                     │
     67-Feature Flow Dict                            │
               │                                     │
   ┌───────────┴───────────┐                         │
   │ Dual Random Forest ML │                         │
   │ Binary + Multiclass   │                         │
   └───────────┬───────────┘                         │
               │                                     │
   ┌───────────┴───────────┐             ┌───────────┴───────────┐
   │ Deterministic Rules   │             │ Phishing Random Forest│
   │ 10 Heuristics/4 Signs │             │ & Lexical Heuristics  │
   └───────────┬───────────┘             └───────────┬───────────┘
               │                                     │
               └──────────────────┬──────────────────┘
                                  │
                   Local Threat Intelligence (IOC Store)
                                  │
                      Calibrated ThreatScorer (0–100)
                                  │
                     Multi-Stage Event Correlator
                        (300s Sliding Window)
                                  │
                           Incident Manager
                                  │
                      Intrusion Prevention Engine
                    (detect_only | simulate | enforce)
                                  │
                   SQLite Unified Security Database
                                  │
                     FastAPI REST Gateway (Port 8000)
                                  │
                    SOC Dashboard (React 18 / Vite)
```

---

## 5. Implementation

The system is organized into two primary sub-projects:
- **`backend/`**: Python 3.13 service orchestrator utilizing FastAPI, Scikit-Learn, Scapy, and SQLite3.
  - `app/api/`: Modular REST routers for events, incidents, network, phishing, rules, threat intelligence, and health.
  - `app/ml/` & `app/network/`: Model loaders, feature extractors, and predictor pipelines.
  - `app/rules/`: Deterministic heuristic and signature engine with temporal state tracking.
  - `app/threat_intel/`: SQLite IOC repository with LRU caching and bulk import/export.
  - `app/correlation/`: Normalizer, event correlator, and incident manager.
  - `app/prevention/`: Prevention engine, IP blocklist manager, and rate limiter.
  - `app/database/`: Thread-safe database manager with automatic schema migration.
  - `scripts/phase10_validation/`: Bounded, local-only end-to-end validation runner and report generator.
- **`frontend/`**: Single-page application developed with React 18, TypeScript, and Vite, incorporating a dedicated dark cybersecurity design system with zero external UI framework dependencies.

---

## 6. Machine Learning Methodology

### Phishing URL Detector
- **Dataset**: PhiUSIIL (235,370 unique URLs post-deduplication; 425 duplicate URLs dropped).
- **Features**: 15 static lexical, structural, and information-theoretic features.
- **Model**: `RandomForestClassifier` (`n_estimators=100`, `max_depth=22`, `min_samples_split=5`, `min_samples_leaf=2`).
- **Data Split**: Stratified 70% Train (164,759), 15% Validation (35,305), 15% Test (35,306).

### Network IDS Detector
- **Dataset**: CIC-IDS2017 (2,498,883 unique flows post-deduplication across 8 capture files; 331,860 cross-file duplicates removed).
- **Features**: 67 statistical flow features (10 constant zero-variance columns and 1 duplicate column dropped; Infs/NaNs sanitized; stored in float32).
- **Class Balancing**: Stratified 70/15/15 split. Training partition attack flows were 100% preserved (298,019), while benign training flows were capped at 150,000 samples via stratified sampling (`random_state=42`), producing a balanced training set of 448,019 flows. Validation (374,832) and Test (374,833) partitions were left completely unadulterated.
- **Architecture**: Dual Random Forest (Model 1: Binary Gate; Model 2: 9-Class Multiclass Classifier).

---

## 7. Detection Engine (ML + Heuristics + Signatures)

CIPHER prevents single-point detection failure by combining statistical inference with deterministic verification:
- **ML Inference**: Estimates probability of malice based on structural patterns; provides robust generalization across novel feature variations.
- **Deterministic Heuristics (10 Rules)**: Evaluates observable temporal behaviors against established attack thresholds:
  - Multi-port horizontal reconnaissance sweeps ($\ge 10$ ports / 60s).
  - Half-open SYN scan probes with zero ACK and zero backward response.
  - Authentication storm retries targeting SSH, FTP, Telnet, SMB, and RDP ($\ge 5$ attempts / 60s).
  - Volumetric flooding anomalies ($> 50,000$ pkts/s or $> 50,000,000$ bytes/s).
  - Multi-source distributed DDoS floods ($\ge 3$ sources targeting the same destination).
- **Signatures (4 Rules)**: Deterministic pattern matching on protocol profiles, service ports, and raw IPv4 URL hostnames.
- **Threat Scoring Synergy**: ThreatScorer weights ML (70%) and Heuristics (30%), with rule-dominant override capabilities when high-confidence heuristic thresholds are met.

---

## 8. Threat Intelligence & Local IOC Store

- **Design Philosophy**: Local-first and private. Indicators are matched in-process without transmitting queries across the public Internet.
- **Data Formats**: Supports `IP`, `DOMAIN`, `URL`, and `HASH` indicators.
- **Caching & Performance**: Backed by indexed SQLite storage and an in-memory LRU cache (capacity: 5,000 items), achieving sub-millisecond lookups.
- **Dominant Severity Floor**: Matches elevate the synthesized threat score through non-additive severity floors (e.g., `CRITICAL` matches enforce a risk score floor $\ge 85$ up to 100), ensuring malicious indicators cannot be diluted by low ML probabilities.

---

## 9. Correlation & Incident Management

- **Correlation Identity Invariant**: To prevent false incident consolidation, network events are correlated strictly by `(source_ip, destination_ip)`. Different destination systems initiate independent incident chains.
- **Temporal Sliding Window**: Events occurring within 300 seconds of an existing active chain are merged.
- **Kill-Chain Escalation**: Sequential transitions (e.g., Reconnaissance $\to$ Weaponization $\to$ Exploitation) set `escalation_detected=True` and boost the calibrated incident correlation score.
- **Persistence**: Active chains are synchronized to SQLite tables `incidents` and `incident_events` with lifecycle state transitions (`ACTIVE`, `INVESTIGATING`, `RESOLVED`).

---

## 10. Intrusion Prevention System (IPS)

- **Modes**:
  - `detect_only` (Default): System monitors and logs defensive recommendations without altering host networking.
  - `simulate`: Simulates containment by writing to the SQLite blocklist with automated TTL countdowns; safe for live demonstrations.
  - `enforce`: Reserved active containment mode with strict host safety invariants.
- **Flow Rate Limiter**: Monitors ingress connection rates per source to curb volumetric connection storms.

---

## 11. SOC Dashboard

Developed in `frontend/` using React 18, TypeScript, and Vite:
- **Ten Dedicated Views**: Overview KPI, Live Events stream, Correlated Incidents, Network IDS analysis, Phishing URL inspector, Threat Intelligence repository, Detection Rules registry, Prevention blocklist, Live Sensor telemetry, and System Health diagnostics.
- **Evidence Modal**: Click-to-inspect modal displaying network 5-tuple, ML probabilities, triggered rules, matched IOCs, correlated incident links, and prevention decisions.
- **API Proxy**: Communicates with the backend via Vite's development proxy, ensuring same-origin security without modifying CORS policies.

---

## 12. Controlled Local Validation (Phase 10)

Phase 10 validated the complete defensive pipeline across eight distinct scenarios under strict air-gapped localhost boundaries:
- **Scenario A (Benign Traffic)**: Verified standard HTTP flows produce low risk (4/100, `LOW`) and zero false critical alerts.
- **Scenario B (Port Scan Sweep)**: Verified 12 bounded connection probes trigger `HEUR-PORTSCAN-001` and `HEUR-PORTSCAN-002` (score 80/100, `CRITICAL`).
- **Scenario C (Auth Storm)**: Verified 6 bounded connections to port 22 satisfy `HEUR-BRUTEFORCE-001` without modifying production rule port lists (score 50/100, `HIGH`).
- **Scenario D (Controlled Flood)**: Evaluated synthetic flow exceeding 50,000 pkts/s; triggered `HEUR-DOS-001` and `HEUR-DOS-002` without saturating host sockets.
- **Scenario E (IOC Correlation)**: Registered synthetic test indicator `203.0.113.199`; confirmed risk elevation to 98/100 (`CRITICAL`), verified disabled IOC isolation, and safely purged the test record.
- **Scenario F (Multi-Stage Correlation)**: Ingested sequential `PORT_SCAN` $\to$ `BRUTE_FORCE` chain; confirmed incident linking, escalation flag, and destination separation.
- **Scenario G (Prevention Simulation)**: Validated `simulate` and `detect_only` modes without modifying host firewall rules.
- **Scenario H (Full Pipeline Provenance)**: Established unbroken 6-stage provenance chain with exact entity IDs.

---

## 13. Quantitative Results Summary

| Subsystem / Metric | Measured Value | Benchmark Partition |
|:---|:---:|:---|
| **Phishing Model Accuracy** | **99.66%** | PhiUSIIL Held-Out Test Set (35,306 URLs) |
| **Phishing Precision / Recall** | **99.91% / 99.29%** | PhiUSIIL Held-Out Test Set |
| **Phishing False Positive Rate** | **0.064%** | PhiUSIIL Held-Out Test Set (13 / 20,228 benign) |
| **Network IDS Binary Accuracy** | **99.903%** | CIC-IDS2017 Held-Out Test Set (374,833 flows) |
| **Network Binary Precision / Recall** | **99.520% / 99.914%** | CIC-IDS2017 Held-Out Test Set |
| **Network Binary False Positive Rate**| **0.099%** | CIC-IDS2017 Held-Out Test Set (308 / 310,972 benign)|
| **Network Multiclass Accuracy** | **99.900%** | CIC-IDS2017 Held-Out Test Set |
| **Network Multiclass Macro F1** | **96.142%** | CIC-IDS2017 Held-Out Test Set |
| **Backend Test Suite (Pytest)** | **152 passed (100%)** | Full backend test suite (`pytest tests/`) |
| **Frontend Test Suite (Vitest)** | **11 passed (100%)** | Full frontend test suite (`npm run test`) |
| **Phase 10 Validation Scenarios** | **8 / 8 passed (100%)** | Controlled local validation suite |

---

## 14. Security & Safety Controls

- **Confined Loopback Target**: Sockets are programmatically restricted to `127.0.0.1` / `::1`. Remote IPs raise a `ValueError`.
- **Zero Host Tampering**: No alterations to Windows Firewall (`netsh`), Defender, or registry.
- **Resource Ceilings**: Maximum 50 connections, 15-second execution timeouts, and 50,000 in-memory flows.
- **Data Isolation**: Test IOCs tagged `CIPHER_PHASE10_TEST` are automatically cleaned up post-validation.
- **Input Sanitization**: Extreme lengths, malformed URLs, and infinite numeric values are sanitized at ingest.

---

## 15. Limitations

- **Historical Benchmark (CIC-IDS2017)**: Captured in 2017 with specific attack toolsets; modern evasions may exhibit domain shift.
- **Sparse Test Support for Minority Classes**: Infiltration (5 test flows) and Heartbleed (1 test flow) have limited statistical representation.
- **Encrypted Payload Visibility**: The live sensor operates on Layer 3/4 flow metadata; it does not perform TLS decryption.
- **Lexical Phishing Bounds**: Phishing detection operates on static URL strings; it does not render dynamic JavaScript or execute DOM parsing.
- **IOC Store Scope**: Matching is bounded by the indicators present in the local database.
- **No Absolute Zero False Positive/Negative Claim**: Operating in complex network environments requires ongoing tuning.

---

## 16. Future Work

- Automated ingestion of standardized threat feeds via STIX/TAXII.
- Hardware-accelerated packet capture utilizing eBPF or DPDK for 10Gbps+ carrier links.
- Integration of local, privacy-preserving Large Language Models (via Ollama or ONNX) for natural language security incident summarization.
- Graph neural network (GNN) correlation for complex lateral movement mapping.

---

## 17. Conclusion

CIPHER demonstrates that a local-first, privacy-preserving cybersecurity platform can achieve enterprise-grade intrusion detection and event response without relying on cloud infrastructure. By unifying dual-domain machine learning models, deterministic heuristic/signature engines, high-speed threat intelligence, and multi-stage correlation, CIPHER provides an accountable, evidence-based, and defense-in-depth security posture.

---

## 18. Reproducibility Instructions

### Prerequisites
- Python 3.11+ (Python 3.13 verified)
- Node.js 18+ (Node.js 20+ verified)
- Npcap (required only for live network packet sniffing; all synthetic and API tests run without Npcap)

### 1. Backend Setup & Test Execution
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run complete regression test suite (152 tests)
pytest tests/ -v

# Run Phase 10 controlled local validation (8 scenarios)
python -m scripts.phase10_validation.runner
```

### 2. Frontend Setup & Build
```powershell
cd frontend
npm install

# Run frontend test suite (11 tests)
npm run test

# Type-check and compile production bundle
npx tsc --noEmit
npm run build
```

### 3. Running the Integrated Demonstration
```powershell
# Terminal 1: Backend
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Frontend
cd frontend
npm run dev

# Open browser to: http://localhost:5173
```
