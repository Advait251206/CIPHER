# CIPHER — Engineering & Scientific Methodology

This document provides a systematic account of the methodology, algorithms, feature pipelines, and architectural decisions employed across all ten development phases of **CIPHER** (*Cyber Intrusion Prevention & Heuristic Event Response*).

---

## Phase 1: Core System Foundation & Architecture
- **Objective**: Establish a production-grade, local-first backend runtime, schema definitions, and persistent logging layer.
- **Technology**: Python 3.13, FastAPI, Pydantic v2, SQLite3.
- **Architecture**:
  - Centralized application router (`app/main.py`) exposing standardized JSON REST APIs.
  - Thread-safe SQLite repository (`app/database/database.py`) with automatic schema initialization, index creation, and write-ahead logging (WAL) compatibility.
  - Environment-based configuration with strict local bindings (`API_HOST=127.0.0.1`, `API_PORT=8000`, `LOCAL_ONLY=true`).
  - Core health and diagnostic endpoints (`/api/health`, `/api/system/status`).

---

## Phase 2: Phishing URL Detection Methodology
- **Dataset**: PhiUSIIL Phishing URL Dataset (published in *Computers & Security*, 2024).
- **Data Hygiene & Deduplication**:
  - Raw instances loaded: **235,795**.
  - Missing value audit: 0 missing labels.
  - Exact duplicate row removal: Identified and eliminated duplicate entries.
  - URL-level deduplication: **425 duplicate URLs removed**, leaving **235,370 unique, verified URLs**.
  - Strict deduplication before splitting guarantees zero URL leakage between training and evaluation partitions.
- **Feature Extraction Pipeline (28 Features)**:
  - Extracted solely via static lexical, structural, and information-theoretic parsing without making live HTTP/DNS queries.
  - *Length & Component metrics*: `URLLength`, `DomainLength`, `PathLength`, `QueryLength`, `TLDLength`, `NoOfSubDomain`.
  - *Character & Obfuscation metrics*: `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `CharContinuationRate`, `SpacialCharRatioInURL`, `NoOfDotsInURL`, `NoOfHyphensInURL`, `NoOfOtherSpecialCharsInURL`.
  - *Syntactic & Security flags*: `IsHTTPS`, `IsDomainIP`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfAtInURL`, `SuspiciousKeywordCount`, `IsSuspiciousTLD`.
  - *Entropy*: `URLEntropy`, `DomainEntropy` (Shannon entropy calculated on character distributions).
- **Partitioning**: Stratified random split (random_state=42) preserving class distribution:
  - Training Set: **70%** (164,759 URLs)
  - Validation Set: **15%** (35,305 URLs)
  - Held-out Test Set: **15%** (35,306 URLs)
- **Model Training**:
  - Evaluated candidate architectures: Random Forest, HistGradientBoosting, and Logistic Regression.
  - Selected model: `RandomForestClassifier` (`n_estimators=100`, `max_depth=22`, `min_samples_split=5`, `min_samples_leaf=2`, `random_state=42`).
  - Serialized via `joblib` into `models/phishing/phishing_model.joblib` and `models/phishing/feature_pipeline.joblib`.

---

## Phase 3: CIC-IDS2017 Network Intrusion Detection Methodology
- **Dataset**: Canadian Institute for Cybersecurity CIC-IDS2017 benchmark dataset (`MachineLearningCSV`), covering 8 packet capture windows across 5 business days.
- **Raw Ingestion & Deduplication**:
  - Raw flow records ingested: **2,830,743**.
  - Dropped zero-entropy constant columns: `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`, `CWE Flag Count`, `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`, `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, `Bwd Avg Bulk Rate`.
  - Dropped extractor artifact: `Fwd Header Length.1`.
  - Removed exact intra-file duplicates.
  - Performed **global cross-file deduplication**: Removed **331,860 exact duplicate flows**, yielding **2,498,883 unique flow records**.
- **Data Sanitization**:
  - Infinite values (`+inf`, `-inf`) in `Flow Bytes/s` and `Flow Packets/s` imputed using the 99.9th percentile of finite values.
  - Missing values (`NaN`) imputed with median feature values.
  - Converted float representations to `float32` to optimize memory consumption.
- **Attack Taxonomy & Label Normalization**:
  - Mapped 15 heterogeneous attack labels into 8 standardized attack classes plus `BENIGN`:
    - `PORT_SCAN`: PortScan
    - `DDOS`: DDoS
    - `DOS`: DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest
    - `BRUTE_FORCE`: FTP-Patator, SSH-Patator
    - `BOTNET`: Bot
    - `WEB_ATTACK`: Web Attack – Brute Force, Web Attack – XSS, Web Attack – SQL Injection
    - `INFILTRATION`: Infiltration
    - `OTHER_ATTACK`: Heartbleed
- **Stratified Partitioning**:
  - Stratified across all attack classes to guarantee test representation:
    - Training Partition: **70%** (1,749,218 flows)
    - Validation Partition: **15%** (374,832 flows)
    - Test Partition: **15%** (374,833 flows)
- **Training Set Class Balancing (Benign Cap)**:
  - To prevent majority-class domination while retaining 100% of attack instances, the training partition capped benign flows at **150,000 samples** via stratified sampling with a fixed seed.
  - Resulting training set: **448,019 flows** (298,019 attack flows + 150,000 benign flows).
  - Validation and test partitions were maintained in their **natural, unadulterated class distributions** (each containing ~310,972 benign and ~63,861 attack flows) to measure authentic generalized performance.
- **Dual Random Forest Architecture**:
  - *Model 1 (Binary Gate)*: `n_estimators=100`, `max_depth=24`, `min_samples_leaf=2`. Fast, high-recall discriminator between Benign and Malicious traffic.
  - *Model 2 (Multiclass Classifier)*: Specializes across the 8 attack categories, activated when the binary gate confirms an attack.
  - Model artifacts serialized to `models/network/network_ids_model.joblib` and `models/network/network_feature_pipeline.joblib`.

---

## Phase 4: Defensive Intrusion Prevention System (IPS)
- **Objective**: Synthesize detection findings into actionable defensive responses while guaranteeing Windows host stability.
- **Operational Modes**:
  1. `detect_only` (Default): System monitors and logs security events without applying active host or firewall alterations (`MONITORED_ONLY`).
  2. `simulate`: Simulates IP blocking by registering IP entries into a persistent SQLite blocklist with automated time-to-live (TTL) countdowns (`SIMULATED_BLOCK`, `SIMULATED_TEMPORARY_BLOCK`). Operating system firewall rules are never touched.
  3. `enforce`: Reserved active containment mode for controlled environments. Enforces host protection invariants (never disables Defender or modifies system registries).
- **Rate Limiting**: Sliding-window `FlowRateLimiter` to detect aggressive connection storms from individual sources.

---

## Phase 5: Live Packet Capture & Real-Time Flow Aggregation
- **Packet Ingestion**: Integrated Scapy's `AsyncSniffer` binding to Npcap on Windows interfaces.
- **Stateful Flow Aggregation**:
  - Bounded flow table capped at **50,000 active flows**.
  - Bidirectional 5-tuple flow tracking (`source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`).
  - Real-time computation of 67 flow features matching the CIC-IDS2017 feature schema (inter-arrival times, packet length statistics, flag distributions, segment sizes).
  - Eviction timers: **5-second idle timeout** and **60-second active timeout**.
  - Finalized flows are automatically dispatched to `NetworkService.analyze_flow` for detection and correlation.

---

## Phase 6: Unified Security Event Correlation & Incident Management
- **Unified Event Model**: Standardized `NormalizedEvent` schema unifying Phishing URL submissions and Network IDS detections.
- **Correlation Identity Invariant**:
  - Rejects single `source_ip` correlation as insufficient evidence.
  - Network events are correlated by `(source_ip, destination_ip)`. Different destination targets generate independent incident chains.
  - Phishing events are correlated by `domain / url`.
- **Temporal Sliding Window**: Configurable **300-second window** (`CORRELATION_WINDOW_SECONDS`). Events occurring outside this window initiate new incident chains.
- **Multi-Stage Attack Progression**: Identifies kill-chain progression (e.g., Reconnaissance / `PORT_SCAN` followed by Exploitation / `BRUTE_FORCE`), setting `escalation_detected=True` and boosting the calibrated correlation score.
- **Bounded State**: In-memory active chain pool capped at **10,000 entries** with LRU eviction and SQLite database synchronization.

---

## Phase 7: Heuristic & Signature Detection Engine
- **Objective**: Deterministic rule layer operating in synergy with ML models.
- **Implemented Heuristic Rules (10)**:
  - `HEUR-PORTSCAN-001`: Multi-Port Reconnaissance Sweep ($\ge 10$ distinct destination ports in 60s).
  - `HEUR-PORTSCAN-002`: Half-Open SYN Scan Probe (SYN flag without ACK, 0 backward packets, short duration).
  - `HEUR-BRUTEFORCE-001`: Auth Port Storm ($\ge 5$ connection attempts to ports 21, 22, 23, 445, 3389 in 60s).
  - `HEUR-BRUTEFORCE-002`: Auth Port Churn (rapid connection retries).
  - `HEUR-DOS-001`: Volumetric Packet Rate Anomaly ($> 50,000$ packets/s).
  - `HEUR-DOS-002`: Volumetric Byte Rate Anomaly ($> 5,000,000$ bytes/s).
  - `HEUR-DOS-003`: Extreme Traffic Asymmetry.
  - `HEUR-DDOS-001`: Multi-Source Distributed Flood ($\ge 3$ distinct sources targeting same destination).
  - `HEUR-ANOMALY-001`: Suspicious TCP Flag Combinations (SYN-FIN, NULL, Xmas scans).
  - `HEUR-ANOMALY-002`: Legacy Botnet IRC Communications (ports 6667–7000).
- **Implemented Signature Rules (4)**:
  - `SIGN-PORTSCAN-001`: Port Scan Flow Pattern.
  - `SIGN-BRUTEFORCE-001`: Brute-Force Auth Flow Pattern.
  - `SIGN-WEB-001`: Web Service Traffic Pattern.
  - `SIGN-PHISH-001`: Raw IPv4 Hostname in URL.
- **State Bounding**: Internal sliding-window trackers capped at **10,000 entries**.

---

## Phase 8: Local Threat Intelligence & IOC Correlation
- **Design Principle**: Local-first and privacy-preserving. Zero external API calls, zero DNS queries to third parties.
- **Data Model**: Structured IOC representation covering 4 indicator types: `IP`, `DOMAIN`, `URL`, and `HASH`.
- **Indexing & In-Memory Cache**:
  - Backed by SQLite table `threat_intel_iocs` with unique normalized indexing.
  - Thread-safe in-memory LRU cache capped at **5,000 entries** for sub-millisecond lookups.
  - Bulk import/export support (JSON & CSV) with batch ceilings of **1,000 records** per transaction.
- **ThreatScorer Integration (Dominant Severity Floor)**:
  - Non-additive risk synthesis: Evaluates the single dominant (strongest) IOC evidence rather than summing matches.
  - Applies calibrated risk floors:
    - `CRITICAL`: floor $\ge 75 + 25 \times \text{confidence}$ (up to 100).
    - `HIGH`: floor $\ge 50 + 24 \times \text{confidence}$.
    - `MEDIUM`: floor $\ge 25 + 24 \times \text{confidence}$.
    - `LOW`: floor $\ge 10 + 14 \times \text{confidence}$.
  - Floor-preserving: If existing risk exceeds the IOC floor, the higher risk is retained.
  - Elevates benign or unknown classifications to the matching IOC attack category.

---

## Phase 9: Unified SOC Operations Dashboard
- **Frontend Stack**: React 18, TypeScript 5, Vite 6, Vanilla CSS design tokens.
- **Architectural Integration**:
  - Developed in `frontend/` alongside `backend/`.
  - Zero external UI libraries or Tailwind dependencies; engineered using a dedicated dark-themed cybersecurity design system (glassmorphism, monospace metrics, accessibility-compliant severity color coding).
  - Centralized typed API client (`src/api/client.ts`) communicating through Vite's reverse proxy (`/api` $\to$ `http://127.0.0.1:8000`), maintaining same-origin integrity without modifying backend CORS policies.
- **Ten Functional Views**:
  1. *Overview*: 8 operational KPI counters, active incidents feed, attack breakdown chart, live subsystem status.
  2. *Live Events*: Unified stream table, filtering, auto-refresh, and structured evidence modal.
  3. *Incidents*: Multi-stage incident chains, escalation indicators, event timeline, resolution workflow.
  4. *Network IDS*: Dual Random Forest metrics, feature importance charts, interactive flow sandbox.
  5. *Phishing*: URL analysis interface with presets, 28-feature inspection, risk gauge, security guidance.
  6. *Threat Intelligence*: IOC repository management, indicator search, active/disabled toggles, bulk import.
  7. *Detection Rules*: 14 heuristic and signature rules, live toggle controls, rule evaluation sandbox.
  8. *Prevention*: IPS mode governance (`detect_only`, `simulate`, `enforce`), TTL blocklist management.
  9. *Live Sensor*: Npcap interface selector, packet telemetry, BPF filtering, start/stop controls.
  10. *System Health*: Diagnostic health checks across all backend subsystems and model artifacts.

---

## Phase 10: Controlled Local End-to-End Validation
- **Methodology**: Evaluates the complete, integrated pipeline across 8 diverse scenarios (A through H).
- **Safety Invariants**:
  - Strict loopback confinement (`127.0.0.1` / `::1`). Non-local IP requests are rejected by programmatic assertion.
  - Bounded connection counts ($\le 50$) and execution timeouts ($\le 15.0$s).
  - DoS logic evaluated safely using synthetic flow fixtures exceeding 50,000 pkts/s; localhost is never flooded.
  - Zero modifications to host firewall (`netsh`), Defender, or registry.
  - Test IOCs are isolated and purged upon validation completion.
- **Automated Reporting**: Generates machine-readable `validation_report.json` and human-readable `validation_summary.md` in `artifacts/phase10/`.
