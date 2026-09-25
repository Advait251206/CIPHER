# CIPHER: Cyber Intrusion Prevention & Heuristic Event Response

CIPHER is a **local-first, privacy-preserving, dual-subsystem cybersecurity platform** combining:
1. **Phishing Website & URL Detection** (trained on PhiUSIIL)
2. **Network Intrusion Detection & Prevention System (Network IDPS)** (trained on CIC-IDS2017)
3. **Deterministic Heuristic Engine & Rules**
4. **Unified Multi-Factor Threat Scoring (0–100)**
5. **Multi-Mode Intrusion Prevention System (IPS)** (`detect_only`, `simulate`, `enforce`)
6. **Centralized SQLite Event Auditing & Streaming**
7. **Production-Ready FastAPI REST Service**

CIPHER executes **100% locally on the host machine (`127.0.0.1`)** with zero external cloud dependencies, zero external inference calls, and zero privacy leakage.

---

## High-Level Architecture

```
                               CIPHER Security Engine
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
        SUBSYSTEM 1: PHISHING                           SUBSYSTEM 2: NETWORK IDPS
                 │                                               │
     PhiUSIIL URL Dataset (235k)                     CIC-IDS2017 Flows (2.83M)
                 │                                               │
        15 Lexical Features                             67 Flow Statistics
                 │                                               │
       Random Forest Predictor                         Dual Random Forest
                 │                                   (Binary Gate + Multiclass)
                 │                                               │
        URL Heuristic Rules                            Flow Heuristic Rules
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         │
                           Unified Threat Scoring Engine
                                (0 - 100 Risk Score)
                           [LOW | MEDIUM | HIGH | CRITICAL]
                                         │
                           Intrusion Prevention Engine
                       (detect_only | simulate | enforce)
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
      Persistent IP Blocklist                           Centralized Event DB
       (TTL Expiration, SQLite)                      (Phishing & Network Streams)
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         │
                               FastAPI REST API
                         (/api/phishing, /api/network,
                          /api/events, /api/health)
                                         │
                         SOC Operations Dashboard
                               (frontend)
```

---

## Implementation Status: All 10 Phases Complete

| Component | Status | Description |
| :--- | :--- | :--- |
| **Phishing URL Detection** | **COMPLETE** | 15 lexical features, Random Forest, URL heuristics, risk scoring, SQLite logging. |
| **Network IDS ML Models** | **COMPLETE** | Dual Random Forest (Binary + 9-Class Multiclass) trained on 2.5M CIC-IDS2017 flows. |
| **Network Flow Preprocessing** | **COMPLETE** | Memory-safe Parquet pipeline, Inf/NaN sanitization, deduplication, stratified split. |
| **Network Heuristic Rules** | **COMPLETE** | Deterministic rules for Port Scan, DoS flood, DDoS, Brute Force, Botnet. |
| **Unified Threat Scoring** | **COMPLETE** | Calibrated 0–100 threat score and 4 severity bands, decoupled from raw confidence. |
| **IPS Prevention Engine** | **COMPLETE** | `detect_only` (default safe), `simulate`, and `enforce` modes with Windows host safety. |
| **Persistent IP Blocklist** | **COMPLETE** | SQLite-backed blocklist with TTL expiration, auto-block thresholds, and manual overrides. |
| **Rate Limiter** | **COMPLETE** | Sliding-window in-memory flow frequency tracker per source IP. |
| **Network REST API** | **COMPLETE** | Endpoints for analyze, health, stats, model metadata, rules, blocklist, and unified events. |
| **Safe Network Simulator** | **COMPLETE** | Synthetic flow generator for Normal, Port Scan, DoS, DDoS, and Brute Force flows. |
| **Live Packet Capture** | **COMPLETE** | Local-first packet sensor (Scapy+Npcap), bidirectional flow tracker, 67-feature builder, background worker. |
| **Unified Event Correlation** | **COMPLETE** | Multi-dimensional correlation, sliding-window (300s), attack escalation, junction persistence, incident lifecycle. |
| **Heuristic + Signature Engine** | **COMPLETE** | 10 network heuristics, 4 deterministic signatures, multi-source DDoS, bounded temporal tracking, REST APIs. |
| **Threat Intelligence & IOCs** | **COMPLETE** | Local SQLite IOC store (IP, Domain, URL, Hash), exact matcher, LRU cache (5k), dominant severity floor. |
| **SOC Operations Dashboard** | **COMPLETE** | React 18 + TypeScript + Vite single-page dashboard with 10 operational views and dark cybersecurity design system. |
| **Controlled Local Validation** | **COMPLETE** | Phase 10 local validation: 8/8 scenarios passed (A–H) with 6-stage provenance tracing and strict loopback safety. |
| **Automated Test Suite** | **COMPLETE** | 152 backend pytest cases + 11 frontend vitest cases passing with 100% success. |
| **Deep Application WAF** | **PLANNED FOR FUTURE** | HTTP payload inspection for deep SQLi / XSS payload decoding. |
| **Host Firewall Enforcement** | **PLANNED FOR FUTURE** | Controlled production OS firewall driver (guaranteed disabled in dev for Windows safety). |

---

## Subsystem 1: Phishing URL Detection

- **Dataset**: PhiUSIIL Phishing URL Dataset (235,370 clean records).
- **Features**: 28 reproducible lexical, length, syntactic, and information-entropy features.
- **Model**: Single Random Forest Classifier (~3.1 MB artifact).
- **Test Performance**:
  - **Accuracy**: 99.66%
  - **Precision**: 99.91%
  - **Recall**: 99.29%
  - **F1 Score**: 0.9960
  - **ROC-AUC**: 0.9991
  - **False Positive Rate (FPR)**: 0.064% (13 false alarms across 20,228 legitimate test URLs).
- **Endpoint**: `POST /api/phishing/analyze`

---

## Subsystem 2: Network Intrusion Detection (CIC-IDS2017)

### 1. The Dataset
Trained on the canonical **CIC-IDS2017 dataset** (`MachineLearningCSV.zip`):
- **8 Raw Capture Files**:
  1. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (225,745 flows)
  2. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (286,467 flows)
  3. `Friday-WorkingHours-Morning.pcap_ISCX.csv` (191,033 flows)
  4. `Monday-WorkingHours.pcap_ISCX.csv` (529,918 flows)
  5. `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (288,602 flows)
  6. `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (170,366 flows)
  7. `Tuesday-WorkingHours.pcap_ISCX.csv` (445,909 flows)
  8. `Wednesday-workingHours.pcap_ISCX.csv` (692,703 flows)
- **Total Raw Rows**: 2,830,743 flows.
- **Unique Deduplicated Flows**: 2,498,883 flows (331,860 duplicate records removed to prevent memorization).

### 2. Attack Taxonomy Normalization (15 Raw -> 9 Normalized Classes)
| Raw CIC-IDS2017 Label | CIPHER Normalized Class | Description |
| :--- | :--- | :--- |
| `BENIGN` | `BENIGN` | Baseline legitimate network traffic |
| `PortScan` | `PORT_SCAN` | Horizontal and vertical port sweep reconnaissance |
| `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` | `DOS` | Single-source volumetric / state-exhaustion DoS |
| `DDoS` | `DDOS` | Distributed volumetric flood assaults |
| `FTP-Patator`, `SSH-Patator` | `BRUTE_FORCE` | Automated dictionary credential attacks on auth ports |
| `Bot` | `BOTNET` | Infected host C2 beaconing and command communication |
| `Web Attack - Brute Force`, `Web Attack - XSS`, `Web Attack - Sql Injection` | `WEB_ATTACK` | Web application probe & exploit attempts |
| `Infiltration` | `INFILTRATION` | Internal network breach and lateral movement |
| `Heartbleed` | `OTHER_ATTACK` | Severe protocol vulnerability exploitation |

### 3. Data Cleaning & Sanitization Decisions
1. **Column Whitespace**: Stripped all leading and trailing whitespace from column headers (e.g. `' Destination Port'` -> `'Destination Port'`).
2. **Duplicate Feature Removal**: Dropped `Fwd Header Length.1` (exact duplicate of `Fwd Header Length` created by ISCX flow extractor).
3. **Zero-Entropy Constant Columns**: Dropped 10 invariant columns containing 100% zeros:
   - `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`, `CWE Flag Count`
   - `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`
   - `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, `Bwd Avg Bulk Rate`
4. **Infinity and NaN Sanitization**: `+Inf` values in `Flow Bytes/s` and `Flow Packets/s` (caused by division by zero on instantaneous flows with `Flow Duration = 0`) were clamped to the 99.9th percentile valid float values. Missing values (`NaN`) were imputed using feature medians.
5. **Memory Optimization**: Cast all 67 numerical feature columns to `float32` (50% RAM reduction, 658 MB total in memory for 2.5M rows).

### 4. Leakage-Safe Stratified Splitting Strategy
- **Why Stratified by Category?**: Attack scripts in CIC-IDS2017 were executed during specific time windows (e.g., Web Attacks occurred solely in the first 55% of Thursday morning; Heartbleed only in the last 15% of Wednesday). A naive chronological file slice leaves rare attacks absent from either train or test. A global stratified split (70% Train, 15% Val, 15% Test) ensures **every attack class is evaluated on completely unseen test data** without temporal leakage.
- **Cross-File Flow Deduplication**: Deduplicated across all files before splitting to eliminate identical flow signatures between train and test.
- **Training Balance**: Retained 100% of attack flows across all classes in the training set and capped benign traffic to 150,000 samples to prevent class swamping and maximize tree diversity.
- **Validation and Test Sets**: Left 100% unskewed (representing the natural baseline distribution).

| Partition | Total Samples | Benign Samples | Attack Samples | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Train** | 448,019 | 150,000 | 298,019 | Model training with balanced class representation |
| **Validation** | 374,832 | 310,971 | 63,861 | Model selection & hyperparameter calibration |
| **Test (Held-Out)** | 374,833 | 310,972 | 63,861 | Final unskewed benchmark evaluation |

---

## Network IDS Model Architecture & Performance

### Model Architecture
- **Dual Random Forest**:
  1. **Binary Gate**: Specialized binary Random Forest (`BENIGN` vs `ATTACK`) trained for high recall and minimal false positives.
  2. **Multiclass Classifier**: 9-class Random Forest for attack categorization.
- **Hyperparameters**: `n_estimators=100`, `max_depth=24`, `min_samples_leaf=2`, `max_features="sqrt"`, `n_jobs=-1`, `random_state=42`.
- **Training Time**: 9.73s (Binary) + 13.02s (Multiclass) on Intel Core Ultra 9.

### Test Set Evaluation (374,833 Unseen Test Flows)

#### Binary Metrics (BENIGN vs ATTACK)
- **Accuracy**: **99.903%**
- **Precision**: **99.520%**
- **Recall**: **99.914%**
- **F1-Score**: **99.716%**
- **ROC-AUC**: **1.0000**
- **PR-AUC**: **0.9999**
- **Confusion Matrix**:
  - True Negatives (TN): **310,664**
  - False Positives (FP): **308** (FPR = **0.099%**)
  - False Negatives (FN): **55** (FNR = **0.086%**)
  - True Positives (TP): **63,806**

#### Multiclass Classification Report (9 Categories)
```
              precision    recall  f1-score   support

      BENIGN     0.9998    0.9990    0.9994    310972
      BOTNET     0.6939    0.9283    0.7942       293
 BRUTE_FORCE     0.9978    0.9978    0.9978      1373
        DDOS     0.9995    0.9998    0.9997     19203
         DOS     0.9960    0.9992    0.9976     29042
INFILTRATION     1.0000    0.8000    0.8889         5
OTHER_ATTACK     1.0000    1.0000    1.0000         1
   PORT_SCAN     0.9953    0.9991    0.9972     13623
  WEB_ATTACK     0.9873    0.9688    0.9780       321

    accuracy                         0.9990    374833
   macro avg     0.9633    0.9658    0.9614    374833
weighted avg     0.9991    0.9990    0.9990    374833
```

#### Top 15 Important Features
1. `Bwd Packet Length Std` (0.0506)
2. `Fwd Packet Length Max` (0.0502)
3. `Avg Fwd Segment Size` (0.0454)
4. `Subflow Fwd Bytes` (0.0449)
5. `Fwd Packet Length Mean` (0.0417)
6. `Total Length of Fwd Packets` (0.0358)
7. `Packet Length Variance` (0.0340)
8. `Packet Length Std` (0.0337)
9. `Bwd Packet Length Mean` (0.0298)
10. `Average Packet Size` (0.0291)
11. `Idle Min` (0.0286)
12. `Idle Mean` (0.0283)
13. `Init_Win_bytes_backward` (0.0274)
14. `Idle Max` (0.0269)
15. `Subflow Bwd Bytes` (0.0247)

### Real-Time Feature Compatibility Classification
- **STREAMING_COMPUTABLE** (63 features): Can be computed in real-time by streaming accumulators during live packet aggregation (packet counts, byte counts, header sizes, TCP flag counts, running mean/variance).
- **FLOW_COMPLETION_REQUIRED** (4 features): `Active Mean/Std/Max/Min` and `Idle Mean/Std/Max/Min` require session idle timeouts or connection closure to compute.

---

## Deterministic Heuristics & Unified Threat Scoring

### Deterministic Network Rules
- `NET-PSCAN-01`: Half-Open SYN Scan (SYN set, zero ACK, zero response, short duration).
- `NET-PSCAN-02`: Zero-Response Scan Probe (unresponsive outbound probe packets).
- `NET-DOS-01`: Extreme Packet Flood Rate (forward rate > 50,000 pkts/s).
- `NET-DOS-02`: Volumetric Bandwidth Flood (> 50 MB/s transfer rate).
- `NET-DOS-03`: Asymmetric Flood Burst (mean IAT < 50µs, Down/Up ratio = 0).
- `NET-DDOS-01`: Uniform Flood DDoS (high rate with packet length variance < 5.0).
- `NET-BRUTE-01`: Auth Service Churn (truncated connection bursts to ports 21, 22, 23, 445, 3389).
- `NET-BOT-01`: Periodic C2 Beaconing (high-precision inter-arrival timing std < 5µs).
- `NET-BOT-02`: IRC C2 Port Target (monitors ports 6667–7000).
- `NET-WEB-01`: Web Service Traffic Anomaly (high rate directed at web ports; note: WAF required for payload inspection).

### Threat Scoring Logic
- **Decoupled from ML Confidence**: High confidence on a benign probe does not yield a high threat score. A port scan has lower intrinsic severity than active command-and-control or volumetric service destruction.
- **Formula**: Blends ML attack probability, category severity multiplier, deterministic heuristic evidence, and repetition frequency.
- **Severity Bands**:
  - `0 - 24`: **LOW** (Passive telemetry logging)
  - `25 - 49`: **MEDIUM** (Operator alert / rate limit)
  - `50 - 74`: **HIGH** (Temporary IP containment / throttling)
  - `75 - 100`: **CRITICAL** (Immediate source isolation / containment)

---

## IPS Prevention Architecture & Windows Safety

CIPHER provides an Intrusion Prevention System (IPS) architecture with three operational modes:

### Operational Modes (`CIPHER_PREVENTION_MODE`)
1. **`detect_only` (DEFAULT)**:
   - Evaluates flows, calculates threat scores, logs security events, and records recommended actions.
   - **Guarantees zero modifications to host firewall or Windows Defender.**
2. **`simulate`**:
   - Executes full defensive logic, records simulated IP block actions, and stores entries in the persistent SQLite blocklist with a simulation flag.
   - **Guarantees zero modifications to host firewall or Windows Defender.**
3. **`enforce`**:
   - Reserved for future production deployment in a controlled environment. Requires explicit administrator credentials.

### Host Safety Principles (Windows Environment)
- CIPHER **NEVER** disables Windows Defender.
- CIPHER **NEVER** deletes or disables the Windows Firewall.
- CIPHER **NEVER** injects unrestricted firewall bypass rules.
- Live packet capture runs in user space through Scapy/Npcap. Depending on the Windows interface and Npcap configuration, packet capture may require elevated privileges.
- Live sensor defaults to `detect_only` and does not modify the host firewall unless an explicit enforcement mode is configured.

### Persistent IP Blocklist
- SQLite-backed table `ip_blocklist` supporting temporary containment with TTL expiration, manual unblock overrides, and auto-block thresholds (`threat_score >= 80`).
- Sliding window flow rate limiter tracks connection bursts per source IP.

---

## REST API Reference

### 1. Network IDPS Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/network/health` | Subsystem runtime health, model load status, prevention mode |
| `POST` | `/api/network/analyze` | Analyzes normalized network flow; returns classification, score, action |
| `GET` | `/api/network/events` | Lists locally recorded network security events with filters |
| `GET` | `/api/network/events/{id}` | Retrieves specific network security event by UUID |
| `GET` | `/api/network/stats` | Aggregated flow metrics, attacks by type, severity distribution |
| `GET` | `/api/network/model` | Trained model metadata, held-out test metrics, feature importance |
| `GET` | `/api/network/rules` | Inspect active deterministic heuristic detection rules |
| `GET` | `/api/network/blocklist` | Lists active and expired entries in the IPS blocklist |
| `DELETE`| `/api/network/blocklist/{ip}`| Manually unblocks a contained source IP |

### 2. Live Sensor Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/network/interfaces` | Enumerate available host network adapters (name, description, IP, status) |
| `GET` | `/api/network/sensor/status` | Real-time telemetry (packets, active/completed flows, detections, errors) |
| `POST` | `/api/network/sensor/start` | Start live packet sniffing on operator-selected interface with optional BPF |
| `POST` | `/api/network/sensor/stop` | Gracefully stop sensor and flush remaining flows to the detection pipeline |

### 3. Unified Event Stream

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/events` | Unified stream across Phishing, Network IDS, and future subsystems |
| `GET` | `/api/events/{id}` | Retrieves detailed event record by UUID |
| `GET` | `/api/stats` | High-level system threat summary |

**Filters supported on `/api/events`**:
- `event_type`: `PHISHING` | `NETWORK`
- `attack_type`: `PORT_SCAN`, `DOS`, `DDOS`, `BRUTE_FORCE`, `BOTNET`, `WEB_ATTACK`, `INFILTRATION`, `OTHER_ATTACK`, `BENIGN`
- `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `source_ip`: Filter by origin IP or hostname
- `status`: `NEW`, `BLOCKED`, `INVESTIGATING`, `RESOLVED`

---

## Subsystem 3: Live Network Packet Sensor & Flow Aggregation

The CIPHER Live Network Sensor bridges live physical network packets into the trained CIC-IDS2017 detection engine.

### Architecture

```
                       REAL NETWORK PACKETS
                                │
                       Scapy + Npcap Sniffer
                      (Non-blocking background thread)
                                │
                   Cheap O(1) Packet Callback
                   (IP/TCP/UDP metadata extraction)
                   (ZERO application payload stored)
                                │
                   Bidirectional Flow Aggregator
                 (Canonical 5-tuple, Forward/Backward)
                                │
                   Flow Expiration & Finalization
            (Idle Timeout: 5s  •  Active Max Timeout: 60s)
                                │
                 Live 67-Feature Builder (µs Units)
                 (Exact schema & feature sequence match)
                                │
                Canonical Network IDS Pipeline
          (Binary Gate + Multiclass RF + Deterministic Heuristics)
                                │
                   Unified Threat Scoring (0–100)
                                │
                     IPS Prevention Decision
      (defaults to detect_only, respects configured mode)
                                │
                    Centralized SQLite Event Log
                                │
                        FastAPI REST APIs
                (/api/network/events, /api/events)
```

### Critical Model Limitation: Offline Dataset Model vs Live Packet Sensor

> [!IMPORTANT]
> **Honest Scientific Boundary**:
> The underlying Machine Learning models were trained on the offline, synthetically simulated **CIC-IDS2017 dataset**.
> Real-world live network traffic distributions, MTU fragmentation patterns, operating system TCP stacks, and background user traffic differ significantly from synthetic 2017 testbeds.
> 
> - CIPHER **does NOT** claim that training on CIC-IDS2017 guarantees identical statistical performance on arbitrary real-world production networks.
> - The live sensor implements the most faithful semantic translation possible into the 67 CIC features (accurately computing microsecond IATs, header byte accumulations, TCP flag bitmasks, and subflow accounting).
> - Every live feature construction outputs a calibrated `feature_completeness` indicator (e.g. `1.0` for full bidirectional streams, `0.85` for unidirectional probes).
> - Deterministic heuristics (`NET-PSCAN-01`, `NET-DOS-01`, etc.) act as a reliable ground-truth safety net when ML distributions face live domain shift.

### Zero Payload Persistence Guarantee

The live sensor strictly operates as a **flow-metadata IDS**:
- **Application payloads are NEVER saved or logged.**
- Passwords, cookies, session tokens, HTTP request bodies, and database query contents are completely ignored.
- Only protocol headers, port numbers, packet lengths, TCP control flags, window sizes, and microsecond arrival timestamps are extracted.

### Windows Setup & Privilege Requirements

On Windows systems, live raw packet capture operates via the **Npcap driver**:
1. Download and install Npcap from [https://npcap.com](https://npcap.com).
2. During installation, select **"Install Npcap in WinPcap API-compatible Mode"**.
3. **Privilege Boundary**: Live packet capture runs in user space through Scapy/Npcap. Depending on the Windows interface and Npcap configuration (e.g., if Npcap driver access was restricted to Administrators during install), packet capture may require elevated privileges.
4. No special firewall modifications or disabling Windows Defender is ever required.

### Sensor Configuration Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CIPHER_FLOW_IDLE_TIMEOUT` | `5.0` | Inactivity duration in seconds before finalizing an idle flow |
| `CIPHER_FLOW_ACTIVE_TIMEOUT`| `60.0`| Maximum seconds a long-lived flow can remain open before chunk expiration |
| `CIPHER_MAX_ACTIVE_FLOWS` | `50000` | Bounded memory capacity for concurrent active flows (evicts oldest on limit) |
| `CIPHER_SENSOR_INTERFACE` | `None` | Default network interface name or GUID |
| `CIPHER_SENSOR_BPF` | `None` | Default Berkeley Packet Filter expression (e.g., `ip`, `tcp or udp`) |
| `CIPHER_PREVENTION_MODE` | `detect_only` | Live sensor defaults to detect_only and does not modify the host firewall unless an explicit enforcement mode is configured |

### Live Console Demo Tools

CIPHER includes two console utilities for testing live capture safely without third-party network impacts:

#### 1. Live Sensor Telemetry Console (`scripts/live_network_demo.py`)
```bash
# List available network adapters:
python scripts/live_network_demo.py --list-interfaces

# Start monitoring an adapter (e.g. Wi-Fi or Loopback):
python scripts/live_network_demo.py --interface "Wi-Fi" --idle-timeout 5.0

# Gracefully stop with Ctrl+C
```

#### 2. Safe Local Traffic Generator (`scripts/generate_test_traffic.py`)
Generates controlled, harmless test traffic strictly against a temporary local server on `127.0.0.1`:
```bash
python scripts/generate_test_traffic.py --tcp-requests 5 --udp-packets 10 --probe-ports 5
```

---

## Example API Request and Response

### Request: `POST /api/network/analyze`
```json
{
  "source_ip": "10.0.0.88",
  "destination_ip": "192.168.1.50",
  "source_port": 41250,
  "destination_port": 8443,
  "protocol": "TCP",
  "features": {
    "Destination Port": 8443,
    "Flow Duration": 45,
    "Total Fwd Packets": 1,
    "Total Backward Packets": 0,
    "Flow Packets/s": 22222.2,
    "SYN Flag Count": 1,
    "ACK Flag Count": 0
  }
}
```

### Response (200 OK)
```json
{
  "event_id": "40112bb9-983f-423e-9813-5eb164c86c3c",
  "timestamp": "2026-09-14T20:18:22Z",
  "event_type": "NETWORK",
  "attack_type": "PORT_SCAN",
  "classification": "ATTACK",
  "source_ip": "10.0.0.88",
  "destination_ip": "192.168.1.50",
  "source_port": 41250,
  "destination_port": 8443,
  "protocol": "TCP",
  "ml_prediction": "PORT_SCAN",
  "ml_confidence": 1.0,
  "ml_attack_prob": 0.0,
  "threat_score": 80,
  "severity": "CRITICAL",
  "detection_method": "HEURISTIC",
  "explanation": "Probable Port Scan detected: Source host generated connection probes against destination port 8443 with rapid probe intervals and half-open flags.",
  "reasons": [
    "Probable SYN port scan probe: SYN flag set with zero ACK and zero backward response (Duration=45µs)",
    "Unresponsive outbound probe flow characteristic of automated port reconnaissance"
  ],
  "recommended_action": "TEMPORARY_BLOCK",
  "applied_action": "MONITORED_ONLY",
  "prevention_mode": "detect_only",
  "model_version": "CIPHER Network Intrusion Detection System"
}
```

---

## Phase 6: Unified Detection & Security Event Correlation

### Purpose
The **Unified Detection & Security Event Correlation Layer** bridges CIPHER's independent detection subsystems (Phishing Detector, Network ML, Heuristics, and Live Sensor) into a coherent, incident-aware IDPS. Rather than analyzing and storing attacks in complete isolation, the correlation layer:
1. Normalizes disparate detector outputs into a canonical internal format without altering original events.
2. Identifies related suspicious activities across safe, multi-dimensional correlation identities.
3. Quantifies attack repetition and attack diversity within a bounded sliding time window.
4. Detects potential attack escalation sequences (e.g. reconnaissance $\to$ authentication compromise $\to$ denial of service).
5. Creates, updates, and tracks security incident lifecycles (`OPEN`, `RESOLVED`).
6. Routes aggregated threat assessments through the existing `PreventionEngine` without duplicating prevention logic.
7. Persists incident-event links in SQLite using a many-to-many junction table (`incident_events`) to prevent record duplication.

> [!NOTE]
> **Correlation Disclaimer**: Correlation identifies related suspicious activity based on observable event relationships and temporal proximity. It does not definitively prove the identity or attribution of an external threat actor.

---

### Correlation Architecture

```
  Existing Detectors
  [Phishing ML] [Network ML] [Heuristics] [Live Sensor]
                         │
                         ▼
             Unified Event Normalizer
       (Canonical NormalizedEvent Representation)
                         │
                         ▼
             Event Correlation Engine
    ┌─────────────────────────────────────────────────┐
    │  • Strict Correlation Key: (src_ip, dst_ip)     │
    │  • Configurable Sliding Window: 300s            │
    │  • Secondary Source Sweep Reconnaissance Signal │
    │  • Repetition (+4/ea, max +20)                  │
    │  • Attack Diversity (+10/2 cats, +20/3+ cats)   │
    │  • Escalation Detection (+15 bonus)             │
    │  • Bounded Correlation Score [0 - 100]          │
    └─────────────────────────────────────────────────┘
                         │
                         ▼
                 Incident Manager
      (Lifecycle: OPEN / RESOLVED State Transitions)
                         │
                         ▼
             Existing PreventionEngine
    (Evaluates Response: detect_only, simulate, enforce)
                         │
                         ▼
                SQLite Persistence
       [incidents] ◄── [incident_events] ──► [security_events]
                         │
                         ▼
               FastAPI REST Endpoints
   (GET /api/incidents, GET /api/incidents/{id},
    GET /api/correlation/stats, POST /api/incidents/{id}/resolve)
```

---

### Correlation Criteria & Strict Identity Rules

To prevent false aggregation, CIPHER enforces strict correlation boundaries:
- **Do NOT correlate solely by `source_ip` alone**: Different destination systems create separate incident chains. For example, `10.0.0.5 -> 192.168.1.10` and `10.0.0.5 -> 192.168.1.20` do not merge into one incident.
- **Primary Network Identity**: Preferred correlation key is `(source_ip, destination_ip)`.
- **Primary Phishing Identity**: Preferred correlation key is `domain` (normalized hostname).
- **Secondary Source Signal**: Tracks recent `source_ip` activity across destinations to identify horizontal scanning/sweeps and boost incident priority without merging distinct destination records.
- **Sliding Time Window**: Default `300 seconds` (`CIPHER_CORRELATION_WINDOW`). Events arriving after the window closes automatically initiate a new incident chain.

---

### Attack Escalation Sequences

The engine detects temporal attack patterns characteristic of multi-stage intrusions:
- `PORT_SCAN` $\to$ `BRUTE_FORCE` (Reconnaissance to Credential Attack)
- `PORT_SCAN` $\to$ `DOS` / `DDOS` (Reconnaissance to Service Disruption)
- `PORT_SCAN` $\to$ `WEB_ATTACK` (Reconnaissance to Web Application Exploit)
- `BRUTE_FORCE` $\to$ `DOS` / `DDOS` (Failed Auth to Resource Exhaustion)
- `PHISHING` $\to$ `INFILTRATION` / `BOTNET` (Initial Access to Command & Control)

When an escalation sequence occurs, `escalation_detected = True`, an escalation score bonus (+15) is applied, and the incident summary explicitly flags the observed progression.

---

### Incident Lifecycle & REST API

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/incidents` | `GET` | List correlated incidents with optional filtering by `status`, `severity`, or `source_ip`. |
| `/api/incidents/{incident_id}` | `GET` | Retrieve full incident details including associated event items. |
| `/api/incidents/{incident_id}/events` | `GET` | Drill down into complete original security events linked to this incident. |
| `/api/incidents/{incident_id}/resolve` | `POST` | Manually close an incident and mark it as `RESOLVED`. |
| `/api/correlation/stats` | `GET` | Aggregated correlation metrics: open vs resolved, escalations, top sources, severity breakdown. |
| `/api/correlation/process` | `POST` | Ingest and normalize a security event directly into the correlation engine. |

---

### Interactive Correlation Demo Console

A safe demonstration script is provided at `scripts/demo_correlation.py`:

```bash
python scripts/demo_correlation.py
```
Demonstrates sequential `PORT_SCAN` $\to$ `BRUTE_FORCE` $\to$ `DOS` against `127.0.0.1`, escalation detection, score bounding (0–100), `detect_only` safety, and destination-isolated incident branching.

---

## Phase 7: Heuristic + Signature Detection Engine

### Purpose
The **Heuristic + Signature Detection Engine** strengthens CIPHER's deterministic detection capabilities alongside the local Machine Learning models. The engine provides deterministic heuristic and signature-based detection for configured patterns across network flow metadata and phishing URL structures.

The heuristic engine does **not** replace ML detection; rather, ML and deterministic rules operate as complementary detection mechanisms:
- **Machine Learning**: Identifies subtle, high-dimensional statistical variations and multi-class traffic distributions learned from training data.
- **Deterministic Heuristics & Signatures**: Instantly recognize known attack signatures, threshold-based volumetric rate spikes, and behavioral patterns (e.g. multi-port sweeps, authentication storms, multi-source distributed floods) with zero ambiguity and human-auditable explanations.

```
Detectors (Network ML, Phishing, Live Sensor)
                      │
                      ▼
            Unified Security Event
           (Canonical NormalizedEvent)
                      │
                      ▼
          Heuristic + Signature Engine
  ┌──────────────────────────────────────────────┐
  │  • Multi-Source Target Aggregation (DDoS)    │
  │  • Multi-Port Sweep Tracking (Port Scan)     │
  │  • Auth Port Retry Frequency (Brute Force)   │
  │  • Rate Thresholds (DoS Packets & Bytes)     │
  │  • Flag Anomalies & Legacy IRC Ports         │
  │  • Deterministic Signatures                  │
  │  • Separated Phishing Signatures (URL only)  │
  └──────────────────────────────────────────────┘
                      │
                      ▼
           Existing Threat Scoring
           (Preserves ML & Heuristic weights)
                      │
                      ▼
         Existing Correlation Engine
         (Incident tracking & escalation)
                      │
                      ▼
         Existing Prevention Engine
         (detect_only, simulate, enforce)
                      │
                      ▼
           SQLite / REST APIs / Dashboard
```

---

### Registered Rule Categories & Rules

#### 1. Network Heuristics (`HEUR-`)
- **`HEUR-PORTSCAN-001`** (*Multi-Port Reconnaissance Sweep*): Detects a single source IP probing $\ge 10$ distinct destination ports within $60$s (`MEDIUM`, Confidence: 0.85).
- **`HEUR-PORTSCAN-002`** (*Half-Open SYN Scan Probe*): Identifies SYN flag without ACK or backward response on short flow duration (`MEDIUM`, Confidence: 0.80).
- **`HEUR-BRUTEFORCE-001`** (*Authentication Port Storm*): Detects $\ge 5$ connection bursts against authentication ports (21, 22, 23, 445, 3389) within $60$s (`HIGH`, Confidence: 0.85).
- **`HEUR-BRUTEFORCE-002`** (*Auth Service Session Churn*): Identifies rapid, short-lived truncated sessions targeting authentication services (`MEDIUM`, Confidence: 0.75).
- **`HEUR-DOS-001`** (*Extreme Packet Flood Rate*): Triggers when forward packet rate exceeds $50,000$ pkts/s (`CRITICAL`, Confidence: 0.90).
- **`HEUR-DOS-002`** (*Volumetric Bandwidth Flood*): Flags flows exceeding $5$ MB/s volumetric bandwidth (`HIGH`, Confidence: 0.85).
- **`HEUR-DOS-003`** (*Asymmetric Flood Burst*): Rapid asymmetric request burst with low IAT and zero server reply (`MEDIUM`, Confidence: 0.75).
- **`HEUR-DDOS-001`** (*Distributed Multi-Source Target Flood*): Detects $\ge 3$ distinct source IPs targeting the same destination with aggregate high volume within $60$s (`CRITICAL`, Confidence: 0.90).
- **`HEUR-SUSPICIOUS-001`** (*Abnormal TCP Flags Anomaly*): Identifies illegal or evasive flag combinations like SYN+FIN set simultaneously (`LOW`, Confidence: 0.70).
- **`HEUR-SUSPICIOUS-002`** (*Suspicious Legacy IRC Communication*): Flags outbound communication targeting legacy IRC ports 6667, 6668, 6669, 7000 (`LOW`, Confidence: 0.60).

#### 2. Deterministic Signatures (`SIGN-`)
- **`SIGN-PORTSCAN-001`** (*Port Reconnaissance Probe Signature*): Matches flow fingerprint of automated port reconnaissance tools (`MEDIUM`, Confidence: 0.85).
- **`SIGN-BRUTEFORCE-001`** (*Auth Service Retry Signature*): Matches high-frequency credential retry pattern on authentication service ports (`HIGH`, Confidence: 0.85).
- **`SIGN-WEB-001`** (*Web Service Anomaly Signature*): Matches elevated request burst rate on standard web ports 80, 443, 8080, 8443 (`LOW`, Confidence: 0.65).
- **`SIGN-PHISH-001`** (*Raw IPv4 Hostname Signature*): Evaluated strictly on `PHISHING` events; identifies raw IPv4 addresses used directly in URL hostnames (`HIGH`, Confidence: 0.90).

---

### Configurable Thresholds

All thresholds are environment-driven with conservative defaults:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CIPHER_HEURISTIC_PORT_SCAN_THRESHOLD` | `10` | Minimum distinct destination ports probed from a source to trigger sweep heuristic |
| `CIPHER_HEURISTIC_PORT_SCAN_WINDOW` | `60.0` | Sliding window in seconds for port sweep aggregation |
| `CIPHER_HEURISTIC_BRUTE_FORCE_THRESHOLD` | `5` | Minimum connection attempts to auth ports to trigger brute-force storm |
| `CIPHER_HEURISTIC_BRUTE_FORCE_WINDOW` | `60.0` | Sliding window in seconds for auth attempt tracking |
| `CIPHER_HEURISTIC_DOS_PACKET_RATE` | `50000.0` | Packet rate threshold in pkts/s for volumetric DoS |
| `CIPHER_HEURISTIC_DOS_BYTE_RATE` | `50000000.0` | Bandwidth threshold in bytes/s ($50$ MB/s) for volumetric DoS |
| `CIPHER_HEURISTIC_DDOS_SOURCES_THRESHOLD` | `3` | Minimum distinct sources targeting same destination for DDoS multi-source rule |
| `CIPHER_HEURISTIC_DDOS_WINDOW` | `60.0` | Sliding window in seconds for DDoS destination aggregation |
| `CIPHER_HEURISTIC_MAX_STATE_ENTRIES` | `10000` | Bounded capacity for in-memory temporal tracking tables |

---

### Rule Management REST API

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/rules` | `GET` | List all registered rules with optional filtering by `category`, `severity`, or `enabled_only`. |
| `/api/rules/{rule_id}` | `GET` | Retrieve metadata, description, and active thresholds for a specific rule. |
| `/api/rules/{rule_id}/enable` | `POST` | Enable a disabled heuristic or signature rule. |
| `/api/rules/{rule_id}/disable` | `POST` | Disable an active heuristic or signature rule. |
| `/api/rules/evaluate` | `POST` | Test a security event directly against all active rules and return structured matches. |

---

---

## Phase 8: Threat Intelligence & IOC Correlation Layer

CIPHER incorporates a local-first, privacy-preserving **Threat Intelligence and IOC Correlation Layer**. This subsystem matches observed security events across network flows, phishing URLs, and host indicators against known Indicators of Compromise (IOCs) stored locally in SQLite without requiring external API keys, commercial subscriptions, or external network queries.

> [!NOTE]
> **Privacy & Offline Operation**: Threat-intelligence matching is performed locally and does not automatically transmit observed indicators to external services. All lookups query the local SQLite database (`threat_intel_iocs`) with in-memory caching.

---

### Pipeline Integration

```
[Phishing Detector]      [Network IDS]      [Live Packet Sensor]
         \                    |                    /
          \                   |                   /
           ▼                  ▼                  ▼
     ┌──────────────────────────────────────────────────┐
     │              Unified Security Event              │
     │     (NormalizedEvent with IPs, Domain, URL)      │
     └──────────────────────────────────────────────────┘
                              │
                              ▼
     ┌──────────────────────────────────────────────────┐
     │         Phase 7 Deterministic Rule Engine        │
     │            (Heuristics & Signatures)             │
     └──────────────────────────────────────────────────┘
                              │
                              ▼
     ┌──────────────────────────────────────────────────┐
     │       Phase 8 Threat Intelligence Matcher        │
     │       • Exact IP matching (Source / Dest)        │
     │       • Normalized Domain matching               │
     │       • Canonicalized URL matching               │
     │       • Exact Hash matching                      │
     │       • Expiration & Disabled Filtering          │
     └──────────────────────────────────────────────────┘
                              │
                              ▼
     ┌──────────────────────────────────────────────────┐
     │            Existing ThreatScorer                 │
     │    • Preserves ML & Heuristic authority          │
     │    • Applies dominant IOC severity floor         │
     │    • Zero double-counting (non-additive)         │
     └──────────────────────────────────────────────────┘
                              │
                              ▼
     ┌──────────────────────────────────────────────────┐
     │          Existing Correlation Engine             │
     │  (Incident chains with (src, dst) / (domain))    │
     └──────────────────────────────────────────────────┘
                              │
                              ▼
     ┌──────────────────────────────────────────────────┐
     │           Existing Prevention Engine             │
     │        (detect_only / simulate / enforce)        │
     └──────────────────────────────────────────────────┘
                              │
                              ▼
     ┌──────────────────────────────────────────────────┐
     │        SQLite Persistence & REST APIs            │
     └──────────────────────────────────────────────────┘
```

---

### Supported IOC Types

| Type | Indicator Example | Normalization & Validation |
| :--- | :--- | :--- |
| `IP` | `203.0.113.10`, `2001:db8::10` | Validated via standard IPv4/IPv6 address parsers; exact canonical string comparison against source and destination IPs. |
| `DOMAIN` | `example-threat.test` | Lowercased, trailing dots stripped, protocol schemes and ports stripped; exact match against observed hostnames. |
| `URL` | `http://example-threat.test/login` | Canonicalized scheme, lowercase netloc, normalized path; exact match against observed URLs. |
| `HASH` | `e3b0c44298fc1c...` | Validated hexadecimal strings (MD5 32 chars, SHA-1 40 chars, SHA-256 64 chars); exact match against metadata hashes. |

---

### ThreatScorer Synthesis & Mathematical Safety

Threat intelligence matches provide structured evidence (`metadata["threat_intel_matches"]`) rather than acting as an independent scoring engine. Scoring adheres to strict principles:

1. **Dominant Evidence Floor**: An active IOC match guarantees a calibrated severity floor:
   - `CRITICAL` IOC: $\max(75, \text{int}(75 + 25 \times \text{confidence}))$ ($75-100$ band)
   - `HIGH` IOC: $\max(50, \text{int}(50 + 24 \times \text{confidence}))$ ($50-74$ band)
   - `MEDIUM` IOC: $\max(25, \text{int}(25 + 24 \times \text{confidence}))$ ($25-49$ band)
   - `LOW` IOC: $\max(10, \text{int}(10 + 14 \times \text{confidence}))$ ($10-24$ band)
2. **Floor-Preserving**: If existing ML or heuristic threat scores are higher than the IOC floor, existing scores are strictly preserved.
3. **Non-Additive (Zero Double-Counting)**: If multiple matching IOCs are found for an event, only the single most dominant IOC floor is evaluated. Matches are never summed or multiplied.
4. **Classification Integrity**: An active IOC match ensures benign or unclassified events are elevated to `ATTACK` (or the specific IOC category) / `SUSPICIOUS`, preventing known threats from remaining benign.

---

### Safe Synthetic Demo Dataset

To prevent artificial threat intelligence from entering production records, demo IOCs are **NOT** automatically seeded on startup (`CIPHER_LOAD_DEMO_IOCS=false` by default). Demo indicators use reserved documentation ranges (RFC 5737 `203.0.113.10`, `198.51.100.25`, RFC 3849 `2001:db8::10`, and `.test` domains) and are explicitly tagged `source="CIPHER_DEMO"`.

---

### Threat Intelligence REST API

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/threat-intel/iocs` | `GET` | List registered IOCs with filtering by `ioc_type`, `severity`, or `enabled_only`. |
| `/api/threat-intel/iocs/{ioc_id}` | `GET` | Retrieve metadata, expiration status, and tags for an IOC. |
| `/api/threat-intel/iocs` | `POST` | Register a new validated IOC record. |
| `/api/threat-intel/iocs/{ioc_id}` | `DELETE` | Delete an IOC record. |
| `/api/threat-intel/iocs/{ioc_id}/enable` | `POST` | Re-enable an inactive IOC. |
| `/api/threat-intel/iocs/{ioc_id}/disable` | `POST` | Disable an IOC to exclude it from active matching. |
| `/api/threat-intel/check` | `POST` | Directly check an indicator value against active intelligence without generating an event. |
| `/api/threat-intel/import/json` | `POST` | Bulk import up to 1,000 IOCs from a structured JSON list. |
| `/api/threat-intel/import/csv` | `POST` | Bulk import up to 1,000 IOCs from a raw CSV file/body. |

---

## Safe Network Simulator

A safe test-data simulator is provided at `scripts/simulate_network_events.py`. It generates realistic synthetic flows matching the scenarios without sending real attack packets:

```bash
# Run standalone in-process:
python scripts/simulate_network_events.py

# Or run against a running CIPHER server:
python scripts/simulate_network_events.py --api-url http://127.0.0.1:8000/api/network/analyze
```

---

## Running CIPHER Locally

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
```

### 3. Run Automated Tests
```bash
pytest tests/
```
*(All 140 tests covering Phishing, Network Dataset, Model, Heuristics, Scoring, Prevention, Live Sensor, Unified Correlation, Rule Engine, and Threat Intelligence IOCs run in ~4.0 seconds)*

### 4. Start the Backend API
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- Interactive API Docs: `http://127.0.0.1:8000/docs`
- Alternative ReDoc: `http://127.0.0.1:8000/redoc`
- System Status: `http://127.0.0.1:8000/api/system/status`
- Network Health: `http://127.0.0.1:8000/api/network/health`
- Threat Intel IOCs: `http://127.0.0.1:8000/api/threat-intel/iocs`
