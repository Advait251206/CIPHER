# CIPHER — Final Presentation Slide Deck Outline (15 Slides)

> **Note (v1.3, Oct 2026):** This document predates the v1.3 hardening release. Model metrics have been reconciled with the committed artifacts; where any figure here differs from [model_results.md](model_results.md) (generated from the artifacts), model_results.md is authoritative. Security and prevention behaviour changed in v1.3: see [SECURITY.md](../SECURITY.md) and [CHANGELOG.md](../CHANGELOG.md).


This outline is designed for a concise, high-impact 10–15 minute capstone or technical presentation.

---

### Slide 1: Title & Project Identity
- **Title**: CIPHER: Cyber Intrusion Prevention & Heuristic Event Response
- **Subtitle**: A Local-First, Defense-in-Depth IDPS with Machine Learning, Deterministic Heuristics, and Unified SOC Operations
- **Author**: Engineering & Capstone Project
- **Key Tenet**: 100% local execution, zero external cloud inference, zero telemetry leakage.

---

### Slide 2: Problem Statement
- Modern cybersecurity operations suffer from:
  1. *Tool Fragmentation*: Siloed network sniffers, URL filters, and threat feeds.
  2. *Cloud Privacy Hazards*: Transmitting internal indicators and IP addresses to third-party APIs risks data leakage.
  3. *Alert Fatigue*: Isolated single-event alerts overwhelm SOC analysts without multi-stage correlation.
  4. *Destructive Prevention*: Immature IPS solutions disrupt legitimate enterprise networking with aggressive false positives.

---

### Slide 3: Proposed Solution
- **CIPHER**: A cohesive, unified defensive platform bridging machine learning with deterministic rule enforcement.
- Dual threat detection: Phishing URL analysis (15 features) + Network IDS (67 features).
- Defense-in-depth: ML inference $\to$ Heuristics/Signatures $\to$ Local IOC Matching $\to$ Calibrated ThreatScorer (0–100).
- Stateful multi-stage event correlation + non-destructive IPS simulation + modern React SOC dashboard.

---

### Slide 4: System Architecture
- Flow diagram: Packet capture / REST API $\to$ Feature extraction $\to$ Detection $\to$ Threat Intelligence $\to$ ThreatScorer $\to$ Correlation $\to$ Prevention $\to$ SQLite $\to$ FastAPI $\to$ SOC Dashboard.
- Unified data pipeline guaranteeing that all components communicate via standardized schemas.

---

### Slide 5: Dual Detection Layer (ML + Heuristics + Signatures)
- **Machine Learning**: Generalizes across unseen feature variations; outputs probability and attack taxonomy.
- **Deterministic Heuristics (10 rules)**: Temporal state tracking for Port Scans ($\ge 10$ ports/60s), Brute Force ($\ge 5$ attempts/60s), and DoS ($>50,000$ pkts/s).
- **Signatures (4 rules)**: Deterministic pattern matching on structural flow markers and IP hostnames.
- **Synergy**: ThreatScorer weights ML (70%) and Heuristics (30%), preventing low-confidence ML hallucinations from triggering critical alerts.

---

### Slide 6: Network IDS & Real-Time Sensor
- Trained on **2.49M deduplicated flows** from the CIC-IDS2017 benchmark.
- **Dual Random Forest**: Fast binary gate filters benign traffic; multiclass model classifies 8 attack categories.
- **Live Sensor**: Scapy AsyncSniffer on Npcap interfaces; tracks up to 50,000 bidirectional flows in memory; computes 67 features on 5s idle / 60s active timeouts.

---

### Slide 7: Threat Intelligence & Event Correlation
- **Local Threat Intelligence**: SQLite-backed store for IP, Domain, URL, and Hash indicators with 5,000-entry in-memory cache.
- **Dominant Severity Floor**: Matches elevate threat score (e.g., CRITICAL $\ge 85$) without additive score distortion.
- **Correlation Identity Rule**: Network events require `(source_ip, destination_ip)` to merge; distinct targets create separate incident chains.
- **Kill-Chain Progression**: Automatically detects escalation from Reconnaissance (`PORT_SCAN`) to Exploitation (`BRUTE_FORCE`).

---

### Slide 8: Defensive Intrusion Prevention
- **Three Operational Modes**:
  - `detect_only` (Default): Passive monitoring; logs actions with zero OS alterations.
  - `simulate`: Records containment actions in SQLite blocklist with automated TTL countdown; safe for demos.
  - `enforce`: Reserved active containment adhering to strict Windows safety invariants.
- **Rate Limiting**: Defends against rapid connection flooding from individual hosts.

---

### Slide 9: Unified SOC Operations Dashboard
- Built with **React 18 + TypeScript + Vite + Vanilla CSS** cybersecurity design system.
- Ten comprehensive views: Overview KPI, Live Events, Incidents, Network IDS, Phishing, Threat Intel, Detection Rules, Prevention, Live Sensor, and System Health.
- Structured Event Modal: Displays complete evidence (network 5-tuple, ML probability, triggered rules, matched IOCs, incident links).

---

### Slide 10: Quantitative Machine Learning Results
- **Phishing Detector (PhiUSIIL)**:
  - Accuracy: **98.75%**, Precision: **98.79%**, Recall: **98.28%**, F1: **0.9853**, FPR: **0.900%**.
- **Network IDS (CIC-IDS2017)**:
  - Binary Gate: Accuracy: **99.903%**, Precision: **99.450%**, Recall: **99.941%**, F1: **0.99695**.
  - Multiclass Classifier: Accuracy: **99.897%**, Macro F1: **90.036%**, Weighted F1: **99.899%**.
- *Held-out Evaluation*: All metrics measured on 15% unseen test partitions.

---

### Slide 11: Phase 10 Controlled Local Validation
- Eight end-to-end scenarios (A through H) executed in a strictly isolated environment.
- Traffic classes: Real Local Traffic (loopback HTTP/port sweep) vs. Controlled Synthetic Data (volumetric flood, test IOCs) vs. Engine Verification.
- Result: **8/8 Scenarios Passed in 5.18 seconds**.

---

### Slide 12: End-to-End Provenance Demonstration
- **Scenario H Provenance Chain**:
  `Network Flow` $\to$ `Event ID` $\to$ `Rule Match` $\to$ `IOC Match` $\to$ `Incident ID` $\to$ `Prevention Action`
- Demonstrates seamless event propagation and identity preservation across all architectural layers.

---

### Slide 13: Security & Safety by Design
- **Localhost Boundary**: Socket targets restricted strictly to `127.0.0.1` / `::1`.
- **No Host Tampering by Default**: firewall rules only in `enforce` mode; validation intercepts and counts firewall calls (0 attempted).
- **Bounded Resource Ceilings**: Maximum 50 connections, 15s execution timeout, 50,000 sensor flows.
- **Data Hygiene**: Test IOCs tagged `CIPHER_PHASE10_TEST` and purged post-validation.

---

### Slide 14: Honest Technical Limitations
- *Historical Benchmark*: CIC-IDS2017 flows reflect 2017 toolset distributions; real-world networks exhibit domain drift.
- *Sparse Test Support*: Infiltration (5 samples) and Heartbleed (1 sample) have limited statistical test representation.
- *Encrypted Payloads*: Sensor inspects Layer 3/4 flow metadata; does not perform TLS decryption.
- *Lexical Phishing*: URL inspection only; does not execute client-side JavaScript or render DOM trees.

---

### Slide 15: Conclusion & Future Work
- **Accomplishment**: Delivered an integrated, local-first, privacy-preserving, 10-phase cybersecurity platform with verified 152-test backend and 11-test frontend suites.
- **Future Enhancements**:
  - Integration of automated local STIX/TAXII threat feed ingestion.
  - Hardware-accelerated packet capture (DPDK / eBPF) for multi-gigabit carrier networks.
  - Zero-shot LLM explanation assistance running strictly on local Ollama/ONNX runtimes.
