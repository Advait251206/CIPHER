# CIPHER — Defensible Claims & Evaluation Boundaries

To maintain rigorous scientific credibility and professional integrity, all presentations, documentation, and technical claims regarding **CIPHER** must adhere to the boundaries defined in this document.

---

## 1. Approved Defensible Claims

The following statements are technically grounded, empirically verifiable, and supported by automated test suites and serialized artifacts:

1. **Integrated Multi-Layered Architecture**:
   > *"CIPHER integrates machine-learning detection, heuristic and signature-based detection, local threat-intelligence correlation, multi-stage incident correlation, defensive prevention controls, and SOC visualization into a unified security platform."*

2. **Empirical Benchmark Evaluation**:
   > *"CIPHER's network intrusion models and phishing URL models were evaluated on independent, held-out test partitions from the CIC-IDS2017 and PhiUSIIL benchmarks. On these test partitions, the models achieved 99.90% and 99.66% accuracy, respectively."*

3. **Controlled Local Validation**:
   > *"Phase 10 validated the complete defensive pipeline across eight distinct scenarios using controlled localhost traffic, synthetic fixtures, and engine verification without introducing operational risks to the host."*

4. **Defense-in-Depth Synergy**:
   > *"Deterministic heuristic and signature rules operate alongside machine learning models, ensuring that observable indicators (such as multi-port sweeps or credential storms) are flagged even if statistical ML confidence fluctuates."*

5. **Local-First Privacy Guarantee**:
   > *"CIPHER performs all feature extraction, ML inference, and IOC matching locally on the host (`127.0.0.1`), ensuring zero external telemetry or threat query transmission to third-party cloud services."*

6. **Safe Prevention Defaults**:
   > *"By default, the Intrusion Prevention Engine operates in `detect_only` and `simulate` modes, ensuring non-destructive evaluation and zero host firewall tampering during demonstration and testing."*

---

## 2. Strictly Prohibited (Non-Defensible) Claims

The following claims are scientifically invalid, mathematically impossible in open environments, or unsupported by the current architecture. **They must never be made:**

| Prohibited Claim | Why It Is Non-Defensible | Accurate Replacement Language |
|:---|:---|:---|
| ❌ *"CIPHER detects 100% of all real-world cyber attacks."* | Novel zero-day exploits, advanced persistent threats (APTs), and out-of-distribution attacks evade historical benchmarks. | *"CIPHER detects recognized attack categories represented in benchmark corpora and deterministic heuristic rule signatures."* |
| ❌ *"CIPHER achieves zero false positives and zero false negatives."* | No statistical or heuristic classifier in open networks achieves perfect classification without trade-offs. | *"CIPHER demonstrates a low false positive rate (0.064% phishing, 0.099% network) on held-out benchmark test sets."* |
| ❌ *"CIPHER has 99.9% real-world accuracy on live corporate networks."* | Real-world networks experience protocol drift, asymmetric routing, and traffic profiles different from CIC-IDS2017. | *"CIPHER achieved 99.90% accuracy on the CIC-IDS2017 held-out test dataset."* |
| ❌ *"CIPHER replaces commercial enterprise next-generation firewalls (NGFW)."* | CIPHER is a software IDPS research prototype focusing on dual-subsystem detection and correlation; it is not a carrier-grade hardware appliance. | *"CIPHER provides a modular, extensible, host-level IDPS framework suitable for edge, endpoint, or SOC deployment."* |
| ❌ *"CIPHER inspects encrypted malware payloads inside HTTPS/TLS."* | The live sensor analyzes Layer 3/4 flow metadata and statistical metrics; it does not perform TLS man-in-the-middle decryption. | *"CIPHER detects encrypted attacks through behavioral flow metadata, frequency patterns, and packet size distributions."* |
| ❌ *"CIPHER is physically air-gapped."* | CIPHER's software architecture operates locally without cloud dependencies, but the host itself may be connected to a local network. | *"CIPHER operates local-first with zero external cloud dependencies."* |
