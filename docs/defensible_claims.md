# CIPHER — Defensible Claims & Evaluation Boundaries

To maintain rigorous scientific credibility and professional integrity, all presentations, documentation, and technical claims regarding **CIPHER** must adhere to the boundaries defined in this document.

---

## 1. Approved Defensible Claims

The following statements are technically grounded, empirically verifiable, and supported by automated test suites and serialized artifacts:

1. **Integrated Multi-Layered Architecture**:
   > *"CIPHER integrates machine-learning detection, heuristic and signature-based detection, local threat-intelligence correlation, multi-stage incident correlation, defensive prevention controls, and SOC visualization into a unified security platform."*

2. **Empirical Benchmark Evaluation**:
   > *"On random stratified held-out partitions, the network IDS binary gate reached 99.90% accuracy on CIC-IDS2017 and the phishing URL model reached 98.75% accuracy (0.90% FPR) on PhiUSIIL. These are benchmark figures; a real-world URL probe shows the phishing model does not transfer to legitimate URLs with paths."*

   Every figure must match the generated tables in [model_results.md](model_results.md).

3. **Controlled Local Validation**:
   > *"Phase 10 validated the complete defensive pipeline across eight distinct scenarios using controlled localhost traffic, synthetic fixtures, and engine verification without introducing operational risks to the host."*

4. **Defense-in-Depth Synergy**:
   > *"Deterministic heuristic and signature rules operate alongside machine learning models, ensuring that observable indicators (such as multi-port sweeps or credential storms) are flagged even if statistical ML confidence fluctuates."*

5. **Local-First Privacy Guarantee**:
   > *"CIPHER performs all feature extraction, ML inference, and IOC matching locally on the host (`127.0.0.1`), ensuring zero external telemetry or threat query transmission to third-party cloud services."*

6. **Safe Prevention Defaults**:
   > *"The prevention engine defaults to `detect_only`, and a missing or invalid mode also resolves to `detect_only`. Host firewall rules are created only in `enforce` mode, never for protected addresses, and are removed when their TTL expires. The validation runner intercepts and counts firewall calls (0 in the committed run)."*

7. **Authenticated Control Plane**:
   > *"State-changing API calls require a per-install token and an allowed browser Origin; the backend listens on 127.0.0.1 only."*

---

## 2. Strictly Prohibited (Non-Defensible) Claims

The following claims are scientifically invalid, mathematically impossible in open environments, or unsupported by the current architecture. **They must never be made:**

| Prohibited Claim | Why It Is Non-Defensible | Accurate Replacement Language |
|:---|:---|:---|
| ❌ *"CIPHER detects 100% of all real-world cyber attacks."* | Novel zero-day exploits, advanced persistent threats (APTs), and out-of-distribution attacks evade historical benchmarks. | *"CIPHER detects recognized attack categories represented in benchmark corpora and deterministic heuristic rule signatures."* |
| ❌ *"CIPHER achieves zero false positives and zero false negatives."* | No statistical or heuristic classifier in open networks achieves perfect classification without trade-offs. | *"On random-split benchmark test sets the false positive rate was 0.90% (phishing URLs) and 0.10% (network flows)."* |
| ❌ *"CIPHER has 99.9% real-world accuracy on live corporate networks."* | Real-world networks experience protocol drift, asymmetric routing, and traffic profiles different from CIC-IDS2017. | *"The binary network model achieved 99.90% accuracy on a random-split CIC-IDS2017 test partition."* |
| ❌ *"CIPHER replaces commercial enterprise next-generation firewalls (NGFW)."* | CIPHER is a software IDPS research prototype focusing on dual-subsystem detection and correlation; it is not a carrier-grade hardware appliance. | *"CIPHER provides a modular, extensible, host-level IDPS framework suitable for edge, endpoint, or SOC deployment."* |
| ❌ *"CIPHER inspects encrypted malware payloads inside HTTPS/TLS."* | The live sensor analyzes Layer 3/4 flow metadata and statistical metrics; it does not perform TLS man-in-the-middle decryption. | *"CIPHER detects encrypted attacks through behavioral flow metadata, frequency patterns, and packet size distributions."* |
| ❌ *"CIPHER is physically air-gapped."* | CIPHER's software architecture operates locally without cloud dependencies, but the host itself may be connected to a local network. | *"CIPHER operates local-first with zero external cloud dependencies."* |
| ❌ *"CIPHER's phishing model achieves 99% accuracy on real URLs."* | The raw model flags 15/15 legitimate deep links in the probe (PhiUSIIL legitimate URLs are homepages only). | *"On PhiUSIIL's random-split test set the model reached 98.75% accuracy; it does not yet generalise to legitimate URLs with paths."* |
| ❌ *"The WAF blocks SQL injection and XSS in real time."* | It inspects single plaintext TCP segments from a passive tap; the request reaches the app before the RST. | *"The WAF detects common SQLi/XSS/traversal patterns in plaintext HTTP and attempts best-effort connection teardown."* |
| ❌ *"The browser extension protects tabs in real time."* | It scans only when the popup is opened. | *"The extension scans the current tab or open email on demand."* |
