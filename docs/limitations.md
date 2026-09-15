# CIPHER — Technical Limitations & Operational Boundaries

A core tenet of defensible cybersecurity engineering is technical honesty. This document outlines the known limitations, architectural boundaries, and operational constraints of **CIPHER**.

---

## 1. Dataset & Benchmark Limitations

### Historical Benchmark Constraints (CIC-IDS2017)
- The Network IDS models were trained on the Canadian Institute for Cybersecurity's CIC-IDS2017 benchmark.
- While CIC-IDS2017 is widely recognized in academic literature, it represents a laboratory-generated dataset captured in 2017.
- Attack traffic within the corpus was generated using specific contemporary toolsets (LOIC for DDoS, Patator for brute force, Hulk/GoldenEye for DoS, ARES for Botnets).
- Modern automated exploit frameworks and novel evasion techniques (e.g., fragmented packet injection, polymorphic payloads) may exhibit flow profiles differing from this baseline.

### Representation Imbalances in Minority Classes
- As documented in the [Model Results](file:///d:/Advait251206/College/5th%20Sem/IDPS/Project/docs/model_results.md), certain attack categories contain limited test set support:
  - `INFILTRATION`: 5 test samples.
  - `OTHER_ATTACK` (Heartbleed): 1 test sample.
  - `BOTNET`: Precision is lower (69.39%) due to statistical overlap with legitimate polling behavior.
- High reported accuracy (99.9%) reflects performance on the benchmark's held-out test partition and must **not** be interpreted as universal real-world accuracy across all operational enterprise environments.

---

## 2. Domain Shift in Real-World Network Deployments

- **Protocol Evolution**: Real-world enterprise traffic increasingly relies on newer transport protocols (e.g., QUIC over UDP, HTTP/3, TLS 1.3 encrypted handshakes) whose packet size and inter-arrival distributions differ from traditional TCP/HTTP streams.
- **Asymmetrical Routing**: Live packet sniffers deployed on multi-homed or load-balanced networks may observe only unidirectional traffic (forward packets without backward replies), which can distort bidirectional metrics such as `Flow IAT` and `Down/Up Ratio`.

---

## 3. Phishing Detection Scope

- **Lexical and Structural Bounds**: The phishing detection engine inspects static lexical, syntactic, and information-theoretic features of the URL string alone.
- **No Dynamic Page Inspection**: To preserve local privacy, ensure air-gapped execution, and prevent drive-by malware infections, CIPHER does not:
  - Render target HTML DOM trees.
  - Execute client-side JavaScript.
  - Inspect server SSL/TLS certificates dynamically.
  - Follow complex conditional redirect chains (e.g., CAPTCHA cloaking or IP-targeted cloaking).
- **Legitimate Infrastructure Abuse**: Phishing URLs hosted on legitimate platforms (e.g., `docs.google.com`, `forms.office.com`, `supabase.co`) share high structural entropy and reputable TLDs with benign services, requiring supplementary human review or domain context.

---

## 4. Encrypted Traffic & Payload Visibility

- **Metadata-Only Analysis**: The live network sensor captures IP/TCP/UDP packet headers and aggregates flow-level statistical summaries. It does not perform Deep Packet Inspection (DPI) into encrypted payloads.
- **Application-Layer Visibility**: Malicious commands delivered over encrypted protocols (HTTPS, SSH, TLS tunnels) are invisible to payload inspection. Detections rely entirely on behavioral flow metadata (frequency, packet sizing, duration, session flags).

---

## 5. Threat Intelligence & Local IOC Store

- **Coverage Boundary**: Local IOC matching operates strictly on indicators present in the local SQLite database (`threat_intel_iocs`).
- **No Autonomous Threat Feeds**: CIPHER does not automatically scrape external commercial or open-source feeds. If an adversary uses previously unseen infrastructure, IP fast-flux, or dynamic DNS generation algorithms (DGA), the IOC layer will not match until intelligence is imported.

---

## 6. Heuristic & Signature Thresholds

- Thresholds configured in `app/rules/config.py` are engineering defaults calibrated for standard enterprise scenarios:
  - `PORT_SCAN_THRESHOLD = 10` distinct ports in 60 seconds.
  - `BRUTE_FORCE_THRESHOLD = 5` attempts in 60 seconds.
  - `DOS_PACKET_RATE_THRESHOLD = 50,000` packets/second.
  - `DOS_BYTE_RATE_THRESHOLD = 5,000,000` bytes/second.
  - `DDOS_SOURCES_THRESHOLD = 3` sources in 60 seconds.
- These thresholds are not universal physical laws. Highly specialized environments (e.g., financial trading desks with microsecond bursts or legitimate horizontal vulnerability scanners) may require custom threshold tuning to avoid false positives or false negatives.

---

## 7. Prevention Engine & Defensive Containment

- **Safe Default Stance**: The default operating mode is intentionally `detect_only` (`MONITORED_ONLY`). This guarantees that CIPHER will never disrupt legitimate host networking during demonstration, evaluation, or development.
- **Simulate Mode Boundary**: In `simulate` mode, IP addresses are registered in the local SQLite blocklist with automated TTL expiration, but the underlying operating system firewall is not altered.
- **Enforce Mode Requirements**: Active host blocking via Windows Firewall requires explicit administrative privileges and careful exclusion of loopback and critical management subnets to prevent self-lockout.

---

## 8. False Positives & False Negatives

- No security system achieves zero false positives or zero false negatives.
- **False Positive Risks**: Legitimate automated workflows (e.g., continuous deployment pipelines, internal network discovery scripts, rapid API load testing) may mimic Port Scan or Brute Force patterns.
- **False Negative Risks**: Low-and-slow attackers who probe fewer than 10 ports per minute, space login attempts across hours, or randomize packet intervals can stay beneath deterministic heuristic radar, requiring defense-in-depth correlation and ML scrutiny.
