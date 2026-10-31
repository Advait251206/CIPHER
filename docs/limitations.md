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
- As documented in the [Model Results](model_results.md), certain attack categories contain limited test set support:
  - `INFILTRATION`: 6 test samples.
  - `OTHER_ATTACK` (Heartbleed): 2 test samples.
  - `BOTNET`: Precision is lower (about 70%) due to statistical overlap with legitimate polling behavior.
- High reported accuracy (99.9%) reflects performance on a *random* held-out partition, where near-duplicate flows from the same session can appear in train and test, and must **not** be interpreted as universal real-world accuracy across all operational enterprise environments.

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
  - `DDOS_SOURCES_THRESHOLD = 3` sources in 60 seconds **and** `DDOS_AGGREGATE_PACKET_RATE = 10,000` packets/second summed over those sources.
  - Web-login ports (`CIPHER_WEB_LOGIN_PORTS`, default 5174) use a brute-force threshold of 30 connections per 60 s, because browsers open several connections per page.
- These thresholds are not universal physical laws. Highly specialized environments (e.g., financial trading desks with microsecond bursts or legitimate horizontal vulnerability scanners) may require custom threshold tuning to avoid false positives or false negatives.

---

## 7. Prevention Engine & Defensive Containment

- **Safe Default Stance**: The default operating mode is intentionally `detect_only` (`MONITORED_ONLY`). This guarantees that CIPHER will never disrupt legitimate host networking during demonstration, evaluation, or development.
- **Simulate Mode Boundary**: In `simulate` mode, IP addresses are registered in the local SQLite blocklist with automated TTL expiration, but the underlying operating system firewall is not altered (verified by tests that mock `subprocess.run`).
- **Enforce Mode Requirements**: Active host blocking via Windows Firewall requires administrative privileges. Loopback, link-local, multicast, the host's own addresses and anything in `CIPHER_PROTECTED_IPS` are never blocked; add your gateway and DNS servers there. Expired blocks remove their firewall rule.
- **Spoofed sources**: an attacker who can spoof source addresses can still cause blocks of unprotected third-party IPs in `enforce` mode. Keep `enforce` for controlled lab use.
- **Rate limiting** is advisory only (`RATE_LIMIT` is recommended and logged, not enforced).

---

## 8. False Positives & False Negatives

- No security system achieves zero false positives or zero false negatives.
- **False Positive Risks**: Legitimate automated workflows (e.g., continuous deployment pipelines, internal network discovery scripts, rapid API load testing) may mimic Port Scan or Brute Force patterns.
- **False Negative Risks**: Low-and-slow attackers who probe fewer than 10 ports per minute, space login attempts across hours, or randomize packet intervals can stay beneath deterministic heuristic radar, requiring defense-in-depth correlation and ML scrutiny.

---

## 9. Benchmark-to-Deployment Gap (measured)

- **Phishing URL shortcut**: PhiUSIIL's legitimate class contains only bare homepages, so the model treats any URL with a path as suspicious. The real-world probe (`python -m training.probe_phishing`) shows the raw model flagging 15/15 legitimate deep links. See [model_results.md](model_results.md#4-real-world-url-probe-raw-model-vs-full-service).
- **Live feature skew**: the live flow builder computes packet-length features from full wire length (including link-layer headers), whereas CICFlowMeter uses payload length; its active/idle threshold (1 s) and flow timeouts (5 s idle, 60 s active) also differ from CICFlowMeter's (5 s activity, 120 s flow timeout). ML verdicts on live traffic are therefore less reliable than on the benchmark, and live detections are dominated by the heuristic rules.
- **Email corpora**: training corpora differ by era and source; the model may partly learn corpus style.

## 10. WAF and Live Sensor Scope

- The WAF inspects individual TCP segments of **plaintext HTTP** sent to `CIPHER_WAF_PORTS` (default 5174, 8080). There is no stream reassembly, so payloads split across segments are missed, and HTTPS is invisible.
- The sensor is a passive tap. The forged TCP RST races the server's response; the request has already been processed. This is detection with best-effort teardown, not inline prevention.
- By default the sensor tracks **all** ports (required for port-scan detection). `CIPHER_MONITORED_PORTS` narrows it, at the cost of scan visibility.
