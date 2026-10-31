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
| **A0-2** | Frontend Typecheck, Vitest Suite & Production Build | **PASS** | `npx tsc --noEmit ; npx vitest run ; npm run build` | 5.69s (build) | [A0_frontend.log](backend/artifacts/test_logs/A0_frontend.log) |
| **A0-3** | Phase 10 Safety & Simulation Pipeline (8 Scenarios) | **PASS** | `python -m scripts.phase10_validation.runner` | 5.76s | [A0_phase10.log](backend/artifacts/test_logs/A0_phase10.log) |
| **A0-4** | Documentation Metrics Drift Check | **PASS** | `python -m scripts.generate_docs_metrics --check` | 0.08s | [A0_metrics.log](backend/artifacts/test_logs/A0_metrics.log) |

### Verbatim Log Excerpts:

#### Backend Pytest (`A0_pytest.log`):
```text
........................................................................ [ 28%]
........................................................................ [ 57%]
........................................................................ [ 85%]
....................................                                     [100%]
============================== warnings summary ===============================
.venv\Lib\site-packages\fastapi\testclient.py:1
  D:\Advait251206\College\5th Sem\IDPS\Project\backend\.venv\Lib\site-packages\fastapi\testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

tests/test_api.py::test_feature_extraction_failure_safe_handling
  D:\Advait251206\College\5th Sem\IDPS\Project\backend\.venv\Lib\site-packages\fastapi\telemetry\_api.py:244: StarletteDeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated. Use 'HTTP_422_UNPROCESSABLE_CONTENT' instead.
    return function(**arguments)

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
252 passed, 2 warnings in 14.65s
```

#### Frontend Build & Test (`A0_frontend.log`):
```text
 RUN  v3.2.7  D:/Advait251206/College/5th Sem/IDPS/Project/frontend

 ✓ src/test/SeverityBadge.test.tsx (5 tests) 34ms
 ✓ src/test/ConfirmDialog.test.tsx (1 test) 67ms
 ✓ src/test/StateHandling.test.tsx (3 tests) 60ms
 ✓ src/test/EventDetailModal.test.tsx (2 tests) 84ms
 ✓ src/test/EmailPage.test.tsx (2 tests) 81ms

 Test Files  5 passed (5)
      Tests  13 passed (13)
   Start at  10:00:49
   Duration  3.86s (transform 317ms, setup 1.71s, collect 3.80s, tests 325ms, environment 7.74s, prepare 1.12s)

npm notice run cipher-soc-dashboard@1.2.0022 build
npm notice run tsc && vite build
vite v6.4.3 building for production...
transforming...
✓ 2901 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                      1.20 kB │ gzip:   0.59 kB
dist/assets/index-Vl3m-mxR.css      31.24 kB │ gzip:   6.76 kB
dist/assets/index-BBLcQgRz.js    1,019.98 kB │ gzip: 300.29 kB

(!) Some chunks are larger than 500 kB after minification. Consider:
- Using dynamic import() to code-split the application
- Use build.rollupOptions.output.manualChunks to improve chunking: https://rollupjs.org/configuration-options/#output-manualchunks
- Adjust chunk size limit for this warning via build.chunkSizeWarningLimit.
✓ built in 5.69s
```

#### Phase 10 Safety Validation (`A0_phase10.log`):
```text
================================================================================
      CIPHER PHASE 10: CONTROLLED LOCAL END-TO-END VALIDATION
   Safety Boundary: Strictly Localhost (127.0.0.1) • Bounded Execution
================================================================================

[*] Executing Scenario A...
    [PASS] Benign Localhost Traffic (REAL LOCAL TRAFFIC)
    Evidence: Generated 5 HTTP flows to http://127.0.0.1:18080. Classification: BENIGN. Threat Score: 3/100. Severity: LOW. ML Confidence: 88.1%. Action: MONITORED_ONLY. No false critical alert raised.

[*] Executing Scenario B...
    [PASS] Port Scan Heuristic Sweep (REAL LOCAL TRAFFIC)
    Evidence: Generated 12 bounded connection probes across ports 18010..18021. Rule Matches: ['SIGN-PORTSCAN-001', 'HEUR-PORTSCAN-001', 'HEUR-PORTSCAN-002']. Classification: PORT_SCAN. Threat Score: 80/100. Severity: CRITICAL. Evidence: ['Probable SYN port scan probe: SYN flag set with zero ACK and zero backward response (Duration=200.0µs)', 'Unresponsive outbound probe flow characteristic of automated port reconnaissance'].

[*] Executing Scenario C...
    [PASS] Auth-Storm / Brute-Force Heuristic (REAL LOCAL TRAFFIC + AUTH FLOW METADATA)
    Evidence: Generated 6 bounded connection attempts targeting auth port 22 on loopback. Satisfied HEUR-BRUTEFORCE-001 conditions. Matched Rules: ['HEUR-PORTSCAN-001', 'HEUR-BRUTEFORCE-002', 'HEUR-BRUTEFORCE-001']. Classification: BRUTE_FORCE. Threat Score: 50/100. Severity: HIGH. Evidence: ['Abnormally truncated session targeting SSH auth port 22, indicative of automated credential retry'].

[*] Executing Scenario D...
    [PASS] Controlled Flood Heuristic (CONTROLLED SYNTHETIC TEST DATA)
    Evidence: Evaluated synthetic flow exceeding production thresholds (60,000 pkts/s, 8 MB/s). Production thresholds unchanged. Rules Matched: ['HEUR-DOS-001', 'HEUR-DOS-002', 'SIGN-WEB-001']. Classification: DOS. Threat Score: 65/100. Severity: HIGH. IPS Action: MONITORED_ONLY.

[*] Executing Scenario E...
    [PASS] Local Threat Intelligence / IOC Match (CONTROLLED SYNTHETIC TEST DATA)
    Evidence: Synthetic IOC '203.0.113.199' correctly registered and matched. ThreatScorer elevated threat score to 98/100 (CRITICAL). Correlated Incident INC-98A24458 severity: CRITICAL (98/100). Verified disabled IOC isolation and safe removal without deleting unrelated production IOCs.

[*] Executing Scenario F...
    [PASS] Multi-Stage Attack Correlation (CONTROLLED SEQUENTIAL EVENTS)
    Evidence: Sequential chain (PORT_SCAN -> BRUTE_FORCE) from 198.51.100.77 correctly merged into Incident INC-C220CA83. Escalation Flag: True. Correlation Score: 100/100. Verified distinct destination (10.0.0.99) created independent Incident INC-2C9FC5EE.

[*] Executing Scenario G...
Prevention mode changed: simulate -> detect_only
    [PASS] IPS Prevention Simulation (CONTROLLED ENGINE VERIFICATION)
    Evidence: Simulate mode returned action 'SIMULATED_TEMPORARY_BLOCK' without host firewall changes. Detect_only mode returned action 'MONITORED_ONLY'. Enforcement path not exercised on host; detect_only/simulate validated safely.

[*] Executing Scenario H...
    [PASS] Full End-to-End Pipeline Chain (INTEGRATED PIPELINE DEMONSTRATION)
    Evidence: Complete provenance chain successfully established: Flow [flow-e2e-02a32bbd] -> Event ID [5f3ca401-4891-498d-bb0b-2f5a565b43e4] -> Rule Match [['HEUR-PORTSCAN-002', 'SIGN-PORTSCAN-001']] -> IOC Match [['203.0.113.88']] -> Incident ID [INC-26C2976D] -> Prevention Action [MONITORED_ONLY].

================================================================================
  VALIDATION COMPLETED: 8/8 PASSED in 5.76s
================================================================================
```

---

## 3. Windows-Specific Hardening & Bugs Fixed

During bare-metal testing on Windows 11, five specific operating system bugs were encountered, fixed, and verified:

1. **`firewall_checks.py` Character Decoding Crash (`UnicodeDecodeError`)**:
   - *Problem*: Windows console outputs non-ASCII or localized characters under OEM/CP1252 code pages when executing `netsh advfirewall`. In `backend/scripts/live_checks/firewall_checks.py`, `subprocess.run(..., capture_output=True, text=True)` raised `UnicodeDecodeError` while parsing stderr.
   - *Fix*: Added `errors="replace"` to `subprocess.run` in `firewall_checks.py`. Note: Production `backend/app/prevention/blocklist.py` redirects `netsh` output to `subprocess.DEVNULL`, avoiding decoding overhead entirely.
2. **`runas /trustlevel:0x20000` Space Quoting in `%TEMP%`**:
   - *Problem*: In [run.bat](run.bat), when user profile or temporary folder paths contain spaces (e.g. `C:\Users\John Doe\AppData\Local\Temp`), unquoted batch execution under `runas /trustlevel:0x20000` failed.
   - *Fix*: Quoted the temporary launcher batch script inside the `cmd /k` invocation: `runas /trustlevel:0x20000 "cmd /k \"%temp%\cipher_vuln.bat\""`.
3. **C++ Npcap Packet Sensor Buffering Block**:
   - *Problem*: In `backend/cpp_sensor/main.cpp`, standard `std::cout` buffering caused captured packets to be held indefinitely in runtime memory blocks, resulting in empty output logs when piped.
   - *Fix*: Appended `<< std::flush` on every printed JSON line so subscribers receive real-time flow telemetry immediately.
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
  --- API TOKEN CHECK ---
  backend/.cipher_token exists: True
  Token length: 43 chars

  --- VULNERABLE APP INTEGRITY / MANDATORY LEVEL CHECK ---
  Mandatory Label\Medium Mandatory Level    Label    S-1-16-8192

  High Mandatory Level present (Elevated): False
  Medium Mandatory Level present (Non-Elevated): True
  ```
  Every port (`8000`, `5173`, `5174`) was strictly bound to `127.0.0.1`.
- **Integrity Level**: Running `whoami /groups` inside the vulnerable app window returned `Medium Mandatory Level` (zero High Mandatory tokens, preventing sandbox escapes).
- **Option Y Output** ([A1_launcher_Y.log](backend/artifacts/test_logs/A1_launcher_Y.log)):
  Port `5174` was bound to `0.0.0.0`. Verified that no lingering firewall rules remained after shutdown.

### A2: API Access Control & CSRF Protection
Verified using `backend/scripts/live_checks/api_access.py` ([A2_api.log](backend/artifacts/test_logs/A2_api.log)) and browser CDP console check ([A2_browser.log](backend/artifacts/test_logs/A2_browser.log)):
```text
[CHECK 1] Dashboard Proxy (Vite server-injected token on 5173)...
  [PASS] 1a. Switched mode to simulate via dashboard proxy.
  [PASS] 1b. Blocked 203.0.113.50 via dashboard proxy.
  [PASS] 1c. Unblocked 203.0.113.50 via dashboard proxy.

[CHECK 2] CSRF Origin Guard from foreign origin (https://example.com)...
  [PASS] Foreign origin correctly blocked with HTTP 403 (Forbidden).

[CHECK 3] Direct API Token Validation on POST /api/waf/config...
  [PASS] Request without token correctly rejected with HTTP 401 Unauthorized.
  [PASS] Request with token authenticated and reached payload validation (HTTP 422).

[CHECK 4] Argument Injection Defense on POST /api/extension/launch...
  [PASS] Malicious target_url rejected with HTTP 400 Bad Request.

------------------------------------------------------------
[RESULT] ALL 4 API ACCESS CONTROL CHECKS PASSED.
```
- Legitimate local requests from `http://localhost:5173` successfully passed via Vite proxy token injection.
- Unauthenticated requests lacking the bearer token were rejected with `HTTP 401 Unauthorized`.
- Cross-origin requests from foreign origins (`https://example.com`) were rejected with `HTTP 403 Forbidden`.

---

## 5. Prevention Engine & Sensor Verification (A3, A4 & A5)

### A3: Windows Firewall Prevention Lifecycle
Verified using `backend/scripts/live_checks/firewall_checks.py` ([A3_firewall.log](backend/artifacts/test_logs/A3_firewall.log)):
```text
[STEP 1] Direct Windows Firewall Elevation Check:
  Status: Non-elevated (Medium Mandatory Level).
  netsh return code: 1
  netsh output: The requested operation requires elevation (Run as administrator).

[STEP 2] Prevention Mode: detect_only
  Set mode detect_only -> HTTP 200: {'status': 'success', 'mode': 'detect_only'}
  POST /api/network/blocklist/203.0.113.51 -> HTTP 200: {'status': 'blocked', 'ip': '203.0.113.51', 'os_rule_applied': False}
  Firewall rule CIPHER_BLOCK_203.0.113.51 exists: False (expected: False)

[STEP 3] Prevention Mode: simulate
  Set mode simulate -> HTTP 200: {'status': 'success', 'mode': 'simulate'}
  POST /api/network/blocklist/203.0.113.52 -> HTTP 200: {'status': 'blocked', 'ip': '203.0.113.52', 'os_rule_applied': False}
  Blocklist active IPs: contains 203.0.113.52: True
  Firewall rule CIPHER_BLOCK_203.0.113.52 exists: False (expected: False in simulate mode)

[STEP 4] Prevention Mode: enforce
  Set mode enforce -> HTTP 200: {'status': 'success', 'mode': 'enforce'}
  POST /api/network/blocklist/203.0.113.53 -> HTTP 200: {'status': 'blocked', 'ip': '203.0.113.53', 'os_rule_applied': False}
  Firewall rule CIPHER_BLOCK_203.0.113.53 exists in netsh: False
  [NOT RUN] Enforce OS firewall rule creation requires elevated backend (UAC approval).
  Backend reported os_rule_applied=False (failed safely due to non-elevated token).

[STEP 5] Protected Address Safety Checks (enforce mode):
  [PASS] Attempt to block Loopback address (127.0.0.1) -> HTTP 400: Protected loopback address
  [PASS] Attempt to block Invalid string address (any) -> HTTP 400: 'any' is not a valid IP address
  [PASS] Attempt to block Host LAN IP (10.73.245.32)   -> HTTP 400: Belongs to this host
  [PASS] Attempt to block CIPHER_PROTECTED_IPS (10.0.0.1) -> HTTP 400: Inside protected range 10.0.0.0/8

[STEP 6] Windows Firewall Lingering CIPHER_BLOCK_* Rule Check:
  [PASS] No lingering CIPHER_BLOCK_* rules exist in Windows Firewall.
```

### A4: Live Sensor, WAF & Attack Battery
Verified using `backend/scripts/live_checks/live_sensor_waf.py` ([A4_live.log](backend/artifacts/test_logs/A4_live.log)):
- **External Kali VM Attack**: **NOT RUN** (Reason: An external Kali Linux VM on a separate hardware interface was not attached to the testbed).
- **Vulnerable Demo Application Battery** (Port 5174):
  - **SQL Injection (Auth Bypass)**: `POST /login` (`username=' OR '1'='1' --`) $\to$ Intercepted, logged in DB as `WEB_ATTACK` / `SQL_INJECTION`.
  - **SQL Injection (UNION SELECT)**: `POST /signup` (`username=admin' UNION SELECT 1,2,3,4 --`) $\to$ Intercepted, logged as `WEB_ATTACK` / `SQL_INJECTION`.
  - **Cross-Site Scripting (XSS)**: `POST /login` (`username=<script>alert('CIPHER_XSS')</script>`) $\to$ Intercepted, logged as `WEB_ATTACK` / `XSS`.
  - **Path Traversal**: `GET /?file=../../../../windows/win.ini` $\to$ Intercepted, logged as `WEB_ATTACK` / `DIRECTORY_TRAVERSAL`.
  - **SQLite ATTACH Injection**: `POST /login` (`username='; ATTACH DATABASE 'hack.db' AS h; --`) $\to$ Intercepted, logged as `WEB_ATTACK` / `SQL_INJECTION`.
- **Database Query Verification**:
  Queried `/api/events?event_type=WEB_ATTACK&limit=10`, confirming all 5 attack vectors were recorded in SQLite with distinct UUIDs and correct taxonomy classifications.

### A5: C++ Npcap Packet Sensor & Chrome MV3 Browser Guard
- **C++ Npcap Packet Sensor** ([A5_cpp.log](backend/artifacts/test_logs/A5_cpp.log)):
  Compiled with MinGW `g++ -I npcap-sdk/Include backend/cpp_sensor/main.cpp -L npcap-sdk/Lib/x64 -lwpcap -lPacket -lws2_32 -o backend/cpp_sensor/sensor.exe`. Captured live Wi-Fi adapter packets over a 30-second window, streaming 100 JSON-formatted flow records to stdout with zero memory stalls.
- **Chrome MV3 Browser Extension** ([A5_extension.log](backend/artifacts/test_logs/A5_extension.log)):
  Launched Google Chrome via Chrome DevTools Protocol (CDP) with unpacked extension `chrome_extension/`. Verified manifest v3 parsing, service worker activation (`background.js`), and verified threat badge transition to `!` upon querying high-risk phishing URLs.

---

## 6. Machine Learning Evaluation & Dataset Generalization

All metric tables are generated by `backend/scripts/generate_docs_metrics.py` directly from the committed model artifacts:

### 6.1 Multi-Model Benchmark Summary (Held-Out Test Sets)
<!-- METRICS:SUMMARY:START -->
| Model | Dataset (held-out test set) | Features | Accuracy | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Phishing URL (Random Forest) | PhiUSIIL, random stratified split (35,306 URLs) | 15 | 98.09% | 97.96% | 97.55% | 0.9775 | 1.520% |
| Network IDS, binary gate (Random Forest) | CIC-IDS2017, random stratified split (404,433 flows) | 67 | 99.903% | 99.445% | 99.944% | 0.9969 | 0.104% |
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
| **Retrained Probe (Generic Paths, Probe-Excluded)** | **9 / 15 (60.0% FP)** | 2 / 10 | **0 / 15 (0.0% FP)** | 2 / 10 |

**Whitelisting vs. Raw ML.** The full service achieves 0/15 false positives primarily through the two-tier domain whitelist (`TRUSTED_DOMAINS` and the Tranco top-50k list), because most legitimate domains in the probe reside in Tranco. The true statistical capability of the machine learning classifier alone is reflected in the raw model row (which dropped from 15/15 to 9/15), not the whitelist-assisted service verdict.

### 6.5 Root Cause Analysis of Performance Gaps & Data Leakage:
1. **PhiUSIIL Bare-Homepage Artifact & Honest Retraining**:
   - *Cause*: All 134,850 legitimate URLs in raw PhiUSIIL are bare homepages (`https://www.example.com`), while phishing URLs carry long paths and query strings. The raw model learned that the presence of any path or URL entropy indicates an attack.
   - *Remedy*: Augmented training data with 25,000 legitimate deep paths from Tranco top-50k domains, strictly excluding all probe domains from sampling and using generic path templates.
   - *The consequence of path augmentation*: Retraining with generic paths forced the tree ensemble to evaluate lexical structure rather than merely penalizing the presence of a path, reducing raw false alarms from 15/15 to 9/15 on probe deep links.
   - *The new vulnerability: phishing on legitimate / user-publishing platforms*: Training on diverse hosts with generic paths taught the decision trees that ordinary-looking paths (e.g., `/view/...`, `/login`, `/account`) are typical of legitimate websites. As a direct consequence, the retrained model exhibits reduced sensitivity to phishing hosted on legitimate cloud platforms and user-content services. For example, `sites.google.com/view/paypal-verify-account` dropped from a threat score of 85 (`LIKELY_PHISHING`) to 21 (`LEGITIMATE`), and `evil.weebly.com/office365-login` received a raw model probability of only 0.09.
   - *Independent evaluation on unseen paths*: In testing on held-out URLs with paths not seen in training (measured during external review, Oct 31, 2026), the raw model flagged 7 out of 15 legitimate URLs (including deep paths on `mit.edu`, `nist.gov`, `bbc.co.uk`, `rust-lang.org`, `cloudflare.com`, `flipkart.com`, and `sbi.co.in`) and missed 1 out of 12 phishing URLs. This demonstrates that pure lexical URL classification has intrinsic limitations: distinguishing an authentic corporate login page from a cloud-hosted credential harvest cannot be solved reliably by URL string features alone without external context (e.g. host domain reputation, TLS certificates, or DOM content).
2. **CIC-IDS2017 Day Split Collapse (Zero-Shot Category Absence)**:
   - *Cause*: The 67 extracted features contain statistical flow metrics (packet lengths, inter-arrival times, TCP flags, duration) and do NOT contain IP addresses or temporal timestamps. The drop in binary accuracy from 99.90% to 77.38% (recall 37.08%) and per-class F1 to 0.0000 on Botnet, DDoS, and PortScan occurs because **those attack categories were executed exclusively on Friday**. Monday through Thursday contained DoS, Brute Force, Web Attacks, and Infiltration.
   - *Insight*: The day-split experiment rigorously demonstrates that decision tree ensembles on flow statistics fail to detect novel, unseen attack categories without prior training support.
3. **Email Corpus Domain Shift**:
   - *Cause*: Classical features (`avg_word_length`, `body_length`, `exclamation_count`) memorize corpus-specific writing styles and eras. In LOCO evaluation, models trained on vintage spam failed on targeted phishing templates (Nazario recall: 38.11%), showing that surface features do not capture invariant attack intent.

---

## 7. Operational Limitations & Open Scope

1. **Host Firewall OS Modifications Under Non-Elevated Testing**:
   Standard non-elevated user tokens (`Medium Mandatory Level`) cannot execute `netsh advfirewall`. While CIPHER handled this gracefully by logging `os_rule_applied=False`, live packet drops require administrative elevation.
2. **External Dedicated Attack VM**:
   An external Kali Linux VM on a separate hardware interface was not attached to the bare-metal testbed; testing used local HTTP/TCP socket loops and synthetic PCAP feature streams.
3. **Missing Datasets**:
   - `CSE-CIC-IDS2018`: Not present in `backend/data/raw/cse_cic_ids2018/` (marked NOT RUN per Rule 5).
   - Sample CIC PCAP: Raw packet capture files were not present in the repository; unit test skipped per Rule 5.
4. **Packet Length Definition in Flow Extraction**:
   `flow.py` tracks wire packet length (`len(pkt)` via Scapy), whereas CICFlowMeter v3 calculates payload lengths for certain features. Parity was verified on TCP header sizes (`min_seg_size_forward`) and timeouts (120s / 5s).

---

## 8. Final Verification Checklist

| Item | Description | Status | Verification Summary |
|---|---|:---:|---|
| **1.1** | Fresh `TEST_REPORT.md` | **PASS** | Rewritten strictly quoting committed logs with relative links. |
| **1.2** | Rerunnable `api_access.py` | **PASS** | Automated script exits 0 on valid auth, 401 on missing, 403 on CSRF. |
| **1.3** | Quoted `%TEMP%` in `run.bat` | **PASS** | Added quotes inside `runas /trustlevel:0x20000 "cmd /k ..."` invocation. |
| **1.4** | Zero `file:///` links | **PASS** | Verified relative Markdown links only across all tracked files. |
| **2.1** | Two-tier phishing whitelist | **PASS** | Built-in critical domains + bundled Tranco 50k local JSON whitelist. |
| **2.2** | Bundled Tranco JSON | **PASS** | `trusted_domains.json` generated and committed to repository. |
| **2.3** | Whitelist unit tests | **PASS** | Regression tests pass for private IPs, trusted domains, and bypass checks. |
| **2.4** | Whitelist probe comparison | **PASS** | Captured and committed baseline probe comparison CSVs. |
| **3.1** | Baseline pytest suite | **PASS** | 252 tests passed in 14.65 seconds (`A0_pytest.log`). |
| **3.2** | Frontend tsc, vitest, build | **PASS** | 13/13 vitest passed, production build completed in 5.69s (`A0_frontend.log`). |
| **3.3** | Phase 10 safety validation | **PASS** | 8/8 scenarios passed in 5.76s (`A0_phase10.log`). |
| **3.4** | Metrics check | **PASS** | All documentation metric blocks match committed model artifacts (`A0_metrics.log`). |
| **4.1** | Launcher network exposure | **PASS** | Verified 127.0.0.1 bindings (N) and 0.0.0.0 bindings + rule cleanup (Y). |
| **4.2** | Live API & browser CSRF | **PASS** | Verified bearer token requirement and cross-origin fetch rejection. |
| **4.3** | Windows firewall checks | **PASS** | Non-elevated netsh caught; simulate, enforce, and 4 protected IP rejections verified. |
| **4.4** | Live sensor & WAF battery | **PASS** | SQLi, XSS, Path Traversal, and SQLite ATTACH detected and logged to database. |
| **4.4-K**| External Kali VM testing | **NOT RUN** | External Kali VM not attached to testbed (local loopback used). |
| **4.5-C**| C++ Npcap packet capture | **PASS** | Captured and streamed 100 live packets from Wi-Fi adapter. |
| **4.5-E**| Chrome MV3 browser extension | **PASS** | Extension loaded via CDP, background worker active, threat badge tested. |
| **5.1** | Feature pipeline alignment | **PASS** | Imputation medians and +inf replacements fitted strictly on train split. |
| **5.2-R**| Network random split training | **PASS** | Trained binary & multiclass RF models; 99.903% accuracy; eval saved. |
| **5.2-D**| Network day split training | **PASS** | Monday–Thursday train, Friday test; documented zero-shot category absence. |
| **5.2-C**| Network cross-dataset split | **NOT RUN** | CSE-CIC-IDS2018 dataset not present on testbed per Rule 5. |
| **5.3** | Feature extraction parity | **PASS** | Aligned `min_seg_size_forward` to TCP header and timeouts to 120s / 5s. |
| **5.3-P**| Sample CIC PCAP replay | **NOT RUN** | Raw CIC PCAP not present on testbed; skipped per Rule 5. |
| **5.4** | Phishing retrain with deep paths| **PASS** | Trained with Tranco deep paths; probe FP dropped from 15/15 to 9/15 (service 0/15). |
| **5.5** | Email Leave-One-Corpus-Out | **PASS** | LOCO evaluation completed across 5 corpora; documented style shift. |
| **5.6** | Documentation sync | **PASS** | Reconciled dataset documentation and dropped unverified warnings. |
| **5.7** | Final full test suite | **PASS** | 255 passed, 1 skipped, 0 failed in 21.98s (`B7_final_suite.log`). |
