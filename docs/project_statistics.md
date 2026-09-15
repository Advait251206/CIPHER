# CIPHER — Verified Project Statistics & System Parameters

This reference document compiles verified numerical statistics, architectural thresholds, operational capacities, and test metrics confirmed by the active implementation of **CIPHER**.

---

## 1. Quality Assurance & Regression Verification
- **Total Backend Pytest Cases**: **152 passed** (0 failed, 2 Starlette deprecation warnings, execution time ~13s)
- **Total Frontend Vitest Cases**: **11 passed** (0 failed, execution time ~1.3s)
- **Frontend TypeScript Compiler Status**: **0 errors** (`npx tsc --noEmit`)
- **Frontend Production Build**: **PASS** (1,901 modules transformed in 1.34s)
- **Phase 10 End-to-End Validation Scenarios**: **8 evaluated, 8 passed (100% pass rate)**

---

## 2. Dataset Dimensions & Training Volumes
- **PhiUSIIL Phishing URL Dataset**:
  - Raw instances loaded: **235,795**
  - Deduplicated instances: **235,370 unique URLs** (425 duplicates dropped)
  - Features extracted: **28 lexical, structural, and information-theoretic features**
  - Train partition (70%): **164,759 URLs**
  - Validation partition (15%): **35,305 URLs**
  - Held-out test partition (15%): **35,306 URLs**
- **CIC-IDS2017 Network Intrusion Benchmark**:
  - Raw flow records ingested: **2,830,743 flows** across 8 capture windows
  - Deduplicated flows: **2,498,883 unique flows** (331,860 cross-file duplicates removed)
  - Features extracted: **67 statistical flow features** (constant/duplicate columns removed)
  - Raw 70% train split: 1,749,218 flows (298,019 attacks + 1,451,199 benign)
  - Benign training sample cap: **150,000 flows** (stratified sample with fixed seed 42)
  - Balanced training dataset: **448,019 flows** (298,019 attacks + 150,000 benign)
  - Unadulterated validation partition (15%): **374,832 flows**
  - Unadulterated held-out test partition (15%): **374,833 flows**

---

## 3. Subsystem Limits, Caches & Timing Windows
- **Multi-Stage Event Correlation**:
  - Temporal correlation sliding window: **300 seconds** (`CORRELATION_WINDOW_SECONDS`)
  - Maximum active correlation chains in memory: **10,000 chains**
  - Correlation identity invariant: `(source_ip, destination_ip)` for network flows, `(domain/url)` for phishing
- **Threat Intelligence & IOC Store**:
  - In-memory thread-safe LRU cache capacity: **5,000 indicators**
  - Single-transaction bulk import limit: **1,000 records**
  - Supported indicator formats: `IP`, `DOMAIN`, `URL`, `HASH`
- **Live Packet Capture Sensor**:
  - Maximum concurrent in-memory active flows: **50,000 flows**
  - Flow idle timeout: **5 seconds**
  - Flow active timeout: **60 seconds**
- **Deterministic Heuristic & Signature Engine**:
  - Total registered rules: **14 rules** (10 heuristics, 4 signatures)
  - Temporal state entry capacity: **10,000 entries**
  - Port scan trigger threshold: $\ge 10$ distinct destination ports within **60 seconds**
  - Brute force trigger threshold: $\ge 5$ authentication attempts within **60 seconds**
  - Volumetric DoS packet rate threshold: $> 50,000$ packets/second
  - Volumetric DoS byte rate threshold: $> 5,000,000$ bytes/second
  - Distributed DoS source threshold: $\ge 3$ distinct sources within **60 seconds**
- **Intrusion Prevention Engine**:
  - Supported operational modes: **3 modes** (`detect_only`, `simulate`, `enforce`)
  - Default operational mode: `detect_only` (safe, passive logging)
  - Default simulated temporary block duration: **60 minutes**

---

## 4. Software & Interface Footprint
- **Backend Framework**: Python 3.13 / FastAPI 0.115 / Scikit-Learn 1.6 / Scapy 2.6
- **Database**: SQLite3 with WAL mode and composite indexing
- **Frontend Framework**: React 18.3 / TypeScript 5.6 / Vite 6.4 / Vanilla CSS
- **REST API Surface**: **27 distinct endpoints** organized across 8 modular routers
- **SOC Dashboard Views**: **10 full operational views**
