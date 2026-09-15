# CIPHER — Demonstration Runbook (8–12 Minutes)

This step-by-step runbook provides a complete, polished demonstration flow for presenting **CIPHER** (*Cyber Intrusion Prevention & Heuristic Event Response*) to evaluators, technical reviewers, or project examiners.

> [!IMPORTANT]
> **Safety Boundary Reminder**:
> All traffic generated during this demonstration is strictly confined to **localhost loopback (`127.0.0.1`)**. No external networks, public IP addresses, or destructive floods are utilized.

---

## Preparation & Environment Startup (Minute 0–2)

### Terminal 1: Launch FastAPI Backend
```powershell
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
*Confirmation: Console logs show database initialized, Phishing model loaded (`phiusiil-rf-v1`), and Network IDS model loaded (`cicids2017-dual-rf-v1`).*

### Terminal 2: Launch SOC Frontend
```powershell
cd frontend
npm run dev
```
*Confirmation: Vite starts the local development server at `http://localhost:5173`.*

---

## Demonstration Sequence (Minute 2–10)

### 1. System Health & Architecture Overview (Minute 2–3)
- Navigate browser to: **`http://localhost:5173`**
- Click **System Health** in the sidebar:
  - Highlight the 6 operational health cards: API Gateway, SQLite Database, Phishing Engine, Network IDS Engine, Prevention Engine, and Live Sensor.
  - Explain local-first guarantee: All models execute in-process without third-party cloud API dependencies.
- Click **Overview**:
  - Show the 8 real-time KPI counters (Critical, High, Medium, Low, Active Incidents, Flows Analyzed, Blocked IPs, Live Sensor status).

### 2. Network IDS Dual Random Forest Model Inspection (Minute 3–4)
- Click **Network IDS** in the sidebar:
  - Show Model Metadata: Dual Random Forest architecture (Binary Gate + 9-Class Multiclass) trained on 2.49M deduplicated flows from CIC-IDS2017 across 67 features.
  - Show Top Feature Importances (e.g., `Destination Port`, `Flow Duration`, `Packet Length Mean`).
  - Demonstrate Interactive Flow Sandbox: Select a preset (e.g., "Benign HTTP Flow"), click **Analyze Flow**, and observe sub-millisecond inference and threat scoring.

### 3. Phishing Detection Subsystem (Minute 4–5)
- Click **Phishing** in the sidebar:
  - Point out local privacy banner: *"Analysis is performed locally on this machine. CIPHER does not automatically transmit submitted indicators to external services."*
  - Select preset "Suspicious IP Host" (`http://192.168.1.1/login.php?user=admin&token=secure`).
  - Click **Analyze URL**:
  - Show 28-feature lexical extraction, Shannon entropy values, Random Forest attack probability, and heuristic keyword flags.
  - Review the actionable recommendation.

### 4. Benign vs. Port Scan Live Detection (Minute 5–7)
- Open Terminal 3:
```powershell
cd backend
python -c "from scripts.phase10_validation.scenarios import run_scenario_a_benign; print(run_scenario_a_benign())"
```
- Return to dashboard, click **Live Events**:
  - Show the newly arrived benign HTTP event: Threat Score **4/100** (`LOW`), Action `MONITORED_ONLY`.
- In Terminal 3, run the controlled port scan sweep:
```powershell
python -c "from scripts.phase10_validation.scenarios import run_scenario_b_port_scan; print(run_scenario_b_port_scan())"
```
- Refresh or observe Live Events:
  - Show `PORT_SCAN` event: Threat Score **80/100** (`CRITICAL`).
  - Click the event to open the **Event Evidence Modal**:
  - Show evidence breakdown: Triggered rules (`HEUR-PORTSCAN-001`, `SIGN-PORTSCAN-001`), half-open SYN flags, and reasoning.

### 5. Threat Intelligence & Incident Correlation (Minute 7–9)
- Click **Threat Intelligence** in the sidebar:
  - Show local SQLite IOC store (`threat_intel_iocs`).
  - Add or inspect a test indicator (e.g., `203.0.113.88`, Category: `SCANNER`, Severity: `HIGH`).
  - Demonstrate instant lookup: Enter `203.0.113.88` in the indicator search to show immediate in-memory cache hit.
- Click **Incidents**:
  - Show correlated incident chains.
  - Explain the **Correlation Identity Rule**: Incidents are correlated by `(source_ip, destination_ip)`, preventing unrelated targets from being merged.
  - Show multi-stage progression: `PORT_SCAN` followed by `BRUTE_FORCE` sets `escalation_detected=True` and boosts correlation score.
  - Demonstrate incident resolution: Click **Resolve Incident** with confirmation dialog.

### 6. Prevention Engine Simulation (Minute 9–10)
- Click **Prevention** in the sidebar:
  - Show IPS Mode Card (`detect_only` vs. `simulate`).
  - Show Active Blocklist: Display blocked IPs with dynamic TTL expiration countdowns.
  - Explain host safety invariant: In `simulate` mode, block actions are recorded in SQLite to demonstrate response workflows without altering the operating system firewall.

---

## Conclusion & Defensibility Walkthrough (Minute 10–12)

### 7. Full Provenance Chain & Validation Execution
- Run the full Phase 10 validation runner in Terminal 3:
```powershell
cd backend
python -m scripts.phase10_validation.runner
```
- Highlight console output: **8/8 PASSED in ~5.2 seconds**.
- Display the generated audit files:
  - `backend/artifacts/phase10/validation_summary.md`
  - Show Scenario H's unbroken 6-stage provenance chain:
    `Flow ID` $\to$ `Event ID` $\to$ `Rule Match` $\to$ `IOC Match` $\to$ `Incident ID` $\to$ `Prevention Action`.

### 8. Final Technical Summary
- Point to documentation in `docs/`:
  - `docs/model_results.md`: Empirical metrics on held-out test partitions (99.66% Phishing, 99.90% Network IDS).
  - `docs/limitations.md`: Honest appraisal of historical datasets, low-support categories, encrypted traffic, and domain shift.
- Conclude: CIPHER delivers a complete, cohesive, defensible, and fully validated intrusion prevention platform.
