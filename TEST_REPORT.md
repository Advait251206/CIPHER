# CIPHER v1.3 — Test & Verification Report

**Platform**: Windows 11 / PowerShell 5.1 & pwsh  
**Target Version**: CIPHER v1.3.0  
**Verification Date**: 2026-10-31  

_This report is generated strictly from verbatim log files captured under `backend/artifacts/test_logs/`. No results or metrics are hand-typed or simulated._

---

## 1. Summary of Verification Runs

| Phase | Check Description | Result | Verbatim Log Link |
|---|---|:---:|---|
| Phase 3.1 | Backend Pytest Suite | PENDING | [A0_pytest.log](backend/artifacts/test_logs/A0_pytest.log) |
| Phase 3.2 | Frontend Build & Vitest | PENDING | [A0_frontend.log](backend/artifacts/test_logs/A0_frontend.log) |
| Phase 3.3 | Phase 10 Validation Pipeline | PENDING | [A0_phase10.log](backend/artifacts/test_logs/A0_phase10.log) |
| Phase 3.4 | Metrics Single Source of Truth | PENDING | [A0_metrics.log](backend/artifacts/test_logs/A0_metrics.log) |
| Phase 4.1 | Launcher Isolation (N & Y) | PENDING | [A1_launcher_N.log](backend/artifacts/test_logs/A1_launcher_N.log), [A1_launcher_Y.log](backend/artifacts/test_logs/A1_launcher_Y.log) |
| Phase 4.2 | API Access Control & CSRF Guard | PENDING | [A2_api.log](backend/artifacts/test_logs/A2_api.log), [A2_browser.log](backend/artifacts/test_logs/A2_browser.log) |
| Phase 4.3 | Windows Firewall Prevention Lifecycle | PENDING | [A3_firewall.log](backend/artifacts/test_logs/A3_firewall.log) |
| Phase 4.4 | Live Sensor, WAF, & Attack Ingestion | PENDING | [A4_live.log](backend/artifacts/test_logs/A4_live.log) |
| Phase 4.5 | Browser Guard Extension & C++ Sensor | PENDING | [A5_extension.log](backend/artifacts/test_logs/A5_extension.log), [A5_cpp.log](backend/artifacts/test_logs/A5_cpp.log) |
| Phase 5.1 | Network Feature Pipeline Alignment | PENDING | [B1_network_pipeline.log](backend/artifacts/test_logs/B1_network_pipeline.log) |
| Phase 5.2 | Network Splits (Random / Day / Cross) | PENDING | [B2_network_splits.log](backend/artifacts/test_logs/B2_network_splits.log) |
| Phase 5.3 | Live Feature Parity with CICFlowMeter | PENDING | [B3_feature_parity.log](backend/artifacts/test_logs/B3_feature_parity.log) |
| Phase 5.4 | Phishing Retrain & Deep Path Probe | PENDING | [B4_phishing_retrain.log](backend/artifacts/test_logs/B4_phishing_retrain.log) |
| Phase 5.5 | Email Leave-One-Corpus-Out Benchmark | PENDING | [B5_email_loco.log](backend/artifacts/test_logs/B5_email_loco.log) |
| Phase 5.7 | Final Full Verification Run | PENDING | [B7_final_suite.log](backend/artifacts/test_logs/B7_final_suite.log) |
