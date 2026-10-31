# CIPHER — Evidence Index & Verifiable Claims Matrix

> **Note (v1.3, Oct 2026):** This document predates the v1.3 hardening release. Model metrics have been reconciled with the committed artifacts; where any figure here differs from [model_results.md](model_results.md) (generated from the artifacts), model_results.md is authoritative. Security and prevention behaviour changed in v1.3: see [SECURITY.md](../SECURITY.md) and [CHANGELOG.md](../CHANGELOG.md).


This document maps every major technical claim made regarding **CIPHER** to verifiable files, serialized artifacts, test suites, and empirical reports within the codebase.

---

## 1. Machine Learning & Model Performance Claims

| Claim | Measured Value | Verifiable Evidence Location |
|:---|:---:|:---|
| **Phishing Test Accuracy** | 98.75% | [model_metadata.json](../backend/models/phishing/model_metadata.json)<br/>[evaluation_report.txt](../backend/models/phishing/evaluation_report.txt) |
| **Phishing Test Precision & Recall** | Prec: 98.79%<br/>Rec: 98.28% | [model_metadata.json](../backend/models/phishing/model_metadata.json) |
| **Phishing Confusion Matrix** | TN=20,046, FP=182<br/>FN=259, TP=14,819 | [model_metadata.json](../backend/models/phishing/model_metadata.json) |
| **Phishing Feature Count** | 15 features | [model_metadata.json](../backend/models/phishing/model_metadata.json)<br/>[feature_extractor.py](../backend/app/ml/feature_extractor.py) |
| **Network IDS Binary Accuracy** | 99.903% | [network_model_metadata.json](../backend/models/network/network_model_metadata.json)<br/>[network_evaluation_report.txt](../backend/models/network/network_evaluation_report.txt) |
| **Network Binary Confusion Matrix** | TN=340,228, FP=353<br/>FN=38, TP=63,823 | [network_model_metadata.json](../backend/models/network/network_model_metadata.json) |
| **Network Multiclass Metrics** | Acc: 99.897%<br/>Macro F1: 90.036% | [network_model_metadata.json](../backend/models/network/network_model_metadata.json) |
| **Network Feature Count** | 67 features | [network_model_metadata.json](../backend/models/network/network_model_metadata.json) |
| **Documented Minority Class Weakness** | Botnet Prec: 69.77%<br/>Infiltration: 6 test samples | [network_model_metadata.json](../backend/models/network/network_model_metadata.json)<br/>[model_results.md](../docs/model_results.md) |

---

## 2. Dataset Cleaning & Ingestion Claims

| Claim | Quantified Metric | Verifiable Evidence Location |
|:---|:---:|:---|
| **PhiUSIIL Deduplication** | 235,795 $\to$ 235,370 unique URLs (425 duplicates dropped) | [preprocess_phiusiil.py](../backend/training/preprocess_phiusiil.py)<br/>[test_detection.py](../backend/tests/test_detection.py) |
| **CIC-IDS2017 Deduplication** | 2,830,743 $\to$ 2,498,883 unique flows (331,860 duplicates dropped) | [preprocess_cic_ids2017.py](../backend/training/preprocess_cic_ids2017.py)<br/>[test_network_dataset.py](../backend/tests/test_network_dataset.py) |
| **CIC-IDS2017 Benign Training Cap** | 150,000 benign training flows capped; Val/Test unadulterated | [preprocess_cic_ids2017.py](../backend/training/preprocess_cic_ids2017.py)<br/>[dataset_documentation.md](../docs/dataset_documentation.md) |

---

## 3. End-to-End Validation & Provenance Claims

| Claim | Observed Outcome | Verifiable Evidence Location |
|:---|:---:|:---|
| **Phase 10 Scenario Matrix (A–H)** | 8/8 Scenarios Passed in 5.18s | [validation_report.json](../backend/artifacts/phase10/validation_report.json)<br/>[validation_summary.md](../backend/artifacts/phase10/validation_summary.md) |
| **Scenario H Provenance Chain** | Flow $\to$ Event $\to$ Rule $\to$ IOC $\to$ Incident $\to$ Prevention | [validation_report.json](../backend/artifacts/phase10/validation_report.json)<br/>[scenarios.py](../backend/scripts/phase10_validation/scenarios.py) |
| **Strict Loopback Confinement** | Non-loopback IPs raise `ValueError` | [config.py](../backend/scripts/phase10_validation/config.py)<br/>[test_phase10_validation.py](../backend/tests/test_phase10_validation.py) |
| **Test IOC Isolation & Cleanup** | `CIPHER_PHASE10_TEST` indicators purged | [scenarios.py](../backend/scripts/phase10_validation/scenarios.py)<br/>[test_phase10_validation.py](../backend/tests/test_phase10_validation.py) |
| **Zero Host Modification Invariant** | Firewall untouched in `simulate`/`detect_only` (mock-verified in test_prevention_safety.py) | [prevention_engine.py](../backend/app/prevention/prevention_engine.py)<br/>[test_prevention.py](../backend/tests/test_prevention.py) |

---

## 4. Software Quality & Regression Test Claims

| Claim | Verified Execution Output | Verifiable Evidence Location |
|:---|:---:|:---|
| **Backend Test Suite Execution** | see CI (`pytest tests -q`) | `pytest tests/ -q`<br/>13 test modules in [tests/](../backend/tests/) |
| **Frontend Test Suite Execution** | see CI (`npx vitest run`) | `npm run test`<br/>4 test suites in [frontend/src/test/](../frontend/src/test/) |
| **Frontend TypeScript Type Check** | 0 type errors | `npx tsc --noEmit` executed cleanly |
| **Frontend Production Build** | Production bundle compiled in 1.34s | `npm run build`<br/>Output in [frontend/dist/](../frontend/dist/) |
