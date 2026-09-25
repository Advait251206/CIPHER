# CIPHER — Evidence Index & Verifiable Claims Matrix

This document maps every major technical claim made regarding **CIPHER** to verifiable files, serialized artifacts, test suites, and empirical reports within the codebase.

---

## 1. Machine Learning & Model Performance Claims

| Claim | Measured Value | Verifiable Evidence Location |
|:---|:---:|:---|
| **Phishing Test Accuracy** | 99.66% | [model_metadata.json](../backend/models/phishing/model_metadata.json#L149)<br/>[evaluation_report.txt](../backend/models/phishing/evaluation_report.txt) |
| **Phishing Test Precision & Recall** | Prec: 99.91%<br/>Rec: 99.29% | [model_metadata.json](../backend/models/phishing/model_metadata.json#L150-L151) |
| **Phishing Confusion Matrix** | TN=20,215, FP=13<br/>FN=107, TP=14,971 | [model_metadata.json](../backend/models/phishing/model_metadata.json#L157-L162) |
| **Phishing Feature Count** | 15 features | [model_metadata.json](../backend/models/phishing/model_metadata.json#L8)<br/>[feature_extractor.py](../backend/app/ml/feature_extractor.py) |
| **Network IDS Binary Accuracy** | 99.903% | [network_model_metadata.json](../backend/models/network/network_model_metadata.json#L126)<br/>[network_evaluation_report.txt](../backend/models/network/network_evaluation_report.txt) |
| **Network Binary Confusion Matrix** | TN=310,664, FP=308<br/>FN=55, TP=63,806 | [network_model_metadata.json](../backend/models/network/network_model_metadata.json#L132-L135) |
| **Network Multiclass Metrics** | Acc: 99.900%<br/>Macro F1: 96.142% | [network_model_metadata.json](../backend/models/network/network_model_metadata.json#L140-L142) |
| **Network Feature Count** | 67 features | [network_model_metadata.json](../backend/models/network/network_model_metadata.json#L21) |
| **Documented Minority Class Weakness** | Botnet Prec: 69.39%<br/>Infiltration: 5 test samples | [network_model_metadata.json](../backend/models/network/network_model_metadata.json#L150-L179)<br/>[model_results.md](../docs/model_results.md) |

---

## 2. Dataset Cleaning & Ingestion Claims

| Claim | Quantified Metric | Verifiable Evidence Location |
|:---|:---:|:---|
| **PhiUSIIL Deduplication** | 235,795 $\to$ 235,370 unique URLs (425 duplicates dropped) | [preprocess_phiusiil.py](../backend/training/preprocess_phiusiil.py)<br/>[test_detection.py](../backend/tests/test_detection.py) |
| **CIC-IDS2017 Deduplication** | 2,830,743 $\to$ 2,498,883 unique flows (331,860 duplicates dropped) | [preprocess_cic_ids2017.py](../backend/training/preprocess_cic_ids2017.py#L170-L181)<br/>[test_network_dataset.py](../backend/tests/test_network_dataset.py) |
| **CIC-IDS2017 Benign Training Cap** | 150,000 benign training flows capped; Val/Test unadulterated | [preprocess_cic_ids2017.py](../backend/training/preprocess_cic_ids2017.py#L208-L218)<br/>[dataset_documentation.md](../docs/dataset_documentation.md) |

---

## 3. End-to-End Validation & Provenance Claims

| Claim | Observed Outcome | Verifiable Evidence Location |
|:---|:---:|:---|
| **Phase 10 Scenario Matrix (A–H)** | 8/8 Scenarios Passed in 5.18s | [validation_report.json](../backend/artifacts/phase10/validation_report.json)<br/>[validation_summary.md](../backend/artifacts/phase10/validation_summary.md) |
| **Scenario H Provenance Chain** | Flow $\to$ Event $\to$ Rule $\to$ IOC $\to$ Incident $\to$ Prevention | [validation_report.json](../backend/artifacts/phase10/validation_report.json#L189-L204)<br/>[scenarios.py](../backend/scripts/phase10_validation/scenarios.py#L505-L596) |
| **Strict Loopback Confinement** | Non-loopback IPs raise `ValueError` | [config.py](../backend/scripts/phase10_validation/config.py#L49-L58)<br/>[test_phase10_validation.py](../backend/tests/test_phase10_validation.py#L38-L47) |
| **Test IOC Isolation & Cleanup** | `CIPHER_PHASE10_TEST` indicators purged | [scenarios.py](../backend/scripts/phase10_validation/scenarios.py#L363-L367)<br/>[test_phase10_validation.py](../backend/tests/test_phase10_validation.py#L86-L96) |
| **Zero Host Modification Invariant** | Firewall untouched in `simulate`/`detect_only` | [prevention_engine.py](../backend/app/prevention/prevention_engine.py#L84-L109)<br/>[test_prevention.py](../backend/tests/test_prevention.py) |

---

## 4. Software Quality & Regression Test Claims

| Claim | Verified Execution Output | Verifiable Evidence Location |
|:---|:---:|:---|
| **Backend Test Suite Execution** | 152 passed, 0 failed in ~13s | `pytest tests/ -q`<br/>13 test modules in [tests/](../backend/tests/) |
| **Frontend Test Suite Execution** | 11 passed, 0 failed in ~1.3s | `npm run test`<br/>4 test suites in [frontend/src/test/](../frontend/src/test/) |
| **Frontend TypeScript Type Check** | 0 type errors | `npx tsc --noEmit` executed cleanly |
| **Frontend Production Build** | Production bundle compiled in 1.34s | `npm run build`<br/>Output in [frontend/dist/](../frontend/dist/) |
