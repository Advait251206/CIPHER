# CIPHER — Machine Learning Evaluation & Benchmark Results

This document presents the empirical evaluation metrics measured on the independent, held-out test partitions for both of CIPHER's machine learning subsystems:
1. **Phishing URL Detector** (Random Forest trained on PhiUSIIL)
2. **Network Intrusion Detection System** (Dual Random Forest trained on CIC-IDS2017)

> [!IMPORTANT]
> **Scientific Integrity & Generalization Disclaimer**:
> These metrics were rigorously measured on the specified held-out datasets and benchmark partitions. They should **not** be interpreted as universal real-world attack detection accuracy. Real-world networks and web traffic exhibit ongoing concept drift, zero-day evasion techniques, and varied structural distributions not fully represented in historical benchmark corpora.

---

## 1. Phishing URL Model Evaluation

### Test Partition Configuration
- **Dataset**: PhiUSIIL Phishing URL Dataset
- **Evaluation Set Size**: **35,306 unique, unseen URLs** (15% held-out test partition)
- **Features Extracted**: 28 static lexical, structural, and information-theoretic features
- **Model**: `RandomForestClassifier` (`n_estimators=100`, `max_depth=22`, `random_state=42`)

### Quantitative Metrics
| Metric | Measured Value | Description |
|:---|:---:|:---|
| **Accuracy** | **99.66%** | Overall proportion of correct predictions |
| **Precision** | **99.91%** | True positives divided by all predicted phishing URLs |
| **Recall (Sensitivity)** | **99.29%** | Proportion of actual phishing URLs correctly identified |
| **F1-Score** | **0.9960** | Harmonic mean of precision and recall |
| **ROC-AUC** | **0.9991** | Area under the Receiver Operating Characteristic curve |
| **Specificity** | **99.94%** | Proportion of legitimate URLs correctly identified |
| **False Positive Rate (FPR)** | **0.064%** | Legitimate URLs erroneously flagged as phishing (13 / 20,228) |
| **False Negative Rate (FNR)** | **0.710%** | Phishing URLs missed by the classifier (107 / 15,078) |
| **Inference Throughput** | **161,916 URLs/s** | Benchmark execution speed on local hardware |

### Phishing Confusion Matrix (Test Set: 35,306 samples)
```text
                   Predicted Legitimate    Predicted Phishing
Actual Legitimate        20,215 (TN)               13 (FP)
Actual Phishing             107 (FN)           14,971 (TP)
```

---

## 2. Network IDS Binary Model Evaluation

### Test Partition Configuration
- **Dataset**: CIC-IDS2017 (`MachineLearningCSV`, 8 packet capture windows)
- **Evaluation Set Size**: **374,833 unique, unseen flows** (15% natural held-out test partition)
- **Features**: 67 bidirectional statistical flow features
- **Model**: `RandomForestClassifier` (Binary Gate: `n_estimators=100`, `max_depth=24`, `min_samples_leaf=2`)

### Binary Detection Metrics
| Metric | Measured Value | Formula / Details |
|:---|:---:|:---|
| **Accuracy** | **99.903%** | $(310,664 + 63,806) / 374,833$ |
| **Precision** | **99.520%** | $63,806 / (63,806 + 308)$ |
| **Recall** | **99.914%** | $63,806 / (63,806 + 55)$ |
| **F1-Score** | **99.716%** | Harmonic mean |
| **ROC-AUC** | **1.0000** | Measured: 0.999969 |
| **PR-AUC** | **0.9999** | Measured: 0.999878 |
| **False Positive Rate (FPR)** | **0.099%** | $308 / 310,972$ benign flows |
| **False Negative Rate (FNR)** | **0.086%** | $55 / 63,861$ attack flows |

### Binary Confusion Matrix (Test Set: 374,833 samples)
```text
                   Predicted Benign        Predicted Attack
Actual Benign        310,664 (TN)              308 (FP)
Actual Attack             55 (FN)           63,806 (TP)
```

---

## 3. Network IDS Multiclass Model Evaluation

When the binary gate classifies incoming traffic as malicious, Model 2 (Multiclass Random Forest) maps the flow to one of eight specialized attack taxonomies.

### Summary Multiclass Metrics
- **Multiclass Accuracy**: **99.900%**
- **Macro-Averaged F1-Score**: **96.142%**
- **Weighted-Averaged F1-Score**: **99.902%**

### Per-Class Detailed Performance Breakdown
| Attack Category | Precision | Recall | F1-Score | Test Set Support | Support Classification |
|:---|:---:|:---:|:---:|:---:|:---:|
| **BENIGN** | 99.98% | 99.90% | 99.94% | 310,972 | Massive Support |
| **DOS** | 99.60% | 99.92% | 99.76% | 29,042 | High Support |
| **DDOS** | 99.95% | 99.98% | 99.97% | 19,203 | High Support |
| **PORT_SCAN** | 99.53% | 99.91% | 99.72% | 13,623 | High Support |
| **BRUTE_FORCE** | 99.78% | 99.78% | 99.78% | 1,373 | Moderate Support |
| **WEB_ATTACK** | 98.73% | 96.88% | 97.80% | 321 | Low Support |
| **BOTNET** | **69.39%** | **92.83%** | **79.42%** | 293 | Low Support (Weak Precision) |
| **INFILTRATION** | **100.0%** | **80.00%** | **88.89%** | **5** | Extremely Low Support |
| **OTHER_ATTACK** | **100.0%** | **100.0%** | **100.0%** | **1** | Single Sample Support |

---

## 4. Technical Analysis of Weaknesses and Low-Support Categories

A rigorous scientific review requires highlighting areas where machine learning models face empirical limitations:

1. **BOTNET Precision (69.39%)**:
   - While recall is high (92.83%), precision is noticeably lower than other classes.
   - *Root Cause*: Botnet traffic in CIC-IDS2017 (ARES botnet IRC traffic) shares statistical flow volume and timing profiles with benign background HTTP/DNS polling.
   - *Mitigation in CIPHER*: Phase 7 introduced deterministic heuristic `HEUR-ANOMALY-002` (monitoring legacy IRC ports 6667–7000) and Phase 8 introduced IOC matching to cross-verify botnet detections rather than relying solely on ML flow probabilities.

2. **INFILTRATION Support (5 Test Samples)**:
   - Infiltration attacks (e.g., Dropbox downloads executing backdoor payloads) comprise only 36 total flows in the entire 2.83M CIC-IDS2017 corpus.
   - In the 15% stratified test partition, only 5 flows were present.
   - *Conclusion*: A reported recall of 80% (4/5 detected) is statistically fragile due to the extreme scarcity of samples. CIPHER does not claim robust real-world infiltration detection on ML alone.

3. **OTHER_ATTACK Support (1 Test Sample)**:
   - Heartbleed vulnerability flows comprise only 11 total instances across CIC-IDS2017.
   - In the test set, exactly 1 flow was present.
   - *Conclusion*: 100% precision/recall on a single sample is statistically anecdotal and cannot guarantee generalization to real-world Heartbleed exploitation.

4. **Synergistic Architecture Justification**:
   - The existence of these low-support and lower-precision categories directly validates CIPHER's multi-layered defense-in-depth architecture.
   - When ML confidence is low or support is sparse, the **Heuristic Rule Engine** (Phase 7) and **Threat Intelligence IOC Layer** (Phase 8) provide deterministic ground truth, ensuring high-risk threats are never silently ignored.
