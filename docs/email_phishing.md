# CIPHER Email Phishing Detection Subsystem

## 1. Overview & Architectural Role

The **CIPHER Email Phishing Detection Subsystem** provides multi-tiered, explainable machine learning and heuristic inspection of suspicious incoming emails. It expands CIPHER (*Cyber Intrusion Prevention & Heuristic Event Response*) beyond network flow monitoring and standalone URL scanning into proactive webmail and message inspection.

### Core Architectural Invariants:
1. **Local-First & Strict Privacy**: In-flight email bodies and headers are inspected purely in-memory. **Raw email bodies are never persisted** to SQLite databases, disk logs, or external cloud telemetry.
2. **Authoritative Subsystem Reuse**: Embedded hyperlinks extracted from email bodies are automatically routed to CIPHER's existing 28-feature Random Forest Phishing URL model (`PhishingService`). Sender domains, IPs, and targets are correlated against CIPHER's local SQLite Threat Intelligence IOC repository.
3. **Calibrated Threat Scoring**: Predictions from the 32-feature email model are fused with URL risk scores, IOC matches, and deterministic heuristic flags through `threat_scorer.py` to calculate a unified risk score (0–100) and severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

---

## 2. Dataset Provenance & Ingestion

### Source Archive Audit
The model is trained on a comprehensive Kaggle phishing email collection (`archive.zip`) comprising six distinct corpus sources:
- **CEAS_08**: Cleaned subset from the 2008 Spam Conference evaluation.
- **Enron**: Legitimate corporate communications from the Enron email corpus.
- **Ling**: Academic and linguistic mailing list discussions (benign control).
- **Nazario**: Historic, verified spear phishing and credential harvesting campaigns collected by Jose Nazario.
- **Nigerian_Fraud**: 419 advance-fee fraud and financial wire transfer scam archives.
- **SpamAssasin**: Standard corpus of public benign and spam messages from the Apache SpamAssassin project.

*Note on deduplication*: A 7th file in the archive (`phishing_email.csv`, 82,486 rows) was audited and determined to be an unstratified concatenation of the other six files. To prevent data contamination and duplicate weighting, ingestion extracted only the 6 primary sources and removed duplicate message texts, yielding **82,388 unique emails** with an even balance of legitimate (43,266) and malicious (39,122) examples.

### Stratified Train / Validation / Held-Out Test Partitioning
- **Train Set (70%)**: 57,671 samples (Parquet)
- **Validation Set (15%)**: 12,358 samples (Parquet)
- **Held-Out Test Set (15%)**: 12,359 samples (Parquet)
All partitions were generated using stratified random sampling with fixed seed `42` to guarantee zero data leakage between training and evaluation.

---

## 3. Leak-Free 32-Feature Extraction Architecture

The feature extractor (`backend/app/ml/email_feature_extractor.py`) computes 32 numerical features across five behavioral dimensions:

### A. Lexical & Structural Metrics
1. `char_count`: Character length of the message body.
2. `word_count`: Total word count.
3. `avg_word_length`: Mean characters per word.
4. `uppercase_ratio`: Ratio of uppercase alphabetic characters (shouting / urgency signal).
5. `digit_ratio`: Ratio of numeric digits to total characters.
6. `special_char_ratio`: Frequency of non-alphanumeric punctuation marks.
7. `line_count`: Total newline count.
8. `body_entropy`: Shannon entropy of byte distributions (detects encoded/obfuscated content).

### B. Psychological & Urgency Heuristics
9. `urgency_keyword_count`: Frequency of immediate action words (*urgent, immediate, suspend, expire, deadline, attention, critical, restricted*).
10. `action_keyword_count`: Call-to-action triggers (*click, login, update, verify, confirm, reactivate, validate*).
11. `threat_keyword_count`: Punitive threats (*lawsuit, legal, arrested, subpoena, breach, compromised*).
12. `has_urgency_in_subject`: Binary indicator for urgent language in the email subject line.
13. `excessive_punctuation`: Frequency of chained exclamation/question marks (*!!!*, *???*).

### C. Financial & Credential Harvesting Lures
14. `financial_keyword_count`: Currency and banking terms (*bank, invoice, wire, transfer, payment, billing, credit card*).
15. `dollar_symbol_count`: Raw count of currency glyphs (`$`, `€`, `£`).
16. `credential_keyword_count`: Authentication lure words (*password, credential, username, pin, ssn, identity*).
17. `advance_fee_phrases`: Phrases characteristic of 419 fraud (*inheritance, beneficiary, barrister, next of kin, fund transfer*).

### D. HTML & Obfuscation Indicators
18. `html_tag_count`: Total HTML markup tags embedded in body.
19. `has_form_tag`: Presence of `<form>` input containers within the email body.
20. `has_iframe_tag`: Presence of hidden `<iframe>` structures.
21. `has_script_tag`: Presence of `<script>` execution tags.
22. `hidden_element_count`: Zero-size, display-none, or hidden CSS styles.
23. `base64_encoded_blocks`: Count of base64-encoded binary payload fragments.

### E. Link, Domain & Attachment Signals
24. `url_count`: Total hyperlinks extracted from headers and body.
25. `ip_as_host_url_count`: Links where the hostname is a direct IPv4/IPv6 address.
26. `shortened_url_count`: Use of URL shorteners (*bit.ly, tinyurl, t.co, is.gd*).
27. `suspicious_tld_count`: Links pointing to high-risk TLDs (*.xyz, .top, .buzz, .club, .work*).
28. `sender_domain_mismatch`: Mismatch between sender display name and From header domain.
29. `has_freemail_sender`: Sender address from public freemail providers (*gmail.com, yahoo.com, hotmail.com*).
30. `suspicious_attachment_count`: Mentions of executable/script extensions (*.exe, .vbs, .scr, .iso, .bat*).
31. `subject_char_count`: Subject line character length.
32. `subject_uppercase_ratio`: Proportion of capital letters in subject line.

---

## 4. Model Training & Evaluation Benchmarks

Three classical, CPU-efficient architectures were benchmarked on the 12,358-sample validation set:

| Model Architecture | Validation Accuracy | Validation F1 | Validation ROC-AUC | Training Time |
| :--- | :--- | :--- | :--- | :--- |
| **Random Forest (150 trees, max_depth=20)** | **91.08%** | **91.18%** | **0.9722** | ~14.8s |
| HistGradientBoosting (max_iter=150) | 89.85% | 90.04% | 0.9657 | ~4.2s |
| Logistic Regression (L2 regularization, C=1.0) | 75.42% | 75.38% | 0.8345 | ~1.1s |

### Final Held-Out Test Set Performance (12,359 unobserved samples)
- **Model Selected**: Random Forest Classifier
- **Accuracy**: **91.528%**
- **F1-Score**: **91.619%**
- **Precision**: **94.237%**
- **Recall**: **89.143%**
- **ROC-AUC**: **0.9736**
- **PR-AUC**: **0.9784**
- **Confusion Matrix**:
  - True Negatives (Benign): **5,589**
  - False Positives: **350**
  - False Negatives: **697**
  - True Positives (Phishing): **5,723**
- **Inference Throughput**: **80,945 samples/second** on standard CPU.

---

## 5. Explainable AI (XAI) & Evidence Generation

Raw numerical ML probabilities alone are insufficient for SOC analysts. The `EmailExplanationService` analyzes the extracted feature vector and model confidence to generate plain-language, actionable evidence bullets:
- Detects disproportionate uppercase ratio (*"Excessive uppercase lettering indicates artificial urgency or shouting"*).
- Identifies credential collection lures (*"Email contains explicit credential/password verification terminology"*).
- Highlights risky URL hosting (*"Email contains hyperlinks with raw IP addresses as hostnames"*).
- Reports known bad indicators (*"Hyperlink target matches active Threat Intelligence IOC store"*).

---

## 6. REST API Endpoints

- `POST /api/email/analyze`: Full structured email inspection (sender, recipient, subject, body, urls).
- `POST /api/email/analyze-text`: Quick raw text/RFC 822 string analysis.
- `GET /api/email/model`: Returns model metadata, architecture, features, and test metrics.
- `GET /api/email/health`: Subsystem readiness probe.

---

## 7. Limitations & Defensible Claims

1. **Probabilistic Boundary**: ML classifiers are statistical evaluators. Extremely short or novel benign emails may occasionally exhibit high entropy, and benign invoices may contain dollar signs and banking terms. CIPHER uses corroboration thresholds to prevent uncorroborated text from triggering false positives.
2. **Header Forgery**: Without local SPF/DKIM/DMARC DNS lookup records (which would violate the zero-external-network privacy invariant), sender authenticity is evaluated heuristically.
3. **Encrypted Attachments**: Encrypted archive attachments (.zip with password) cannot be inspected without keys; CIPHER flags the presence of archive attachments as an advisory signal.
