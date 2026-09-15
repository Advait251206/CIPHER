# CIPHER Data Directory

This directory houses raw and processed training datasets for the CIPHER machine learning engine.

## Directory Structure

```
data/
├── raw/
│   └── phiusiil/
│       └── PhiUSIIL_Phishing_URL_Dataset.csv   # Raw, untouched dataset from UCI/IEEE
└── processed/
    └── phiusiil/
        ├── train.parquet / train.csv           # 70% training split (164,759 rows)
        ├── val.parquet / val.csv               # 15% validation split (35,305 rows)
        ├── test.parquet / test.csv             # 15% held-out test split (35,306 rows)
        └── preprocessing_metadata.json        # Preprocessing audit trail
```

## Dataset Information
- **Source**: PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2023)
- **Total Initial Rows**: 235,795
- **Unique URLs after Deduplication**: 235,370 (425 duplicate pairs safely removed)
- **Class Balance**: 134,850 Legitimate (57.29%), 100,520 Phishing (42.71%)
- **Target Label Standard**: Normalized so `0 = LEGITIMATE`, `1 = PHISHING`
- **Leakage Prevention**: Stratified splitting ensures zero URL overlap between train, validation, and test partitions.
