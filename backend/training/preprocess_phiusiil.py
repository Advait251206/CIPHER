"""
CIPHER - PhiUSIIL Dataset Preprocessing Pipeline
Cleans, deduplicates, normalizes labels, prevents data leakage, extracts features,
and splits into Train (70%), Validation (15%), and Test (15%) sets.
"""

import os
import sys
import json
import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# Add project root and backend to path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.ml.feature_extractor import FeatureExtractor


def preprocess_phiusiil(
    raw_csv_path: str = None,
    output_dir: str = None,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42
):
    print("=" * 65)
    print("CIPHER - PHIUSIIL PREPROCESSING & LEAKAGE PREVENTION")
    print("=" * 65)

    if raw_csv_path is None:
        raw_csv_path = os.path.join(backend_root, "data", "raw", "phiusiil", "PhiUSIIL_Phishing_URL_Dataset.csv")
    if output_dir is None:
        output_dir = os.path.join(backend_root, "data", "processed", "phiusiil")

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(raw_csv_path):
        raise FileNotFoundError(f"Raw PhiUSIIL dataset not found at: {raw_csv_path}")

    # 1. Load raw dataset (Preserving raw file unchanged)
    print(f"\n[1/6] Loading raw dataset from: {raw_csv_path}")
    t0 = time.time()
    df_raw = pd.read_csv(raw_csv_path)
    initial_rows = len(df_raw)
    initial_cols = len(df_raw.columns)
    print(f"      Loaded {initial_rows:,} rows, {initial_cols} columns in {time.time()-t0:.2f}s")

    # 2. Clean invalid / missing records
    print("\n[2/6] Checking missing values and cleaning records...")
    missing_counts = df_raw.isnull().sum().sum()
    print(f"      Total missing values in raw dataset: {missing_counts}")
    df_clean = df_raw.dropna(subset=['URL', 'label']).copy()

    # 3. Deduplication & Leakage Prevention
    print("\n[3/6] Analyzing and removing duplicates...")
    exact_row_dups = df_clean.duplicated().sum()
    print(f"      Exact duplicate rows: {exact_row_dups}")
    if exact_row_dups > 0:
        df_clean = df_clean.drop_duplicates()

    # Check duplicate URLs
    url_dups = df_clean.duplicated(subset=['URL'], keep='first').sum()
    print(f"      Duplicate URLs detected: {url_dups}")
    # Drop duplicate URLs to ensure zero duplicate URL leakage across splits
    df_clean = df_clean.drop_duplicates(subset=['URL'], keep='first').reset_index(drop=True)
    post_dedup_rows = len(df_clean)
    print(f"      Remaining unique URLs: {post_dedup_rows:,} (dropped {initial_rows - post_dedup_rows} rows)")

    # 4. Target Label Normalization
    print("\n[4/6] Normalizing labels...")
    # Raw PhiUSIIL: 1 = Legitimate, 0 = Phishing
    # CIPHER Standard: 0 = LEGITIMATE, 1 = PHISHING
    print("      Raw label distribution:")
    print(df_clean['label'].value_counts())

    raw_label_1_legit = int((df_clean['label'] == 1).sum())
    raw_label_0_phish = int((df_clean['label'] == 0).sum())

    # Invert labels: 1 - label
    df_clean['normalized_label'] = 1 - df_clean['label']
    norm_counts = df_clean['normalized_label'].value_counts()
    print(f"      Normalized labels (0=Legitimate, 1=Phishing):")
    print(f"        0 (Legitimate): {norm_counts.get(0, 0):,} ({norm_counts.get(0, 0)/post_dedup_rows*100:.2f}%)")
    print(f"        1 (Phishing):   {norm_counts.get(1, 0):,} ({norm_counts.get(1, 0)/post_dedup_rows*100:.2f}%)")

    # 5. Extract reproducible URL features using FeatureExtractor
    print("\n[5/6] Extracting 28 reproducible URL features for local inference...")
    extractor = FeatureExtractor()
    t_feat = time.time()
    feature_df = extractor.extract_features_dataframe(df_clean['URL'])
    print(f"      Extracted features for {len(feature_df):,} URLs in {time.time()-t_feat:.2f}s")

    # Assemble processed dataframe
    # Include metadata (URL, Domain) and target
    feature_df['URL'] = df_clean['URL'].values
    feature_df['Domain'] = df_clean['Domain'].values if 'Domain' in df_clean.columns else ""
    feature_df['label'] = df_clean['normalized_label'].values

    # 6. Leakage-Free Stratified Train / Validation / Test Split
    print("\n[6/6] Splitting dataset into Train (70%), Validation (15%), Test (15%)...")
    # First split: 70% train, 30% temp
    train_df, temp_df = train_test_split(
        feature_df,
        train_size=train_ratio,
        random_state=random_state,
        stratify=feature_df['label']
    )

    # Second split: split 30% temp into 15% validation and 15% test (50/50 of temp)
    val_df, test_df = train_test_split(
        temp_df,
        train_size=0.5,
        random_state=random_state,
        stratify=temp_df['label']
    )

    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    print(f"      Train Set:      {len(train_df):,} samples ({len(train_df)/len(feature_df)*100:.1f}%)")
    print(f"        Legitimate (0): {(train_df['label']==0).sum():,} | Phishing (1): {(train_df['label']==1).sum():,}")
    print(f"      Validation Set: {len(val_df):,} samples ({len(val_df)/len(feature_df)*100:.1f}%)")
    print(f"        Legitimate (0): {(val_df['label']==0).sum():,} | Phishing (1): {(val_df['label']==1).sum():,}")
    print(f"      Test Set:       {len(test_df):,} samples ({len(test_df)/len(feature_df)*100:.1f}%)")
    print(f"        Legitimate (0): {(test_df['label']==0).sum():,} | Phishing (1): {(test_df['label']==1).sum():,}")

    # Check zero URL overlap
    train_urls = set(train_df['URL'])
    val_urls = set(val_df['URL'])
    test_urls = set(test_df['URL'])
    overlap_train_val = len(train_urls.intersection(val_urls))
    overlap_train_test = len(train_urls.intersection(test_urls))
    overlap_val_test = len(val_urls.intersection(test_urls))
    print(f"      Verification - URL Overlaps across splits: Train-Val={overlap_train_val}, Train-Test={overlap_train_test}, Val-Test={overlap_val_test}")
    assert overlap_train_val == 0, "Data leakage detected: Train and Validation sets share URLs!"
    assert overlap_train_test == 0, "Data leakage detected: Train and Test sets share URLs!"
    assert overlap_val_test == 0, "Data leakage detected: Validation and Test sets share URLs!"

    # Save processed files
    print("\nSaving processed datasets to:", output_dir)
    # Parquet (fast binary format)
    train_df.to_parquet(os.path.join(output_dir, "train.parquet"), index=False)
    val_df.to_parquet(os.path.join(output_dir, "val.parquet"), index=False)
    test_df.to_parquet(os.path.join(output_dir, "test.parquet"), index=False)

    # Also save CSV for portability
    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    val_df.to_csv(os.path.join(output_dir, "val.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir, "test.csv"), index=False)

    # Save preprocessing metadata
    metadata = {
        "dataset_name": "PhiUSIIL Phishing URL Dataset",
        "raw_file": os.path.basename(raw_csv_path),
        "raw_row_count": initial_rows,
        "raw_col_count": initial_cols,
        "raw_label_mapping": {"1": "Legitimate", "0": "Phishing"},
        "normalized_label_mapping": {"0": "LEGITIMATE", "1": "PHISHING"},
        "duplicates_removed": int(initial_rows - post_dedup_rows),
        "total_processed_samples": post_dedup_rows,
        "features_extracted_count": len(extractor.feature_names),
        "feature_names": extractor.feature_names,
        "split_strategy": "Stratified random split after URL deduplication",
        "random_state": random_state,
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "train_class_distribution": {
            "legitimate_0": int((train_df['label'] == 0).sum()),
            "phishing_1": int((train_df['label'] == 1).sum())
        },
        "val_class_distribution": {
            "legitimate_0": int((val_df['label'] == 0).sum()),
            "phishing_1": int((val_df['label'] == 1).sum())
        },
        "test_class_distribution": {
            "legitimate_0": int((test_df['label'] == 0).sum()),
            "phishing_1": int((test_df['label'] == 1).sum())
        },
        "preprocessing_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url_overlap_train_test": overlap_train_test,
    }

    metadata_path = os.path.join(output_dir, "preprocessing_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"      Preprocessing metadata written to: {metadata_path}")
    print("=" * 65)
    print("PREPROCESSING COMPLETED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    preprocess_phiusiil()
