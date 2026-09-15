"""
CIPHER Email Dataset Preprocessing Pipeline
Ingests the 6 source datasets, deduplicates text records, extracts 32 leak-free features,
performs stratified 70/15/15 partitioning, and saves Snappy Parquet partitions.
"""

import os
import sys
import json
import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.ml.email_feature_extractor import EmailFeatureExtractor


def preprocess_email_corpus():
    print("=" * 80)
    print("CIPHER PHASE 12 — EMAIL DATASET PREPROCESSING & PARTITIONING")
    print("=" * 80)
    start_time = time.time()

    raw_dir = os.path.join(backend_root, "data", "raw", "email_phishing")
    processed_dir = os.path.join(backend_root, "data", "processed", "email_phishing")
    meta_dir = os.path.join(processed_dir, "metadata")
    os.makedirs(processed_dir, exist_ok=True)
    os.makedirs(meta_dir, exist_ok=True)

    sources = [
        "CEAS_08.csv",
        "Enron.csv",
        "Ling.csv",
        "Nazario.csv",
        "Nigerian_Fraud.csv",
        "SpamAssasin.csv"
    ]

    print("\n[1/5] Ingesting 6 source corpora from raw directory...")
    dfs = []
    source_stats = {}
    for s in sources:
        fpath = os.path.join(raw_dir, s)
        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Source file not found: {fpath}")
        df_src = pd.read_csv(fpath, low_memory=False)
        row_cnt = len(df_src)
        source_stats[s] = {
            "rows": row_cnt,
            "columns": list(df_src.columns)
        }
        df_src["source_corpus"] = s
        if "text" in df_src.columns and "body" not in df_src.columns:
            df_src["body"] = df_src["text"]
        
        # Standardize columns
        std_cols = ["subject", "body", "label", "source_corpus"]
        if "sender" in df_src.columns:
            std_cols.append("sender")
        else:
            df_src["sender"] = ""
            std_cols.append("sender")
            
        dfs.append(df_src[std_cols])
        print(f"      - {s:20s}: {row_cnt:>6,d} rows")

    master_df = pd.concat(dfs, ignore_index=True)
    total_raw_rows = len(master_df)
    print(f"      Total Ingested Rows: {total_raw_rows:,}")

    # [2/5] Cleaning & Deduplication
    print("\n[2/5] Performing rigorous text cleaning & deduplication...")
    master_df["subject"] = master_df["subject"].fillna("").astype(str)
    master_df["body"] = master_df["body"].fillna("").astype(str)
    master_df["sender"] = master_df["sender"].fillna("").astype(str)
    master_df["label"] = master_df["label"].astype(int)

    # Clean text key for deduplication
    clean_text = master_df["subject"].str.strip() + " " + master_df["body"].str.strip()
    
    # Filter empty texts
    non_empty_mask = clean_text.str.len() >= 10
    dropped_empty = int((~non_empty_mask).sum())
    master_df = master_df[non_empty_mask].copy()
    clean_text = clean_text[non_empty_mask]

    # Deduplicate
    dup_mask = clean_text.duplicated(keep="first")
    duplicates_removed = int(dup_mask.sum())
    dedup_df = master_df[~dup_mask].copy().reset_index(drop=True)
    total_dedup_rows = len(dedup_df)

    print(f"      - Empty records pruned (<10 chars): {dropped_empty}")
    print(f"      - Duplicate records removed:       {duplicates_removed:,}")
    print(f"      - Final Master Deduplicated Rows:  {total_dedup_rows:,}")

    # Class distribution
    label_counts = dedup_df["label"].value_counts().to_dict()
    print(f"      - Class Distribution: 0 (BENIGN): {label_counts.get(0, 0):,}, 1 (MALICIOUS): {label_counts.get(1, 0):,}")

    # [3/5] Feature Extraction
    print(f"\n[3/5] Extracting 32 leak-free features across {total_dedup_rows:,} records...")
    extractor = EmailFeatureExtractor()
    feature_names = extractor.feature_names

    feature_records = []
    t_feat_start = time.time()
    for idx, row in dedup_df.iterrows():
        feats = extractor.extract_features(
            subject=row["subject"],
            body=row["body"],
            sender=row["sender"]
        )
        feature_records.append(feats)
        if (idx + 1) % 20000 == 0 or (idx + 1) == total_dedup_rows:
            pct = ((idx + 1) / total_dedup_rows) * 100
            print(f"      - Extracted {idx + 1:,} / {total_dedup_rows:,} ({pct:.1f}%) in {time.time() - t_feat_start:.1f}s")

    X_df = pd.DataFrame(feature_records, columns=feature_names)
    X_df["label"] = dedup_df["label"].values
    X_df["source_corpus"] = dedup_df["source_corpus"].values

    # [4/5] Stratified Splitting (70% Train, 15% Val, 15% Test)
    print("\n[4/5] Executing stratified train/val/test split (70 / 15 / 15, seed=42)...")
    # First split: 70% train, 30% temp
    train_df, temp_df = train_test_split(
        X_df,
        test_size=0.30,
        random_state=42,
        stratify=X_df["label"]
    )
    # Second split: 15% val, 15% test (50/50 split of the 30% temp)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=42,
        stratify=temp_df["label"]
    )

    print(f"      - Training Set (70%):   {len(train_df):,d} samples ({train_df['label'].value_counts().to_dict()})")
    print(f"      - Validation Set (15%): {len(val_df):,d} samples ({val_df['label'].value_counts().to_dict()})")
    print(f"      - Held-Out Test (15%):  {len(test_df):,d} samples ({test_df['label'].value_counts().to_dict()})")

    # [5/5] Serialization
    print("\n[5/5] Serializing Snappy Parquet partitions and audit metadata...")
    train_path = os.path.join(processed_dir, "train.parquet")
    val_path = os.path.join(processed_dir, "val.parquet")
    test_path = os.path.join(processed_dir, "test.parquet")

    train_df.to_parquet(train_path, compression="snappy", index=False)
    val_df.to_parquet(val_path, compression="snappy", index=False)
    test_df.to_parquet(test_path, compression="snappy", index=False)

    metadata = {
        "dataset_name": "Kaggle Phishing Email Multi-Corpus Aggregation",
        "dataset_sources": sources,
        "source_statistics": source_stats,
        "total_raw_rows": total_raw_rows,
        "dropped_empty": dropped_empty,
        "duplicates_removed": duplicates_removed,
        "total_processed_samples": total_dedup_rows,
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "split_strategy": "Stratified 70/15/15 by binary label (random_state=42)",
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "class_mapping": {
            "0": "BENIGN / LEGITIMATE",
            "1": "MALICIOUS / PHISHING-LIKE"
        },
        "train_class_distribution": {str(k): int(v) for k, v in train_df["label"].value_counts().items()},
        "val_class_distribution": {str(k): int(v) for k, v in val_df["label"].value_counts().items()},
        "test_class_distribution": {str(k): int(v) for k, v in test_df["label"].value_counts().items()},
        "preprocessing_duration_seconds": round(time.time() - start_time, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    meta_path = os.path.join(meta_dir, "email_preprocessing_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"      - Saved: {train_path} ({os.path.getsize(train_path):,} bytes)")
    print(f"      - Saved: {val_path} ({os.path.getsize(val_path):,} bytes)")
    print(f"      - Saved: {test_path} ({os.path.getsize(test_path):,} bytes)")
    print(f"      - Saved: {meta_path}")
    print(f"\nPreprocessing successfully completed in {time.time() - start_time:.2f}s!")


if __name__ == "__main__":
    preprocess_email_corpus()
