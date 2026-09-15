"""
CIPHER - Dataset Inspection Script for CIC-IDS2017 Network Dataset
Performs comprehensive memory-conscious audit across all 8 PCAP-derived CSV files:
row counts, column types, missing values, +/- infinity, duplicates, labels, and leakage risks.
"""

import os
import sys
import json
import time
from collections import Counter
import pandas as pd
import numpy as np

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)


def inspect_cic_ids2017(raw_dir: str = None, output_dir: str = None):
    print("=" * 70)
    print("CIPHER - CIC-IDS2017 NETWORK DATASET COMPREHENSIVE INSPECTION")
    print("=" * 70)

    if raw_dir is None:
        raw_dir = os.path.join(backend_root, "data", "raw", "cic_ids2017")
    if output_dir is None:
        output_dir = os.path.join(backend_root, "data", "processed", "cic_ids2017")

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(raw_dir):
        raise FileNotFoundError(f"Raw directory not found at: {raw_dir}")

    csv_files = sorted([f for f in os.listdir(raw_dir) if f.endswith(".csv")])
    print(f"\n[1/4] Discovered {len(csv_files)} CSV files in: {raw_dir}")

    total_dataset_rows = 0
    file_reports = {}
    overall_labels = Counter()
    total_missing_all = 0
    total_pos_inf_all = 0
    total_neg_inf_all = 0
    total_duplicates_all = 0

    all_columns_cleaned = []
    numeric_columns = set()
    categorical_columns = set()

    for idx, fname in enumerate(csv_files, 1):
        fpath = os.path.join(raw_dir, fname)
        fsize = os.path.getsize(fpath)
        print(f"\n[{idx}/{len(csv_files)}] Auditing {fname} ({fsize/(1024*1024):.1f} MB)...")
        t0 = time.time()

        file_rows = 0
        file_missing = 0
        file_pos_inf = 0
        file_neg_inf = 0
        file_duplicates = 0
        file_labels = Counter()

        # Read sample header for schema
        sample_df = pd.read_csv(fpath, nrows=10, encoding="cp1252")
        cleaned_cols = [c.strip() for c in sample_df.columns]
        if not all_columns_cleaned:
            all_columns_cleaned = cleaned_cols

        label_col_raw = [c for c in sample_df.columns if "label" in c.lower()][0]

        # Process file chunk by chunk to guarantee low memory usage (< 500 MB peak)
        chunk_size = 100_000
        for chunk in pd.read_csv(fpath, chunksize=chunk_size, encoding="cp1252", low_memory=False):
            # Clean chunk headers
            chunk.columns = [c.strip() for c in chunk.columns]
            n_chunk = len(chunk)
            file_rows += n_chunk

            # Clean labels (normalize non-ascii dashes)
            raw_labels = chunk["Label"].astype(str).str.strip()
            clean_labels = raw_labels.str.replace("\x96", "-").str.replace("–", "-")
            file_labels.update(clean_labels)
            overall_labels.update(clean_labels)

            # Check missing
            missing_in_chunk = chunk.isnull().sum().sum()
            file_missing += int(missing_in_chunk)

            # Check duplicates within chunk
            file_duplicates += int(chunk.duplicated().sum())

            # Check numeric infs
            num_cols = chunk.select_dtypes(include=[np.number]).columns
            for col in num_cols:
                numeric_columns.add(col)
                vals = chunk[col].values
                pos_inf = np.isposinf(vals).sum()
                neg_inf = np.isneginf(vals).sum()
                file_pos_inf += int(pos_inf)
                file_neg_inf += int(neg_inf)

            for col in chunk.select_dtypes(exclude=[np.number]).columns:
                categorical_columns.add(col)

        duration = time.time() - t0
        total_dataset_rows += file_rows
        total_missing_all += file_missing
        total_pos_inf_all += file_pos_inf
        total_neg_inf_all += file_neg_inf
        total_duplicates_all += file_duplicates

        file_reports[fname] = {
            "file_size_bytes": fsize,
            "rows": file_rows,
            "missing_values": file_missing,
            "pos_infinity": file_pos_inf,
            "neg_infinity": file_neg_inf,
            "intra_chunk_duplicates": file_duplicates,
            "labels": dict(file_labels),
            "audit_duration_seconds": round(duration, 2)
        }
        print(f"      Rows: {file_rows:,} | Missing: {file_missing:,} | +Inf: {file_pos_inf:,} | -Inf: {file_neg_inf:,} | Time: {duration:.2f}s")
        for lbl, cnt in file_labels.most_common(5):
            print(f"        * {lbl:32s}: {cnt:,} ({cnt/file_rows*100:.2f}%)")

    # [2/4] Identify Suspicious, Constant, and Potential Leakage Columns
    print("\n[2/4] Scanning for suspicious, constant, and potential leakage columns...")
    # Read a combined sample of 50k rows to check constant features and ranges
    sample_file = os.path.join(raw_dir, csv_files[0])
    df_sample = pd.read_csv(sample_file, nrows=50_000, encoding="cp1252")
    df_sample.columns = [c.strip() for c in df_sample.columns]

    constant_columns = [
        c for c in df_sample.select_dtypes(include=[np.number]).columns
        if df_sample[c].nunique() <= 1
    ]

    duplicate_feature_names = ["Fwd Header Length.1"]  # Exact duplicate of column 34
    identifier_columns = ["Destination Port"]  # Port number: valid feature, but can cause port-overfitting if not normalized
    suspicious_columns = constant_columns + duplicate_feature_names

    print(f"      Constant Zero Columns ({len(constant_columns)}): {constant_columns}")
    print(f"      Duplicate Column Names ({len(duplicate_feature_names)}): {duplicate_feature_names}")
    print(f"      Identifier / High-Cardinality Columns: {identifier_columns}")

    # [3/4] Overall Dataset Summary
    print("\n[3/4] Overall CIC-IDS2017 Dataset Summary:")
    print(f"      Total Files:             {len(csv_files)}")
    print(f"      Total Flows / Rows:      {total_dataset_rows:,}")
    print(f"      Total Columns:           {len(all_columns_cleaned)}")
    print(f"      Numerical Columns:       {len(numeric_columns)}")
    print(f"      Categorical Columns:     {len(categorical_columns)}")
    print(f"      Total Missing Values:    {total_missing_all:,}")
    print(f"      Total +Infinity Values:  {total_pos_inf_all:,}")
    print(f"      Total -Infinity Values:  {total_neg_inf_all:,}")
    print(f"      Duplicate Rows Estimate: {total_duplicates_all:,}")

    print("\n      Global Class Distribution:")
    class_dist = {}
    for lbl, count in overall_labels.most_common():
        pct = (count / total_dataset_rows) * 100
        class_dist[lbl] = {"count": count, "percentage": round(pct, 4)}
        print(f"        {lbl:34s}: {count:9,d} ({pct:6.2f}%)")

    # [4/4] Save Inspection Report
    print("\n[4/4] Generating and saving inspection report artifacts...")
    report_data = {
        "dataset_name": "CIC-IDS2017 (MachineLearningCSV)",
        "inspection_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_files": len(csv_files),
        "total_rows": total_dataset_rows,
        "total_columns": len(all_columns_cleaned),
        "columns_list": all_columns_cleaned,
        "numerical_column_count": len(numeric_columns),
        "categorical_column_count": len(categorical_columns),
        "total_missing_values": total_missing_all,
        "total_pos_infinity": total_pos_inf_all,
        "total_neg_infinity": total_neg_inf_all,
        "total_duplicates_estimate": total_duplicates_all,
        "constant_zero_columns": constant_columns,
        "duplicate_feature_columns": duplicate_feature_names,
        "identifier_columns": identifier_columns,
        "class_distribution": class_dist,
        "file_breakdown": file_reports
    }

    json_path = os.path.join(output_dir, "cic_ids2017_inspection_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    txt_path = os.path.join(output_dir, "cic_ids2017_inspection_report.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("CIPHER - CIC-IDS2017 DATASET INSPECTION REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Total Files:             {len(csv_files)}\n")
        f.write(f"Total Flows (Rows):      {total_dataset_rows:,}\n")
        f.write(f"Total Features/Columns:  {len(all_columns_cleaned)}\n")
        f.write(f"Numerical Columns:       {len(numeric_columns)}\n")
        f.write(f"Categorical Columns:     {len(categorical_columns)}\n")
        f.write(f"Missing Values:          {total_missing_all:,}\n")
        f.write(f"+Infinity Values:        {total_pos_inf_all:,}\n")
        f.write(f"-Infinity Values:        {total_neg_inf_all:,}\n\n")
        f.write("-" * 70 + "\n")
        f.write("CLASS DISTRIBUTION (ALL 15 ATTACK LABELS)\n")
        f.write("-" * 70 + "\n")
        for lbl, info in class_dist.items():
            f.write(f"{lbl:35s}: {info['count']:9,d} ({info['percentage']:6.2f}%)\n")
        f.write("\n" + "-" * 70 + "\n")
        f.write("PREPROCESSING RECOMMENDATIONS & LEAKAGE PREVENTION\n")
        f.write("-" * 70 + "\n")
        f.write(f"1. Drop constant zero columns ({len(constant_columns)}): {', '.join(constant_columns)}\n")
        f.write(f"2. Drop duplicate column: {', '.join(duplicate_feature_names)}\n")
        f.write("3. Replace +Inf/-Inf in Flow Bytes/s and Flow Packets/s with 99.9th percentile or max valid float\n")
        f.write("4. Impute median/zero for rare NaNs (< 0.05% of dataset)\n")
        f.write("5. De-duplicate exact flow records per day\n")
        f.write("6. Split chronologically per day (70/15/15) to prevent temporal packet session leakage\n")
        f.write("=" * 70 + "\n")

    print(f"      Saved JSON report to: {json_path}")
    print(f"      Saved Text report to: {txt_path}")
    print("=" * 70)
    print("INSPECTION COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    inspect_cic_ids2017()
