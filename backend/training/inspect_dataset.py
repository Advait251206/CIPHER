"""
CIPHER - Dataset Inspection Script for PhiUSIIL Phishing URL Dataset
Analyzes dataset dimensions, columns, label distribution, nulls, duplicates, and feature categories.
"""

import os
import sys
import pandas as pd
import numpy as np

def inspect_dataset(file_path: str):
    print("=" * 60)
    print("CIPHER - PHIUSIIL DATASET INSPECTION")
    print("=" * 60)

    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    file_size_bytes = os.path.getsize(file_path)
    file_size_mb = file_size_bytes / (1024 * 1024)

    print(f"File Path: {file_path}")
    print(f"Exact Filename: {os.path.basename(file_path)}")
    print(f"File Format: CSV")
    print(f"File Size: {file_size_bytes:,} bytes ({file_size_mb:.2f} MB)")

    # Read CSV
    print("\nLoading dataset...")
    df = pd.read_csv(file_path)

    n_rows, n_cols = df.shape
    print(f"Number of Rows: {n_rows:,}")
    print(f"Number of Columns: {n_cols}")

    print("\n--- Column Names & Data Types ---")
    for idx, (col, dtype) in enumerate(zip(df.columns, df.dtypes), 1):
        print(f"{idx:2d}. {col:30s} -> {dtype}")

    # Detect URL column and Label column
    possible_url_cols = [c for c in df.columns if 'url' in c.lower()]
    possible_label_cols = [c for c in df.columns if any(k in c.lower() for k in ['label', 'target', 'class', 'result', 'status', 'phishing'])]

    print(f"\nDetected Potential URL Columns: {possible_url_cols}")
    print(f"Detected Potential Label Columns: {possible_label_cols}")

    url_col = possible_url_cols[0] if possible_url_cols else None
    label_col = possible_label_cols[0] if possible_label_cols else None

    print(f"Identified URL column: '{url_col}'")
    print(f"Identified Label column: '{label_col}'")

    if label_col:
        print("\n--- Class Distribution ---")
        val_counts = df[label_col].value_counts(dropna=False)
        val_pcts = df[label_col].value_counts(normalize=True, dropna=False) * 100
        for val, cnt in val_counts.items():
            pct = val_pcts[val]
            print(f"Value: {val} | Count: {cnt:,} ({pct:.2f}%)")

    # Missing values
    print("\n--- Missing Values Summary ---")
    missing = df.isnull().sum()
    total_missing = missing.sum()
    print(f"Total Missing Values Across All Columns: {total_missing}")
    if total_missing > 0:
        cols_with_missing = missing[missing > 0]
        for col, count in cols_with_missing.items():
            print(f"  {col}: {count:,} missing ({(count / n_rows) * 100:.2f}%)")
    else:
        print("  No missing values found in any column.")

    # Duplicates
    print("\n--- Duplicate Analysis ---")
    exact_row_dups = df.duplicated().sum()
    print(f"Exact Duplicate Rows: {exact_row_dups:,} ({(exact_row_dups / n_rows) * 100:.2f}%)")

    if url_col:
        url_dups = df.duplicated(subset=[url_col]).sum()
        unique_urls = df[url_col].nunique()
        print(f"Unique URLs: {unique_urls:,}")
        print(f"Duplicate URLs: {url_dups:,} ({(url_dups / n_rows) * 100:.2f}%)")

        if url_dups > 0:
            # Check if any duplicate URLs have conflicting labels
            if label_col:
                conflicts = df.groupby(url_col)[label_col].nunique()
                conflicting_urls = (conflicts > 1).sum()
                print(f"Duplicate URLs with CONFLICTING labels: {conflicting_urls:,}")

    # Sample rows
    print("\n--- First 3 Sample Rows (Transposed preview of first 15 columns) ---")
    print(df.iloc[:3, :min(15, n_cols)].T)

    print("\n--- Feature Category Analysis ---")
    # Categorize columns into URL-only vs Webpage/DOM vs Network/External
    url_only_features = []
    webpage_dom_features = []
    external_network_features = []
    metadata_cols = []

    for col in df.columns:
        col_lower = col.lower()
        if col in [url_col, label_col] or col_lower in ['id', 'index', 'filename']:
            metadata_cols.append(col)
        elif any(k in col_lower for k in [
            'html', 'dom', 'tag', 'script', 'form', 'anchor', 'iframe', 'image',
            'body', 'head', 'title', 'meta', 'css', 'js', 'link', 'page', 'text',
            'content', 'table', 'button', 'input', 'line_of_code', 'hidden', 'popup'
        ]):
            webpage_dom_features.append(col)
        elif any(k in col_lower for k in [
            'dns', 'whois', 'registrar', 'age', 'ttl', 'server', 'ip_address',
            'country', 'traffic', 'rank', 'pagerank', 'alexa', 'certificate', 'ssl',
            'asn', 'nameserver'
        ]):
            external_network_features.append(col)
        else:
            # Check if feature depends on URL lexical characteristics
            url_only_features.append(col)

    print(f"Metadata / Identifiers ({len(metadata_cols)}): {metadata_cols}")
    print(f"\nURL-Only Lexical Features ({len(url_only_features)}):")
    for f in url_only_features:
        print(f"  - {f} ({df[f].dtype})")

    print(f"\nWebpage / DOM Features ({len(webpage_dom_features)}):")
    for f in webpage_dom_features:
        print(f"  - {f} ({df[f].dtype})")

    print(f"\nExternal / Network / DNS Features ({len(external_network_features)}):")
    for f in external_network_features:
        print(f"  - {f} ({df[f].dtype})")

    print("=" * 60)

if __name__ == "__main__":
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "raw", "phiusiil", "PhiUSIIL_Phishing_URL_Dataset.csv"
    )
    inspect_dataset(default_path)
