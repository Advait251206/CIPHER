import pandas as pd
import os
import glob
from pathlib import Path

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)

def main():
    print("=" * 60)
    print("CIPHER - Custom Baseline Merger")
    print("=" * 60)

    # Locate baseline CSV files
    baseline_files = glob.glob(os.path.join(backend_root, "baseline_*.csv"))
    if not baseline_files:
        print("[ERROR] No baseline_*.csv files found in backend directory.")
        return

    print(f"Found {len(baseline_files)} baseline files to merge:")
    for f in baseline_files:
        print(f" - {os.path.basename(f)}")

    # Columns to drop from the custom baseline capture output
    columns_to_drop = ["Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp", "Destination Port.1"]

    combined_dfs = []
    total_rows = 0

    for fpath in baseline_files:
        print(f"\nProcessing {os.path.basename(fpath)}...")
        df = pd.read_csv(fpath)
        print(f" -> Raw rows: {len(df):,}")

        # Drop extra columns used for capture context but not for ML
        cols_to_drop = [c for c in columns_to_drop if c in df.columns]
        df = df.drop(columns=cols_to_drop)

        # Add Label column
        df["Label"] = "BENIGN"

        combined_dfs.append(df)
        total_rows += len(df)

    if not combined_dfs:
        print("[ERROR] No data to merge.")
        return

    print(f"\nMerging {len(combined_dfs)} DataFrames...")
    master_df = pd.concat(combined_dfs, ignore_index=True)

    # Remove duplicates
    n_before = len(master_df)
    master_df = master_df.drop_duplicates()
    n_after = len(master_df)
    print(f"Dropped {n_before - n_after:,} cross-file duplicate flows.")
    print(f"Final dataset size: {n_after:,} flows.")

    # Save to the raw cic_ids2017 directory so preprocess script finds it automatically
    out_dir = os.path.join(backend_root, "data", "raw", "cic_ids2017")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "custom_baseline_master.csv")

    print(f"Saving merged baseline to {out_path}...")
    master_df.to_csv(out_path, index=False)
    print("[SUCCESS] Done!")

if __name__ == "__main__":
    main()
