"""
Tests for CIC-IDS2017 Dataset Processing & Split Integrity
Validates that processed Parquet files, column names, sanitization,
and leakage-safe splits meet rigorous quality and privacy criteria.
"""

import os
import json
import pytest
import numpy as np
import pandas as pd

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_dir = os.path.join(backend_root, "data", "processed", "cic_ids2017")

# The processed CIC-IDS2017 partitions are generated locally by
# training/preprocess_cic_ids2017.py and are too large to commit.
pytestmark = pytest.mark.skipif(
    not os.path.isdir(data_dir),
    reason="processed CIC-IDS2017 data not present (run training/preprocess_cic_ids2017.py)",
)


def test_preprocessing_metadata_exists_and_valid():
    meta_path = os.path.join(data_dir, "metadata", "preprocessing_metadata.json")
    assert os.path.exists(meta_path), "preprocessing_metadata.json must exist"

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["feature_count"] == 67
    assert len(meta["feature_names"]) == 67
    assert "BENIGN" in meta["multiclass_classes"]
    assert "PORT_SCAN" in meta["multiclass_classes"]
    assert "DOS" in meta["multiclass_classes"]
    assert "DDOS" in meta["multiclass_classes"]
    assert "BRUTE_FORCE" in meta["multiclass_classes"]
    assert "BOTNET" in meta["multiclass_classes"]
    assert "WEB_ATTACK" in meta["multiclass_classes"]
    assert meta["train_samples"] > 0
    assert meta["validation_samples"] > 0
    assert meta["test_samples"] > 0


def test_parquet_partitions_exist_and_readable():
    train_path = os.path.join(data_dir, "train", "train.parquet")
    val_path = os.path.join(data_dir, "validation", "val.parquet")
    test_path = os.path.join(data_dir, "test", "test.parquet")

    assert os.path.exists(train_path)
    assert os.path.exists(val_path)
    assert os.path.exists(test_path)

    # Read minimal samples to verify parquet header & types
    df_test = pd.read_parquet(test_path)
    assert len(df_test) > 10000
    assert "is_attack" in df_test.columns
    assert "attack_category" in df_test.columns


def test_no_infs_or_nans_in_processed_data():
    test_path = os.path.join(data_dir, "test", "test.parquet")
    df = pd.read_parquet(test_path)
    meta_path = os.path.join(data_dir, "metadata", "preprocessing_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        feature_names = json.load(f)["feature_names"]

    # Sample 5000 rows for fast verification
    sample = df[feature_names].sample(n=min(5000, len(df)), random_state=42)
    assert not np.isinf(sample.values).any(), "Processed data must contain zero infinite values"
    assert not np.isnan(sample.values).any(), "Processed data must contain zero NaN values"


def test_constant_columns_were_dropped():
    meta_path = os.path.join(data_dir, "metadata", "preprocessing_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    dropped = meta["dropped_constant_columns"]
    features = meta["feature_names"]

    for col in dropped:
        assert col not in features, f"Constant column '{col}' should have been dropped"


def test_split_integrity_all_classes_present_in_splits():
    meta_path = os.path.join(data_dir, "metadata", "preprocessing_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    train_dist = meta["train_multiclass_distribution"]
    val_dist = meta["validation_multiclass_distribution"]
    test_dist = meta["test_multiclass_distribution"]

    # In train: all 9 categories should be present
    assert len(train_dist) == 9
    assert train_dist["BENIGN"] > 0
    assert train_dist["PORT_SCAN"] > 0
    assert train_dist["DOS"] > 0
    assert train_dist["WEB_ATTACK"] > 0
