"""
Tests for Train/Inference Parity in Network Feature Preprocessing.
Verifies that NetworkFeaturePipeline applies identical +inf replacements,
-inf truncations, and imputation medians fitted strictly on the train partition.
"""

import os
import json
import numpy as np
import pandas as pd
import pytest

from app.network.feature_extractor import NetworkFeaturePipeline


@pytest.fixture(scope="module")
def metadata():
    backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    meta_path = os.path.join(
        backend_root,
        "data",
        "processed",
        "cic_ids2017",
        "metadata",
        "preprocessing_metadata.json"
    )
    if not os.path.exists(meta_path):
        pytest.skip(f"CIC-IDS2017 preprocessing metadata not found at {meta_path} (fresh clone / gitignored dataset)")
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_train_inference_parity_inf_and_nan(metadata):
    feature_names = metadata["feature_names"]
    medians = metadata["feature_medians"]
    pos_inf_replacements = metadata["pos_inf_replacements"]

    pipeline = NetworkFeaturePipeline(feature_names)

    # Construct test input with normal values, +inf, -inf, NaN, and missing keys
    test_dict = {}
    for i, name in enumerate(feature_names):
        if i % 5 == 0:
            test_dict[name] = float("inf")
        elif i % 5 == 1:
            test_dict[name] = float("-inf")
        elif i % 5 == 2:
            test_dict[name] = float("nan")
        elif i % 5 == 3:
            test_dict[name] = 42.0 + i
        # i % 5 == 4 is intentionally omitted (missing key)

    # 1. Transform dict input
    vec_dict = pipeline.transform(test_dict)
    assert isinstance(vec_dict, np.ndarray)
    assert vec_dict.shape == (1, len(feature_names))
    assert vec_dict.dtype == np.float32
    assert not np.isnan(vec_dict).any()
    assert not np.isinf(vec_dict).any()

    # 2. Transform DataFrame input
    df_input = pd.DataFrame([test_dict])
    vec_df = pipeline.transform(df_input)
    assert isinstance(vec_df, np.ndarray)
    assert vec_df.shape == (1, len(feature_names))
    assert not np.isnan(vec_df).any()
    assert not np.isinf(vec_df).any()

    # Assert exact parity between dict and DataFrame transform paths
    np.testing.assert_allclose(vec_dict, vec_df, rtol=1e-5, atol=1e-5)

    # 3. Assert exact match with train-fitted metadata parameters
    for idx, name in enumerate(feature_names):
        val = vec_dict[0, idx]
        expected_median = medians[name]
        expected_pos_inf = pos_inf_replacements[name]

        if idx % 5 == 0:
            # +inf should be replaced by train-fitted 99.9th percentile
            assert np.isclose(val, expected_pos_inf, rtol=1e-4), (
                f"Feature '{name}' +inf mismatch: got {val}, expected {expected_pos_inf}"
            )
        elif idx % 5 == 1:
            # -inf should be replaced by 0.0
            assert val == 0.0, f"Feature '{name}' -inf mismatch: got {val}, expected 0.0"
        elif idx % 5 == 2:
            # NaN should be imputed with train-fitted median
            assert np.isclose(val, expected_median, rtol=1e-4), (
                f"Feature '{name}' NaN mismatch: got {val}, expected median {expected_median}"
            )
        elif idx % 5 == 3:
            # Normal float should be preserved
            expected_val = 42.0 + idx
            assert np.isclose(val, expected_val, rtol=1e-4), (
                f"Feature '{name}' normal value mismatch: got {val}, expected {expected_val}"
            )
        elif idx % 5 == 4:
            # Missing feature should be imputed with train-fitted median
            assert np.isclose(val, expected_median, rtol=1e-4), (
                f"Feature '{name}' missing feature mismatch: got {val}, expected median {expected_median}"
            )

