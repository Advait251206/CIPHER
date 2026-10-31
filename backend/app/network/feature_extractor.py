"""
CIPHER Network Flow Feature Extractor and Sanitizer
Guarantees strict feature ordering, type conversion, Inf/NaN sanitization,
and missing value imputation for network flow inference.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd

logger = logging.getLogger("cipher.network.extractor")


class NetworkFeaturePipeline:
    """
    Standardizes network flow feature vectors for local ML inference.
    Enforces identical feature sequence and preprocessing used in training.
    """
    def __init__(self, feature_names: List[str]):
        self.feature_names = list(feature_names)
        self.feature_count = len(self.feature_names)
        self.medians: Dict[str, float] = {}
        self.pos_inf_replacements: Dict[str, float] = {}
        self._load_defaults_from_metadata()

    def _load_defaults_from_metadata(self):
        backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        meta_candidates = [
            os.path.join(backend_root, "data", "processed", "cic_ids2017", "metadata", "preprocessing_metadata.json"),
            os.path.join(backend_root, "models", "network", "network_model_metadata.json")
        ]
        for p in meta_candidates:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if "feature_medians" in data:
                            self.medians = {k: float(v) for k, v in data["feature_medians"].items()}
                        if "pos_inf_replacements" in data:
                            self.pos_inf_replacements = {k: float(v) for k, v in data["pos_inf_replacements"].items()}
                        break
                except Exception as e:
                    logger.warning(f"Failed to load metadata medians from {p}: {e}")

        # Ensure hardcoded fallback defaults for any missing features
        for col in self.feature_names:
            if col not in self.medians:
                self.medians[col] = 0.0
            if col not in self.pos_inf_replacements:
                self.pos_inf_replacements[col] = 1e6

    def __setstate__(self, state):
        self.__dict__.update(state)
        if "pos_inf_replacements" not in self.__dict__:
            self.pos_inf_replacements = {}
            self._load_defaults_from_metadata()

    def fit(self, X):
        if isinstance(X, pd.DataFrame):
            for col in self.feature_names:
                if col in X.columns:
                    vals = X[col].values
                    pos_mask = np.isposinf(vals)
                    neg_mask = np.isneginf(vals)
                    nan_mask = np.isnan(vals)
                    valid_vals = vals[~pos_mask & ~neg_mask & ~nan_mask]
                    self.medians[col] = float(np.median(valid_vals)) if len(valid_vals) > 0 else 0.0
                    self.pos_inf_replacements[col] = float(np.percentile(valid_vals, 99.9)) if len(valid_vals) > 0 else 1e6
                else:
                    self.medians[col] = 0.0
                    self.pos_inf_replacements[col] = 1e6
        return self

    def transform(self, X) -> np.ndarray:
        pos_replacements = getattr(self, "pos_inf_replacements", {})
        if isinstance(X, dict):
            # Convert single flow dictionary into ordered float array
            row = []
            for col in self.feature_names:
                val = X.get(col, self.medians.get(col, 0.0))
                try:
                    val = float(val)
                except (ValueError, TypeError):
                    val = self.medians.get(col, 0.0)
                if np.isposinf(val):
                    val = pos_replacements.get(col, 1e6)
                elif np.isneginf(val):
                    val = 0.0
                elif np.isnan(val):
                    val = self.medians.get(col, 0.0)
                row.append(val)
            return np.array([row], dtype=np.float32)

        elif isinstance(X, pd.DataFrame):
            df_out = pd.DataFrame(index=X.index)
            for col in self.feature_names:
                if col in X.columns:
                    df_out[col] = X[col]
                else:
                    df_out[col] = self.medians.get(col, 0.0)

            for col in self.feature_names:
                vals = df_out[col].values
                pos_mask = np.isposinf(vals)
                neg_mask = np.isneginf(vals)
                nan_mask = np.isnan(vals)
                if pos_mask.any():
                    df_out.loc[pos_mask, col] = pos_replacements.get(col, 1e6)
                if neg_mask.any():
                    df_out.loc[neg_mask, col] = 0.0
                if nan_mask.any():
                    df_out.loc[nan_mask, col] = self.medians.get(col, 0.0)

            return df_out.values.astype(np.float32)

        elif isinstance(X, np.ndarray):
            arr = X.astype(np.float32)
            if arr.ndim == 2 and arr.shape[1] == self.feature_count:
                for idx, col in enumerate(self.feature_names):
                    col_vals = arr[:, idx]
                    p_mask = np.isposinf(col_vals)
                    n_mask = np.isneginf(col_vals)
                    nan_mask = np.isnan(col_vals)
                    if p_mask.any():
                        arr[p_mask, idx] = pos_replacements.get(col, 1e6)
                    if n_mask.any():
                        arr[n_mask, idx] = 0.0
                    if nan_mask.any():
                        arr[nan_mask, idx] = self.medians.get(col, 0.0)
                return arr
            return np.nan_to_num(arr, nan=0.0, posinf=1e6, neginf=0.0)
        else:
            raise ValueError(f"Unsupported input type for transform: {type(X)}")


class NetworkFeatureExtractor:
    """
    Feature extractor for offline CSV flows and future live packet capture flow aggregation.
    """
    def __init__(self, pipeline: Optional[NetworkFeaturePipeline] = None):
        self.pipeline = pipeline

    def extract_features(self, raw_flow_dict: Dict[str, Any]) -> np.ndarray:
        """Transforms raw flow dictionary into standardized ML input matrix."""
        if self.pipeline is None:
            raise RuntimeError("NetworkFeaturePipeline is not loaded.")
        return self.pipeline.transform(raw_flow_dict)
