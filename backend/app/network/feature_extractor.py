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

    def fit(self, X):
        if isinstance(X, pd.DataFrame):
            for col in self.feature_names:
                if col in X.columns:
                    val = float(X[col].median())
                    self.medians[col] = 0.0 if np.isnan(val) else val
                else:
                    self.medians[col] = 0.0
        return self

    def transform(self, X) -> np.ndarray:
        if isinstance(X, dict):
            # Convert single flow dictionary into ordered float array
            row = []
            for col in self.feature_names:
                val = X.get(col, self.medians.get(col, 0.0))
                try:
                    val = float(val)
                except (ValueError, TypeError):
                    val = 0.0
                if np.isposinf(val):
                    val = 1e6
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

            arr = df_out.values.astype(np.float32)
            pos_mask = np.isposinf(arr)
            neg_mask = np.isneginf(arr)
            nan_mask = np.isnan(arr)
            arr[pos_mask] = 1e6
            arr[neg_mask] = 0.0
            arr[nan_mask] = 0.0
            return arr

        elif isinstance(X, np.ndarray):
            arr = np.nan_to_num(X.astype(np.float32), nan=0.0, posinf=1e6, neginf=0.0)
            return arr
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
