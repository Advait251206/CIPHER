"""
CIPHER Predictor Module
Wraps model inference, guarantees feature alignment, and produces calibrated ML probabilities.
"""

import logging
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np

from app.ml.model_loader import ModelLoader

logger = logging.getLogger("cipher.predictor")


class Predictor:
    """Performs local, offline inference using the cached Random Forest model."""

    def __init__(self):
        self.loader = ModelLoader()

    def predict_phishing_probability(self, features: Dict[str, Any]) -> Tuple[float, str]:
        """
        Runs ML model inference.
        Returns:
            phishing_probability (float): 0.0 to 1.0 (probability URL is phishing)
            model_version (str): identifier of active model
        """
        if not self.loader.is_ready:
            raise RuntimeError("ML model or feature pipeline is not available on this system.")

        model = self.loader.model
        pipeline = self.loader.pipeline
        feature_order = pipeline.get("feature_order", list(features.keys()))

        # Construct single-row DataFrame aligned strictly to training feature order
        feature_row = {f: features.get(f, 0) for f in feature_order}
        df_input = pd.DataFrame([feature_row], columns=feature_order)

        try:
            # Predict probability: class 0 = Legitimate, class 1 = Phishing
            probs = model.predict_proba(df_input)[0]
            phishing_prob = float(probs[1])
            return round(phishing_prob, 4), self.loader.model_version
        except Exception as e:
            logger.error(f"Inference execution failed: {e}")
            raise RuntimeError(f"Model prediction failed: {str(e)}")
