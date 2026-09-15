"""
CIPHER Network Predictor
Executes dual-model ML inference (Binary Gate + Multiclass Granular) on normalized network flows.
Guarantees local execution with zero cloud calls.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import logging

from app.network.model_loader import NetworkModelLoader
from app.network.feature_extractor import NetworkFeatureExtractor

logger = logging.getLogger("cipher.network.predictor")


class NetworkPredictor:
    """Orchestrates local ML inference for network flows."""

    def __init__(self, loader: Optional[NetworkModelLoader] = None):
        self.loader = loader or NetworkModelLoader()
        if not self.loader.is_ready:
            raise RuntimeError("NetworkModelLoader is not initialized or model files are missing.")
        self.extractor = NetworkFeatureExtractor(self.loader.pipeline)

    def predict_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs binary and multiclass inference on a network flow.

        Returns:
            Dict containing:
                - is_attack: bool
                - attack_probability: float (0.0 - 1.0)
                - predicted_category: str (e.g. BENIGN, PORT_SCAN, DOS, etc.)
                - class_probabilities: Dict[str, float]
                - model_confidence: float
        """
        # 1. Standardize and sanitize features
        X = self.extractor.extract_features(flow_dict)

        # 2. Binary Prediction (BENIGN vs ATTACK)
        bin_probs = self.loader.binary_model.predict_proba(X)[0]
        attack_prob = float(bin_probs[1]) if len(bin_probs) > 1 else float(bin_probs[0])
        is_attack = attack_prob >= 0.50

        # 3. Multiclass Prediction (9 Categories)
        multi_probs = self.loader.multiclass_model.predict_proba(X)[0]
        multi_idx = int(np.argmax(multi_probs))
        predicted_category = self.loader.classes[multi_idx]

        # Map class probabilities
        class_probs = {
            self.loader.classes[i]: round(float(prob), 4)
            for i, prob in enumerate(multi_probs)
        }

        # Calibration: If binary model confidently indicates BENIGN, ensure multiclass does not spuriously flag rare attack
        if not is_attack and predicted_category != "BENIGN":
            # If binary probability of attack is very low (< 0.20), preserve BENIGN
            if attack_prob < 0.20:
                predicted_category = "BENIGN"

        confidence = round(max(multi_probs), 4)

        return {
            "is_attack": is_attack,
            "attack_probability": round(attack_prob, 4),
            "predicted_category": predicted_category,
            "class_probabilities": class_probs,
            "model_confidence": confidence
        }
