"""
Tests for Network IDS Model Loading and Prediction
Verifies model deserialization, feature pipeline consistency,
and dual (binary and multiclass) inference.
"""

import pytest
import numpy as np

from app.network.model_loader import NetworkModelLoader
from app.network.feature_extractor import NetworkFeatureExtractor
from app.network.predictor import NetworkPredictor


@pytest.fixture(scope="module")
def model_loader():
    loader = NetworkModelLoader()
    assert loader.is_ready, "NetworkModelLoader must be ready"
    return loader


def test_model_loader_initialization(model_loader):
    assert model_loader.is_ready is True
    assert model_loader.binary_model is not None
    assert model_loader.multiclass_model is not None
    assert model_loader.pipeline is not None
    assert model_loader.feature_count == 67
    assert len(model_loader.classes) == 9


def test_feature_pipeline_standardizes_vector(model_loader):
    extractor = NetworkFeatureExtractor(model_loader.pipeline)
    raw_dict = {
        "Destination Port": 80,
        "Flow Duration": 1500,
        "Total Fwd Packets": 5
    }
    vec = extractor.extract_features(raw_dict)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (1, 67)
    assert vec.dtype == np.float32
    assert not np.isnan(vec).any()
    assert not np.isinf(vec).any()


def test_predictor_executes_binary_and_multiclass(model_loader):
    predictor = NetworkPredictor(model_loader)
    flow = {
        "Destination Port": 443,
        "Flow Duration": 25000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 12,
        "Flow Packets/s": 880.0
    }
    result = predictor.predict_flow(flow)

    assert "is_attack" in result
    assert "attack_probability" in result
    assert "predicted_category" in result
    assert "class_probabilities" in result
    assert "model_confidence" in result

    assert 0.0 <= result["attack_probability"] <= 1.0
    assert 0.0 <= result["model_confidence"] <= 1.0
    assert result["predicted_category"] in model_loader.classes
    assert len(result["class_probabilities"]) == 9


def test_predictor_handles_empty_or_extreme_dict(model_loader):
    predictor = NetworkPredictor(model_loader)
    # Completely empty dict with unknown keys
    empty_flow = {"unknown_key": 999.9}
    res_empty = predictor.predict_flow(empty_flow)
    assert res_empty["predicted_category"] in model_loader.classes

    # Extreme inf/nan values
    extreme_flow = {
        "Destination Port": 80,
        "Flow Bytes/s": float("inf"),
        "Flow Packets/s": float("-inf")
    }
    res_extreme = predictor.predict_flow(extreme_flow)
    assert 0.0 <= res_extreme["attack_probability"] <= 1.0
