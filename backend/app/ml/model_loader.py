"""
CIPHER Model Loader
Safely loads and caches the serialized Random Forest model, pipeline, and metadata.
Ensures local-only execution and robust error handling without fake fallback predictions.
"""

import os
import json
import logging
import joblib
from typing import Optional, Dict, Any

logger = logging.getLogger("cipher.model_loader")


class ModelLoader:
    """Manages lifecycle and thread-safe caching of local ML artifacts."""

    _instance = None
    _model = None
    _pipeline = None
    _metadata = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelLoader, cls).__new__(cls)
            cls._instance._load_artifacts()
        return cls._instance

    def _load_artifacts(self):
        backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        models_dir = os.path.join(backend_root, "models", "phishing")

        model_path = os.getenv("MODEL_PATH", os.path.join(models_dir, "phishing_model.joblib"))
        if not os.path.isabs(model_path):
            model_path = os.path.join(backend_root, model_path)

        pipeline_path = os.getenv("PIPELINE_PATH", os.path.join(models_dir, "feature_pipeline.joblib"))
        if not os.path.isabs(pipeline_path):
            pipeline_path = os.path.join(backend_root, pipeline_path)

        metadata_path = os.path.join(models_dir, "model_metadata.json")

        if not os.path.exists(model_path):
            logger.error(f"Phishing model file not found at: {model_path}")
            self._model = None
        else:
            try:
                self._model = joblib.load(model_path)
                logger.info(f"Successfully loaded phishing model from: {model_path}")
            except Exception as e:
                logger.error(f"Failed to load phishing model: {e}")
                self._model = None

        if not os.path.exists(pipeline_path):
            logger.error(f"Feature pipeline file not found at: {pipeline_path}")
            self._pipeline = None
        else:
            try:
                self._pipeline = joblib.load(pipeline_path)
                logger.info(f"Successfully loaded feature pipeline from: {pipeline_path}")
            except Exception as e:
                logger.error(f"Failed to load feature pipeline: {e}")
                self._pipeline = None

        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r") as f:
                    self._metadata = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load metadata: {e}")
                self._metadata = {}
        else:
            self._metadata = {}

    @property
    def is_ready(self) -> bool:
        return self._model is not None and self._pipeline is not None

    @property
    def model(self):
        if self._model is None:
            self._load_artifacts()
        return self._model

    @property
    def pipeline(self):
        if self._pipeline is None:
            self._load_artifacts()
        return self._pipeline

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata or {}

    @property
    def model_version(self) -> str:
        if self._metadata and "model_version" in self._metadata:
            return self._metadata["model_version"]
        return "phiusiil-rf-v1"
