"""
CIPHER Network IDS Model Loader
Thread-safe singleton responsible for deserializing and caching the trained
Random Forest Network IDS models, feature pipeline, and training metadata.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
import joblib

from app.network.feature_extractor import NetworkFeaturePipeline

logger = logging.getLogger("cipher.network.loader")


class NetworkModelLoader:
    """Singleton model manager for local Network IDS inference."""
    _instance: Optional["NetworkModelLoader"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(NetworkModelLoader, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return

        backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.models_dir = os.path.join(backend_root, "models", "network")

        self.model_path = os.path.join(self.models_dir, "network_ids_model.joblib")
        self.pipeline_path = os.path.join(self.models_dir, "network_feature_pipeline.joblib")
        self.metadata_path = os.path.join(self.models_dir, "network_model_metadata.json")

        self.binary_model = None
        self.multiclass_model = None
        self.pipeline: Optional[NetworkFeaturePipeline] = None
        self.metadata: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.classes: List[str] = []
        self.class_to_idx: Dict[str, int] = {}
        self.idx_to_class: Dict[int, str] = {}
        self.is_ready = False

        self._load_artifacts()
        self._initialized = True

    def _load_artifacts(self):
        """Loads models, feature pipeline, and metadata from disk."""
        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"Network IDS model file not found at: {self.model_path}")
                return

            # 1. Load Metadata
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            # 2. Load Pipeline
            if os.path.exists(self.pipeline_path):
                import sys
                from app.network.feature_extractor import NetworkFeaturePipeline
                
                # Workaround for unpickling models trained when the class was in __main__
                if not hasattr(sys.modules['__main__'], 'NetworkFeaturePipeline'):
                    setattr(sys.modules['__main__'], 'NetworkFeaturePipeline', NetworkFeaturePipeline)
                    
                self.pipeline = joblib.load(self.pipeline_path)

            # 3. Load Models
            bundle = joblib.load(self.model_path)
            self.binary_model = bundle.get("binary_model")
            self.multiclass_model = bundle.get("multiclass_model")
            self.feature_names = bundle.get("feature_names", self.metadata.get("feature_names", []))
            self.classes = bundle.get("classes", self.metadata.get("classes", []))
            self.class_to_idx = bundle.get("class_to_idx", self.metadata.get("class_to_idx", {}))
            self.idx_to_class = {int(k): v for k, v in bundle.get("idx_to_class", {}).items()}

            if self.binary_model and self.multiclass_model and self.pipeline:
                self.is_ready = True
                logger.info(
                    f"CIPHER Network IDS loaded successfully ({len(self.feature_names)} features, {len(self.classes)} classes)"
                )
            else:
                logger.warning("Network IDS models or pipeline incomplete after loading.")

        except Exception as e:
            logger.error(f"Failed to load Network IDS artifacts: {e}", exc_info=True)
            self.is_ready = False

    @property
    def model_version(self) -> str:
        return self.metadata.get("model_name", "CIPHER-Network-IDS-v1")

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)
