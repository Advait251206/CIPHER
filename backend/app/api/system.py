"""
CIPHER System Status API Router
Exposes system diagnostics, ML model parameters, and local environment state.
"""

import time
from fastapi import APIRouter
from app.schemas.events import SystemStatusResponse
from app.ml.model_loader import ModelLoader
from app.database.database import Database

router = APIRouter(prefix="/system", tags=["System Diagnostics"])

_SERVER_START_TIME = time.time()


@router.get("/status", response_model=SystemStatusResponse, summary="Get CIPHER Engine Diagnostics")
def get_system_status():
    """Returns runtime metrics, loaded ML model metadata, feature definitions, and local database path."""
    loader = ModelLoader()
    meta = loader.metadata
    pipeline = loader.pipeline or {}
    db = Database()

    uptime = time.time() - _SERVER_START_TIME

    feature_names = pipeline.get("feature_names", [])

    return SystemStatusResponse(
        system_name="CIPHER (Cyber Intrusion Prevention & Heuristic Event Response)",
        environment="local",
        local_only=True,
        model_version=loader.model_version,
        model_loaded=loader.is_ready,
        feature_count=len(feature_names),
        feature_names=feature_names,
        database_path=db.db_path,
        uptime_seconds=round(uptime, 2)
    )
