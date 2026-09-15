"""
CIPHER Health API Router
Provides system liveness and dependency status.
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from app.schemas.events import HealthResponse
from app.ml.model_loader import ModelLoader
from app.database.database import Database

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse, summary="Check API and Model Health")
def get_health():
    """Returns local-first service health, database state, and model load status."""
    loader = ModelLoader()
    model_ok = loader.is_ready

    db_ok = True
    try:
        db = Database()
        db.get_stats()
    except Exception:
        db_ok = False

    status_str = "ok" if (model_ok and db_ok) else "degraded"

    return HealthResponse(
        status=status_str,
        version="1.0.0",
        local_only=True,
        model_loaded=model_ok,
        database_connected=db_ok,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
