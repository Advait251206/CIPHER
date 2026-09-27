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

import socket
import requests

@router.get("/vulnerable-app-status", summary="Check Vulnerable App Health")
def get_vulnerable_app_status():
    """Checks if the vulnerable test application is running on the local IPv4 address."""
    # Attempt to get the local network IPv4 address (e.g., 192.168.x.x)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to a public DNS server to determine the correct outgoing interface IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    target_url = f"http://{local_ip}:5174/"
    
    try:
        response = requests.get(target_url, timeout=2)
        is_online = response.status_code == 200
    except requests.RequestException:
        is_online = False
    
    return {
        "status": "online" if is_online else "offline",
        "url": target_url,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
