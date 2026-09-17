"""
CIPHER (Cyber Intrusion Prevention & Heuristic Event Response)
Main FastAPI Application Entrypoint.
Local-first, privacy-preserving cybersecurity engine integrating:
1. Phishing URL Threat Detection (PhiUSIIL Random Forest)
2. Network Intrusion Detection & Prevention (CIC-IDS2017 Dual Random Forest)
3. Deterministic Heuristics & Unified Threat Scoring
4. Multi-Mode IPS Prevention Architecture (detect_only, simulate, enforce)
"""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load local environment configuration
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cipher.main")

from app.database.database import Database
from app.ml.model_loader import ModelLoader as PhishingModelLoader
from app.network.model_loader import NetworkModelLoader
from app.api import health, phishing, email, network, events, system, incidents, rules, threat_intel, extension


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes local database and pre-warms ML models on server startup."""
    logger.info("Initializing CIPHER local security engine...")
    db = Database()

    # Pre-warm Phishing Subsystem
    phish_loader = PhishingModelLoader()
    if phish_loader.is_ready:
        logger.info(f"Phishing model loaded: {phish_loader.model_version}")
    else:
        logger.warning("Phishing ML model not found. Run train_phishing_model.py to initialize.")

    # Pre-warm Network IDPS Subsystem
    net_loader = NetworkModelLoader()
    if net_loader.is_ready:
        logger.info(f"Network IDS model loaded: {net_loader.model_version} ({net_loader.feature_count} features)")
    else:
        logger.warning("Network IDS model not found. Run train_network_model.py to initialize.")

    # Pre-warm Email Phishing Subsystem (Phase 12)
    try:
        from app.api.email import get_email_service
        email_svc = get_email_service()
        if email_svc.is_ready:
            logger.info(f"Email Phishing model loaded: {email_svc.model_version}")
        else:
            logger.warning("Email ML model not found. Run train_email_model.py to initialize.")
    except Exception as e:
        logger.warning(f"Error loading email service on startup: {e}")

    yield
    logger.info("Shutting down CIPHER local security engine...")
    try:
        from app.network.live_sensor import get_sensor_service
        sensor = get_sensor_service()
        if sensor.is_running:
            logger.info("Stopping live network sensor on application shutdown...")
            sensor.stop()
    except Exception as e:
        logger.warning(f"Error stopping sensor on shutdown: {e}")


app = FastAPI(
    title="CIPHER Security API",
    description="""
**Cyber Intrusion Prevention & Heuristic Event Response (CIPHER)**

Local-First, Privacy-Preserving Intrusion Detection and Threat Analysis Engine.
- **Privacy Guarantee**: All ML inference runs locally on this device. Zero telemetry, zero external cloud inference.
- **Subsystem 1 (Phishing)**: 28-feature Random Forest ML model trained on PhiUSIIL with independent URL Heuristic Threat Detection.
- **Subsystem 2 (Network IDPS)**: Dual Random Forest ML model (Binary Gate + 9-Class Multiclass) trained on CIC-IDS2017 with deterministic flow heuristics.
- **Unified Defense**: Standardized threat scoring (0-100), severity classification, evidence-backed explanations, and multi-mode IPS architecture (detect_only, simulate, enforce).
    """,
    version="1.1.0021",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for local development (frontend running on Vite, Next.js, or local extension)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers under /api
app.include_router(health.router, prefix="/api")
app.include_router(phishing.router, prefix="/api")
app.include_router(email.router, prefix="/api")
app.include_router(network.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(rules.router, prefix="/api")
app.include_router(threat_intel.router, prefix="/api")
app.include_router(extension.router, prefix="/api")


@app.get("/", tags=["Root"])
def root_redirect():
    """Root landing endpoint providing quick pointers."""
    return {
        "service": "CIPHER Local Cybersecurity Backend",
        "status": "online",
        "version": "1.2.0",
        "documentation": "/docs",
        "health_check": "/api/health",
        "subsystems": {
            "phishing": {
                "analyze_endpoint": "POST /api/phishing/analyze"
            },
            "email": {
                "analyze_endpoint": "POST /api/email/analyze",
                "analyze_text": "POST /api/email/analyze-text",
                "model_info": "GET /api/email/model",
                "health": "GET /api/email/health"
            },
            "network": {
                "health": "GET /api/network/health",
                "analyze_endpoint": "POST /api/network/analyze",
                "stats": "GET /api/network/stats",
                "model_info": "GET /api/network/model",
                "rules": "GET /api/network/rules",
                "blocklist": "GET /api/network/blocklist"
            },
            "events": {
                "unified_stream": "GET /api/events",
                "stats": "GET /api/stats"
            },
            "incidents": {
                "list": "GET /api/incidents",
                "stats": "GET /api/correlation/stats"
            },
            "rules": {
                "list": "GET /api/rules",
                "evaluate": "POST /api/rules/evaluate"
            },
            "threat_intel": {
                "iocs": "GET /api/threat-intel/iocs",
                "check": "POST /api/threat-intel/check"
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
