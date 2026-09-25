from pathlib import Path
import json
"""
CIPHER REST API Automated Test Suite
Tests all endpoints, error handling, edge cases, model unavailability, and database persistence.
"""

import pytest
import sys
import os
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.main import app
from app.ml.model_loader import ModelLoader


@pytest.fixture
def client():
    return TestClient(app)


# --- System & Health Endpoint Tests ---

def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["ok", "degraded"]
    assert data["local_only"] is True
    assert data["model_loaded"] is True
    assert data["database_connected"] is True


def test_system_status_endpoint(client):
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["system_name"].startswith("CIPHER")
    assert data["local_only"] is True
    meta_path = Path(__file__).resolve().parents[1] / "models" / "phishing" / "model_metadata.json"
    expected = json.loads(meta_path.read_text(encoding="utf-8"))["feature_names"]
    assert data["feature_count"] == len(expected)
    assert data["feature_names"] == expected
    assert "IsHTTPS" in data["feature_names"]


# --- Core Phishing Detection Endpoint Tests ---

def test_analyze_legitimate_url(client):
    payload = {"url": "https://www.google.com"}
    response = client.post("/api/phishing/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "LEGITIMATE"
    assert data["severity"] in ["LOW", "MEDIUM"]
    assert data["risk_score"] < 40
    assert data["confidence"] > 0.5
    assert data["ml_score"] < 0.5
    assert isinstance(data["reasons"], list)
    assert len(data["reasons"]) > 0
    assert "recommendation" in data
    # www.google.com is on the Tranco allow-list, which answers before the model.
    assert data["model_version"] == "cipher-whitelist-v1"
    assert data["event_id"] is not None


def test_analyze_phishing_url(client):
    payload = {"url": "http://paypal-security-verification.xyz/login-credential-update?token=1234"}
    response = client.post("/api/phishing/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] in ["SUSPICIOUS", "LIKELY_PHISHING"]
    assert data["severity"] in ["HIGH", "CRITICAL"]
    assert data["risk_score"] >= 60
    assert data["ml_score"] > 0.5
    assert data["heuristic_score"] > 30
    assert any("brand" in r.lower() or "tld" in r.lower() or "credential" in r.lower() for r in data["reasons"])


# 9. Invalid URL Format
def test_invalid_url_handling(client):
    # Spaces and non-URL garbage
    payload = {"url": "   "}
    response = client.post("/api/phishing/analyze", json=payload)
    assert response.status_code == 422


# 10. Empty URL Input
def test_empty_url_rejected(client):
    payload = {"url": ""}
    response = client.post("/api/phishing/analyze", json=payload)
    assert response.status_code == 422
    assert "URL cannot be empty" in response.text


# 11. Missing Request Fields
def test_missing_fields_rejected(client):
    payload = {}
    response = client.post("/api/phishing/analyze", json=payload)
    assert response.status_code == 422


# 12. ML Model Unavailable Safe Failure (Never return fake predictions)
def test_ml_model_unavailable_fails_safely(client):
    with patch.object(ModelLoader, "is_ready", False):
        payload = {"url": "https://example.com"}
        response = client.post("/api/phishing/analyze", json=payload)
        assert response.status_code == 503
        assert "not loaded or unavailable" in response.json()["detail"]


# 13. Database Failure Resilience
def test_database_failure_resilience(client):
    with patch("app.services.event_service.EventService.record_scan_event", side_effect=Exception("DB Locked")):
        payload = {"url": "https://www.wikipedia.org"}
        # Scan should succeed even if local event storage encounters an I/O error
        response = client.post("/api/phishing/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "LEGITIMATE"
        assert data["event_id"] is None


# 14. Feature Extraction Failure Handled Safely
def test_feature_extraction_failure_safe_handling(client):
    with patch("app.ml.feature_extractor.FeatureExtractor.extract_features", side_effect=Exception("Parsing Corrupted")):
        payload = {"url": "https://valid-format.com"}
        response = client.post("/api/phishing/analyze", json=payload)
        assert response.status_code in [422, 500]


# --- Event Auditing & Stats Tests ---

def test_events_listing_and_detail(client):
    # First, perform an analysis to ensure at least one event is in DB
    scan_resp = client.post("/api/phishing/analyze", json={"url": "https://www.python.org"})
    assert scan_resp.status_code == 200
    event_id = scan_resp.json()["event_id"]

    # List events
    events_resp = client.get("/api/events?limit=10")
    assert events_resp.status_code == 200
    events_data = events_resp.json()
    assert events_data["total_returned"] >= 1
    assert any(ev["event_id"] == event_id for ev in events_data["events"])

    # Get single event by ID
    single_resp = client.get(f"/api/events/{event_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["event_id"] == event_id
    assert single_resp.json()["domain"] == "www.python.org"


def test_event_not_found(client):
    response = client.get("/api/events/non-existent-uuid-99999")
    assert response.status_code == 404


def test_stats_endpoint(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_scans"] >= 1
    assert "average_risk_score" in stats
