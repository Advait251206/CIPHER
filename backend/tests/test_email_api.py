"""
CIPHER Email Phishing API & Integration Tests
Tests /api/email endpoints, privacy guarantees (no raw body stored), URL integration,
oversized payload rejection, and model telemetry.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.database import Database


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_email_health_endpoint(client):
    response = client.get("/api/email/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True
    assert data["feature_count"] == 32


def test_email_model_info_endpoint(client):
    response = client.get("/api/email/model")
    assert response.status_code == 200
    data = response.json()
    assert "Random Forest" in data["model_name"]
    assert data["feature_count"] == 32
    assert len(data["feature_names"]) == 32
    assert "accuracy" in data["test_metrics"]
    assert data["test_metrics"]["accuracy"] > 0.85


def test_analyze_benign_academic_email(client):
    payload = {
        "sender": "Professor Davis <rdavis@stanford.edu>",
        "recipient": "advait@university.edu",
        "subject": "CS 229 Midterm Exam Schedule",
        "body": "Dear students,\nThe midterm exam is scheduled for next Thursday in Hall B. Please bring a calculator and student ID.\nRegards,\nProf. Davis",
        "urls": []
    }
    response = client.post("/api/email/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] in ("LEGITIMATE", "SUSPICIOUS")
    assert data["risk_score"] < 60
    assert "evidence" in data
    assert len(data["evidence"]) >= 1
    assert "event_id" in data
    assert data["event_id"] is not None

    # Verify event stored in database WITHOUT raw body
    db = Database()
    stored = db.get_event(data["event_id"])
    assert stored is not None
    assert stored["source"] == "EMAIL"
    assert stored["event_type"] == "EMAIL_PHISHING"
    # Ensure raw body string is NOT in the database record
    assert "Dear students,\nThe midterm exam" not in str(stored)


def test_analyze_credential_phishing_email_with_weaponized_url(client):
    payload = {
        "sender": "Microsoft Security Alert <security-noreply@microsoft-login-update.xyz>",
        "recipient": "victim@target-corp.com",
        "subject": "CRITICAL: Your Microsoft 365 password expires in 2 hours!",
        "body": "Your account has been restricted due to multiple failed login attempts. You must act immediately.\nClick here to reset your password and authenticate: http://192.168.1.55/login?auth=token\nFailure to verify will lead to immediate account termination.",
        "urls": []
    }
    response = client.post("/api/email/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "MALICIOUS_EMAIL"
    assert data["risk_score"] >= 70
    assert data["severity"] in ("HIGH", "CRITICAL")
    assert len(data["urls_analyzed"]) == 1
    assert data["urls_analyzed"][0]["url"] == "http://192.168.1.55/login?auth=token"

    # Evidence checks
    evidence_text = " ".join(data["evidence"]).lower()
    assert "urgent" in evidence_text or "coercive" in evidence_text or "credential" in evidence_text
    assert "url" in evidence_text or "raw ip" in evidence_text or "mismatch" in evidence_text


def test_quick_text_endpoint(client):
    payload = {
        "text": "Subject: Wire Transfer Confirmation\nBody: Please wire funds to account 98765 immediately.",
        "sender": "finance@scam.top"
    }
    response = client.post("/api/email/analyze-text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "evidence" in data


def test_oversized_body_rejection(client):
    oversized_body = "Phishing lure text " * 30_000  # > 500,000 characters
    payload = {
        "subject": "Too large test",
        "body": oversized_body
    }
    response = client.post("/api/email/analyze", json=payload)
    assert response.status_code == 422
    assert "exceeds maximum allowable length" in response.text
