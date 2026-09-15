"""
Tests for CIPHER Network IDPS REST API Endpoints
Validates /api/network/health, /api/network/analyze, /api/network/events,
/api/network/stats, /api/network/model, /api/network/rules, /api/network/blocklist,
and unified /api/events filtering.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_network_health_endpoint():
    response = client.get("/api/network/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["subsystem"] == "CIPHER-Network-IDPS"
    assert data["model_loaded"] is True
    assert data["feature_count"] == 67
    assert data["prevention_mode"] in ["detect_only", "simulate", "enforce"]


def test_network_model_info_endpoint():
    response = client.get("/api/network/model")
    assert response.status_code == 200
    data = response.json()
    assert data["dataset"] == "CIC-IDS2017 (MachineLearningCSV)"
    assert data["feature_count"] == 67
    assert "BENIGN" in data["classes"]
    assert "PORT_SCAN" in data["classes"]
    assert "binary_metrics" in data
    assert data["binary_metrics"]["accuracy"] > 0.95


def test_network_rules_endpoint():
    response = client.get("/api/network/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["total_rules"] >= 8
    assert any(r["rule_id"] == "NET-PSCAN-01" for r in data["rules"])
    assert any(r["rule_id"] == "NET-DOS-01" for r in data["rules"])


def test_network_analyze_benign_flow():
    payload = {
        "source_ip": "192.168.1.100",
        "destination_ip": "93.184.216.34",
        "source_port": 54321,
        "destination_port": 443,
        "protocol": "TCP",
        "features": {
            "Destination Port": 443,
            "Flow Duration": 120000,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 15,
            "Flow Packets/s": 208.3,
            "SYN Flag Count": 1,
            "ACK Flag Count": 1
        }
    }
    response = client.post("/api/network/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["event_type"] == "NETWORK"
    assert data["attack_type"] == "BENIGN"
    assert data["severity"] == "LOW"
    assert data["threat_score"] <= 24
    assert data["recommended_action"] == "LOG"
    assert data["applied_action"] == "MONITORED_ONLY"


def test_network_analyze_port_scan_flow():
    payload = {
        "source_ip": "10.0.0.50",
        "destination_ip": "192.168.1.1",
        "source_port": 40123,
        "destination_port": 8080,
        "protocol": "TCP",
        "features": {
            "Destination Port": 8080,
            "Flow Duration": 40,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Flow Packets/s": 25000.0,
            "SYN Flag Count": 1,
            "ACK Flag Count": 0
        }
    }
    response = client.post("/api/network/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["event_type"] == "NETWORK"
    assert data["attack_type"] == "PORT_SCAN"
    assert data["threat_score"] >= 70
    assert data["severity"] in ["HIGH", "CRITICAL"]
    assert "Port Scan" in data["explanation"]


def test_network_events_listing_and_filtering():
    response = client.get("/api/network/events?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert "total_returned" in data


def test_network_stats_endpoint():
    response = client.get("/api/network/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_network_flows" in data
    assert "attacks_by_type" in data
    assert "severity_distribution" in data


def test_unified_events_endpoint_supports_filters():
    # Query all events
    res_all = client.get("/api/events?limit=5")
    assert res_all.status_code == 200

    # Query with event_type=NETWORK filter
    res_net = client.get("/api/events?event_type=NETWORK&limit=5")
    assert res_net.status_code == 200
    for ev in res_net.json()["events"]:
        assert ev["event_type"] == "NETWORK"

    # Query with event_type=PHISHING filter
    res_phish = client.get("/api/events?event_type=PHISHING&limit=5")
    assert res_phish.status_code == 200
    for ev in res_phish.json()["events"]:
        assert ev["event_type"] == "PHISHING"


def test_blocklist_endpoint_and_unblock():
    # Get active blocklist
    res = client.get("/api/network/blocklist")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_invalid_network_analyze_payload():
    # Missing required 'features' dict
    response = client.post("/api/network/analyze", json={"source_ip": "10.0.0.1"})
    assert response.status_code in [422, 400]
