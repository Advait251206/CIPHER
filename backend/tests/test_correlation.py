"""
CIPHER Phase 6 — Unified Detection & Security Event Correlation Test Suite
Tests multi-dimensional correlation, strict identity rules, sliding window management,
attack repetition and diversity scoring, attack escalation detection, prevention integration,
SQLite junction persistence, and REST API endpoints.
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database.database import Database
from app.correlation.models import NormalizedEvent
from app.correlation.normalizer import EventNormalizer
from app.correlation.correlator import EventCorrelator, CorrelatedChain, DEFAULT_CORRELATION_WINDOW_SECONDS
from app.correlation.incident import IncidentManager
from app.correlation.service import CorrelationService, get_correlation_service
from app.prevention.prevention_engine import PreventionEngine


@pytest.fixture
def test_db(tmp_path):
    """Provides an isolated SQLite database instance for tests."""
    db_file = tmp_path / "test_correlation.db"
    return Database(db_path=str(db_file))


@pytest.fixture
def isolated_service(test_db):
    """Provides an isolated CorrelationService using isolated DB and correlator."""
    correlator = EventCorrelator(window_seconds=300)
    incident_mgr = IncidentManager(test_db)
    prevention_engine = PreventionEngine(mode="detect_only")
    return CorrelationService(
        correlator=correlator,
        incident_mgr=incident_mgr,
        prevention_engine=prevention_engine,
        db=test_db
    )


def test_1_single_event_creates_incident(isolated_service):
    """A single security event creates a new open incident."""
    raw_event = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.85,
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP"
    }
    incident = isolated_service.process_event(raw_event)

    assert incident is not None
    assert incident["incident_id"].startswith("INC-")
    assert incident["status"] == "OPEN"
    assert incident["event_count"] == 1
    assert "PORT_SCAN" in incident["attack_categories"]
    assert incident["source_ip"] == "192.168.1.50"
    assert incident["destination_ip"] == "10.0.0.1"
    assert incident["correlation_score"] >= 45


def test_2_two_related_events_correlate(isolated_service):
    """Two events with matching (source_ip, destination_ip) within window merge into one incident."""
    now = datetime.now(timezone.utc)
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 55,
        "confidence": 0.85,
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5"
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc1["incident_id"] == inc2["incident_id"]
    assert inc2["event_count"] == 2
    assert inc2["correlation_score"] > inc1["correlation_score"]  # repetition bonus


def test_3_unrelated_source_ips_create_separate_incidents(isolated_service):
    """Events from different source IPs create separate incidents."""
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "source_ip": "10.0.0.1",
        "destination_ip": "192.168.1.1"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "source_ip": "10.0.0.2",
        "destination_ip": "192.168.1.1"
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc1["incident_id"] != inc2["incident_id"]


def test_4_same_source_different_destinations_not_merged(isolated_service):
    """
    CRITICAL RULE: Do NOT use source_ip alone to merge incidents.
    Different destination systems create separate incident chains.
    """
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "source_ip": "10.0.0.50",
        "destination_ip": "192.168.1.10"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "source_ip": "10.0.0.50",
        "destination_ip": "192.168.1.20"  # Different destination!
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc1["incident_id"] != inc2["incident_id"]
    assert inc1["destination_ip"] == "192.168.1.10"
    assert inc2["destination_ip"] == "192.168.1.20"


def test_5_same_source_same_attack_repetition(isolated_service):
    """Repeated attacks of the same category increase correlation score boundedly."""
    now = datetime.now(timezone.utc)
    base_event = {
        "source": "network",
        "attack_type": "DOS",
        "risk_score": 70,
        "confidence": 0.9,
        "source_ip": "192.168.5.5",
        "destination_ip": "10.0.0.2"
    }

    incidents = []
    for i in range(4):
        ev = dict(base_event)
        ev["event_id"] = str(uuid.uuid4())
        ev["timestamp"] = (now + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        inc = isolated_service.process_event(ev)
        incidents.append(inc)

    # All belong to same incident
    assert all(inc["incident_id"] == incidents[0]["incident_id"] for inc in incidents)
    # Correlation score increased with repetitions
    assert incidents[-1]["correlation_score"] > incidents[0]["correlation_score"]
    assert incidents[-1]["event_count"] == 4
    assert incidents[-1]["correlation_score"] <= 100


def test_6_attack_diversity_increases_priority(isolated_service):
    """Multiple distinct attack categories from same source to same target boost correlation score."""
    now = datetime.now(timezone.utc)
    ev_recon = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 40,
        "confidence": 0.7,
        "source_ip": "172.16.0.4",
        "destination_ip": "10.0.0.8"
    }
    ev_auth = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "BRUTE_FORCE",
        "risk_score": 60,
        "confidence": 0.8,
        "source_ip": "172.16.0.4",
        "destination_ip": "10.0.0.8"
    }

    inc1 = isolated_service.process_event(ev_recon)
    inc2 = isolated_service.process_event(ev_auth)

    assert inc1["incident_id"] == inc2["incident_id"]
    assert len(inc2["attack_categories"]) == 2
    assert "PORT_SCAN" in inc2["attack_categories"]
    assert "BRUTE_FORCE" in inc2["attack_categories"]


def test_7_temporal_correlation_within_window(isolated_service):
    """Events occurring within the default 300s window are correlated."""
    now = datetime.now(timezone.utc)
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.8,
        "source_ip": "10.10.10.10",
        "destination_ip": "10.10.10.20"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=250)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.8,
        "source_ip": "10.10.10.10",
        "destination_ip": "10.10.10.20"
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc1["incident_id"] == inc2["incident_id"]
    assert inc2["event_count"] == 2


def test_8_events_outside_window_create_new_incident(isolated_service):
    """Events occurring past the correlation window start a new incident chain."""
    now = datetime.now(timezone.utc)
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.8,
        "source_ip": "10.20.30.40",
        "destination_ip": "10.20.30.50"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        # 350 seconds later (> 300 seconds default window)
        "timestamp": (now + timedelta(seconds=350)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.8,
        "source_ip": "10.20.30.40",
        "destination_ip": "10.20.30.50"
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc1["incident_id"] != inc2["incident_id"]


def test_9_attack_escalation_detection(isolated_service):
    """Recognizes PORT_SCAN -> BRUTE_FORCE -> DOS escalation progression."""
    now = datetime.now(timezone.utc)
    src = "192.168.100.99"
    dst = "10.0.0.100"

    ev1 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 40,
        "confidence": 0.8,
        "source_ip": src,
        "destination_ip": dst
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "BRUTE_FORCE",
        "risk_score": 65,
        "confidence": 0.85,
        "source_ip": src,
        "destination_ip": dst
    }
    ev3 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "DOS",
        "risk_score": 85,
        "confidence": 0.95,
        "source_ip": src,
        "destination_ip": dst
    }

    isolated_service.process_event(ev1)
    isolated_service.process_event(ev2)
    final_inc = isolated_service.process_event(ev3)

    assert final_inc["escalation_detected"] is True
    assert "Potential attack escalation" in final_inc["summary"]
    assert final_inc["severity"] in ("HIGH", "CRITICAL")


def test_10_no_false_correlation_between_unrelated_sources(isolated_service):
    """Events from distinct sources targeting different servers remain isolated."""
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "DOS",
        "risk_score": 80,
        "confidence": 0.9,
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "DOS",
        "risk_score": 80,
        "confidence": 0.9,
        "source_ip": "3.3.3.3",
        "destination_ip": "4.4.4.4"
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc1["incident_id"] != inc2["incident_id"]


def test_11_incident_creation_schema_and_fields(isolated_service):
    """Validates complete field structure of created incident."""
    ev = {
        "event_id": "test-uuid-12345",
        "source": "network",
        "attack_type": "BOTNET",
        "risk_score": 75,
        "confidence": 0.92,
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.15",
        "protocol": "TCP"
    }
    inc = isolated_service.process_event(ev)

    for field in ["incident_id", "created_at", "updated_at", "status", "source_ip",
                  "destination_ip", "event_count", "attack_categories", "first_seen",
                  "last_seen", "correlation_score", "severity", "confidence",
                  "escalation_detected", "summary"]:
        assert field in inc


def test_12_incident_update_tracks_lifecycle(isolated_service):
    """Verifies that subsequent events update last_seen, updated_at, and event count."""
    now = datetime.now(timezone.utc)
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 40,
        "confidence": 0.7,
        "source_ip": "192.168.1.5",
        "destination_ip": "10.0.0.2"
    }
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=45)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.75,
        "source_ip": "192.168.1.5",
        "destination_ip": "10.0.0.2"
    }

    inc1 = isolated_service.process_event(ev1)
    inc2 = isolated_service.process_event(ev2)

    assert inc2["event_count"] == 2
    assert inc2["last_seen"] > inc1["first_seen"]


def test_13_incident_resolution(isolated_service):
    """An incident can be marked as RESOLVED and fetched via API/service."""
    ev = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "source_ip": "192.168.20.20",
        "destination_ip": "10.0.0.1"
    }
    inc = isolated_service.process_event(ev)
    inc_id = inc["incident_id"]

    success = isolated_service.resolve_incident(inc_id)
    assert success is True

    fetched = isolated_service.get_incident(inc_id)
    assert fetched["status"] == "RESOLVED"


def test_14_score_remains_strictly_bounded_0_to_100(isolated_service):
    """Ensures correlation score never exceeds 100 or drops below 0 even under heavy floods."""
    now = datetime.now(timezone.utc)
    for i in range(25):
        ev = {
            "event_id": str(uuid.uuid4()),
            "timestamp": (now + timedelta(seconds=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "network",
            "attack_type": "DOS",
            "risk_score": 98,
            "confidence": 0.99,
            "source_ip": "10.99.99.99",
            "destination_ip": "10.0.0.1"
        }
        inc = isolated_service.process_event(ev)
        assert 0 <= inc["correlation_score"] <= 100


def test_15_malformed_event_handling(isolated_service):
    """Handles malformed inputs, missing keys, and unexpected types without raising exceptions."""
    malformed_inputs = [
        {},
        {"random_key": 12345},
        {"source_ip": None, "risk_score": "not_an_int"},
        {"confidence": 999.0, "risk_score": -50}
    ]
    for m in malformed_inputs:
        inc = isolated_service.process_event(m)  # must not raise
        # Benign/unknown LOW events are filtered by design and open no incident.
        if inc is not None:
            assert "incident_id" in inc
            assert 0 <= inc["correlation_score"] <= 100


def test_16_bounded_correlation_state_pruning():
    """Verifies that active chains are pruned to prevent memory exhaustion."""
    correlator = EventCorrelator(window_seconds=10)
    now = datetime.now(timezone.utc)

    # Insert an event with timestamp 30 seconds in the past
    past_event = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=(now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source="network",
        attack_category="PORT_SCAN",
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1"
    )
    correlator.process_event(past_event)

    # Trigger prune by processing a current event
    current_event = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        source="network",
        attack_category="DOS",
        source_ip="192.168.1.2",
        destination_ip="10.0.0.2"
    )
    correlator.process_event(current_event)

    # The old chain should be pruned
    assert correlator.get_active_chain("net:192.168.1.1->10.0.0.1") is None
    # Current chain should remain
    assert correlator.get_active_chain("net:192.168.1.2->10.0.0.2") is not None


def test_17_database_junction_persistence(test_db):
    """Verifies that incident_events junction table accurately records original event links."""
    # 1. Save underlying security event in database
    ev_id = "test-junction-ev-1"
    test_db.save_event({
        "event_id": ev_id,
        "classification": "PORT_SCAN",
        "risk_score": 50,
        "confidence": 0.8,
        "severity": "MEDIUM",
        "domain": "192.168.1.50"
    })

    # 2. Save incident referencing that event
    inc_mgr = IncidentManager(test_db)
    chain = CorrelatedChain(
        incident_id="INC-JUNCTION-TEST",
        correlation_key="net:192.168.1.50->10.0.0.1",
        initial_event=NormalizedEvent(
            event_id=ev_id,
            source="network",
            attack_category="PORT_SCAN",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1"
        )
    )
    inc_mgr.persist_chain(chain, is_new=True)

    # 3. Retrieve incident and linked events
    inc = test_db.get_incident("INC-JUNCTION-TEST")
    assert inc is not None
    assert ev_id in inc["event_ids"]

    linked_events = test_db.get_incident_events("INC-JUNCTION-TEST")
    assert len(linked_events) == 1
    assert linked_events[0]["event_id"] == ev_id


def test_18_api_endpoints_integration():
    """Validates FastAPI REST endpoints for incidents, event drilldown, and stats."""
    client = TestClient(app)

    # 1. Ingest event via /api/correlation/process
    ev_payload = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 65,
        "confidence": 0.85,
        "source_ip": "10.88.88.88",
        "destination_ip": "192.168.0.1"
    }
    resp_proc = client.post("/api/correlation/process", json=ev_payload)
    assert resp_proc.status_code == 200
    data = resp_proc.json()
    inc_id = data["incident_id"]

    # 2. List incidents via GET /api/incidents
    resp_list = client.get("/api/incidents")
    assert resp_list.status_code == 200
    inc_list = resp_list.json()
    assert inc_list["total_returned"] >= 1
    assert any(i["incident_id"] == inc_id for i in inc_list["incidents"])

    # 3. Get single incident via GET /api/incidents/{incident_id}
    resp_get = client.get(f"/api/incidents/{inc_id}")
    assert resp_get.status_code == 200
    detail = resp_get.json()
    assert detail["incident"]["incident_id"] == inc_id

    # 4. Get events via GET /api/incidents/{incident_id}/events
    resp_events = client.get(f"/api/incidents/{inc_id}/events")
    assert resp_events.status_code == 200
    assert isinstance(resp_events.json(), list)

    # 5. Correlation stats via GET /api/correlation/stats
    resp_stats = client.get("/api/correlation/stats")
    assert resp_stats.status_code == 200
    stats = resp_stats.json()
    assert stats["total_incidents"] >= 1

    # 6. Resolve incident via POST /api/incidents/{incident_id}/resolve
    resp_res = client.post(f"/api/incidents/{inc_id}/resolve")
    assert resp_res.status_code == 200
    assert resp_res.json()["status"] == "RESOLVED"


def test_19_prevention_mode_compatibility(test_db):
    """Verifies that detect_only logs recommended action without taking host enforcement."""
    engine = PreventionEngine(mode="detect_only")
    service = CorrelationService(
        incident_mgr=IncidentManager(test_db),
        prevention_engine=engine,
        db=test_db
    )

    ev = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "DOS",
        "risk_score": 95,
        "confidence": 0.99,
        "source_ip": "203.0.113.10",
        "destination_ip": "10.0.0.1"
    }
    inc = service.process_event(ev)

    # In detect_only, applied_action must remain MONITORED_ONLY / non-destructive
    assert inc["applied_action"] == "MONITORED_ONLY"
    assert inc["recommended_action"] in ("BLOCK", "TEMPORARY_BLOCK")
