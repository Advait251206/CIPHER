"""
CIPHER Phase 7 — Deterministic Heuristic + Signature Detection Engine Test Suite
Validates rule models, rule engine execution, network heuristics, signatures,
DDoS multi-source aggregation, separation of phishing signatures, REST APIs,
safety guarantees, and pipeline integration.
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rules.models import BaseRule, RuleMatch, RuleItem
from app.rules.engine import RuleEngine
from app.rules.config import (
    PORT_SCAN_THRESHOLD,
    BRUTE_FORCE_THRESHOLD,
    DOS_PACKET_RATE_THRESHOLD,
    DOS_BYTE_RATE_THRESHOLD,
    DDOS_SOURCES_THRESHOLD
)
from app.rules.heuristics import (
    PortScanSweepRule,
    PortScanSynRule,
    BruteForceStormRule,
    BruteForceChurnRule,
    DosPacketRateRule,
    DosByteRateRule,
    DosAsymmetricRule,
    DdosMultiSourceRule,
    SuspiciousFlagsRule,
    SuspiciousIrcRule
)
from app.rules.signatures import (
    PortScanSignature,
    BruteForceSignature,
    WebServiceSignature,
    PhishingIpHostSignature
)
from app.correlation.service import CorrelationService
from app.correlation.correlator import EventCorrelator
from app.correlation.incident import IncidentManager
from app.prevention.prevention_engine import PreventionEngine
from app.database.database import Database

client = TestClient(app)


# =============================================================================
# 1. Rule Model & Engine Basics
# =============================================================================

def test_rule_model_instantiation_and_to_item():
    """Validates BaseRule instantiation, item serialization, and bounds."""
    rule = PortScanSweepRule()
    item = rule.to_item()

    assert item.rule_id == "HEUR-PORTSCAN-001"
    assert item.category == "PORT_SCAN"
    assert item.severity == "MEDIUM"
    assert item.enabled is True
    assert 0.0 <= item.confidence <= 1.0
    assert "network" in item.tags


def test_disabled_rule_is_ignored():
    """A disabled rule must not match regardless of input triggers."""
    engine = RuleEngine()
    engine.set_rule_enabled("HEUR-DOS-001", False)

    flood_event = {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "features": {
            "Flow Packets/s": DOS_PACKET_RATE_THRESHOLD + 10000,
            "Fwd Packets/s": DOS_PACKET_RATE_THRESHOLD + 10000
        }
    }
    matches = engine.evaluate(flood_event)
    assert not any(m.rule_id == "HEUR-DOS-001" for m in matches)

    # Re-enable and verify it matches
    engine.set_rule_enabled("HEUR-DOS-001", True)
    matches_after = engine.evaluate(flood_event)
    assert any(m.rule_id == "HEUR-DOS-001" for m in matches_after)


def test_malformed_event_handling_safe():
    """Malformed or empty event payloads do not crash the engine."""
    engine = RuleEngine()
    assert engine.evaluate({}) == []
    assert engine.evaluate({"features": "not_a_dict"}) == []
    assert engine.evaluate({"destination_port": "invalid_port"}) == []


# =============================================================================
# 2. Port Scan Heuristic Tests
# =============================================================================

def test_port_scan_below_threshold_no_alert():
    """Destination port probes below threshold do not trigger HEUR-PORTSCAN-001."""
    engine = RuleEngine()
    src = "192.168.10.55"

    for port in range(1, PORT_SCAN_THRESHOLD - 1):
        event = {
            "source_ip": src,
            "destination_ip": "10.0.0.1",
            "destination_port": port,
            "features": {"Destination Port": port}
        }
        matches = engine.evaluate(event)
        assert not any(m.rule_id == "HEUR-PORTSCAN-001" for m in matches)


def test_port_scan_above_threshold_triggers_alert():
    """Probing >= PORT_SCAN_THRESHOLD distinct ports triggers HEUR-PORTSCAN-001."""
    engine = RuleEngine()
    src = "192.168.10.60"

    matched = False
    for port in range(1, PORT_SCAN_THRESHOLD + 2):
        event = {
            "source_ip": src,
            "destination_ip": "10.0.0.1",
            "destination_port": port,
            "features": {"Destination Port": port}
        }
        matches = engine.evaluate(event)
        if any(m.rule_id == "HEUR-PORTSCAN-001" for m in matches):
            matched = True
            sweep_match = next(m for m in matches if m.rule_id == "HEUR-PORTSCAN-001")
            assert "probed" in sweep_match.explanation
            assert str(src) in sweep_match.explanation
            assert sweep_match.severity == "MEDIUM"
            break

    assert matched is True


def test_port_scan_syn_probe_heuristic():
    """Half-open SYN probe with zero backward reply triggers HEUR-PORTSCAN-002."""
    engine = RuleEngine()
    event = {
        "source_ip": "172.16.1.10",
        "destination_ip": "10.0.0.5",
        "features": {
            "SYN Flag Count": 1,
            "ACK Flag Count": 0,
            "Total Backward Packets": 0,
            "Total Fwd Packets": 1,
            "Flow Duration": 45
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-PORTSCAN-002" for m in matches)
    syn_match = next(m for m in matches if m.rule_id == "HEUR-PORTSCAN-002")
    assert "Half-open SYN probe detected" in syn_match.explanation


# =============================================================================
# 3. Brute Force Heuristic Tests
# =============================================================================

def test_brute_force_below_threshold_no_alert():
    """Fewer connection attempts than threshold to SSH port 22 do not trigger storm rule."""
    engine = RuleEngine()
    src = "10.1.1.1"
    dst = "10.1.1.2"

    for _ in range(BRUTE_FORCE_THRESHOLD - 1):
        event = {
            "source_ip": src,
            "destination_ip": dst,
            "destination_port": 22,
            "features": {"Destination Port": 22}
        }
        matches = engine.evaluate(event)
        assert not any(m.rule_id == "HEUR-BRUTEFORCE-001" for m in matches)


def test_brute_force_above_threshold_triggers_alert():
    """Connection bursts >= BRUTE_FORCE_THRESHOLD to SSH port 22 trigger HEUR-BRUTEFORCE-001."""
    engine = RuleEngine()
    src = "10.1.1.5"
    dst = "10.1.1.2"

    matched = False
    for _ in range(BRUTE_FORCE_THRESHOLD + 1):
        event = {
            "source_ip": src,
            "destination_ip": dst,
            "destination_port": 22,
            "features": {"Destination Port": 22}
        }
        matches = engine.evaluate(event)
        if any(m.rule_id == "HEUR-BRUTEFORCE-001" for m in matches):
            matched = True
            bf_match = next(m for m in matches if m.rule_id == "HEUR-BRUTEFORCE-001")
            assert "brute-force" in bf_match.explanation.lower()
            assert bf_match.severity == "HIGH"
            break

    assert matched is True


def test_brute_force_ignored_on_non_auth_port():
    """Repeated connections to standard Web port 80 do not trigger brute force rules."""
    engine = RuleEngine()
    src = "10.1.1.10"
    dst = "10.1.1.2"

    for _ in range(BRUTE_FORCE_THRESHOLD + 2):
        event = {
            "source_ip": src,
            "destination_ip": dst,
            "destination_port": 80,
            "features": {"Destination Port": 80}
        }
        matches = engine.evaluate(event)
        assert not any(m.rule_id == "HEUR-BRUTEFORCE-001" for m in matches)


def test_brute_force_session_churn_heuristic():
    """Short-lived truncated session with RST flag on auth port triggers HEUR-BRUTEFORCE-002."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.1.1.20",
        "destination_ip": "10.1.1.2",
        "destination_port": 3389,  # RDP
        "features": {
            "Destination Port": 3389,
            "Flow Duration": 150000,
            "Total Fwd Packets": 4,
            "RST Flag Count": 1
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-BRUTEFORCE-002" for m in matches)


# =============================================================================
# 4. Denial of Service (DoS) Heuristic Tests
# =============================================================================

def test_dos_packet_rate_heuristic():
    """Forward packet rates above threshold trigger HEUR-DOS-001 with evidence."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.2.2.1",
        "destination_ip": "10.2.2.2",
        "features": {
            "Flow Packets/s": DOS_PACKET_RATE_THRESHOLD + 5000,
            "Fwd Packets/s": DOS_PACKET_RATE_THRESHOLD + 5000
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-DOS-001" for m in matches)
    match = next(m for m in matches if m.rule_id == "HEUR-DOS-001")
    assert match.severity == "CRITICAL"
    assert "exceeded the configured DoS threshold" in match.explanation


def test_dos_byte_rate_heuristic():
    """High volumetric byte rates trigger HEUR-DOS-002."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.2.2.3",
        "destination_ip": "10.2.2.2",
        "features": {
            "Flow Bytes/s": DOS_BYTE_RATE_THRESHOLD + 1_000_000
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-DOS-002" for m in matches)


def test_dos_asymmetric_burst_heuristic():
    """Rapid asymmetric requests with zero reply trigger HEUR-DOS-003."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.2.2.4",
        "destination_ip": "10.2.2.2",
        "features": {
            "Flow IAT Mean": 25.0,
            "Total Fwd Packets": 60,
            "Down/Up Ratio": 0
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-DOS-003" for m in matches)


# =============================================================================
# 5. Distributed Denial of Service (DDoS) Multi-Source Test
# =============================================================================

def test_ddos_multi_source_aggregation():
    """
    CRITICAL USER REQUIREMENT:
    DDoS triggers on multiple distinct sources targeting the same destination.
    Single source high volume does NOT trigger DDoS multi-source rule.
    """
    engine = RuleEngine()
    target_ip = "192.168.100.1"

    # Single source hitting target does not trigger DDoS multi-source
    ev_single = {
        "source_ip": "10.0.0.1",
        "destination_ip": target_ip,
        "features": {"Flow Packets/s": 30000}
    }
    assert not any(m.rule_id == "HEUR-DDOS-001" for m in engine.evaluate(ev_single))

    # Multiple distinct sources targeting same destination
    matched = False
    for i in range(DDOS_SOURCES_THRESHOLD + 1):
        src_ip = f"10.0.0.{i + 1}"
        ev = {
            "source_ip": src_ip,
            "destination_ip": target_ip,
            "features": {"Flow Packets/s": 30000}
        }
        matches = engine.evaluate(ev)
        if any(m.rule_id == "HEUR-DDOS-001" for m in matches):
            matched = True
            ddos_match = next(m for m in matches if m.rule_id == "HEUR-DDOS-001")
            assert "Distributed flood pattern detected" in ddos_match.explanation
            assert target_ip in ddos_match.explanation
            assert ddos_match.severity == "CRITICAL"
            break

    assert matched is True


# =============================================================================
# 6. Suspicious Traffic Anomalies
# =============================================================================

def test_suspicious_flags_anomaly():
    """SYN+FIN set simultaneously triggers HEUR-SUSPICIOUS-001."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.3.3.1",
        "destination_ip": "10.3.3.2",
        "features": {
            "SYN Flag Count": 1,
            "FIN Flag Count": 1
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-SUSPICIOUS-001" for m in matches)
    match = next(m for m in matches if m.rule_id == "HEUR-SUSPICIOUS-001")
    assert "Illegal TCP flag combination" in match.explanation


def test_suspicious_legacy_irc_communication():
    """
    CRITICAL USER REQUIREMENT:
    Outbound to port 6667 is labeled as suspicious legacy IRC, NOT 'botnet detected'.
    """
    engine = RuleEngine()
    event = {
        "source_ip": "10.3.3.1",
        "destination_ip": "198.51.100.1",
        "destination_port": 6667,
        "features": {"Destination Port": 6667}
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "HEUR-SUSPICIOUS-002" for m in matches)
    match = next(m for m in matches if m.rule_id == "HEUR-SUSPICIOUS-002")
    assert "legacy IRC" in match.explanation
    assert "botnet" not in match.name.lower()
    assert match.severity == "LOW"


# =============================================================================
# 7. Signature Rules & Phishing Separation
# =============================================================================

def test_signature_port_scan():
    """Deterministic signature matches confirmed port scan probe."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.4.4.1",
        "destination_ip": "10.4.4.2",
        "features": {
            "SYN Flag Count": 1,
            "ACK Flag Count": 0,
            "Total Backward Packets": 0,
            "Flow Duration": 2000
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "SIGN-PORTSCAN-001" for m in matches)


def test_signature_web_service_anomaly():
    """High transaction rate on web port 443 triggers SIGN-WEB-001."""
    engine = RuleEngine()
    event = {
        "source_ip": "10.4.4.1",
        "destination_ip": "10.4.4.2",
        "destination_port": 443,
        "features": {
            "Destination Port": 443,
            "Flow Packets/s": 2500
        }
    }
    matches = engine.evaluate(event)
    assert any(m.rule_id == "SIGN-WEB-001" for m in matches)


def test_phishing_signature_cleanly_separated_from_network():
    """
    CRITICAL USER REQUIREMENT:
    SIGN-PHISH-001 is evaluated strictly on PHISHING events;
    Network flow events do NOT evaluate phishing rules.
    """
    engine = RuleEngine()

    # 1. Phishing scan event with raw IP in domain
    phish_event = {
        "source": "phishing",
        "event_type": "PHISHING",
        "domain": "192.168.1.1",
        "url": "http://192.168.1.1/login.php"
    }
    phish_matches = engine.evaluate(phish_event)
    assert any(m.rule_id == "SIGN-PHISH-001" for m in phish_matches)

    # 2. Network flow event should NOT match SIGN-PHISH-001 even if source_ip is an IP
    net_event = {
        "source": "network",
        "event_type": "NETWORK",
        "source_ip": "192.168.1.1",
        "destination_ip": "10.0.0.1",
        "features": {}
    }
    net_matches = engine.evaluate(net_event)
    assert not any(m.rule_id == "SIGN-PHISH-001" for m in net_matches)


# =============================================================================
# 8. REST API Endpoints
# =============================================================================

def test_api_list_rules():
    """GET /api/rules lists registered rules with category filtering."""
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_rules"] >= 10
    assert data["enabled_count"] >= 10

    # Test category filter
    resp_dos = client.get("/api/rules?category=DOS")
    assert resp_dos.status_code == 200
    dos_data = resp_dos.json()
    assert all(r["category"] == "DOS" for r in dos_data["rules"])


def test_api_get_rule_detail():
    """GET /api/rules/{rule_id} returns rule metadata and configurable thresholds."""
    resp = client.get("/api/rules/HEUR-PORTSCAN-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule"]["rule_id"] == "HEUR-PORTSCAN-001"
    assert "PORT_SCAN_THRESHOLD" in data["thresholds"]


def test_api_enable_disable_rule():
    """POST /api/rules/{rule_id}/disable and /enable toggles status."""
    rule_id = "HEUR-SUSPICIOUS-001"

    # Disable
    resp_dis = client.post(f"/api/rules/{rule_id}/disable")
    assert resp_dis.status_code == 200
    assert resp_dis.json()["enabled"] is False

    # Check detail
    resp_get = client.get(f"/api/rules/{rule_id}")
    assert resp_get.json()["rule"]["enabled"] is False

    # Re-enable
    resp_en = client.post(f"/api/rules/{rule_id}/enable")
    assert resp_en.status_code == 200
    assert resp_en.json()["enabled"] is True


def test_api_direct_evaluate():
    """POST /api/rules/evaluate tests payload against active rules."""
    payload = {
        "source_ip": "10.99.99.1",
        "destination_ip": "10.99.99.2",
        "features": {
            "Flow Packets/s": 65000,
            "Fwd Packets/s": 65000
        }
    }
    resp = client.post("/api/rules/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_matched"] >= 1
    assert any(m["rule_id"] == "HEUR-DOS-001" for m in data["matches"])


# =============================================================================
# 9. Pipeline Integration
# =============================================================================

def test_pipeline_integration_attaches_rule_findings(tmp_path):
    """Verifies that unified event processing attaches rule matches to metadata."""
    db = Database(db_path=str(tmp_path / "test_pipe.db"))
    svc = CorrelationService(
        incident_mgr=IncidentManager(db),
        prevention_engine=PreventionEngine(mode="detect_only"),
        db=db
    )

    ev = {
        "event_id": str(uuid.uuid4()),
        "source": "network",
        "attack_type": "BENIGN",
        "source_ip": "192.168.1.15",
        "destination_ip": "10.250.250.1",
        "features": {
            "Flow Packets/s": 80000,
            "Fwd Packets/s": 80000
        }
    }
    inc = svc.process_event(ev)

    assert inc is not None
    # HEUR-DOS-001 matched and provided structured category evidence
    assert "DOS" in inc["attack_categories"]
    assert inc["severity"] in ("HIGH", "CRITICAL")
