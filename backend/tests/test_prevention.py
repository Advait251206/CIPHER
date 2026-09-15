"""
Tests for CIPHER IPS Prevention Architecture
Validates operating modes (detect_only, simulate, enforce), persistent IP blocklisting,
TTL expiration, rate-limiting, and Windows host safety guarantees.
"""

import os
import pytest
from datetime import datetime, timedelta, timezone

from app.prevention.actions import PreventionAction, PreventionMode
from app.prevention.rate_limiter import FlowRateLimiter
from app.prevention.blocklist import IPBlocklistManager
from app.prevention.prevention_engine import PreventionEngine
from app.database.database import Database


@pytest.fixture
def temp_db(tmp_path):
    db_file = str(tmp_path / "test_prevention.db")
    return Database(db_path=db_file)


def test_default_mode_is_detect_only(temp_db):
    engine = PreventionEngine(blocklist_manager=IPBlocklistManager(temp_db))
    assert engine.mode == PreventionMode.DETECT_ONLY.value

    # Evaluate response on a critical threat
    res = engine.evaluate_response(
        threat_score=95,
        attack_type="DOS",
        ml_confidence=0.99,
        source_ip="10.0.0.99"
    )
    assert res["recommended_action"] == PreventionAction.BLOCK.value
    assert res["applied_action"] == "MONITORED_ONLY"
    assert "Operating system firewall was NOT altered" in res["prevention_summary"]


def test_simulation_mode_records_without_host_modification(temp_db):
    mgr = IPBlocklistManager(temp_db)
    engine = PreventionEngine(blocklist_manager=mgr, mode="simulate")
    assert engine.mode == PreventionMode.SIMULATE.value

    res = engine.evaluate_response(
        threat_score=88,
        attack_type="PORT_SCAN",
        ml_confidence=0.95,
        source_ip="192.168.10.45",
        event_id="test-event-123"
    )
    assert res["applied_action"] == "SIMULATED_TEMPORARY_BLOCK"
    assert "No changes made to Windows Defender or host firewall" in res["prevention_summary"]

    # Blocklist was updated in simulation
    is_blocked, entry = mgr.is_blocked("192.168.10.45")
    assert is_blocked is True
    assert entry["attack_type"] == "PORT_SCAN"


def test_blocklist_temporary_expiration(temp_db):
    mgr = IPBlocklistManager(temp_db)
    # Block IP with expiration 1 hour ago
    now = datetime.now(timezone.utc)
    expired_time = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    temp_db.save_blocked_ip(
        ip="172.16.5.99",
        reason="Test expired block",
        attack_type="BRUTE_FORCE",
        threat_score=85,
        expires_at=expired_time
    )

    is_blocked, entry = mgr.is_blocked("172.16.5.99")
    assert is_blocked is False, "Expired block should no longer be active"


def test_manual_unblock(temp_db):
    mgr = IPBlocklistManager(temp_db)
    mgr.block_ip(
        ip="198.51.100.22",
        reason="Test block",
        attack_type="BOTNET",
        threat_score=90
    )
    assert mgr.is_blocked("198.51.100.22")[0] is True

    unblocked = mgr.unblock_ip("198.51.100.22")
    assert unblocked is True
    assert mgr.is_blocked("198.51.100.22")[0] is False


def test_rate_limiter_sliding_window():
    limiter = FlowRateLimiter(window_seconds=10, max_flows_per_window=5)
    ip = "192.0.2.1"

    for i in range(5):
        exceeded, count = limiter.record_flow(ip)
        assert exceeded is False
        assert count == i + 1

    # 6th flow triggers rate limit
    exceeded, count = limiter.record_flow(ip)
    assert exceeded is True
    assert count == 6
