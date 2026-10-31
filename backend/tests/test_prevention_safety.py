"""
Safety regression tests for the prevention engine.
Host firewall calls are always mocked; nothing here touches the real firewall.
"""

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.database.database import Database
from app.prevention.blocklist import IPBlocklistManager, validate_block_target, ProtectedAddressError
from app.prevention.prevention_engine import PreventionEngine, get_prevention_engine, resolve_mode

RUN = "app.prevention.blocklist.subprocess.run"
ON_WINDOWS = "app.prevention.blocklist._firewall_supported"


@pytest.fixture
def mgr(tmp_path):
    return IPBlocklistManager(Database(db_path=str(tmp_path / "prev.db")))


def _netsh_calls(run_mock):
    return [c.args[0] for c in run_mock.call_args_list if c.args and c.args[0][0] == "netsh"]


@pytest.mark.parametrize("value", [None, "", "detect_onyl", "ENFORCE ", "off"])
def test_missing_or_invalid_mode_never_means_enforce(value, monkeypatch):
    if value is None:
        monkeypatch.delenv("CIPHER_PREVENTION_MODE", raising=False)
    else:
        monkeypatch.setenv("CIPHER_PREVENTION_MODE", value)
    engine = PreventionEngine(mode=None)
    expected = "enforce" if value == "ENFORCE " else "detect_only"
    assert engine.mode == expected
    assert resolve_mode("garbage") == "detect_only"


def test_setting_invalid_mode_at_runtime_raises(mgr):
    engine = PreventionEngine(blocklist_manager=mgr, mode="detect_only")
    with pytest.raises(ValueError):
        engine.mode = "enforced"
    assert engine.mode == "detect_only"


@pytest.mark.parametrize("mode", ["detect_only", "simulate"])
def test_non_enforce_modes_never_call_netsh(mode, mgr):
    engine = PreventionEngine(blocklist_manager=mgr, mode=mode)
    with mock.patch(ON_WINDOWS, return_value=True), mock.patch(RUN) as run:
        res = engine.evaluate_response(threat_score=99, attack_type="DOS", ml_confidence=0.99,
                                       source_ip="203.0.113.50")
        engine.contain_ip("203.0.113.51", reason="t", attack_type="DOS", threat_score=99)
    assert _netsh_calls(run) == []
    if mode == "simulate":
        assert res["applied_action"] == "SIMULATED_BLOCK"
        assert mgr.is_blocked("203.0.113.50")[0] is True
    else:
        assert mgr.is_blocked("203.0.113.50")[0] is False


def test_enforce_mode_adds_firewall_rule_on_windows(mgr):
    engine = PreventionEngine(blocklist_manager=mgr, mode="enforce")
    with mock.patch(ON_WINDOWS, return_value=True), mock.patch(RUN) as run:
        run.return_value.returncode = 0
        res = engine.evaluate_response(threat_score=90, attack_type="DOS", ml_confidence=0.9,
                                       source_ip="203.0.113.60")
    calls = _netsh_calls(run)
    assert len(calls) == 1 and "remoteip=203.0.113.60" in calls[0]
    assert res["block_info"]["os_rule_applied"] is True


def test_enforce_mode_skips_firewall_off_windows(mgr):
    engine = PreventionEngine(blocklist_manager=mgr, mode="enforce")
    with mock.patch(ON_WINDOWS, return_value=False), mock.patch(RUN) as run:
        res = engine.evaluate_response(threat_score=90, attack_type="DOS", ml_confidence=0.9,
                                       source_ip="203.0.113.61")
    assert _netsh_calls(run) == []
    assert res["block_info"]["os_rule_applied"] is False


@pytest.mark.parametrize("bad", ["any", "localsubnet", "10.0.0.1/8", "not-an-ip", "", "1.2.3.4 remoteip=any"])
def test_invalid_addresses_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_block_target(bad)


@pytest.mark.parametrize("protected", ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "224.0.0.251", "255.255.255.255"])
def test_protected_addresses_are_never_blocked(protected, mgr):
    with pytest.raises(ProtectedAddressError):
        validate_block_target(protected)
    engine = PreventionEngine(blocklist_manager=mgr, mode="enforce")
    with mock.patch(ON_WINDOWS, return_value=True), mock.patch(RUN) as run:
        res = engine.evaluate_response(threat_score=99, attack_type="DOS", ml_confidence=0.99, source_ip=protected)
    assert _netsh_calls(run) == []
    assert res["block_info"] is None
    assert res["applied_action"].startswith("RECOMMENDED_")


def test_custom_protected_range(monkeypatch):
    monkeypatch.setenv("CIPHER_PROTECTED_IPS", "192.168.1.1,10.10.0.0/16")
    with pytest.raises(ProtectedAddressError):
        validate_block_target("192.168.1.1")
    with pytest.raises(ProtectedAddressError):
        validate_block_target("10.10.4.4")
    assert validate_block_target("192.168.1.2") == "192.168.1.2"


def test_expired_block_removes_firewall_rule(mgr):
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    mgr.db.save_blocked_ip(ip="203.0.113.70", reason="t", attack_type="DOS", threat_score=90, expires_at=past)
    with mock.patch(ON_WINDOWS, return_value=True), mock.patch(RUN) as run:
        assert mgr.is_blocked("203.0.113.70")[0] is False
    deletes = [c for c in _netsh_calls(run) if "delete" in c]
    assert deletes and "name=CIPHER_BLOCK_203.0.113.70" in deletes[0]


def test_manual_block_api_rejects_any_and_loopback():
    from app.main import app
    client = TestClient(app)
    with mock.patch(RUN) as run:
        for bad in ["any", "127.0.0.1", "abc"]:
            r = client.post(f"/api/network/blocklist/{bad}")
            assert r.status_code == 400, bad
    assert _netsh_calls(run) == []


def test_mode_switch_reaches_every_subsystem():
    from app.main import app
    from app.api import network as network_api
    from app.correlation.service import get_correlation_service
    client = TestClient(app)
    try:
        assert client.post("/api/network/prevention-mode", json={"mode": "simulate"}).status_code == 200
        assert network_api.network_service.prevention_engine.mode == "simulate"
        assert get_correlation_service().prevention_engine.mode == "simulate"
        assert get_prevention_engine().mode == "simulate"
    finally:
        client.post("/api/network/prevention-mode", json={"mode": "detect_only"})
    assert get_correlation_service().prevention_engine.mode == "detect_only"
