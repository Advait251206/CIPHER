"""
Unit and integration tests for CIPHER Phase 10 Validation Engine.
Verifies safety boundary enforcement, scenario execution, IOC cleanup isolation,
and provenance chain recording.
"""

import os
import json
import pytest
from pathlib import Path

from scripts.phase10_validation.config import (
    is_safe_local_target,
    assert_safe_target,
    validate_traffic_bounds,
    MAX_ALLOWED_CONNECTIONS,
    MAX_ALLOWED_DURATION_SECONDS
)
from scripts.phase10_validation.scenarios import (
    run_scenario_a_benign,
    run_scenario_b_port_scan,
    run_scenario_c_auth_storm,
    run_scenario_d_controlled_flood,
    run_scenario_e_ioc_match,
    run_scenario_f_correlation,
    run_scenario_g_prevention,
    run_scenario_h_full_chain
)
from scripts.phase10_validation.runner import run_all_scenarios
from scripts.phase10_validation.report import generate_validation_reports
from app.threat_intel.service import get_threat_intel_service


def test_safety_bounds_localhost_allowed():
    """Confirms only localhost / loopback addresses pass safety validation."""
    assert is_safe_local_target("127.0.0.1") is True
    assert is_safe_local_target("127.0.0.2") is True  # Entire 127.0.0.0/8 block is loopback
    assert is_safe_local_target("localhost") is True
    assert is_safe_local_target("::1") is True


def test_safety_bounds_external_ips_rejected():
    """Confirms remote, university, and public IPs are strictly rejected."""
    assert is_safe_local_target("8.8.8.8") is False
    assert is_safe_local_target("1.1.1.1") is False
    assert is_safe_local_target("192.168.1.100") is False
    assert is_safe_local_target("10.0.0.1") is False
    assert is_safe_local_target("example.com") is False

    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        assert_safe_target("8.8.8.8")


def test_safety_traffic_limits_enforced():
    """Confirms request ceilings prevent accidental resource exhaustion."""
    # Valid bounds
    validate_traffic_bounds(connections=10, duration_seconds=5.0)

    # Exceed connections
    with pytest.raises(ValueError, match="exceeds maximum"):
        validate_traffic_bounds(connections=MAX_ALLOWED_CONNECTIONS + 1, duration_seconds=1.0)

    # Exceed duration
    with pytest.raises(ValueError, match="exceeds maximum"):
        validate_traffic_bounds(connections=5, duration_seconds=MAX_ALLOWED_DURATION_SECONDS + 1.0)

    # Negative or zero
    with pytest.raises(ValueError):
        validate_traffic_bounds(connections=0, duration_seconds=1.0)
    with pytest.raises(ValueError):
        validate_traffic_bounds(connections=5, duration_seconds=-1.0)


def test_scenario_a_benign_execution():
    """Scenario A should cleanly pass with benign classification and low score."""
    res = run_scenario_a_benign()
    assert res["status"] == "PASS"
    assert res["scenario"] == "A"
    assert len(res["event_ids"]) > 0


def test_scenario_b_port_scan_execution():
    """Scenario B should pass conditional heuristic evaluation for 12 swept ports."""
    res = run_scenario_b_port_scan()
    assert res["status"] == "PASS"
    assert res["scenario"] == "B"
    assert len(res["rule_matches"]) > 0


def test_scenario_c_auth_storm_execution():
    """Scenario C should satisfy HEUR-BRUTEFORCE-001 on port 22."""
    res = run_scenario_c_auth_storm()
    assert res["status"] == "PASS"
    assert res["scenario"] == "C"


def test_scenario_d_controlled_flood_execution():
    """Scenario D should trigger DoS heuristic without physical flooding."""
    res = run_scenario_d_controlled_flood()
    assert res["status"] == "PASS"
    assert res["scenario"] == "D"
    assert any("DOS" in r for r in res["rule_matches"])


def test_scenario_e_ioc_isolation_and_cleanup():
    """Scenario E should verify match, verify disabled isolation, and clean up test IOC."""
    ti_svc = get_threat_intel_service()
    res = run_scenario_e_ioc_match()
    assert res["status"] == "PASS"
    assert res["scenario"] == "E"

    # Verify no Phase 10 test indicator leaked in store
    active_iocs, _ = ti_svc.list_iocs(limit=100)
    test_iocs = [i for i in active_iocs if "CIPHER_PHASE10_TEST" in i.tags]
    assert len(test_iocs) == 0, "Phase 10 test IOC was not cleaned up"


def test_scenario_f_multi_stage_correlation():
    """Scenario F should verify multi-stage escalation and destination separation."""
    res = run_scenario_f_correlation()
    assert res["status"] == "PASS"
    assert res["scenario"] == "F"
    assert len(res["incident_ids"]) == 2  # Same dest correlated, different dest separate


def test_scenario_g_prevention_simulation():
    """Scenario G should verify simulate and detect_only modes without firewall tampering."""
    res = run_scenario_g_prevention()
    assert res["status"] == "PASS"
    assert res["scenario"] == "G"


def test_scenario_h_full_provenance_chain():
    """Scenario H must record complete chain: Flow -> Event -> Rules -> IOC -> Incident -> Action."""
    res = run_scenario_h_full_chain()
    assert res["status"] == "PASS"
    assert res["scenario"] == "H"
    assert "chain_trace" in res

    chain = res["chain_trace"]
    assert "flow_id" in chain
    assert "event_id" in chain
    assert "rule_matches" in chain
    assert "ioc_matches" in chain
    assert "incident_id" in chain
    assert "prevention_action" in chain
    assert chain["threat_score"] is not None


def test_runner_and_report_generation(tmp_path):
    """Verifies that full runner executes all scenarios and writes report files."""
    data = run_all_scenarios()
    assert data["summary"]["total_scenarios"] == 8
    assert data["summary"]["passed"] == 8
    assert data["summary"]["failed"] == 0

    # Test custom output directory for report generator
    generate_validation_reports(data, output_dir=tmp_path)
    assert (tmp_path / "validation_report.json").exists()
    assert (tmp_path / "validation_summary.md").exists()

    with open(tmp_path / "validation_report.json", "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["phase"] == "10"
    assert len(loaded["scenarios"]) == 8
