"""
Tests for Unified Network Threat Scoring
Validates that ThreatScorer correctly maps ML confidence, attack categories,
and heuristic evidence to the 0-100 risk score and severity bands.
"""

import pytest
from app.detection.threat_scorer import ThreatScorer


@pytest.fixture
def scorer():
    return ThreatScorer()


def test_benign_traffic_scores_low_severity(scorer):
    risk, severity, classification, confidence = scorer.calculate_network_risk(
        ml_attack_prob=0.05,
        predicted_attack_type="BENIGN",
        heuristic_score=0
    )
    assert 0 <= risk <= 24
    assert severity == "LOW"
    assert classification == "BENIGN"
    assert confidence >= 0.90


def test_port_scan_scores_high_or_critical(scorer):
    risk, severity, classification, confidence = scorer.calculate_network_risk(
        ml_attack_prob=0.85,
        predicted_attack_type="PORT_SCAN",
        heuristic_score=60
    )
    assert risk >= 65
    assert severity in ["HIGH", "CRITICAL"]
    assert classification == "ATTACK"


def test_dos_flood_scores_critical_severity(scorer):
    risk, severity, classification, confidence = scorer.calculate_network_risk(
        ml_attack_prob=0.95,
        predicted_attack_type="DOS",
        heuristic_score=75
    )
    assert risk >= 75
    assert severity == "CRITICAL"
    assert classification == "ATTACK"


def test_ml_confidence_decoupled_from_security_risk(scorer):
    # Very high confidence on a low-severity scan should NOT blindly yield 99 risk
    risk, severity, classification, confidence = scorer.calculate_network_risk(
        ml_attack_prob=0.55,
        predicted_attack_type="PORT_SCAN",
        heuristic_score=20
    )
    assert risk < 75  # Kept in measured band, not automatically critical


def test_heuristic_override_preserves_detection_when_ml_misses(scorer):
    # Even if ML missed the attack (prob 0.20), if heuristics strongly caught it (score 80)
    # risk cannot be dampened below HIGH
    risk, severity, classification, confidence = scorer.calculate_network_risk(
        ml_attack_prob=0.20,
        predicted_attack_type="BENIGN",
        heuristic_score=80
    )
    assert risk >= 70
    assert severity in ["HIGH", "CRITICAL"]


def test_network_recommendation_guidance(scorer):
    rec_normal = scorer.get_network_recommendation("LOW", "BENIGN", "LOG")
    assert "NORMAL" in rec_normal

    rec_dos = scorer.get_network_recommendation("CRITICAL", "DOS", "BLOCK")
    assert "Denial of Service" in rec_dos
    assert "[BLOCK]" in rec_dos
