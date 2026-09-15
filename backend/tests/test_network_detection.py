"""
Tests for Network Heuristic Detection Engine
Validates deterministic detection of Port Scans, DoS floods,
DDoS patterns, Brute Force attempts, and Botnet communication.
"""

import pytest
from app.detection.network_detector import NetworkDetector


@pytest.fixture
def detector():
    return NetworkDetector()


def test_benign_flow_produces_zero_heuristic_score(detector):
    flow = {
        "Destination Port": 443,
        "Flow Duration": 50000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 15,
        "Flow Packets/s": 500.0,
        "SYN Flag Count": 1,
        "ACK Flag Count": 1
    }
    score, attack, reasons, rules = detector.evaluate(flow)
    assert score == 0
    assert attack is None
    assert len(rules) == 0


def test_port_scan_syn_probe_detection(detector):
    flow = {
        "Destination Port": 8080,
        "Flow Duration": 50,              # Short duration
        "Total Fwd Packets": 1,
        "Total Backward Packets": 0,      # Zero response
        "SYN Flag Count": 1,              # SYN set
        "ACK Flag Count": 0               # ACK 0
    }
    score, attack, reasons, rules = detector.evaluate(flow)
    assert score >= 45
    assert attack == "PORT_SCAN"
    assert any("SYN port scan" in r for r in reasons)


def test_dos_packet_flood_detection(detector):
    flow = {
        "Destination Port": 80,
        "Flow Duration": 10000,
        "Total Fwd Packets": 1000,
        "Total Backward Packets": 0,
        "Flow Packets/s": 100000.0,       # Extreme packet rate
        "Fwd Packets/s": 100000.0
    }
    score, attack, reasons, rules = detector.evaluate(flow)
    assert score >= 65
    assert attack == "DOS"
    assert any("packet rate" in r.lower() for r in reasons)


def test_ddos_uniform_flood_detection(detector):
    flow = {
        "Destination Port": 80,
        "Flow Duration": 8000,
        "Total Fwd Packets": 500,
        "Total Backward Packets": 0,
        "Flow Packets/s": 62500.0,
        "Packet Length Variance": 0.5,    # Uniform packet length
        "ACK Flag Count": 1
    }
    score, attack, reasons, rules = detector.evaluate(flow)
    assert score >= 70
    assert attack == "DDOS"
    assert any("uniform packet stream" in r.lower() for r in reasons)


def test_brute_force_auth_port_detection(detector):
    flow = {
        "Destination Port": 22,           # SSH port
        "Flow Duration": 80000,           # Truncated
        "Total Fwd Packets": 3,
        "Total Backward Packets": 1,
        "RST Flag Count": 1
    }
    score, attack, reasons, rules = detector.evaluate(flow, destination_port=22)
    assert score >= 50
    assert attack == "BRUTE_FORCE"
    assert any("SSH" in r for r in reasons)


def test_botnet_periodic_beaconing_detection(detector):
    flow = {
        "Destination Port": 49152,
        "Flow Duration": 1000000,
        "Total Fwd Packets": 20,
        "Total Backward Packets": 20,
        "Flow IAT Mean": 50000.0,
        "Flow IAT Std": 2.5               # High-precision periodicity
    }
    score, attack, reasons, rules = detector.evaluate(flow)
    assert score >= 40
    assert attack == "BOTNET"
    assert any("beaconing" in r.lower() for r in reasons)
