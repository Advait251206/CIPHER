"""
CIPHER Live Network Sensor Automated Test Suite
Validates:
1. Flow key normalization
2. Forward/backward packet classification
3. TCP packet accounting
4. UDP packet accounting
5. Packet length statistics
6. Inter-Arrival Time (IAT) calculations
7. TCP flag counting
8. Flow idle timeout
9. Flow active timeout
10. Flow finalization and state transitions
11. Feature vector contains exactly 67 expected features
12. Feature ordering matches model metadata contract
13. NaN / Inf sanitization
14. Malformed packet error handling
15. Bounded flow table memory cleanup
16. Sensor start / stop lifecycle
17. Sensor status REST API
18. Network interfaces REST API
19. Safe detect_only default prevention mode
20. End-to-end integration: packets -> flow -> features -> ML IDS -> SQLite event
"""

import json
import time
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from scapy.layers.inet import IP, TCP, UDP, ICMP

from app.main import app
from app.network.live_sensor.config import SensorConfig
from app.network.live_sensor.flow import FlowKey, FlowState, FlowDirection, BidirectionalFlow
from app.network.live_sensor.flow_tracker import FlowTracker
from app.network.live_sensor.feature_builder import LiveFeatureBuilder, EXPECTED_67_FEATURES
from app.network.live_sensor.packet_capture import validate_bpf_filter, resolve_interface
from app.network.live_sensor.sensor_service import LiveSensorService
from app.network.service import NetworkService
from app.network.schemas import NetworkFlowAnalyzeRequest


@pytest.fixture
def client():
    return TestClient(app)


# 1. Flow Key Normalization
def test_flow_key_normalization():
    key1 = FlowKey.from_endpoints("192.168.1.10", 50000, "10.0.0.1", 80, "TCP")
    key2 = FlowKey.from_endpoints("10.0.0.1", 80, "192.168.1.10", 50000, "tcp")
    assert key1 == key2
    assert key1.protocol == "TCP"
    assert hash(key1) == hash(key2)


# 2. Forward / Backward Packet Classification
def test_forward_backward_classification():
    key = FlowKey.from_endpoints("192.168.1.10", 50000, "10.0.0.1", 80, "TCP")
    flow = BidirectionalFlow(key, "192.168.1.10", 50000, "10.0.0.1", 80, "TCP", start_time=100.0)

    # Initial direction is forward
    assert flow.get_direction("192.168.1.10", 50000) == FlowDirection.FORWARD
    # Reverse response direction is backward
    assert flow.get_direction("10.0.0.1", 80) == FlowDirection.BACKWARD


# 3. TCP Packet Accounting
def test_tcp_packet_accounting():
    tracker = FlowTracker()
    pkt = IP(src="192.168.1.10", dst="10.0.0.1")/TCP(sport=45000, dport=443, flags="S", window=65535)
    flow = tracker.process_packet(pkt)

    assert flow is not None
    assert flow.protocol == "TCP"
    assert flow.dst_port == 443
    assert flow.fwd_packet_count == 1
    assert flow.bwd_packet_count == 0
    assert flow.syn_count == 1
    assert flow.init_win_bytes_fwd == 65535
    assert flow.total_bytes > 0


# 4. UDP Packet Accounting
def test_udp_packet_accounting():
    tracker = FlowTracker()
    pkt = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53000, dport=53)/b"dnsquerydata"
    flow = tracker.process_packet(pkt)

    assert flow is not None
    assert flow.protocol == "UDP"
    assert flow.dst_port == 53
    assert flow.fwd_packet_count == 1
    assert flow.fwd_header_lengths[0] == 28  # 20 IP + 8 UDP


# 5. Packet Length Statistics
def test_packet_length_statistics():
    key = FlowKey.from_endpoints("192.168.1.10", 50000, "10.0.0.1", 80, "TCP")
    flow = BidirectionalFlow(key, "192.168.1.10", 50000, "10.0.0.1", 80, "TCP", start_time=100.0)

    # 3 Forward packets: 100, 200, 300 bytes
    flow.add_packet("192.168.1.10", 50000, "10.0.0.1", 80, packet_len=100, header_len=40, timestamp=100.0)
    flow.add_packet("192.168.1.10", 50000, "10.0.0.1", 80, packet_len=200, header_len=40, timestamp=100.1)
    flow.add_packet("192.168.1.10", 50000, "10.0.0.1", 80, packet_len=300, header_len=40, timestamp=100.2)

    # 2 Backward packets: 400, 600 bytes
    flow.add_packet("10.0.0.1", 80, "192.168.1.10", 50000, packet_len=400, header_len=40, timestamp=100.3)
    flow.add_packet("10.0.0.1", 80, "192.168.1.10", 50000, packet_len=600, header_len=40, timestamp=100.4)

    features, completeness = LiveFeatureBuilder.build_features(flow)

    assert features["Fwd Packet Length Max"] == 300.0
    assert features["Fwd Packet Length Min"] == 100.0
    assert features["Fwd Packet Length Mean"] == 200.0
    assert features["Bwd Packet Length Max"] == 600.0
    assert features["Bwd Packet Length Min"] == 400.0
    assert features["Bwd Packet Length Mean"] == 500.0
    assert features["Min Packet Length"] == 100.0
    assert features["Max Packet Length"] == 600.0
    assert completeness == 1.0


# 6. Inter-Arrival Time (IAT) Calculation
def test_iat_calculation():
    key = FlowKey.from_endpoints("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
    flow = BidirectionalFlow(key, "10.0.0.1", 1234, "10.0.0.2", 80, "TCP", start_time=100.0)

    # t0 = 100.0, t1 = 100.005 (+5000 µs), t2 = 100.015 (+10000 µs)
    flow.add_packet("10.0.0.1", 1234, "10.0.0.2", 80, packet_len=60, header_len=40, timestamp=100.000)
    flow.add_packet("10.0.0.1", 1234, "10.0.0.2", 80, packet_len=60, header_len=40, timestamp=100.005)
    flow.add_packet("10.0.0.1", 1234, "10.0.0.2", 80, packet_len=60, header_len=40, timestamp=100.015)

    features, _ = LiveFeatureBuilder.build_features(flow)

    assert pytest.approx(features["Flow IAT Mean"], rel=1e-2) == 7500.0
    assert pytest.approx(features["Flow IAT Max"], rel=1e-2) == 10000.0
    assert pytest.approx(features["Flow IAT Min"], rel=1e-2) == 5000.0


# 7. TCP Flag Counting
def test_tcp_flag_counting():
    tracker = FlowTracker()
    src = "192.168.1.100"
    dst = "192.168.1.1"

    # SYN
    tracker.process_packet(IP(src=src, dst=dst)/TCP(sport=1000, dport=80, flags="S"))
    # SYN-ACK
    tracker.process_packet(IP(src=dst, dst=src)/TCP(sport=80, dport=1000, flags="SA"))
    # ACK
    tracker.process_packet(IP(src=src, dst=dst)/TCP(sport=1000, dport=80, flags="A"))
    # PSH-ACK
    tracker.process_packet(IP(src=src, dst=dst)/TCP(sport=1000, dport=80, flags="PA")/b"data")
    # FIN-ACK
    flow = tracker.process_packet(IP(src=dst, dst=src)/TCP(sport=80, dport=1000, flags="FA"))

    features, _ = LiveFeatureBuilder.build_features(flow)

    assert features["SYN Flag Count"] == 2.0
    assert features["ACK Flag Count"] == 4.0
    assert features["PSH Flag Count"] == 1.0
    assert features["FIN Flag Count"] == 1.0
    assert features["Fwd PSH Flags"] == 1.0
    assert flow.is_terminated is True


# 8. Flow Idle Timeout
def test_flow_idle_timeout():
    config = SensorConfig(flow_idle_timeout=2.0, flow_active_timeout=60.0)
    tracker = FlowTracker(config)

    pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=111, dport=222)
    pkt.time = 100.0
    tracker.process_packet(pkt)

    assert tracker.active_flow_count == 1

    # At t=101.5, idle timeout (2.0s) has not passed
    assert len(tracker.get_expired_flows(current_time=101.5)) == 0

    # At t=102.5, idle timeout (2.5s > 2.0s) has triggered
    expired = tracker.get_expired_flows(current_time=102.5)
    assert len(expired) == 1
    assert expired[0].state == FlowState.EXPIRED
    assert tracker.active_flow_count == 0


# 9. Flow Active Timeout
def test_flow_active_timeout():
    config = SensorConfig(flow_idle_timeout=5.0, flow_active_timeout=10.0)
    tracker = FlowTracker(config)

    # Packets arrive continuously every 3s (idle timeout never trips)
    for t in [100.0, 103.0, 106.0, 109.0]:
        pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=111, dport=222)
        pkt.time = t
        tracker.process_packet(pkt)

    # At t=109.5, active lifetime is 9.5s < 10.0s
    assert len(tracker.get_expired_flows(current_time=109.5)) == 0

    # At t=110.5, active lifetime is 10.5s >= 10.0s active timeout
    expired = tracker.get_expired_flows(current_time=110.5)
    assert len(expired) == 1
    assert tracker.active_flow_count == 0


# 10. Flow Finalization
def test_flow_finalization():
    config = SensorConfig(flow_idle_timeout=1.0)
    tracker = FlowTracker(config)

    pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=8080, dport=80)
    pkt.time = 50.0
    tracker.process_packet(pkt)

    expired = tracker.get_expired_flows(current_time=52.0)
    assert len(expired) == 1
    assert expired[0].state == FlowState.EXPIRED
    assert tracker.total_flows_expired == 1


# 11. Feature Vector Contains Exactly 67 Features
def test_feature_vector_contains_exact_67_features():
    key = FlowKey.from_endpoints("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
    flow = BidirectionalFlow(key, "10.0.0.1", 1234, "10.0.0.2", 80, "TCP", start_time=10.0)
    flow.add_packet("10.0.0.1", 1234, "10.0.0.2", 80, packet_len=60, header_len=40, timestamp=10.0)

    features, completeness = LiveFeatureBuilder.build_features(flow)

    assert len(features) == 67
    assert set(features.keys()) == set(EXPECTED_67_FEATURES)


# 12. Feature Ordering Matches Model Metadata
def test_feature_ordering_matches_model_metadata():
    meta_path = Path("models/network/network_model_metadata.json")
    assert meta_path.exists(), "Model metadata file must exist"

    with open(meta_path, "r") as f:
        meta = json.load(f)

    expected_from_meta = meta["feature_names"]
    assert len(expected_from_meta) == 67
    assert EXPECTED_67_FEATURES == expected_from_meta


# 13. NaN and Inf Sanitization
def test_nan_inf_sanitization():
    key = FlowKey.from_endpoints("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
    flow = BidirectionalFlow(key, "10.0.0.1", 1234, "10.0.0.2", 80, "TCP", start_time=10.0)
    # Zero duration packet
    flow.add_packet("10.0.0.1", 1234, "10.0.0.2", 80, packet_len=60, header_len=40, timestamp=10.0)

    features, _ = LiveFeatureBuilder.build_features(flow)

    import math
    for k, v in features.items():
        assert not math.isnan(v), f"Feature {k} returned NaN"
        assert not math.isinf(v), f"Feature {k} returned Inf"


# 14. Malformed Packet Handling
def test_malformed_packet_handling():
    tracker = FlowTracker()
    # Non-IP packet (e.g. raw bytes or arbitrary object)
    res = tracker.process_packet(b"not_a_valid_ip_packet")
    assert res is None
    assert tracker.active_flow_count == 0


# 15. Bounded Flow Table Cleanup
def test_bounded_flow_table_cleanup():
    config = SensorConfig(max_active_flows=3)
    tracker = FlowTracker(config)

    # Add 4 distinct flows
    for i in range(4):
        pkt = IP(src=f"10.0.0.{i}", dst="192.168.1.1")/TCP(sport=50000+i, dport=80)
        pkt.time = 100.0 + i
        tracker.process_packet(pkt)

    # Active flows must never exceed bounded capacity (3)
    assert tracker.active_flow_count <= 3
    assert tracker.total_flows_created == 4
    assert tracker.total_flows_expired >= 1


# 16. Sensor Start / Stop Lifecycle
def test_sensor_start_stop_lifecycle():
    sensor = LiveSensorService()
    st1 = sensor.get_status()
    assert st1["running"] is False
    assert st1["active_flows"] == 0

    # Test stop when already stopped is safe and idempotent
    st2 = sensor.stop()
    assert st2["running"] is False


# 17. Sensor Status REST API
def test_sensor_status_api(client):
    res = client.get("/api/network/sensor/status")
    assert res.status_code == 200
    data = res.json()
    assert "running" in data
    assert "packets_captured" in data
    assert "active_flows" in data
    assert "completed_flows" in data
    assert "analyzed_flows" in data
    assert "detected_attacks" in data
    assert "errors" in data


# 18. Network Interfaces REST API
def test_interfaces_api(client):
    res = client.get("/api/network/interfaces")
    assert res.status_code == 200
    data = res.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)
    if len(data["interfaces"]) > 0:
        first = data["interfaces"][0]
        assert "name" in first
        assert "status" in first


# 19. Safe Default Prevention Mode
def test_detect_only_safety():
    config = SensorConfig()
    assert config.analysis_mode == "detect_only"
    assert config.enabled is False


# 20. BPF Filter Validation
def test_bpf_filter_validation():
    # Valid filter should not raise
    validate_bpf_filter("tcp")
    validate_bpf_filter("udp or icmp")
    validate_bpf_filter(None)

    # Invalid filter must raise ValueError
    with pytest.raises(ValueError):
        validate_bpf_filter("malformed filter expression !!&&")


# 21. End-to-End Pipeline Integration: Packets -> Flow -> Features -> NetworkService -> Event DB
def test_end_to_end_ids_pipeline_integration():
    net_service = NetworkService()
    assert net_service.loader.is_ready, "Network IDS model must be ready"

    # Create a synthetic scan flow with rapid half-open SYN packets
    key = FlowKey.from_endpoints("192.168.1.150", 49200, "192.168.1.1", 22, "TCP")
    flow = BidirectionalFlow(key, "192.168.1.150", 49200, "192.168.1.1", 22, "TCP", start_time=100.0)

    # Add SYN packet with zero backward response (scan behavior)
    flow.add_packet(
        "192.168.1.150", 49200, "192.168.1.1", 22,
        packet_len=60, header_len=40, timestamp=100.0,
        tcp_flags={"SYN": True, "FIN": False, "RST": False, "PSH": False, "ACK": False, "URG": False, "ECE": False}
    )

    # Build 67 features
    features, completeness = LiveFeatureBuilder.build_features(flow)
    assert len(features) == 67

    # Run canonical Network IDS pipeline
    req = NetworkFlowAnalyzeRequest(
        source_ip=flow.src_ip,
        destination_ip=flow.dst_ip,
        source_port=flow.src_port,
        destination_port=flow.dst_port,
        protocol=flow.protocol,
        features=features
    )
    result = net_service.analyze_flow(req)

    # Verify unified response fields
    assert result.event_id is not None
    assert result.event_type == "NETWORK"
    assert result.threat_score >= 0
    assert result.severity in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert result.applied_action in ["MONITORED_ONLY", "SIMULATED_BLOCK", "BLOCK"]
    assert len(result.reasons) > 0

    # Verify event was persisted to SQLite database
    saved_event = net_service.db.get_event(result.event_id)
    assert saved_event is not None
    assert saved_event["event_id"] == result.event_id
    assert saved_event["event_type"] == "NETWORK"
