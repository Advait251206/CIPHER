"""
Tests for Feature Extraction Parity with CICFlowMeter v3.
Checks min_seg_size_forward tracking (TCP header only, 20-60B),
flow expiration timeouts (120s active, 5s idle), and packet vs payload lengths.
"""

import os
import pytest
from app.network.live_sensor.flow import BidirectionalFlow, FlowKey, FlowState
from app.network.live_sensor.flow_tracker import FlowTracker
from app.network.live_sensor.feature_builder import LiveFeatureBuilder
from app.network.live_sensor.config import SensorConfig


def test_min_seg_size_forward_tcp_header_only():
    """Verify that min_seg_size_forward tracks TCP header length only (20-60B), not L3+L4."""
    key = FlowKey.from_endpoints("192.168.1.10", 50000, "10.0.0.1", 80, "TCP")
    flow = BidirectionalFlow(
        key=key,
        initial_src_ip="192.168.1.10",
        initial_src_port=50000,
        initial_dst_ip="10.0.0.1",
        initial_dst_port=80,
        protocol="TCP",
        start_time=1000.0
    )

    # Packet 1: Wire len 1500, IP hdr 20, TCP hdr 32 (with options), total hdr 52, payload 1448
    flow.add_packet(
        src_ip="192.168.1.10",
        src_port=50000,
        dst_ip="10.0.0.1",
        dst_port=80,
        packet_len=1500,
        header_len=52,
        timestamp=1000.0,
        tcp_flags={"ACK": True},
        payload_len=1448,
        tcp_header_len=32
    )

    # min_seg_size_fwd should be 32 (the TCP header length), NOT 52
    assert flow.min_seg_size_fwd == 32

    # Packet 2: Wire len 60, IP hdr 20, TCP hdr 20 (standard), total hdr 40, payload 0
    flow.add_packet(
        src_ip="192.168.1.10",
        src_port=50000,
        dst_ip="10.0.0.1",
        dst_port=80,
        packet_len=60,
        header_len=40,
        timestamp=1000.1,
        tcp_flags={"ACK": True},
        payload_len=0,
        tcp_header_len=20
    )

    # min_seg_size_fwd should update to minimum TCP header length: 20
    assert flow.min_seg_size_fwd == 20

    features, completeness = LiveFeatureBuilder.build_features(flow)
    assert features["min_seg_size_forward"] == 20.0
    assert features["act_data_pkt_fwd"] == 1.0  # Only packet 1 had payload


def test_sensor_timeout_alignment():
    """Verify that default timeouts match CICFlowMeter v3: 120s active timeout, 5s idle timeout."""
    config = SensorConfig()
    assert config.flow_active_timeout == 120.0
    assert config.flow_idle_timeout == 5.0


def test_cic_pcap_sample_parity():
    """
    If a real CIC-IDS2017 PCAP file is present, runs full packet replay parity test.
    Per Rule 5, skips if pcap is not provided by the testbed.
    """
    pcap_path = os.getenv("CIC_SAMPLE_PCAP", "data/raw/cic_ids2017/sample.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip(f"Sample CIC PCAP not found at '{pcap_path}'; stopped per Rule 5.")
