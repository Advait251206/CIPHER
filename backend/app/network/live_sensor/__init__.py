"""
CIPHER Live Network Sensor Module
Provides real-time packet capture, bidirectional flow tracking,
CIC-IDS2017 67-feature extraction, and integration with the CIPHER IDS pipeline.
"""

from app.network.live_sensor.config import SensorConfig, load_sensor_config_from_env
from app.network.live_sensor.flow import FlowKey, FlowState, FlowDirection, BidirectionalFlow
from app.network.live_sensor.flow_tracker import FlowTracker
from app.network.live_sensor.feature_builder import LiveFeatureBuilder, EXPECTED_67_FEATURES
from app.network.live_sensor.packet_capture import (
    PacketCapture,
    get_available_interfaces,
    is_npcap_available,
    resolve_interface,
    validate_bpf_filter,
    SCAPY_AVAILABLE
)
from app.network.live_sensor.sensor_service import LiveSensorService, get_sensor_service

__all__ = [
    "SensorConfig",
    "load_sensor_config_from_env",
    "FlowKey",
    "FlowState",
    "FlowDirection",
    "BidirectionalFlow",
    "FlowTracker",
    "LiveFeatureBuilder",
    "EXPECTED_67_FEATURES",
    "PacketCapture",
    "get_available_interfaces",
    "is_npcap_available",
    "resolve_interface",
    "validate_bpf_filter",
    "SCAPY_AVAILABLE",
    "LiveSensorService",
    "get_sensor_service",
]
