"""
CIPHER Live Network Sensor Configuration
Defines settings, timing parameters, BPF filters, and memory bounds for packet capture.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class SensorConfig:
    """Configuration parameters for live network packet capture and flow aggregation."""
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    flow_idle_timeout: float = 5.0        # Seconds of inactivity before flow is finalized
    flow_active_timeout: float = 60.0     # Maximum seconds a flow can remain active before expiration
    min_packets_to_analyze: int = 1       # Minimum packet count required to send flow to IDS
    max_active_flows: int = 50000         # Bounded memory capacity for concurrent active flows
    cleanup_interval_seconds: float = 1.0 # Interval for the background expiration worker
    analysis_mode: str = "detect_only"    # Default: detect_only (does not modify host firewall unless enforcement mode configured)
    enabled: bool = False                 # Default: sensor starts in STOPPED state


def load_sensor_config_from_env() -> SensorConfig:
    """Initializes sensor configuration from environment variables with safe defaults."""
    idle_timeout = float(os.getenv("CIPHER_FLOW_IDLE_TIMEOUT", "5.0"))
    active_timeout = float(os.getenv("CIPHER_FLOW_ACTIVE_TIMEOUT", "60.0"))
    max_flows = int(os.getenv("CIPHER_MAX_ACTIVE_FLOWS", "50000"))
    iface = os.getenv("CIPHER_SENSOR_INTERFACE", None)
    bpf = os.getenv("CIPHER_SENSOR_BPF", None)
    mode = os.getenv("CIPHER_PREVENTION_MODE", "detect_only").lower()

    return SensorConfig(
        interface=iface,
        bpf_filter=bpf,
        flow_idle_timeout=idle_timeout,
        flow_active_timeout=active_timeout,
        max_active_flows=max_flows,
        analysis_mode=mode,
        enabled=False
    )
