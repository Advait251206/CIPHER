"""
CIPHER Live Network Sensor Service
Orchestrates live packet sniffing, flow aggregation, 67-feature extraction,
and handoff to the canonical Network IDS detection/prevention pipeline.
"""

import time
import logging
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.network.live_sensor.config import SensorConfig, load_sensor_config_from_env
from app.network.live_sensor.flow_tracker import FlowTracker
from app.network.live_sensor.packet_capture import (
    PacketCapture,
    get_available_interfaces,
    is_npcap_available,
    SCAPY_AVAILABLE,
    validate_bpf_filter
)
from app.network.live_sensor.feature_builder import LiveFeatureBuilder
from app.network.service import NetworkService
from app.network.schemas import NetworkFlowAnalyzeRequest
from app.network.live_sensor.arp_engine import ARPEngine
from app.correlation.service import CorrelationService

logger = logging.getLogger("cipher.network.live_sensor")


class LiveSensorService:
    """
    Central coordinator for live network intrusion detection.
    Controls packet capture, maintains flow state, periodically finalizes flows,
    and feeds them through the canonical CIPHER ML and threat scoring engines.
    """

    def __init__(
        self,
        config: Optional[SensorConfig] = None,
        network_service: Optional[NetworkService] = None
    ):
        self.config = config or load_sensor_config_from_env()
        self._network_service = network_service
        self.flow_tracker = FlowTracker(self.config)
        self._packet_capture: Optional[PacketCapture] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
        
        self.correlation_service = CorrelationService()
        self.arp_engine = ARPEngine(self.correlation_service)

        # Telemetry counters
        self.interface: Optional[str] = None
        self.bpf_filter: Optional[str] = None
        self.started_at: Optional[str] = None
        self.completed_flows = 0
        self.analyzed_flows = 0
        self.detected_attacks = 0
        self.errors = 0

    @property
    def network_service(self) -> NetworkService:
        """Lazy initialization of NetworkService to ensure DB and models are ready."""
        if self._network_service is None:
            self._network_service = NetworkService()
        return self._network_service

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running and self._packet_capture is not None and self._packet_capture.is_running

    def list_interfaces(self) -> List[Dict[str, Any]]:
        """Returns all available host interfaces for packet capture."""
        return get_available_interfaces()

    def get_status(self) -> Dict[str, Any]:
        """Returns current operational status and telemetry metrics."""
        with self._lock:
            running = self._running and (self._packet_capture is not None and self._packet_capture.is_running)
            pkts = self._packet_capture.packets_captured if self._packet_capture else 0
            cap_errors = self._packet_capture.errors if self._packet_capture else 0
            active = self.flow_tracker.active_flow_count

            return {
                "running": running,
                "interface": self.interface,
                "bpf_filter": self.bpf_filter,
                "packets_captured": pkts,
                "active_flows": active,
                "completed_flows": self.completed_flows,
                "analyzed_flows": self.analyzed_flows,
                "detected_attacks": self.detected_attacks,
                "started_at": self.started_at,
                "errors": self.errors + cap_errors,
                "npcap_available": is_npcap_available(),
                "scapy_available": SCAPY_AVAILABLE
            }

    def start(
        self,
        interface: str,
        bpf_filter: Optional[str] = None,
        flow_idle_timeout: Optional[float] = None,
        flow_active_timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Starts live packet capture and background flow expiration processing.
        """
        with self._lock:
            if self._running:
                logger.warning("[SENSOR] Live sensor is already active.")
                return self.get_status()

            if not SCAPY_AVAILABLE:
                raise RuntimeError("Scapy is not installed. Live packet capture cannot start.")

            if not is_npcap_available():
                raise RuntimeError(
                    "Npcap is not installed or not operational. "
                    "Install Npcap with 'WinPcap API-compatible mode' enabled."
                )

            # Update configuration if custom timeouts supplied
            if flow_idle_timeout is not None:
                self.config.flow_idle_timeout = max(0.5, float(flow_idle_timeout))
            if flow_active_timeout is not None:
                self.config.flow_active_timeout = max(1.0, float(flow_active_timeout))

            # Validate BPF filter syntax ahead of time
            if bpf_filter:
                validate_bpf_filter(bpf_filter)

            self.interface = interface
            self.bpf_filter = bpf_filter
            self.flow_tracker = FlowTracker(self.config)

            # Initialize capture
            self._packet_capture = PacketCapture(
                on_packet=self.flow_tracker.process_packet,
                interface=interface,
                bpf_filter=bpf_filter,
                on_arp=self.arp_engine.process_arp
            )

            # Start capture engine
            self._packet_capture.start()
            self._running = True
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.completed_flows = 0
            self.analyzed_flows = 0
            self.detected_attacks = 0
            self.errors = 0

            # Start background expiration worker
            self._worker_thread = threading.Thread(
                target=self._expiration_worker_loop,
                daemon=True,
                name="cipher-sensor-worker"
            )
            self._worker_thread.start()

            logger.info(f"[SENSOR] Started on interface '{self.interface}' (BPF: '{self.bpf_filter or 'None'}')")

        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """
        Gracefully stops packet capture, finalizes remaining flows, and shuts down worker thread.
        """
        with self._lock:
            if not self._running:
                return self.get_status()

            logger.info("[SENSOR] Stopping live sensor...")
            self._running = False

            if self._packet_capture:
                self._packet_capture.stop()

        # Wait for worker thread to exit
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

        # Final flush: process any remaining active flows
        self._flush_expired_flows(force_all=True)

        logger.info(
            f"[SENSOR] Stopped. Packets: {self._packet_capture.packets_captured if self._packet_capture else 0}, "
            f"Analyzed flows: {self.analyzed_flows}, Detections: {self.detected_attacks}"
        )

        return self.get_status()

    def _expiration_worker_loop(self):
        """Background thread worker scanning for and finalizing expired network flows."""
        while self._running:
            try:
                self._flush_expired_flows(force_all=False)
            except Exception as e:
                self.errors += 1
                logger.error(f"[SENSOR] Error in flow expiration worker loop: {e}")

            time.sleep(self.config.cleanup_interval_seconds)

    def _flush_expired_flows(self, force_all: bool = False):
        """Evicts expired flows and executes canonical ML IDS analysis."""
        now = float("inf") if force_all else time.time()
        expired_flows = self.flow_tracker.get_expired_flows(current_time=now)

        for flow in expired_flows:
            self.completed_flows += 1

            if flow.total_packets < self.config.min_packets_to_analyze:
                continue

            try:
                features, completeness = LiveFeatureBuilder.build_features(flow)

                logger.info(
                    f"[FLOW] Finalized {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                    f"(proto={flow.protocol}, pkts={flow.total_packets}, dur={flow.duration_seconds:.2f}s)"
                )
                logger.info(f"[FEATURES] Built 67 features (quality={completeness:.2f})")

                req = NetworkFlowAnalyzeRequest(
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    source_port=flow.src_port,
                    destination_port=flow.dst_port,
                    protocol=flow.protocol,
                    features=features,
                    timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                )

                # Canonical detection pipeline: ML + Heuristics + Threat Scoring + IPS + SQLite
                res = self.network_service.analyze_flow(req)
                self.analyzed_flows += 1

                if res.attack_type != "BENIGN":
                    self.detected_attacks += 1

                logger.info(f"[IDS] {res.attack_type} (ml_pred={res.ml_prediction}, prob={res.ml_attack_prob:.2f})")
                logger.info(f"[THREAT] score={res.threat_score} severity={res.severity}")
                logger.info(f"[IPS] action={res.applied_action} recommended={res.recommended_action}")

            except Exception as e:
                self.errors += 1
                logger.error(
                    f"[SENSOR] Error analyzing flow {flow.src_ip}:{flow.src_port} -> "
                    f"{flow.dst_ip}:{flow.dst_port}: {e}"
                )


# Global singleton instance
_sensor_service_instance: Optional[LiveSensorService] = None
_instance_lock = threading.Lock()


def get_sensor_service() -> LiveSensorService:
    """Returns the singleton LiveSensorService instance."""
    global _sensor_service_instance
    with _instance_lock:
        if _sensor_service_instance is None:
            _sensor_service_instance = LiveSensorService()
        return _sensor_service_instance
