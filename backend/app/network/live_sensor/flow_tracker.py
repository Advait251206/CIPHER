"""
CIPHER Flow Tracker
Aggregates live network packets into bidirectional flows, tracks state,
enforces idle/active timeouts, and manages bounded in-memory capacity.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any

from app.network.live_sensor.config import SensorConfig
from app.network.live_sensor.flow import FlowKey, FlowState, BidirectionalFlow

logger = logging.getLogger("cipher.network.flow_tracker")


class FlowTracker:
    """
    Thread-safe manager for concurrent active bidirectional network flows.
    Parses L3/L4 packet metadata in O(1) time and periodically evicts expired flows.
    """

    def __init__(self, config: Optional[SensorConfig] = None):
        self.config = config or SensorConfig()
        self._flows: Dict[FlowKey, BidirectionalFlow] = {}
        self._lock = threading.RLock()
        self.total_packets_processed = 0
        self.total_flows_created = 0
        self.total_flows_expired = 0

    @property
    def active_flow_count(self) -> int:
        """Returns current count of active flows."""
        with self._lock:
            return len(self._flows)

    def process_packet(self, packet: Any) -> Optional[BidirectionalFlow]:
        """
        Extracts L3/L4 metadata from a raw/Scapy packet and updates the corresponding flow.
        Returns the updated flow, or None if packet is not an IP packet or malformed.
        
        Zero payload storage: only lengths, headers, flags, and timing are recorded.
        """
        try:
            # 1. Check IP layer (IPv4 primary, IPv6 supported if present)
            has_ip = hasattr(packet, "haslayer") and packet.haslayer("IP")
            has_ipv6 = hasattr(packet, "haslayer") and packet.haslayer("IPv6")

            if not (has_ip or has_ipv6):
                return None

            if has_ip:
                ip_layer = packet["IP"]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                raw_ihl = getattr(ip_layer, "ihl", 5)
                ihl = raw_ihl if raw_ihl is not None else 5
                ip_header_len = int(ihl) * 4
            else:
                ip_layer = packet["IPv6"]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                ip_header_len = 40

            # 2. Check Transport Layer (TCP, UDP, or ICMP)
            protocol = "OTHER"
            src_port = 0
            dst_port = 0
            header_len = ip_header_len
            tcp_flags = None
            window_size = None
            payload_len = 0

            if hasattr(packet, "haslayer") and packet.haslayer("TCP"):
                protocol = "TCP"
                tcp_layer = packet["TCP"]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                raw_dataofs = getattr(tcp_layer, "dataofs", 5)
                dataofs = raw_dataofs if raw_dataofs is not None else 5
                tcp_header_len = int(dataofs) * 4
                header_len += tcp_header_len
                raw_win = getattr(tcp_layer, "window", 0)
                window_size = int(raw_win) if raw_win is not None else 0

                # Bitmask flag extraction: FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20), ECE(0x40)
                raw_flags = int(tcp_layer.flags)
                tcp_flags = {
                    "FIN": bool(raw_flags & 0x01),
                    "SYN": bool(raw_flags & 0x02),
                    "RST": bool(raw_flags & 0x04),
                    "PSH": bool(raw_flags & 0x08),
                    "ACK": bool(raw_flags & 0x10),
                    "URG": bool(raw_flags & 0x20),
                    "ECE": bool(raw_flags & 0x40),
                }

                if hasattr(tcp_layer, "payload"):
                    payload_len = len(tcp_layer.payload)

            elif hasattr(packet, "haslayer") and packet.haslayer("UDP"):
                protocol = "UDP"
                udp_layer = packet["UDP"]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                header_len += 8
                if hasattr(udp_layer, "payload"):
                    payload_len = len(udp_layer.payload)

            elif hasattr(packet, "haslayer") and packet.haslayer("ICMP"):
                protocol = "ICMP"
                header_len += 8
            else:
                # Other L4 protocol
                protocol = str(getattr(ip_layer, "proto", "OTHER"))

            # Packet wire length and timestamp
            packet_len = len(packet)
            pkt_time = float(getattr(packet, "time", time.time()))

            # 3. Canonical Flow Key
            key = FlowKey.from_endpoints(src_ip, src_port, dst_ip, dst_port, protocol)

            with self._lock:
                self.total_packets_processed += 1

                # Memory bound safeguard: if capacity exceeded, evict oldest
                if len(self._flows) >= self.config.max_active_flows and key not in self._flows:
                    self._evict_oldest_under_lock()

                if key not in self._flows:
                    flow = BidirectionalFlow(
                        key=key,
                        initial_src_ip=src_ip,
                        initial_src_port=src_port,
                        initial_dst_ip=dst_ip,
                        initial_dst_port=dst_port,
                        protocol=protocol,
                        start_time=pkt_time
                    )
                    self._flows[key] = flow
                    self.total_flows_created += 1
                else:
                    flow = self._flows[key]

                # Update flow state with packet metadata
                flow.add_packet(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    packet_len=packet_len,
                    header_len=header_len,
                    timestamp=pkt_time,
                    tcp_flags=tcp_flags,
                    window_size=window_size,
                    payload_len=payload_len
                )

                return flow

        except Exception as e:
            logger.debug(f"[FLOW_TRACKER] Error parsing packet: {e}")
            return None

    def _evict_oldest_under_lock(self):
        """Evicts the oldest flow when memory capacity is reached."""
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].last_seen_time)
        evicted = self._flows.pop(oldest_key)
        evicted.state = FlowState.EXPIRED
        self.total_flows_expired += 1
        logger.warning(
            f"[FLOW_TRACKER] Bounded capacity reached ({self.config.max_active_flows}); "
            f"evicted oldest flow {evicted.src_ip}:{evicted.src_port} -> {evicted.dst_ip}:{evicted.dst_port}"
        )

    def get_expired_flows(self, current_time: Optional[float] = None) -> List[BidirectionalFlow]:
        """
        Scans active flows, removes those that have timed out or terminated,
        and returns them for feature extraction and IDS analysis.
        """
        now = current_time if current_time is not None else time.time()
        expired: List[BidirectionalFlow] = []

        with self._lock:
            keys_to_remove = []
            for key, flow in self._flows.items():
                idle_duration = now - flow.last_seen_time
                active_duration = now - flow.start_time

                is_idle = idle_duration >= self.config.flow_idle_timeout
                is_active_timeout = active_duration >= self.config.flow_active_timeout
                is_terminated = flow.is_terminated and (flow.total_packets >= 2 or idle_duration >= 0.5)

                if is_idle or is_active_timeout or is_terminated:
                    keys_to_remove.append(key)
                    flow.state = FlowState.EXPIRED
                    expired.append(flow)

            for k in keys_to_remove:
                del self._flows[k]

            self.total_flows_expired += len(expired)

        return expired

    def clear(self):
        """Clears all active flows and resets counters."""
        with self._lock:
            self._flows.clear()
            self.total_packets_processed = 0
            self.total_flows_created = 0
            self.total_flows_expired = 0
