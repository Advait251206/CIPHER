"""
CIPHER Live Bidirectional Flow Representation
Encapsulates flow state, canonical keying, directional packet accounting,
TCP flag tracking, inter-arrival timing, and lifecycle transitions.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any
import numpy as np


class FlowState(str, Enum):
    """Lifecycle states of a network flow."""
    NEW = "NEW"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    FINALIZED = "FINALIZED"


class FlowDirection(str, Enum):
    """Traffic direction relative to the flow initiator."""
    FORWARD = "FORWARD"
    BACKWARD = "BACKWARD"


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional 5-tuple identifier."""
    ip_low: str
    port_low: int
    ip_high: str
    port_high: int
    protocol: str

    @classmethod
    def from_endpoints(cls, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> "FlowKey":
        """Normalizes source and destination so (A->B) and (B->A) map to identical key."""
        proto = protocol.upper()
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return cls(src_ip, src_port, dst_ip, dst_port, proto)
        else:
            return cls(dst_ip, dst_port, src_ip, src_port, proto)


class BidirectionalFlow:
    """
    State container tracking full layer 3/4 flow statistics across forward
    and backward traffic streams matching the CIC-IDS2017 feature schema.
    """

    def __init__(
        self,
        key: FlowKey,
        initial_src_ip: str,
        initial_src_port: int,
        initial_dst_ip: str,
        initial_dst_port: int,
        protocol: str,
        start_time: float
    ):
        self.key = key
        # Flow initiator endpoints define the FORWARD direction
        self.src_ip = initial_src_ip
        self.src_port = initial_src_port
        self.dst_ip = initial_dst_ip
        self.dst_port = initial_dst_port
        self.protocol = protocol.upper()

        self.start_time = start_time
        self.last_seen_time = start_time
        self.state = FlowState.NEW
        self.is_terminated = False

        # Forward Direction Metrics
        self.fwd_packet_count = 0
        self.fwd_byte_count = 0
        self.fwd_packet_lengths: List[int] = []
        self.fwd_header_lengths: List[int] = []
        self.fwd_timestamps: List[float] = []

        # Backward Direction Metrics
        self.bwd_packet_count = 0
        self.bwd_byte_count = 0
        self.bwd_packet_lengths: List[int] = []
        self.bwd_header_lengths: List[int] = []
        self.bwd_timestamps: List[float] = []

        # Inter-Arrival Times (All Packets)
        self.flow_timestamps: List[float] = []

        # TCP Flag Counts (Combined & Directional)
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.ece_count = 0
        self.fwd_psh_count = 0

        # TCP Window Sizes
        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1

        # TCP Data Segments
        self.act_data_pkt_fwd = 0
        self.min_seg_size_fwd = 20  # Default IPv4/TCP standard header size

        # Active / Idle Period Tracking (Threshold = 1.0s gap between packets)
        self.active_durations: List[float] = []
        self.idle_durations: List[float] = []
        self.current_active_start = start_time
        self.current_active_last = start_time
        self.idle_threshold = 1.0

    def get_direction(self, src_ip: str, src_port: int) -> FlowDirection:
        """Determines whether a packet is in the forward or backward direction."""
        if src_ip == self.src_ip and src_port == self.src_port:
            return FlowDirection.FORWARD
        return FlowDirection.BACKWARD

    def add_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        packet_len: int,
        header_len: int,
        timestamp: float,
        tcp_flags: Optional[Dict[str, bool]] = None,
        window_size: Optional[int] = None,
        payload_len: int = 0
    ):
        """
        Updates flow state with an incoming packet in O(1) time.
        Does NOT inspect or persist application payloads.
        """
        direction = self.get_direction(src_ip, src_port)

        # Active / Idle Tracking
        time_since_last = timestamp - self.last_seen_time
        if self.fwd_packet_count + self.bwd_packet_count > 0:
            if time_since_last >= self.idle_threshold:
                # Previous active period ended; record active and idle durations
                active_time = self.current_active_last - self.current_active_start
                if active_time > 0:
                    self.active_durations.append(active_time)
                self.idle_durations.append(time_since_last)
                self.current_active_start = timestamp

        self.current_active_last = timestamp
        self.last_seen_time = max(self.last_seen_time, timestamp)
        self.flow_timestamps.append(timestamp)

        if direction == FlowDirection.FORWARD:
            self.fwd_packet_count += 1
            self.fwd_byte_count += packet_len
            self.fwd_packet_lengths.append(packet_len)
            self.fwd_header_lengths.append(header_len)
            self.fwd_timestamps.append(timestamp)

            if payload_len > 0:
                self.act_data_pkt_fwd += 1
            if header_len > 0:
                self.min_seg_size_fwd = min(self.min_seg_size_fwd, header_len)
            if window_size is not None and self.init_win_bytes_fwd == -1:
                self.init_win_bytes_fwd = int(window_size)

        else:
            self.bwd_packet_count += 1
            self.bwd_byte_count += packet_len
            self.bwd_packet_lengths.append(packet_len)
            self.bwd_header_lengths.append(header_len)
            self.bwd_timestamps.append(timestamp)

            if window_size is not None and self.init_win_bytes_bwd == -1:
                self.init_win_bytes_bwd = int(window_size)

        # TCP Flags
        if tcp_flags:
            if tcp_flags.get("FIN", False):
                self.fin_count += 1
                self.is_terminated = True
            if tcp_flags.get("SYN", False):
                self.syn_count += 1
            if tcp_flags.get("RST", False):
                self.rst_count += 1
                self.is_terminated = True
            if tcp_flags.get("PSH", False):
                self.psh_count += 1
                if direction == FlowDirection.FORWARD:
                    self.fwd_psh_count += 1
            if tcp_flags.get("ACK", False):
                self.ack_count += 1
            if tcp_flags.get("URG", False):
                self.urg_count += 1
            if tcp_flags.get("ECE", False):
                self.ece_count += 1

        self.state = FlowState.ACTIVE

    @property
    def total_packets(self) -> int:
        return self.fwd_packet_count + self.bwd_packet_count

    @property
    def total_bytes(self) -> int:
        return self.fwd_byte_count + self.bwd_byte_count

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen_time - self.start_time)
