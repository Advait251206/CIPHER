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
        Extracts L3/L4 metadata from a raw/Scapy packet or C++ parsed dictionary and updates the corresponding flow.
        Returns the updated flow, or None if packet is not an IP packet or malformed.
        
        Zero payload storage: only lengths, headers, flags, and timing are recorded.
        """
        try:
            # Handle C++ parsed dictionary
            if isinstance(packet, dict):
                src_ip = packet.get("src_ip", "")
                dst_ip = packet.get("dst_ip", "")
                
                # Ignore IPv6 traffic to prevent false positive noise
                if ":" in str(src_ip) or ":" in str(dst_ip):
                    return None
                    
                src_port = packet.get("src_port", 0)
                dst_port = packet.get("dst_port", 0)
                protocol_num = packet.get("proto", 0)
                
                if protocol_num == 6:
                    protocol = "TCP"
                elif protocol_num == 17:
                    protocol = "UDP"
                elif protocol_num == 1:
                    protocol = "ICMP"
                else:
                    protocol = str(protocol_num)
                
                packet_len = packet.get("pkt_len", 0)
                header_len = packet.get("hdr_len", 0)
                payload_len = packet.get("payload_len", 0)
                window_size = packet.get("win", 0)
                pkt_time = packet.get("ts", time.time())
                
                # Parse TCP flags string (e.g. "SA" -> SYN, ACK)
                tcp_flags = None
                if protocol == "TCP":
                    flags_str = packet.get("flags", "")
                    tcp_flags = {
                        "FIN": "F" in flags_str,
                        "SYN": "S" in flags_str,
                        "RST": "R" in flags_str,
                        "PSH": "P" in flags_str,
                        "ACK": "A" in flags_str,
                        "URG": "U" in flags_str,
                        "ECE": "E" in flags_str,
                    }
                
                # Filter background noise
                if src_port not in [5174, 8000, 8080] and dst_port not in [5174, 8000, 8080]:
                    return None
                    
                # Canonical Flow Key
                key = FlowKey.from_endpoints(src_ip, src_port, dst_ip, dst_port, protocol)
                
                with self._lock:
                    self.total_packets_processed += 1
                    
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

            # Handle traditional Scapy packet
            # 1. Check IP layer (IPv4 primary, IPv6 ignored to prevent false positives)
            has_ip = hasattr(packet, "haslayer") and packet.haslayer("IP")

            if not has_ip:
                return None

            ip_layer = packet["IP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            raw_ihl = getattr(ip_layer, "ihl", 5)
            ihl = raw_ihl if raw_ihl is not None else 5
            ip_header_len = int(ihl) * 4

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
                    raw_payload = bytes(tcp_layer.payload)
                    payload_len = len(raw_payload)
                    
                    # RESTRICT WAF to INCOMING requests to the Vulnerable App (5174) or Backend (8000).
                    # Do not inspect responses (src_port) to avoid false positives on CSS/JS files.
                    if payload_len > 0 and dst_port in [5174, 8000, 8080]:
                        try:
                            # Basic string extraction for WAF payload inspection
                            payload_str = raw_payload.decode("utf-8", errors="ignore")
                            from app.network.live_sensor.waf_engine import waf_engine
                            attack_type, enforce_mode = waf_engine.inspect_payload(payload_str)
                            
                            if attack_type:
                                logger.warning(f"[WAF] {attack_type} detected from {src_ip}:{src_port}! Mode: {enforce_mode}")
                                
                                # Log the WAF detection as an incident in the database
                                try:
                                    import uuid
                                    from datetime import datetime, timezone
                                    from app.database.database import Database
                                    from app.correlation.service import get_correlation_service
                                    
                                    event_id = str(uuid.uuid4())
                                    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                                    
                                    event_record = {
                                        "event_id": event_id,
                                        "timestamp": timestamp,
                                        "event_type": "WEB_ATTACK",
                                        "attack_type": attack_type,
                                        "classification": "Web Application Attack",
                                        "risk_score": 85,
                                        "confidence": "HIGH",
                                        "severity": "HIGH",
                                        "ml_score": 0.0,
                                        "heuristic_score": 100,
                                        "domain": src_ip,
                                        "source_ip": src_ip,
                                        "destination_ip": dst_ip,
                                        "source_port": src_port,
                                        "destination_port": dst_port,
                                        "protocol": "TCP",
                                        "detection_method": "WAF_SIGNATURE",
                                        "reasons": [f"WAF signature matched for {attack_type}"],
                                        "recommendation": f"WAF Engine triggered on malicious HTTP payload. Connection was {'blocked' if enforce_mode == 'enforce' else 'monitored'}.",
                                        "action": "BLOCK" if enforce_mode == "enforce" else "LOG",
                                        "status": "BLOCKED" if enforce_mode == "enforce" else "NEW",
                                        "model_version": "waf_v1",
                                        "source": "live_sensor",
                                        "metadata": {
                                            "prevention_mode": enforce_mode,
                                            "applied_action": "BLOCK" if enforce_mode == "enforce" else "LOG"
                                        }
                                    }
                                    
                                    Database().save_event(event_record)
                                    try:
                                        get_correlation_service().process_event(event_record)
                                    except Exception as corr_err:
                                        logger.warning(f"Correlation failed for WAF event {event_id}: {corr_err}")
                                except Exception as log_e:
                                    logger.error(f"[WAF] Failed to log incident to DB: {log_e}")

                                if enforce_mode == "enforce":
                                    logger.error(f"[IPS] Active TCP RST fired for {attack_type} against {src_ip}")
                                    # Extract seq and ack for forged RST
                                    seq = getattr(tcp_layer, "seq", 0)
                                    ack = getattr(tcp_layer, "ack", 0)
                                    # In a real inline IPS, we'd inject a forged RST packet here.
                                    waf_engine.inject_tcp_rst(src_ip, src_port, dst_ip, dst_port, seq, ack)
                                    
                                    # Automatically block the IP at the network level
                                    try:
                                        from app.network.service import NetworkService
                                        NetworkService().prevention_engine.blocklist.block_ip(
                                            ip=src_ip,
                                            reason=f"WAF Engine Auto-Blocked: {attack_type}",
                                            attack_type=attack_type,
                                            threat_score=100,
                                            duration_minutes=1440
                                        )
                                        logger.info(f"[IPS] Source IP {src_ip} automatically added to Blocklist.")
                                    except Exception as block_e:
                                        logger.error(f"[IPS] Auto-block failed: {block_e}")
                        except Exception as e:
                            logger.debug(f"[WAF] Payload decode error: {e}")

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

            # Filter background noise: Only track flows to/from our monitored applications
            if src_port not in [5174, 8000, 8080] and dst_port not in [5174, 8000, 8080]:
                return None

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
