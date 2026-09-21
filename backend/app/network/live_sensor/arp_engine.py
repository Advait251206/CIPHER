import time
import logging
from typing import Dict, Optional, Any
from collections import defaultdict
from app.correlation.service import CorrelationService
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class ARPEngine:
    def __init__(self, correlation_service: CorrelationService):
        self.correlation_service = correlation_service
        self._ip_to_mac: Dict[str, str] = {}
        
        # MAC -> list of timestamps for requests
        self._request_history: Dict[str, list[float]] = defaultdict(list)
        
        # Configuration
        self.SCAN_TIME_WINDOW = 5.0 # seconds
        self.SCAN_THRESHOLD = 50    # requests per window
        self.CLEANUP_INTERVAL = 30.0 # seconds
        self._last_cleanup = time.time()

    def process_arp(self, pkt: Dict[str, Any]):
        """
        Process an ARP packet dictionary from the C++ sensor.
        pkt format: {"type":"arp", "opcode": 1, "src_mac": "...", "dst_mac": "...", "src_ip": "...", "dst_ip": "...", "ts": 123.45}
        """
        try:
            opcode = pkt.get("opcode")
            src_mac = pkt.get("src_mac")
            src_ip = pkt.get("src_ip")
            ts = pkt.get("ts", time.time())
            
            if not src_mac or not src_ip or src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
                return
                
            self._cleanup_if_needed(ts)

            if opcode == 1:  # ARP Request
                self._handle_arp_request(src_mac, src_ip, ts)
            elif opcode == 2:  # ARP Reply
                self._handle_arp_reply(src_mac, src_ip, ts)

        except Exception as e:
            logger.error(f"[ARP_ENGINE] Error processing ARP packet: {e}")

    def _handle_arp_request(self, src_mac: str, src_ip: str, ts: float):
        history = self._request_history[src_mac]
        history.append(ts)
        
        # Prune old requests
        while history and history[0] < ts - self.SCAN_TIME_WINDOW:
            history.pop(0)
            
        if len(history) > self.SCAN_THRESHOLD:
            # We have a scan
            self._trigger_reconnaissance_alert(src_mac, src_ip, len(history))
            # Clear history to avoid alert flooding
            history.clear()
            
    def _handle_arp_reply(self, src_mac: str, src_ip: str, ts: float):
        if src_ip in self._ip_to_mac:
            known_mac = self._ip_to_mac[src_ip]
            if known_mac != src_mac:
                # Spoofing detected!
                self._trigger_spoofing_alert(src_ip, known_mac, src_mac)
        
        # Update mapping
        self._ip_to_mac[src_ip] = src_mac

    def _cleanup_if_needed(self, current_ts: float):
        if current_ts - self._last_cleanup > self.CLEANUP_INTERVAL:
            self._last_cleanup = current_ts
            # Cleanup request history
            for mac in list(self._request_history.keys()):
                self._request_history[mac] = [
                    t for t in self._request_history[mac] 
                    if t >= current_ts - self.SCAN_TIME_WINDOW
                ]
                if not self._request_history[mac]:
                    del self._request_history[mac]

    def _trigger_reconnaissance_alert(self, src_mac: str, src_ip: str, count: int):
        logger.warning(f"[ARP_ENGINE] Reconnaissance Scan Detected from MAC: {src_mac} (IP: {src_ip})")
        
        synthetic_event = {
            "source_ip": src_ip,
            "destination_ip": "255.255.255.255", # Broadcast representation
            "destination_port": 0,
            "attack_type": "RECONNAISSANCE",
            "severity": "LOW",
            "protocol": "ARP",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ml_attack_prob": 1.0,
            "flow_features": {
                "ARP Requests": count,
                "Time Window (s)": self.SCAN_TIME_WINDOW,
                "Source MAC": src_mac
            },
            "heuristic_reasons": [
                f"Elevated ARP Request frequency: {count} requests within {self.SCAN_TIME_WINDOW} seconds.",
                f"Source MAC address {src_mac} is performing a network sweep."
            ]
        }
        
        # Send to Correlation Engine
        self.correlation_service.process_event(synthetic_event)

    def _trigger_spoofing_alert(self, src_ip: str, known_mac: str, spoofed_mac: str):
        logger.error(f"[ARP_ENGINE] ARP Spoofing Detected! IP {src_ip} claimed by new MAC {spoofed_mac} (was {known_mac})")
        
        synthetic_event = {
            "source_ip": src_ip,
            "destination_ip": "255.255.255.255",
            "destination_port": 0,
            "attack_type": "MITM",
            "severity": "CRITICAL",
            "protocol": "ARP",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ml_attack_prob": 1.0,
            "flow_features": {
                "Spoofed IP": src_ip,
                "Known MAC": known_mac,
                "Spoofed MAC": spoofed_mac
            },
            "heuristic_reasons": [
                f"ARP Spoofing signature detected.",
                f"IP Address {src_ip} was previously mapped to {known_mac}.",
                f"A new device with MAC {spoofed_mac} is now claiming ownership of {src_ip}.",
                "Probable Man-in-the-Middle (MITM) attack attempt."
            ]
        }
        
        self.correlation_service.process_event(synthetic_event)
