"""
CIPHER Network Heuristic & Rule Detection Engine
Evaluates deterministic network flow signatures, TCP flag combinations, port profiles,
and traffic rate anomalies independently of machine learning.
"""

import ipaddress
from typing import Dict, Any, List, Optional, Tuple


class NetworkDetector:
    """Deterministic rule-based network flow anomaly and attack detector."""

    # Well-known authentication service ports targeted by brute-force
    AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}

    # Common service ports
    WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"}
    IRC_BOT_PORTS = {6667, 6668, 6669, 7000}

    # Known legitimate high-volume CDN ASNs/IP blocks
    KNOWN_CDN_SUBNETS = [
        ipaddress.ip_network("104.16.0.0/12"),    # Cloudflare
        ipaddress.ip_network("1.1.1.0/24"),       # Cloudflare DNS
        ipaddress.ip_network("8.8.8.0/24"),       # Google DNS
        ipaddress.ip_network("8.8.4.0/24"),       # Google DNS
        ipaddress.ip_network("103.102.166.0/24"), # Wikimedia
        ipaddress.ip_network("198.35.26.0/23"),   # Wikimedia
        ipaddress.ip_network("14.192.87.0/24"),   # Wikimedia
    ]

    def _is_known_cdn(self, ip_str: Optional[str]) -> bool:
        if not ip_str: return False
        try:
            ip = ipaddress.ip_address(ip_str)
            for subnet in self.KNOWN_CDN_SUBNETS:
                if ip in subnet:
                    return True
        except ValueError:
            pass
        return False

    def evaluate(
        self,
        features: Dict[str, float],
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = "TCP"
    ) -> Tuple[int, Optional[str], List[str], List[Dict[str, Any]]]:
        """
        Evaluates a flow against deterministic heuristic rules.

        Returns:
            heuristic_score (int): 0 to 100
            detected_attack (Optional[str]): Attack category if triggered
            reasons (List[str]): Explanations for triggered rules
            triggered_rules (List[Dict[str, Any]]): Detailed rule metadata
        """
        score = 0
        reasons: List[str] = []
        rules: List[Dict[str, Any]] = []
        attack_candidates: List[Tuple[str, int]] = []

        dst_port = destination_port or int(features.get("Destination Port", 0))

        # ---------------------------------------------------------------------
        # Rule 1: Port Scan - SYN Sweep / Half-Open Connection Signature
        # ---------------------------------------------------------------------
        # Characteristics: SYN flag set, ACK flag 0, short duration, 0 backward packets
        syn_count = features.get("SYN Flag Count", 0)
        ack_count = features.get("ACK Flag Count", 0)
        duration = features.get("Flow Duration", 0)
        bwd_pkts = features.get("Total Backward Packets", 0)
        fwd_pkts = features.get("Total Fwd Packets", 0)

        if syn_count > 0 and ack_count == 0 and bwd_pkts == 0 and duration < 5000:
            score += 45
            reasons.append(
                f"Probable SYN port scan probe: SYN flag set with zero ACK and zero backward response (Duration={duration}µs)"
            )
            rules.append({"rule_id": "NET-PSCAN-01", "name": "Half-Open SYN Scan", "weight": 45})
            attack_candidates.append(("PORT_SCAN", 45))

        # Port Scan Signature 2: Zero backward packets on short flows with RST or FIN
        rst_count = features.get("RST Flag Count", 0)
        if bwd_pkts == 0 and (rst_count > 0 or syn_count > 0) and duration < 10000 and fwd_pkts <= 3:
            score += 35
            reasons.append("Unresponsive outbound probe flow characteristic of automated port reconnaissance")
            rules.append({"rule_id": "NET-PSCAN-02", "name": "Zero-Response Scan Probe", "weight": 35})
            attack_candidates.append(("PORT_SCAN", 35))

        # ---------------------------------------------------------------------
        # Rule 2: Denial of Service (DoS) - Volumetric & High-Rate Exhaustion
        # ---------------------------------------------------------------------
        flow_bytes_per_s = features.get("Flow Bytes/s", 0)
        flow_pkts_per_s = features.get("Flow Packets/s", 0)
        fwd_pkts_per_s = features.get("Fwd Packets/s", 0)
        flow_iat_mean = features.get("Flow IAT Mean", 1e6)
        pkt_len_var = features.get("Packet Length Variance", 100)

        is_cdn = self._is_known_cdn(source_ip) or self._is_known_cdn(destination_ip)
        is_web_port = dst_port in self.WEB_PORTS

        # Require at least 1000 packets to trust per-second rate calculations
        total_pkts = fwd_pkts + bwd_pkts
        
        # Volumetric threshold logic
        volumetric_byte_limit = 50_000_000  # 50 MB/s default
        
        # If it's a web port with high variance, or a known CDN, it's likely legitimate high-bandwidth traffic
        if is_cdn:
            volumetric_byte_limit = float('inf')  # Bypass volumetric DOS for known CDNs
        elif is_web_port and pkt_len_var > 15.0:
            volumetric_byte_limit = 250_000_000   # 250 MB/s (2 Gbps) for variable web traffic

        if (flow_pkts_per_s > 50000 or fwd_pkts_per_s > 50000) and total_pkts >= 1000 and not is_cdn:
            score += 65
            reasons.append(
                f"Abnormal forward packet rate ({fwd_pkts_per_s:,.0f} pkts/s) exceeding normal client behavior"
            )
            rules.append({"rule_id": "NET-DOS-01", "name": "Extreme Packet Flood Rate", "weight": 65})
            attack_candidates.append(("DOS", 65))
        elif flow_bytes_per_s > volumetric_byte_limit and total_pkts > 100:
            score += 50
            reasons.append(
                f"Excessive volumetric flow rate ({flow_bytes_per_s/1e6:.2f} MB/s) indicating bandwidth saturation attempt"
            )
            rules.append({"rule_id": "NET-DOS-02", "name": "Volumetric Bandwidth Flood", "weight": 50})
            attack_candidates.append(("DOS", 50))

        # Low Inter-Arrival Time + Asymmetric ratio
        down_up_ratio = features.get("Down/Up Ratio", 0)
        if flow_iat_mean < 50.0 and fwd_pkts > 50 and down_up_ratio == 0:
            score += 55
            reasons.append(
                f"Asymmetric rapid request burst without server reply (Mean IAT={flow_iat_mean:.1f}µs, Fwd={fwd_pkts}, Down/Up=0)"
            )
            rules.append({"rule_id": "NET-DOS-03", "name": "Asymmetric Flood Burst", "weight": 55})
            attack_candidates.append(("DOS", 55))

        # ---------------------------------------------------------------------
        # Rule 3: Distributed Denial of Service (DDoS) - Uniform Mass Flood
        # ---------------------------------------------------------------------
        # Prevent false positives on short ACK bursts (like rapid downloads) by requiring at least 1000 packets and 0.5s duration
        if (flow_pkts_per_s > 25000 or fwd_pkts_per_s > 25000) and pkt_len_var < 5.0 and fwd_pkts > 1000 and duration > 500000:
            score += 70
            reasons.append(
                f"High-frequency uniform packet stream with near-zero length variance ({pkt_len_var:.2f}), classic botnet/DDoS flooder pattern"
            )
            rules.append({"rule_id": "NET-DDOS-01", "name": "Uniform Flood DDoS", "weight": 70})
            attack_candidates.append(("DDOS", 70))

        # ---------------------------------------------------------------------
        # Rule 4: Brute Force - Authentication Target Pattern
        # ---------------------------------------------------------------------
        if dst_port in self.AUTH_PORTS:
            service_name = self.AUTH_PORTS[dst_port]
            # Rapid short connections to authentication service
            init_win_fwd = features.get("Init_Win_bytes_forward", 0)
            if duration < 500000 and fwd_pkts < 10 and (rst_count > 0 or bwd_pkts <= 2):
                score += 50
                reasons.append(
                    f"Abnormally truncated session targeting {service_name} auth port {dst_port}, indicative of automated credential retry"
                )
                rules.append({"rule_id": "NET-BRUTE-01", "name": f"{service_name} Auth Churn", "weight": 50})
                attack_candidates.append(("BRUTE_FORCE", 50))

        # ---------------------------------------------------------------------
        # Rule 5: Botnet - Periodic Beaconing & Suspicious Ports
        # ---------------------------------------------------------------------
        flow_iat_std = features.get("Flow IAT Std", 1e6)
        if fwd_pkts > 5 and flow_iat_std < 5.0 and flow_iat_mean > 1000.0:
            score += 40
            reasons.append(
                f"High-precision periodic communication rhythm (IAT Std={flow_iat_std:.2f}µs), characteristic of automated C2 beaconing"
            )
            rules.append({"rule_id": "NET-BOT-01", "name": "Periodic C2 Beaconing", "weight": 40})
            attack_candidates.append(("BOTNET", 40))

        if dst_port in self.IRC_BOT_PORTS:
            score += 35
            reasons.append(f"Outbound flow targeting legacy IRC channel port {dst_port}, historically leveraged by botnet C2 servers")
            rules.append({"rule_id": "NET-BOT-02", "name": "IRC C2 Port Target", "weight": 35})
            attack_candidates.append(("BOTNET", 35))

        # ---------------------------------------------------------------------
        # Rule 6: Web Attack Heuristic Note
        # ---------------------------------------------------------------------
        if dst_port in self.WEB_PORTS and (flow_pkts_per_s > 1000 or fwd_pkts > 100):
            # Note: Network flow alone does NOT inspect payload content; detailed SQLi/XSS belongs to WAF
            reasons.append(f"Elevated transaction intensity directed at Web service port {dst_port}")
            rules.append({"rule_id": "NET-WEB-01", "name": "Web Service Traffic Anomaly", "weight": 20})

        # Cap score at 100
        final_score = min(100, score)

        # Determine dominant heuristic attack category
        detected_attack = None
        if attack_candidates:
            # Pick category with highest heuristic weight
            attack_candidates.sort(key=lambda x: x[1], reverse=True)
            detected_attack = attack_candidates[0][0]

        if not reasons:
            reasons.append("Flow metrics conform to standard TCP/IP transport profiles with no anomalous heuristics")

        return final_score, detected_attack, reasons, rules
