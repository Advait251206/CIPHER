import re
import logging
from typing import Optional, Dict, Tuple

logger = logging.getLogger("cipher.waf")

class WAFEngine:
    """
    Lightweight Web Application Firewall (WAF) Engine for Deep Packet Inspection.
    Uses regex signatures to detect SQLi, XSS, and tracks basic Brute Force states.
    """
    def __init__(self):
        # Configuration toggles (can be updated via API)
        self.config = {
            "sql_protection": "detect",   # 'detect', 'enforce', or 'off'
            "xss_protection": "detect",
            "brute_force_protection": "detect"
        }
        
        # SQL Injection Signatures
        self.sqli_patterns = [
            re.compile(r"(?i)(UNION\s+ALL\s+SELECT|UNION\s+SELECT)", re.IGNORECASE),
            re.compile(r"(?i)(\b(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)", re.IGNORECASE),
            re.compile(r"(?i)(\bSELECT\b.*\bFROM\b)", re.IGNORECASE),
            re.compile(r"(?i)(--\s*$|#\s*$|/\*.*\*/)", re.IGNORECASE),
            re.compile(r"(?i)(\bDROP\s+TABLE\b|\bINSERT\s+INTO\b|\bUPDATE\b.*\bSET\b)", re.IGNORECASE)
        ]
        
        # XSS Signatures
        self.xss_patterns = [
            re.compile(r"(?i)(<script.*?>.*?</script>)", re.IGNORECASE | re.DOTALL),
            re.compile(r"(?i)(javascript:)", re.IGNORECASE),
            re.compile(r"(?i)(on\w+\s*=)", re.IGNORECASE),  # onerror=, onload=
            re.compile(r"(?i)(<img\s+src=.*?onerror=)", re.IGNORECASE)
        ]

    def update_config(self, feature: str, mode: str):
        if feature in self.config and mode in ["off", "detect", "enforce"]:
            self.config[feature] = mode
            logger.info(f"WAF Engine: {feature} updated to {mode}")

    def inspect_payload(self, payload_str: str) -> Tuple[Optional[str], str]:
        """
        Inspects raw HTTP payload (usually POST bodies or URL params)
        Returns: (Attack Type, Enforcement Mode) if malicious, else (None, "off")
        """
        # Check SQLi
        if self.config["sql_protection"] != "off":
            for pattern in self.sqli_patterns:
                if pattern.search(payload_str):
                    return "SQL_INJECTION", self.config["sql_protection"]
                    
        # Check XSS
        if self.config["xss_protection"] != "off":
            for pattern in self.xss_patterns:
                if pattern.search(payload_str):
                    return "XSS", self.config["xss_protection"]
                    
        return None, "off"

    def inject_tcp_rst(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, seq: int, ack: int):
        """
        Injects a forged TCP RST packet to kill a malicious connection.
        """
        try:
            from scapy.all import IP, TCP, send
            
            # Forge the RST packet from the perspective of the server (dst) to the client (src)
            # We use the client's SEQ as the server's ACK, and client's ACK as the server's SEQ
            rst_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="RA", seq=ack, ack=seq)
            
            # Send the forged packet
            send(rst_pkt, verbose=False)
            logger.info(f"[IPS] Successfully injected TCP RST to kill connection {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        except Exception as e:
            logger.error(f"[IPS] Failed to inject TCP RST: {e}")

waf_engine = WAFEngine()
