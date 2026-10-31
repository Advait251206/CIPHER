"""
CIPHER Heuristic and Signature Configuration
Provides central, environment-configurable thresholds for deterministic rules.
"""

import os
from typing import Set

# Port Scan Heuristic Thresholds
PORT_SCAN_THRESHOLD: int = int(os.getenv("CIPHER_HEURISTIC_PORT_SCAN_THRESHOLD", 10))
PORT_SCAN_WINDOW_SECONDS: float = float(os.getenv("CIPHER_HEURISTIC_PORT_SCAN_WINDOW", 60.0))

# Brute Force Heuristic Thresholds
BRUTE_FORCE_THRESHOLD: int = int(os.getenv("CIPHER_HEURISTIC_BRUTE_FORCE_THRESHOLD", 5))
BRUTE_FORCE_WINDOW_SECONDS: float = float(os.getenv("CIPHER_HEURISTIC_BRUTE_FORCE_WINDOW", 60.0))

# Denial of Service (DoS) Volumetric Thresholds
DOS_PACKET_RATE_THRESHOLD: float = float(os.getenv("CIPHER_HEURISTIC_DOS_PACKET_RATE", 50000.0))
DOS_BYTE_RATE_THRESHOLD: float = float(os.getenv("CIPHER_HEURISTIC_DOS_BYTE_RATE", 5000000.0))  # 5 MB/s

# Distributed Denial of Service (DDoS) Thresholds (Multiple sources targeting same destination)
DDOS_SOURCES_THRESHOLD: int = int(os.getenv("CIPHER_HEURISTIC_DDOS_SOURCES_THRESHOLD", 3))
DDOS_WINDOW_SECONDS: float = float(os.getenv("CIPHER_HEURISTIC_DDOS_WINDOW", 60.0))
# Distinct sources alone are normal for any server; DDoS also needs aggregate volume (packets/s summed over sources).
DDOS_AGGREGATE_PACKET_RATE: float = float(os.getenv("CIPHER_HEURISTIC_DDOS_AGGREGATE_PPS", 10000.0))

# Memory & State Bounding
MAX_STATE_ENTRIES: int = int(os.getenv("CIPHER_HEURISTIC_MAX_STATE_ENTRIES", 10000))

# Well-known Service Ports
AUTH_PORTS: Set[int] = {21, 22, 23, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP
# Web login endpoints (e.g. the demo app on 5174) get a higher threshold: a browser opens several
# connections per page load, so 5 connections/minute is normal browsing, not brute force.
WEB_LOGIN_PORTS: Set[int] = {int(p) for p in os.getenv("CIPHER_WEB_LOGIN_PORTS", "5174").split(",") if p.strip().isdigit()}
WEB_LOGIN_BRUTE_FORCE_THRESHOLD: int = int(os.getenv("CIPHER_HEURISTIC_WEB_LOGIN_THRESHOLD", 30))
IRC_PORTS: Set[int] = {6667, 6668, 6669, 7000}  # Legacy IRC communication
WEB_PORTS: Set[int] = {80, 443, 8080, 8443}
