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
DOS_BYTE_RATE_THRESHOLD: float = float(os.getenv("CIPHER_HEURISTIC_DOS_BYTE_RATE", 5000000.0))

# Distributed Denial of Service (DDoS) Thresholds (Multiple sources targeting same destination)
DDOS_SOURCES_THRESHOLD: int = int(os.getenv("CIPHER_HEURISTIC_DDOS_SOURCES_THRESHOLD", 3))
DDOS_WINDOW_SECONDS: float = float(os.getenv("CIPHER_HEURISTIC_DDOS_WINDOW", 60.0))

# Memory & State Bounding
MAX_STATE_ENTRIES: int = int(os.getenv("CIPHER_HEURISTIC_MAX_STATE_ENTRIES", 10000))

# Well-known Service Ports
AUTH_PORTS: Set[int] = {21, 22, 23, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP
IRC_PORTS: Set[int] = {6667, 6668, 6669, 7000}  # Legacy IRC communication
WEB_PORTS: Set[int] = {80, 443, 8080, 8443}
