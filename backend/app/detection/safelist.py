"""Trusted traffic sources whose volumetric findings are suppressed.

Defaults match the values that were inlined in the services: GitHub, Azure and
the private ranges, plus the well-known reply ports. Override with
CIPHER_TRUSTED_SUBNETS / CIPHER_TRUSTED_REPLY_PORTS (comma-separated).

Note: the private ranges mean a scan or flood from inside the LAN is treated as
trusted. Set CIPHER_TRUSTED_SUBNETS to just the provider ranges
(140.82.0.0/16,20.0.0.0/8) to detect internal attacks.
"""

import ipaddress
import logging
import os
from typing import List, Optional

logger = logging.getLogger("cipher.safelist")

DEFAULT_SUBNETS = "140.82.0.0/16,20.0.0.0/8,192.168.0.0/16,10.0.0.0/8"
DEFAULT_REPLY_PORTS = "80,443,8080,8443,53"


def _subnets() -> List[ipaddress._BaseNetwork]:
    out = []
    for raw in os.getenv("CIPHER_TRUSTED_SUBNETS", DEFAULT_SUBNETS).split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(ipaddress.ip_network(raw))
        except ValueError:
            logger.warning("Ignoring invalid trusted subnet %r", raw)
    return out


def _reply_ports() -> List[int]:
    out = []
    for raw in os.getenv("CIPHER_TRUSTED_REPLY_PORTS", DEFAULT_REPLY_PORTS).split(","):
        raw = raw.strip()
        if raw.isdigit():
            out.append(int(raw))
    return out


def is_trusted_source(source_ip: Optional[str], source_port: Optional[int] = None) -> bool:
    """True when volumetric findings for this source should be suppressed."""
    if source_port is not None and source_port in _reply_ports():
        return True
    if not source_ip:
        return False
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(ip in net for net in _subnets())
