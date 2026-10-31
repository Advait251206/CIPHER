"""
Address helpers shared by the network detector, correlation layer and rules.

- is_broadcast_or_multicast(): multicast, limited broadcast, and the directed
  broadcast address of each local subnet (from Scapy's routing table when
  available). A plain ".255" suffix is NOT treated as broadcast: in a /16 or
  /23, x.y.z.255 is an ordinary host.
- is_trusted_source(): operator-configured allow-list (CIPHER_TRUSTED_SOURCES).
  There is deliberately no built-in list: source ports and private ranges are
  trivially spoofable or are exactly where a LAN attacker sits.
"""

import os
import ipaddress
import logging
from functools import lru_cache
from typing import FrozenSet, List, Optional

logger = logging.getLogger("cipher.network.net_utils")


@lru_cache(maxsize=1)
def _local_directed_broadcasts() -> FrozenSet[str]:
    addrs = set()
    try:
        from scapy.all import conf  # type: ignore
        for net, mask, _gw, _iface, _addr, _metric in conf.route.routes:
            try:
                if mask in (0, 0xFFFFFFFF):
                    continue
                network = ipaddress.ip_network((net, bin(mask).count("1")), strict=False)
                if network.prefixlen < 31:
                    addrs.add(str(network.broadcast_address))
            except (ValueError, TypeError):
                continue
    except Exception as e:  # scapy missing or no route table
        logger.debug(f"Could not read local routes for broadcast detection: {e}")
    extra = os.getenv("CIPHER_BROADCAST_ADDRESSES", "")
    addrs.update(a.strip() for a in extra.split(",") if a.strip())
    return frozenset(addrs)


def is_broadcast_or_multicast(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast:
        return True
    if addr.version == 4 and str(addr) == "255.255.255.255":
        return True
    return str(addr) in _local_directed_broadcasts()


def _trusted_networks() -> List[ipaddress._BaseNetwork]:
    nets = []
    for item in os.getenv("CIPHER_TRUSTED_SOURCES", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning(f"Ignoring invalid CIPHER_TRUSTED_SOURCES entry: {item!r}")
    return nets


def is_trusted_source(ip: Optional[str]) -> bool:
    """True only for addresses the operator explicitly listed in CIPHER_TRUSTED_SOURCES."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _trusted_networks())
