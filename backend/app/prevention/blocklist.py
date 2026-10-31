"""
CIPHER Persistent IP Blocklist Abstraction
Manages stateful containment lists with TTL expirations and manual operator overrides.

Host firewall rules (Windows `netsh advfirewall`) are created ONLY when the caller
passes apply_os_rule=True, which the PreventionEngine does exclusively in `enforce`
mode. Every address is validated, and protected addresses (loopback, link-local,
multicast, this host, and anything in CIPHER_PROTECTED_IPS) are never blocked.
"""

import os
import socket
import logging
import platform
import ipaddress
import subprocess
from functools import lru_cache
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, timezone

from app.database.database import Database

logger = logging.getLogger("cipher.blocklist")

FIREWALL_RULE_PREFIX = "CIPHER_BLOCK_"


class ProtectedAddressError(ValueError):
    """Raised when a block targets an address CIPHER must never contain."""


@lru_cache(maxsize=1)
def _host_addresses() -> frozenset:
    """Best-effort set of this host's own IP addresses (no packets are sent)."""
    addrs = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addrs.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # TEST-NET address; UDP connect sends nothing
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return frozenset(addrs)


def _protected_networks() -> List[ipaddress._BaseNetwork]:
    nets = []
    for item in os.getenv("CIPHER_PROTECTED_IPS", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning(f"Ignoring invalid CIPHER_PROTECTED_IPS entry: {item!r}")
    return nets


def validate_block_target(ip: str) -> str:
    """Returns the normalized address or raises ValueError / ProtectedAddressError."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError(f"'{ip}' is not a valid IP address.")

    if addr.is_unspecified or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        raise ProtectedAddressError(f"{addr} is a loopback/link-local/multicast/unspecified address and cannot be blocked.")
    if addr.version == 4 and str(addr) == "255.255.255.255":
        raise ProtectedAddressError("The broadcast address cannot be blocked.")
    if str(addr) in _host_addresses():
        raise ProtectedAddressError(f"{addr} belongs to this host and cannot be blocked.")
    for net in _protected_networks():
        if addr.version == net.version and addr in net:
            raise ProtectedAddressError(f"{addr} is inside protected range {net} (CIPHER_PROTECTED_IPS).")
    return str(addr)


def _firewall_supported() -> bool:
    return platform.system() == "Windows"


class IPBlocklistManager:
    """Manages persistent IP containment entries."""

    def __init__(
        self,
        db: Optional[Database] = None,
        auto_block_threshold: int = 80,
        default_temp_block_minutes: Optional[int] = None
    ):
        self.db = db or Database()
        self.auto_block_threshold = auto_block_threshold
        self.default_temp_block_minutes = default_temp_block_minutes or int(
            os.getenv("DEFAULT_TEMP_BLOCK_MINUTES", "60")
        )

    def is_blocked(self, ip: Optional[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Checks whether an IP is currently blocked and active."""
        if not ip:
            return False, None
        self.cleanup_expired()  # expire stale entries (and their firewall rules) first
        return self.db.is_ip_blocked(ip)

    def block_ip(
        self,
        ip: str,
        reason: str,
        attack_type: str,
        threat_score: int,
        duration_minutes: Optional[int] = None,
        source_event_id: Optional[str] = None,
        is_permanent: bool = False,
        apply_os_rule: bool = False
    ) -> Dict[str, Any]:
        """
        Records (or refreshes) a block with TTL expiration.
        Creates a host firewall rule only when apply_os_rule=True (enforce mode).
        Raises ValueError for invalid or protected addresses.
        """
        ip = validate_block_target(ip)
        now = datetime.now(timezone.utc)
        expires_at = None

        if not is_permanent:
            dur = duration_minutes or self.default_temp_block_minutes
            expires_at = (now + timedelta(minutes=dur)).strftime("%Y-%m-%dT%H:%M:%SZ")

        self.db.save_blocked_ip(
            ip=ip,
            reason=reason,
            attack_type=attack_type,
            threat_score=threat_score,
            expires_at=expires_at,
            source_event_id=source_event_id
        )

        os_rule_applied = False
        if apply_os_rule:
            os_rule_applied = self._add_firewall_rule(ip)

        return {
            "ip": ip,
            "status": "ACTIVE",
            "reason": reason,
            "attack_type": attack_type,
            "threat_score": threat_score,
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires_at,
            "is_permanent": is_permanent,
            "os_rule_applied": os_rule_applied
        }

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblocks a previously contained IP and removes any firewall rule."""
        success = self.db.remove_blocked_ip(ip)
        self._remove_firewall_rule(ip)
        return success

    def list_blocked(self, status: str = "ACTIVE") -> List[Dict[str, Any]]:
        """Lists blocked IPs (expiring stale entries first)."""
        self.cleanup_expired()
        return self.db.list_blocked_ips(status=status)

    def cleanup_expired(self) -> int:
        """Expires stale blocks and removes their firewall rules, so TTLs hold at OS level too."""
        expired_ips = self.db.expire_blocks()
        for ip in expired_ips:
            self._remove_firewall_rule(ip)
        return len(expired_ips)

    # ------------------------------------------------------------------
    # Host firewall (Windows only)
    # ------------------------------------------------------------------

    def _add_firewall_rule(self, ip: str) -> bool:
        if not _firewall_supported():
            logger.info(f"[FIREWALL] Host firewall integration is Windows-only; {ip} recorded in blocklist only.")
            return False
        try:
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={FIREWALL_RULE_PREFIX}{ip}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok = result.returncode == 0
            if ok:
                logger.info(f"[FIREWALL] Added inbound block rule for {ip}")
            else:
                logger.error(f"[FIREWALL] netsh failed to add rule for {ip} (exit {result.returncode}); is the backend elevated?")
            return ok
        except Exception as e:
            logger.error(f"[FIREWALL] Failed to add OS rule for {ip}: {e}")
            return False

    def _remove_firewall_rule(self, ip: str) -> None:
        if not _firewall_supported():
            return
        try:
            ip = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return  # never pass unvalidated text to netsh
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={FIREWALL_RULE_PREFIX}{ip}"
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.error(f"[FIREWALL] Failed to remove OS rule for {ip}: {e}")
