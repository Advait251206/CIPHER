"""
CIPHER Persistent IP Blocklist Abstraction
Manages stateful containment lists with configurable confidence thresholds,
TTL expirations, and manual operator overrides.
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from app.database.database import Database


class IPBlocklistManager:
    """Manages persistent IP containment entries."""

    def __init__(
        self,
        db: Optional[Database] = None,
        auto_block_threshold: int = 80,
        default_temp_block_minutes: int = 60
    ):
        self.db = db or Database()
        self.auto_block_threshold = auto_block_threshold
        self.default_temp_block_minutes = default_temp_block_minutes

    def is_blocked(self, ip: Optional[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Checks whether an IP is currently blocked and active."""
        if not ip:
            return False, None
        return self.db.is_ip_blocked(ip)

    def block_ip(
        self,
        ip: str,
        reason: str,
        attack_type: str,
        threat_score: int,
        duration_minutes: Optional[int] = None,
        source_event_id: Optional[str] = None,
        is_permanent: bool = False
    ) -> Dict[str, Any]:
        """
        Adds or updates a blocked IP entry with TTL expiration.
        """
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

        return {
            "ip": ip,
            "status": "ACTIVE",
            "reason": reason,
            "attack_type": attack_type,
            "threat_score": threat_score,
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires_at,
            "is_permanent": is_permanent
        }

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblocks a previously contained IP."""
        return self.db.remove_blocked_ip(ip)

    def list_blocked(self, status: str = "ACTIVE") -> List[Dict[str, Any]]:
        """Lists currently blocked IPs."""
        self.db.cleanup_expired_blocks()
        return self.db.list_blocked_ips(status=status)

    def cleanup_expired(self) -> int:
        """Prunes expired blocks."""
        return self.db.cleanup_expired_blocks()
