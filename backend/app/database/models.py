"""
CIPHER Database Entities
Dataclass representations for local database records across all detection subsystems
(Phishing, Network IDPS, Heuristics, IPS Blocklist).
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class SecurityEventRecord:
    event_id: str
    timestamp: str
    classification: str
    risk_score: int
    confidence: float
    severity: str
    ml_score: float
    heuristic_score: int
    domain: str
    reasons: List[str]
    recommendation: str
    model_version: str
    source: str = "api"
    # Unified Network & System Security Extensions
    event_type: str = "PHISHING"
    attack_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    detection_method: Optional[str] = "ML"
    action: Optional[str] = "ALERT"
    status: Optional[str] = "NEW"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BlocklistRecord:
    id: Optional[int]
    ip: str
    reason: str
    attack_type: str
    threat_score: int
    created_at: str
    expires_at: Optional[str]
    source_event_id: Optional[str]
    status: str = "ACTIVE"
