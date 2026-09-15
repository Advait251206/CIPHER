"""
CIPHER Correlation Models
Defines the unified normalized security event representation and incident data models.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator


class NormalizedEvent(BaseModel):
    """
    Unified, canonical security event representation for all CIPHER detection subsystems.
    Preserves all detection-specific context while enabling cross-subsystem correlation.
    """
    event_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    source: str = "network"  # "network", "phishing", "live_sensor", "api", etc.
    event_type: str = "network_detection"  # "network_detection", "phishing_detection", etc.
    attack_category: str = "BENIGN"  # "PORT_SCAN", "DOS", "DDOS", "BRUTE_FORCE", "BOTNET", "PHISHING", etc.
    severity: str = "LOW"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: int = Field(default=0, ge=0, le=100)

    # Network identifiers (optional for non-network events)
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None

    # Phishing / Web identifiers (optional for non-phishing events)
    domain: Optional[str] = None
    url: Optional[str] = None

    # Context and explanation
    description: Optional[str] = None
    detection_method: Optional[str] = "ML"
    model_probability: Optional[float] = None
    rule_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        if v is None:
            return 0.0
        return max(0.0, min(1.0, float(v)))

    @field_validator("risk_score")
    @classmethod
    def clamp_risk_score(cls, v: int) -> int:
        if v is None:
            return 0
        return max(0, min(100, int(v)))


class IncidentItem(BaseModel):
    """Incident record representing correlated security events."""
    incident_id: str
    created_at: str
    updated_at: str
    status: str = "OPEN"  # "OPEN", "RESOLVED"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_count: int = 1
    attack_categories: List[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    correlation_score: int = Field(default=0, ge=0, le=100)
    severity: str = "LOW"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    escalation_detected: bool = False
    summary: str
    recommended_action: Optional[str] = None
    applied_action: Optional[str] = None
    event_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentsListResponse(BaseModel):
    """Response schema for listing correlated incidents."""
    total_returned: int
    incidents: List[IncidentItem]


class IncidentDetailResponse(BaseModel):
    """Detailed response schema for an incident and its associated events."""
    incident: IncidentItem
    events: List[Dict[str, Any]] = Field(default_factory=list)


class CorrelationStatsResponse(BaseModel):
    """Aggregate statistics from the correlation engine."""
    total_incidents: int
    open_incidents: int
    resolved_incidents: int
    escalations_detected: int
    average_correlation_score: float
    incidents_by_severity: Dict[str, int] = Field(default_factory=dict)
    top_attacking_sources: List[Dict[str, Any]] = Field(default_factory=list)


class IncidentResolveResponse(BaseModel):
    """Response schema after resolving an incident."""
    incident_id: str
    status: str
    message: str
