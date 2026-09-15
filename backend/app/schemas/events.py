"""
CIPHER Event and System Schemas
Pydantic schemas for event querying, statistics, and system health status.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SecurityEventItem(BaseModel):
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
    source: str
    event_type: Optional[str] = "PHISHING"
    attack_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    detection_method: Optional[str] = "ML"
    action: Optional[str] = "ALERT"
    status: Optional[str] = "NEW"
    metadata: Optional[Dict[str, Any]] = None


class EventsListResponse(BaseModel):
    total_returned: int
    events: List[SecurityEventItem]


class SystemStatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    suspicious_detected: int
    legitimate_verified: int
    average_risk_score: float


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    local_only: bool = True
    model_loaded: bool = True
    database_connected: bool = True
    timestamp: str


class SystemStatusResponse(BaseModel):
    system_name: str = "CIPHER"
    environment: str = "local"
    local_only: bool = True
    model_version: str
    model_loaded: bool
    feature_count: int
    feature_names: List[str]
    database_path: str
    uptime_seconds: float
