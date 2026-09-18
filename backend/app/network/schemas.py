"""
CIPHER Network IDPS Pydantic Schemas
Defines request and response structures for Network flow analysis, statistics,
health checks, and IPS blocklist management.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class NetworkFlowAnalyzeRequest(BaseModel):
    source_ip: Optional[str] = Field(default="192.168.1.100", description="Source IPv4 address")
    destination_ip: Optional[str] = Field(default="192.168.1.1", description="Destination IPv4 address")
    source_port: Optional[int] = Field(default=49152, ge=0, le=65535, description="Source transport port")
    destination_port: Optional[int] = Field(default=80, ge=0, le=65535, description="Destination transport port")
    protocol: Optional[str] = Field(default="TCP", description="Transport protocol (TCP/UDP)")
    features: Dict[str, float] = Field(..., description="Network flow features matching CIC-IDS2017 schema")
    timestamp: Optional[str] = Field(default=None, description="Optional ISO timestamp")


class PreventionModeUpdateRequest(BaseModel):
    mode: str = Field(..., description="The prevention mode to set: 'detect_only' or 'enforce'")


class NetworkDetectionResponse(BaseModel):
    event_id: str
    timestamp: str
    event_type: str = "NETWORK"
    attack_type: str
    classification: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    ml_prediction: str
    ml_confidence: float
    ml_attack_prob: float
    threat_score: int
    severity: str
    detection_method: str
    explanation: str
    reasons: List[str]
    recommended_action: str
    applied_action: str
    prevention_mode: str
    model_version: str


class NetworkHealthResponse(BaseModel):
    status: str = "ok"
    subsystem: str = "CIPHER-Network-IDPS"
    model_loaded: bool
    model_version: str
    feature_count: int
    prevention_mode: str
    database_connected: bool
    timestamp: str


class NetworkRuleItem(BaseModel):
    rule_id: str
    name: str
    target_category: str
    description: str
    weight: int


class NetworkRulesResponse(BaseModel):
    total_rules: int
    rules: List[NetworkRuleItem]


class NetworkModelInfoResponse(BaseModel):
    model_name: str
    model_architecture: str
    dataset: str
    feature_count: int
    classes: List[str]
    training_samples: int
    validation_samples: int
    test_samples: int
    binary_metrics: Dict[str, Any]
    multiclass_metrics: Dict[str, Any]
    top_features: Dict[str, float]


class BlocklistEntry(BaseModel):
    id: Optional[int] = None
    ip: str
    reason: str
    attack_type: str
    threat_score: int
    created_at: str
    expires_at: Optional[str]
    source_event_id: Optional[str]
    status: str = "ACTIVE"


class NetworkInterfaceItem(BaseModel):
    name: str = Field(..., description="Adapter name")
    description: str = Field(default="", description="Adapter hardware description")
    address: str = Field(default="", description="Primary IP address")
    guid: Optional[str] = Field(default=None, description="Windows NPF device GUID")
    status: str = Field(default="available", description="Interface status")


class NetworkInterfacesResponse(BaseModel):
    interfaces: List[NetworkInterfaceItem]


class SensorStartRequest(BaseModel):
    interface: str = Field(..., description="Network interface name, GUID, or description")
    bpf_filter: Optional[str] = Field(default=None, description="Optional Berkeley Packet Filter (BPF) syntax")
    flow_idle_timeout: Optional[float] = Field(default=5.0, ge=0.5, le=300.0, description="Seconds of inactivity before flow finalizes")
    flow_active_timeout: Optional[float] = Field(default=60.0, ge=1.0, le=3600.0, description="Maximum lifetime of flow before expiration")


class SensorStatusResponse(BaseModel):
    running: bool
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    packets_captured: int = 0
    active_flows: int = 0
    completed_flows: int = 0
    analyzed_flows: int = 0
    detected_attacks: int = 0
    started_at: Optional[str] = None
    errors: int = 0
    npcap_available: bool = True
    scapy_available: bool = True
