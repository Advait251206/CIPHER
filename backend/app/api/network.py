"""
CIPHER Network IDPS API Router
Provides REST endpoints for network flow analysis, event tracking,
statistics, rule inspectability, and IPS blocklist management.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, status

from app.network.schemas import (
    NetworkFlowAnalyzeRequest,
    NetworkDetectionResponse,
    NetworkHealthResponse,
    NetworkRulesResponse,
    NetworkRuleItem,
    NetworkModelInfoResponse,
    BlocklistEntry,
    NetworkInterfaceItem,
    NetworkInterfacesResponse,
    SensorStartRequest,
    SensorStatusResponse,
    PreventionModeUpdateRequest
)
from app.network.service import NetworkService
from app.network.model_loader import NetworkModelLoader
from app.schemas.events import EventsListResponse, SecurityEventItem
from app.network.live_sensor import get_sensor_service
from app.prevention.actions import PreventionMode

router = APIRouter(prefix="/network", tags=["Network Intrusion Detection & Prevention"])
network_service = NetworkService()


@router.post("/prevention-mode", summary="Set Prevention Mode")
def set_prevention_mode(req: PreventionModeUpdateRequest):
    """Dynamically switch between Detect Only and Enforce modes."""
    valid_modes = [m.value for m in PreventionMode]
    if req.mode not in valid_modes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid mode. Must be one of {valid_modes}"
        )
    network_service.prevention_engine.mode = req.mode
    return {"status": "success", "mode": req.mode}


@router.get("/health", response_model=NetworkHealthResponse, summary="Network IDS Health Check")

def network_health():
    """Returns runtime health, model load status, and active prevention mode."""
    loader = network_service.loader
    return NetworkHealthResponse(
        status="ok" if loader.is_ready else "degraded",
        subsystem="CIPHER-Network-IDPS",
        model_loaded=loader.is_ready,
        model_version=loader.model_version if loader.is_ready else "not_loaded",
        feature_count=loader.feature_count,
        prevention_mode=network_service.prevention_engine.mode,
        database_connected=True,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@router.post("/analyze", response_model=NetworkDetectionResponse, summary="Analyze Network Flow")
def analyze_network_flow(request: NetworkFlowAnalyzeRequest):
    """
    Submits a normalized network flow for real-time ML classification, heuristic rule evaluation,
    threat scoring, and automated IPS response determination.
    """
    try:
        return network_service.analyze_flow(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network flow analysis error: {str(e)}"
        )


@router.get("/events", response_model=EventsListResponse, summary="List Network Security Events")
def list_network_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack category"),
    severity: Optional[str] = Query(default=None, description="Filter by severity band"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP")
):
    """Lists locally recorded network security events with optional filtering."""
    raw_events = network_service.db.list_events(
        limit=limit,
        offset=offset,
        event_type="NETWORK",
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip
    )
    items = [SecurityEventItem(**ev) for ev in raw_events]
    return EventsListResponse(total_returned=len(items), events=items)


@router.get("/events/{event_id}", response_model=SecurityEventItem, summary="Get Network Event by ID")
def get_network_event(event_id: str):
    """Retrieves a single network security event by its UUID."""
    event = network_service.db.get_event(event_id)
    if not event or event.get("event_type") != "NETWORK":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network security event '{event_id}' not found."
        )
    return SecurityEventItem(**event)


@router.get("/stats", summary="Get Network Flow Statistics")
def get_network_stats():
    """Returns aggregated metrics on analyzed flows, detected attacks, top sources, and ports."""
    return network_service.db.get_network_stats()


@router.get("/model", response_model=NetworkModelInfoResponse, summary="Get Model Metadata and Performance")
def get_model_info():
    """Returns trained Network IDS model metadata, held-out test metrics, and feature importance."""
    loader = network_service.loader
    meta = loader.metadata
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metadata is not available."
        )

    return NetworkModelInfoResponse(
        model_name=meta.get("model_name", "CIPHER Network IDS"),
        model_architecture=meta.get("model_architecture", "Dual Random Forest"),
        dataset=meta.get("dataset", "CIC-IDS2017"),
        feature_count=meta.get("feature_count", 67),
        classes=meta.get("classes", []),
        training_samples=meta.get("training_samples", 0),
        validation_samples=meta.get("validation_samples", 0),
        test_samples=meta.get("test_samples", 0),
        binary_metrics=meta.get("binary_metrics", {}),
        multiclass_metrics=meta.get("multiclass_metrics", {}),
        top_features=meta.get("top_15_feature_importances", {})
    )


@router.get("/rules", response_model=NetworkRulesResponse, summary="List Active Heuristic Rules")
def list_network_rules():
    """Lists deterministic heuristic rules currently active in the Network Detector."""
    rules = [
        NetworkRuleItem(
            rule_id="NET-PSCAN-01",
            name="Half-Open SYN Scan",
            target_category="PORT_SCAN",
            description="Detects SYN flag without ACK or backward response on short flow durations.",
            weight=45
        ),
        NetworkRuleItem(
            rule_id="NET-PSCAN-02",
            name="Zero-Response Scan Probe",
            target_category="PORT_SCAN",
            description="Identifies outbound probe packets receiving zero backward response.",
            weight=35
        ),
        NetworkRuleItem(
            rule_id="NET-DOS-01",
            name="Extreme Packet Flood Rate",
            target_category="DOS",
            description="Triggers when forward packet rate exceeds 50,000 pkts/s.",
            weight=65
        ),
        NetworkRuleItem(
            rule_id="NET-DOS-02",
            name="Volumetric Bandwidth Flood",
            target_category="DOS",
            description="Flags flows exceeding 5 MB/s transfer rate.",
            weight=50
        ),
        NetworkRuleItem(
            rule_id="NET-DOS-03",
            name="Asymmetric Flood Burst",
            target_category="DOS",
            description="Detects rapid asymmetric bursts (low IAT, Down/Up=0).",
            weight=55
        ),
        NetworkRuleItem(
            rule_id="NET-DDOS-01",
            name="Uniform Flood DDoS",
            target_category="DDOS",
            description="Flags high-frequency packet streams with near-zero length variance.",
            weight=70
        ),
        NetworkRuleItem(
            rule_id="NET-BRUTE-01",
            name="Auth Service Churn",
            target_category="BRUTE_FORCE",
            description="Detects rapid short-lived connection retries on ports 21, 22, 23, 445, 3389.",
            weight=50
        ),
        NetworkRuleItem(
            rule_id="NET-BOT-01",
            name="Periodic C2 Beaconing",
            target_category="BOTNET",
            description="Identifies highly periodic packet transmission intervals (IAT Std < 5µs).",
            weight=40
        ),
        NetworkRuleItem(
            rule_id="NET-BOT-02",
            name="IRC C2 Port Target",
            target_category="BOTNET",
            description="Monitors outbound connections to legacy IRC command channels (ports 6667-7000).",
            weight=35
        ),
        NetworkRuleItem(
            rule_id="NET-WEB-01",
            name="Web Service Traffic Anomaly",
            target_category="WEB_ATTACK",
            description="Flags high-rate web traffic bursts (requires WAF for payload inspection).",
            weight=20
        )
    ]
    return NetworkRulesResponse(total_rules=len(rules), rules=rules)


@router.get("/blocklist", response_model=List[BlocklistEntry], summary="List Blocked IPs")
def get_blocklist(status: str = Query(default="ACTIVE")):
    """Returns currently active or expired entries in the IPS blocklist."""
    entries = network_service.prevention_engine.blocklist.list_blocked(status=status)
    return [BlocklistEntry(**e) for e in entries]


@router.delete("/blocklist/{ip}", summary="Unblock an IP")
def unblock_ip(ip: str):
    """Manually removes an IP from the active blocklist."""
    success = network_service.prevention_engine.blocklist.unblock_ip(ip)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP '{ip}' is not actively blocked."
        )
    return {"status": "unblocked", "ip": ip}


@router.get("/interfaces", response_model=NetworkInterfacesResponse, summary="List Available Network Interfaces")
def list_network_interfaces():
    """Returns local network interfaces available for packet capture."""
    sensor = get_sensor_service()
    ifaces = sensor.list_interfaces()
    return NetworkInterfacesResponse(interfaces=[NetworkInterfaceItem(**i) for i in ifaces])


@router.get("/sensor/status", response_model=SensorStatusResponse, summary="Get Live Sensor Status")
def get_sensor_status():
    """Returns telemetry and runtime status of the live packet capture sensor."""
    sensor = get_sensor_service()
    return SensorStatusResponse(**sensor.get_status())


@router.post("/sensor/start", response_model=SensorStatusResponse, summary="Start Live Sensor")
def start_sensor(req: SensorStartRequest):
    """
    Starts packet capture and flow aggregation on the specified interface.
    Live sensor defaults to detect_only and does not modify the host firewall unless an explicit enforcement mode is configured.
    """
    sensor = get_sensor_service()
    try:
        status_data = sensor.start(
            interface=req.interface,
            bpf_filter=req.bpf_filter,
            flow_idle_timeout=req.flow_idle_timeout,
            flow_active_timeout=req.flow_active_timeout
        )
        return SensorStatusResponse(**status_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start network sensor: {str(e)}"
        )


@router.post("/sensor/stop", response_model=SensorStatusResponse, summary="Stop Live Sensor")
def stop_sensor():
    """Gracefully stops live packet capture and finalizes remaining active flows."""
    sensor = get_sensor_service()
    try:
        status_data = sensor.stop()
        return SensorStatusResponse(**status_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop network sensor: {str(e)}"
        )
