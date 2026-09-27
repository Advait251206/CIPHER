"""
CIPHER Unified Events and Stats API Router
Enables querying local privacy-safe security incident logs and summary statistics
across all detection subsystems (Phishing, Network IDS, Heuristics, IPS).
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.schemas.events import EventsListResponse, SecurityEventItem, SystemStatsResponse
from app.services.event_service import EventService

router = APIRouter(tags=["Security Events & Stats"])
event_service = EventService()


@router.get("/events", response_model=EventsListResponse, summary="List Recent Security Events")
def list_events(
    limit: int = Query(default=50, ge=1, le=500, description="Max number of events to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type (PHISHING, NETWORK)"),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack type (DOS, PORT_SCAN, etc.)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP or domain"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (NEW, BLOCKED, etc.)"),
    start_time: Optional[str] = Query(default=None, description="Start ISO timestamp filter"),
    end_time: Optional[str] = Query(default=None, description="End ISO timestamp filter")
):
    """
    Retrieves recent locally stored security scanning events across phishing and network streams
    with multi-dimensional filtering.
    """
    raw_events = event_service.list_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        status=status_filter,
        start_time=start_time,
        end_time=end_time
    )
    items = [SecurityEventItem(**ev) for ev in raw_events]
    return EventsListResponse(total_returned=len(items), events=items)


@router.get("/events/{event_id}", response_model=SecurityEventItem, summary="Get Event Details by ID")
def get_event(event_id: str):
    """Retrieves a specific security scan record by its unique UUID."""
    event = event_service.get_event(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' was not found in local database."
        )
    return SecurityEventItem(**event)


@router.get("/stats", response_model=SystemStatsResponse, summary="Get Security Scan Statistics")
def get_stats():
    """Aggregates local threat statistics: total scans, phishing count, suspicious count, average risk."""
    stats_data = event_service.get_stats()
    return SystemStatsResponse(**stats_data)


@router.delete("/events/{event_id}", summary="Delete Security Event by ID")
def delete_event(event_id: str):
    """Deletes a specific security scan record by its unique UUID."""
    success = event_service.delete_event(event_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' was not found in local database."
        )
    return {"status": "success", "deleted": True, "event_id": event_id}

