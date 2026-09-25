"""
CIPHER Security Incidents and Correlation API Router
Provides REST endpoints for querying correlated incidents, associated security events,
correlation statistics, and manual incident resolution.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status

from app.correlation.models import (
    IncidentItem,
    IncidentsListResponse,
    IncidentDetailResponse,
    CorrelationStatsResponse,
    IncidentResolveResponse
)
from app.correlation.service import get_correlation_service

router = APIRouter(tags=["Security Incidents & Correlation"])


@router.get("/incidents", response_model=IncidentsListResponse, summary="List Correlated Security Incidents")
def list_incidents(
    limit: int = Query(default=50, ge=1, le=500, description="Maximum number of incidents to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (OPEN, RESOLVED)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP")
):
    """
    Retrieves correlated security incidents with optional filtering by status, severity, or source IP.
    """
    corr_svc = get_correlation_service()
    raw_incidents = corr_svc.list_incidents(
        limit=limit,
        offset=offset,
        status=status_filter,
        severity=severity,
        source_ip=source_ip
    )
    items = [IncidentItem(**inc) for inc in raw_incidents]
    return IncidentsListResponse(total_returned=len(items), incidents=items)


@router.get("/incidents/{incident_id}", response_model=IncidentDetailResponse, summary="Get Incident Details by ID")
def get_incident(incident_id: str):
    """
    Retrieves details of a specific security incident and its associated events.
    """
    corr_svc = get_correlation_service()
    incident_data = corr_svc.get_incident(incident_id)
    if not incident_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    events = corr_svc.get_incident_events(incident_id)
    return IncidentDetailResponse(
        incident=IncidentItem(**incident_data),
        events=events
    )


@router.get("/incidents/{incident_id}/events", response_model=List[Dict[str, Any]], summary="Get Events Associated with Incident")
def get_incident_events(incident_id: str):
    """
    Retrieves the complete list of security events linked to a specific incident.
    """
    corr_svc = get_correlation_service()
    incident_data = corr_svc.get_incident(incident_id)
    if not incident_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    return corr_svc.get_incident_events(incident_id)


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentResolveResponse, summary="Resolve an Incident")
def resolve_incident(incident_id: str):
    """
    Marks an active incident as RESOLVED.
    """
    corr_svc = get_correlation_service()
    incident_data = corr_svc.get_incident(incident_id)
    if not incident_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found."
        )

    success = corr_svc.resolve_incident(incident_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update status for incident '{incident_id}'."
        )

    return IncidentResolveResponse(
        incident_id=incident_id,
        status="RESOLVED",
        message="Incident marked as resolved."
    )


from pydantic import BaseModel

class BulkDeleteRequest(BaseModel):
    incident_ids: List[str]

@router.delete("/incidents", summary="Delete Multiple Incidents")
def delete_incidents(request: BulkDeleteRequest):
    """
    Deletes a list of incidents from the database and active correlation memory.
    """
    corr_svc = get_correlation_service()
    success = corr_svc.delete_incidents(request.incident_ids)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete some or all specified incidents."
        )

    return {"message": f"Successfully deleted {len(request.incident_ids)} incidents.", "deleted_count": len(request.incident_ids)}



@router.get("/correlation/stats", response_model=CorrelationStatsResponse, summary="Get Correlation Engine Statistics")
def get_correlation_stats():
    """
    Aggregates metrics for the correlation engine: total incidents, open vs resolved,
    escalations detected, and top attacking sources.
    """
    corr_svc = get_correlation_service()
    stats_data = corr_svc.get_correlation_stats()
    return CorrelationStatsResponse(**stats_data)


@router.post("/correlation/process", response_model=IncidentItem, summary="Process Event into Correlation Engine")
def process_event_for_correlation(event_payload: Dict[str, Any]):
    """
    Direct endpoint to normalize and correlate an incoming security event.
    Automatically merges into existing incident or creates a new incident.
    """
    corr_svc = get_correlation_service()
    incident_data = corr_svc.process_event(event_payload)
    return IncidentItem(**incident_data)
