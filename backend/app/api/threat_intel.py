"""
CIPHER Threat Intelligence API Router
Provides REST endpoints for IOC management, lookup checks, and bulk import.
Operates strictly local-first with zero external cloud lookups.
"""

import io
import csv
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Request, status

from app.threat_intel.models import (
    IOCItem,
    IOCCreateRequest,
    IOCListResponse,
    IOCDetailResponse,
    IOCToggleResponse,
    IOCCheckRequest,
    IOCCheckResponse,
    IOCImportRequest,
    IOCImportResponse
)
from app.threat_intel.service import get_threat_intel_service
from app.threat_intel.config import IOC_MAX_BULK_IMPORT

logger = logging.getLogger("cipher.api.threat_intel")

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence & IOCs"])


@router.get("/iocs", response_model=IOCListResponse, summary="List Registered IOCs")
def list_iocs(
    ioc_type: Optional[str] = Query(default=None, description="Filter by IOC type: IP, DOMAIN, URL, HASH"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    enabled_only: bool = Query(default=False, description="Filter only enabled IOC records"),
    limit: int = Query(default=50, ge=1, le=500, description="Pagination limit"),
    offset: int = Query(default=0, ge=0, description="Pagination offset")
):
    """
    Retrieves locally stored Indicators of Compromise with optional filtering.
    """
    service = get_threat_intel_service()
    items, total = service.list_iocs(
        ioc_type=ioc_type,
        severity=severity,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset
    )
    return IOCListResponse(
        total_returned=len(items),
        total_matching=total,
        iocs=items
    )


@router.get("/iocs/{ioc_id}", response_model=IOCDetailResponse, summary="Get IOC Details")
def get_ioc(ioc_id: str):
    """
    Retrieves metadata and current status for a single IOC by ID.
    """
    service = get_threat_intel_service()
    item = service.get_ioc(ioc_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC '{ioc_id}' not found."
        )
    return IOCDetailResponse(ioc=item)


@router.post("/iocs", response_model=IOCDetailResponse, status_code=status.HTTP_201_CREATED, summary="Add IOC")
def create_ioc(req: IOCCreateRequest):
    """
    Registers a new Indicator of Compromise in the local database.
    Rejects malformed indicators and duplicate entries deterministically.
    """
    service = get_threat_intel_service()
    try:
        item = service.add_ioc(req)
        return IOCDetailResponse(ioc=item)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(val_err)
        )
    except Exception as e:
        logger.error(f"Error creating IOC: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register IOC."
        )


@router.delete("/iocs/{ioc_id}", summary="Delete IOC")
def delete_ioc(ioc_id: str):
    """
    Removes an Indicator of Compromise from the local database.
    """
    service = get_threat_intel_service()
    deleted = service.delete_ioc(ioc_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC '{ioc_id}' not found."
        )
    return {"status": "success", "deleted": True, "ioc_id": ioc_id}


@router.post("/iocs/{ioc_id}/enable", response_model=IOCToggleResponse, summary="Enable IOC")
def enable_ioc(ioc_id: str):
    """
    Enables an active Indicator of Compromise.
    """
    service = get_threat_intel_service()
    item = service.get_ioc(ioc_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC '{ioc_id}' not found."
        )
    service.set_ioc_enabled(ioc_id, True)
    return IOCToggleResponse(
        ioc_id=ioc_id,
        enabled=True,
        message=f"IOC '{ioc_id}' enabled."
    )


@router.post("/iocs/{ioc_id}/disable", response_model=IOCToggleResponse, summary="Disable IOC")
def disable_ioc(ioc_id: str):
    """
    Disables an Indicator of Compromise so it no longer generates matches.
    """
    service = get_threat_intel_service()
    item = service.get_ioc(ioc_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC '{ioc_id}' not found."
        )
    service.set_ioc_enabled(ioc_id, False)
    return IOCToggleResponse(
        ioc_id=ioc_id,
        enabled=False,
        message=f"IOC '{ioc_id}' disabled."
    )


@router.post("/check", response_model=IOCCheckResponse, summary="Direct Indicator Check")
def check_indicator(req: IOCCheckRequest):
    """
    Directly checks an indicator (IP, domain, URL, or hash) against active local intelligence.
    Does not transmit data externally.
    """
    service = get_threat_intel_service()
    match = service.check_indicator(req.indicator, ioc_type=req.ioc_type)
    if match:
        return IOCCheckResponse(matched=True, matches=[match])
    return IOCCheckResponse(matched=False, matches=[])


@router.post("/import/json", response_model=IOCImportResponse, summary="JSON Bulk Import")
def import_iocs_json(req: IOCImportRequest):
    """
    Bulk imports validated IOC indicators from a structured JSON list (max 1,000 entries).
    """
    if len(req.iocs) > IOC_MAX_BULK_IMPORT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch exceeds maximum limit of {IOC_MAX_BULK_IMPORT} indicators."
        )

    service = get_threat_intel_service()
    imported, rejected, errors = service.bulk_add(req.iocs)

    return IOCImportResponse(
        total_submitted=len(req.iocs),
        imported_count=imported,
        rejected_count=rejected,
        errors=errors
    )


@router.post("/import", response_model=IOCImportResponse, summary="Bulk Import (JSON Alias)")
def import_iocs_alias(req: IOCImportRequest):
    """Alias to /import/json for backward compatibility."""
    return import_iocs_json(req)


@router.post("/import/csv", response_model=IOCImportResponse, summary="CSV Bulk Import")
async def import_iocs_csv(request: Request):
    """
    Bulk imports IOC indicators from raw CSV text in the request body.
    Expected CSV columns: ioc_type, indicator, severity (optional), confidence (optional), category (optional), description (optional).
    Enforces maximum batch size of 1,000 rows.
    """
    try:
        content_bytes = await request.body()
        content_str = content_bytes.decode("utf-8-sig", errors="replace")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read CSV content: {e}"
        )

    if not content_str.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV body is empty."
        )

    reader = csv.DictReader(io.StringIO(content_str))
    rows = list(reader)

    if len(rows) > IOC_MAX_BULK_IMPORT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CSV contains {len(rows)} rows, which exceeds the limit of {IOC_MAX_BULK_IMPORT}."
        )

    validated_reqs: List[IOCCreateRequest] = []
    errors: List[Dict[str, Any]] = []

    for row_idx, row in enumerate(rows, start=2):  # Row 2 is first data row
        if not any(v and v.strip() for v in row.values() if isinstance(v, str)):
            continue
        try:
            ioc_type = (row.get("ioc_type") or row.get("type") or "").strip().upper()
            indicator = (row.get("indicator") or row.get("value") or "").strip()
            severity = (row.get("severity") or "HIGH").strip().upper()

            conf_raw = row.get("confidence")
            confidence = float(conf_raw) if conf_raw and conf_raw.strip() else 0.85

            category = row.get("category")
            description = row.get("description")
            expires_at = row.get("expires_at")
            tags_raw = row.get("tags")
            tags = [t.strip() for t in tags_raw.split(",")] if tags_raw else []

            req = IOCCreateRequest(
                ioc_type=ioc_type,
                indicator=indicator,
                severity=severity,
                confidence=confidence,
                category=category,
                description=description,
                expires_at=expires_at,
                tags=tags
            )
            validated_reqs.append(req)
        except Exception as err:
            errors.append({
                "row": row_idx,
                "indicator": row.get("indicator", "unknown"),
                "error": str(err)
            })

    service = get_threat_intel_service()
    imported, rejected, db_errors = service.bulk_add(validated_reqs)

    # Combine validation errors and db insertion errors
    all_errors = errors + db_errors
    total_rejected = len(errors) + rejected

    return IOCImportResponse(
        total_submitted=len(validated_reqs) + len(errors),
        imported_count=imported,
        rejected_count=total_rejected,
        errors=all_errors
    )
