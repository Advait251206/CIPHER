"""
CIPHER Threat Intelligence Subsystem
Provides local-first, privacy-preserving Indicators of Compromise (IOC) matching,
store management, and security event correlation.
"""

from app.threat_intel.models import (
    IOCType,
    IOCSeverity,
    IOCItem,
    IOCCreateRequest,
    IOCMatch,
    IOCListResponse,
    IOCDetailResponse,
    IOCToggleResponse,
    IOCCheckRequest,
    IOCCheckResponse,
    IOCImportRequest,
    IOCImportResponse
)
from app.threat_intel.config import (
    ALLOWED_IOC_TYPES,
    ALLOWED_SEVERITIES,
    IOC_CACHE_MAX_ENTRIES,
    IOC_MAX_BULK_IMPORT,
    DEMO_IOC_DATASET
)
from app.threat_intel.store import IOCStore, normalize_indicator
from app.threat_intel.matcher import ThreatIntelMatcher
from app.threat_intel.service import ThreatIntelService, get_threat_intel_service

__all__ = [
    "IOCType",
    "IOCSeverity",
    "IOCItem",
    "IOCCreateRequest",
    "IOCMatch",
    "IOCListResponse",
    "IOCDetailResponse",
    "IOCToggleResponse",
    "IOCCheckRequest",
    "IOCCheckResponse",
    "IOCImportRequest",
    "IOCImportResponse",
    "ALLOWED_IOC_TYPES",
    "ALLOWED_SEVERITIES",
    "IOC_CACHE_MAX_ENTRIES",
    "IOC_MAX_BULK_IMPORT",
    "DEMO_IOC_DATASET",
    "IOCStore",
    "normalize_indicator",
    "ThreatIntelMatcher",
    "ThreatIntelService",
    "get_threat_intel_service"
]
