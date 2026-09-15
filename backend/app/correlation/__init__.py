"""
CIPHER Unified Detection and Event Correlation Package
"""

from app.correlation.models import NormalizedEvent, IncidentItem
from app.correlation.normalizer import EventNormalizer
from app.correlation.correlator import EventCorrelator
from app.correlation.incident import IncidentManager
from app.correlation.service import CorrelationService, get_correlation_service

__all__ = [
    "NormalizedEvent",
    "IncidentItem",
    "EventNormalizer",
    "EventCorrelator",
    "IncidentManager",
    "CorrelationService",
    "get_correlation_service"
]
