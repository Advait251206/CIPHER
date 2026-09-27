"""
CIPHER Event Service
Coordinates event persistence, filtering, and metric aggregation.
"""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.database.database import Database


class EventService:
    """Manages privacy-safe security event recording and querying."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def record_scan_event(
        self,
        domain: str,
        classification: str,
        risk_score: int,
        confidence: float,
        severity: str,
        ml_score: float,
        heuristic_score: int,
        reasons: List[str],
        recommendation: str,
        model_version: str,
        source: str = "api"
    ) -> str:
        """Stores a sanitized security scanning event without sensitive query parameters."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        event_data = {
            "event_id": event_id,
            "timestamp": timestamp,
            "classification": classification,
            "risk_score": risk_score,
            "confidence": confidence,
            "severity": severity,
            "ml_score": ml_score,
            "heuristic_score": heuristic_score,
            "domain": domain,
            "reasons": reasons,
            "recommendation": recommendation,
            "model_version": model_version,
            "source": source
        }
        self.db.save_event(event_data)
        try:
            from app.correlation.service import get_correlation_service
            get_correlation_service().process_event(event_data)
        except Exception as corr_err:
            pass
        return event_id

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_event(event_id)

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        event_type: Optional[str] = None,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.db.list_events(
            limit=limit,
            offset=offset,
            event_type=event_type,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            status=status,
            start_time=start_time,
            end_time=end_time
        )

    def get_stats(self) -> Dict[str, Any]:
        return self.db.get_stats()


    def delete_event(self, event_id: str) -> bool:
        return self.db.delete_event(event_id)
