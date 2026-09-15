"""
CIPHER Incident Manager
Coordinates incident lifecycle states (OPEN, RESOLVED) and synchronizes correlation
chains with SQLite database persistence via the Database repository.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.database.database import Database
from app.correlation.models import IncidentItem
from app.correlation.correlator import CorrelatedChain

logger = logging.getLogger("cipher.correlation.incident")


class IncidentManager:
    """Manages persistence and retrieval of security incident records."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def persist_chain(self, chain: CorrelatedChain, is_new: bool) -> str:
        """
        Saves or updates an incident record in SQLite corresponding to the active chain.
        Also records associations in the incident_events junction table.
        """
        event_ids = [e.event_id for e in chain.events]
        attack_categories = sorted(list(set(e.attack_category for e in chain.events)))

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        incident_data = {
            "incident_id": chain.incident_id,
            "created_at": chain.created_at,
            "updated_at": now_iso,
            "status": chain.status,
            "source_ip": chain.source_ip,
            "destination_ip": chain.destination_ip,
            "event_count": len(chain.events),
            "attack_categories": attack_categories,
            "first_seen": chain.first_seen,
            "last_seen": chain.last_seen,
            "correlation_score": chain.correlation_score,
            "severity": chain.severity,
            "confidence": chain.confidence,
            "escalation_detected": chain.escalation_detected,
            "summary": chain.summary,
            "recommended_action": chain.recommended_action,
            "applied_action": chain.applied_action,
            "metadata": {
                "correlation_key": chain.correlation_key,
                "domain": chain.domain,
                "event_ids": event_ids
            }
        }

        if is_new:
            try:
                self.db.save_incident(incident_data, event_ids=event_ids)
                logger.info(f"Created new incident {chain.incident_id} [{chain.severity}] for {chain.correlation_key}")
            except Exception as e:
                logger.error(f"Failed to create incident {chain.incident_id}: {e}")
        else:
            try:
                updates = {
                    "updated_at": now_iso,
                    "status": chain.status,
                    "event_count": len(chain.events),
                    "attack_categories": attack_categories,
                    "last_seen": chain.last_seen,
                    "correlation_score": chain.correlation_score,
                    "severity": chain.severity,
                    "confidence": chain.confidence,
                    "escalation_detected": chain.escalation_detected,
                    "summary": chain.summary,
                    "recommended_action": chain.recommended_action,
                    "applied_action": chain.applied_action,
                    "metadata": incident_data["metadata"]
                }
                self.db.update_incident(chain.incident_id, updates, new_event_ids=event_ids)
                logger.debug(f"Updated incident {chain.incident_id} ({len(chain.events)} events)")
            except Exception as e:
                logger.error(f"Failed to update incident {chain.incident_id}: {e}")

        return chain.incident_id

    def resolve_incident(self, incident_id: str) -> bool:
        """Marks an existing incident as RESOLVED in the database."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.db.update_incident(
            incident_id=incident_id,
            updates={"status": "RESOLVED", "updated_at": now_iso}
        )

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_incident(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.db.list_incidents(
            limit=limit,
            offset=offset,
            status=status,
            severity=severity,
            source_ip=source_ip
        )

    def get_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        return self.db.get_incident_events(incident_id)

    def get_correlation_stats(self) -> Dict[str, Any]:
        return self.db.get_correlation_stats()
