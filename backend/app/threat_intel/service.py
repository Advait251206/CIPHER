"""
CIPHER Threat Intelligence Service
Orchestrates the local IOC store, matching engine, and optional demo IOC loading.
Follows local-first, privacy-preserving design principles.
"""

import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Union

from app.threat_intel.store import IOCStore
from app.threat_intel.matcher import ThreatIntelMatcher
from app.threat_intel.models import IOCItem, IOCCreateRequest, IOCMatch
from app.threat_intel.config import DEMO_IOC_DATASET, CIPHER_LOAD_DEMO_IOCS

logger = logging.getLogger("cipher.threat_intel.service")


class ThreatIntelService:
    """Service facade for CIPHER Threat Intelligence operations."""

    def __init__(self, store: Optional[IOCStore] = None):
        self.store = store or IOCStore()
        self.matcher = ThreatIntelMatcher(store=self.store)
        self._lock = threading.RLock()

        # Conditionally seed demo IOCs ONLY if explicitly configured via environment variable
        if CIPHER_LOAD_DEMO_IOCS:
            logger.info("CIPHER_LOAD_DEMO_IOCS is active; seeding synthetic demo indicators...")
            self.seed_demo_iocs(force=True)
        else:
            logger.info("Threat Intelligence initialized without demo IOC seeding (CIPHER_LOAD_DEMO_IOCS=false).")

    def seed_demo_iocs(self, force: bool = False) -> int:
        """
        Seeds the safe synthetic demo dataset.
        Never executes unless force=True or CIPHER_LOAD_DEMO_IOCS=True.
        Skips any indicator that already exists to ensure determinism.
        """
        if not force and not CIPHER_LOAD_DEMO_IOCS:
            return 0

        seeded_count = 0
        with self._lock:
            for item_data in DEMO_IOC_DATASET:
                try:
                    req = IOCCreateRequest(**item_data)
                    self.store.add_ioc(req, ioc_id=item_data.get("ioc_id"))
                    seeded_count += 1
                except ValueError:
                    # Already exists or duplicate; safely ignore for demo data
                    pass
                except Exception as e:
                    logger.warning(f"Error seeding demo IOC {item_data.get('indicator')}: {e}")

        if seeded_count > 0:
            logger.info(f"Seeded {seeded_count} synthetic demo IOCs into local intelligence store.")
        return seeded_count

    def match_event(self, event_input: Union[Dict[str, Any], Any]) -> List[IOCMatch]:
        """Matches an observed security event against local active IOCs."""
        return self.matcher.match_event(event_input)

    def check_indicator(self, indicator: str, ioc_type: Optional[str] = None) -> Optional[IOCMatch]:
        """Performs a direct check of a single indicator value."""
        return self.matcher.check_indicator(indicator, ioc_type=ioc_type)

    def add_ioc(self, req: Union[IOCCreateRequest, Dict[str, Any]]) -> IOCItem:
        """Adds a new IOC indicator."""
        return self.store.add_ioc(req)

    def get_ioc(self, ioc_id: str) -> Optional[IOCItem]:
        """Retrieves an IOC record by ID."""
        return self.store.get_ioc(ioc_id)

    def delete_ioc(self, ioc_id: str) -> bool:
        """Deletes an IOC record by ID."""
        return self.store.delete_ioc(ioc_id)

    def set_ioc_enabled(self, ioc_id: str, enabled: bool) -> bool:
        """Enables or disables an IOC record."""
        return self.store.set_ioc_enabled(ioc_id, enabled)

    def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[IOCItem], int]:
        """Lists registered IOCs with filtering."""
        return self.store.list_iocs(
            ioc_type=ioc_type,
            severity=severity,
            enabled_only=enabled_only,
            limit=limit,
            offset=offset
        )

    def bulk_add(self, iocs: List[IOCCreateRequest]) -> Tuple[int, int, List[Dict[str, Any]]]:
        """Bulk adds a list of validated IOC requests."""
        return self.store.bulk_add(iocs)


# Singleton instance
_ti_service_instance: Optional[ThreatIntelService] = None
_ti_lock = threading.Lock()


def get_threat_intel_service() -> ThreatIntelService:
    """Returns the process-wide ThreatIntelService singleton."""
    global _ti_service_instance
    if _ti_service_instance is None:
        with _ti_lock:
            if _ti_service_instance is None:
                _ti_service_instance = ThreatIntelService()
    return _ti_service_instance
