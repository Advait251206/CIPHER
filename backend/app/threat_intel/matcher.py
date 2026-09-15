"""
CIPHER Threat Intelligence Matcher
Performs fast, exact, and normalized IOC matching against observed security event metadata.
Adheres to strict conservative evidence criteria; zero external network queries.
"""

import logging
from typing import Dict, List, Optional, Any, Union

from app.threat_intel.models import IOCMatch, IOCItem
from app.threat_intel.store import IOCStore, normalize_indicator

logger = logging.getLogger("cipher.threat_intel.matcher")


class ThreatIntelMatcher:
    """Matches observed event artifacts against local active IOC records."""

    def __init__(self, store: Optional[IOCStore] = None):
        self.store = store or IOCStore()

    def check_indicator(self, indicator: str, ioc_type: Optional[str] = None) -> Optional[IOCMatch]:
        """
        Direct lookup of a single indicator against active local IOCs.
        Returns structured IOCMatch or None.
        """
        if not indicator or not isinstance(indicator, str):
            return None

        ioc = self.store.get_ioc_by_indicator(indicator, ioc_type=ioc_type, active_only=True)
        if not ioc:
            return None

        explanation = (
            f"Threat intelligence match detected: Indicator '{indicator}' "
            f"matches locally stored {ioc.category} IOC ({ioc.ioc_id})."
        )

        return IOCMatch(
            ioc_id=ioc.ioc_id,
            indicator=ioc.indicator,
            ioc_type=ioc.ioc_type,
            source=ioc.source,
            confidence=ioc.confidence,
            severity=ioc.severity,
            category=ioc.category,
            explanation=explanation,
            matched_field="indicator"
        )

    def match_event(self, event_input: Union[Dict[str, Any], Any]) -> List[IOCMatch]:
        """
        Evaluates an observed event against active local IOCs.
        Checks:
        1. source_ip (IP)
        2. destination_ip (IP)
        3. domain (DOMAIN)
        4. url (URL)
        5. file/payload hashes (HASH)

        Guarantees that duplicate matches for the same IOC within a single event are deduplicated.
        """
        # Convert to dictionary safely
        if hasattr(event_input, "model_dump"):
            raw = event_input.model_dump()
        elif hasattr(event_input, "dict"):
            raw = event_input.dict()
        elif isinstance(event_input, dict):
            raw = dict(event_input)
        else:
            return []

        matches: List[IOCMatch] = []
        matched_ioc_ids = set()

        def _record_match(ioc: IOCItem, field_name: str, observed_val: str):
            if ioc.ioc_id in matched_ioc_ids:
                return
            matched_ioc_ids.add(ioc.ioc_id)

            field_label = field_name.replace("_", " ")
            explanation = (
                f"Threat intelligence match detected: Observed {field_label} '{observed_val}' "
                f"matches locally stored {ioc.category} IOC ({ioc.ioc_id})."
            )

            matches.append(IOCMatch(
                ioc_id=ioc.ioc_id,
                indicator=ioc.indicator,
                ioc_type=ioc.ioc_type,
                source=ioc.source,
                confidence=ioc.confidence,
                severity=ioc.severity,
                category=ioc.category,
                explanation=explanation,
                matched_field=field_name
            ))

        # 1. Match Source IP
        src_ip = raw.get("source_ip")
        if src_ip and isinstance(src_ip, str) and src_ip not in ("unknown", "", "0.0.0.0"):
            ioc = self.store.get_ioc_by_indicator(src_ip, ioc_type="IP", active_only=True)
            if ioc:
                _record_match(ioc, "source_ip", src_ip)

        # 2. Match Destination IP
        dst_ip = raw.get("destination_ip")
        if dst_ip and isinstance(dst_ip, str) and dst_ip not in ("unknown", "", "0.0.0.0"):
            ioc = self.store.get_ioc_by_indicator(dst_ip, ioc_type="IP", active_only=True)
            if ioc:
                _record_match(ioc, "destination_ip", dst_ip)

        # 3. Match Domain
        domain = raw.get("domain")
        if domain and isinstance(domain, str) and domain not in ("unknown", ""):
            # Check if domain is not simply an IP address already checked
            ioc = self.store.get_ioc_by_indicator(domain, ioc_type="DOMAIN", active_only=True)
            if ioc:
                _record_match(ioc, "domain", domain)

        # 4. Match URL
        url = raw.get("url")
        if url and isinstance(url, str) and url.strip():
            ioc = self.store.get_ioc_by_indicator(url, ioc_type="URL", active_only=True)
            if ioc:
                _record_match(ioc, "url", url)

        # 5. Match Hashes (from metadata or features if present)
        metadata = raw.get("metadata") or {}
        features = raw.get("features") or {}
        hash_candidates = []

        for container in (metadata, features, raw):
            if isinstance(container, dict):
                for k in ("hash", "payload_hash", "file_hash", "md5", "sha1", "sha256"):
                    val = container.get(k)
                    if val and isinstance(val, str) and len(val.strip()) in (32, 40, 64):
                        hash_candidates.append((k, val.strip()))

        for field_k, h_val in hash_candidates:
            ioc = self.store.get_ioc_by_indicator(h_val, ioc_type="HASH", active_only=True)
            if ioc:
                _record_match(ioc, field_k, h_val)

        return matches
