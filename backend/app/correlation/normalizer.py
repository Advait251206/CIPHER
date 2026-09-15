"""
CIPHER Event Normalizer
Converts raw detector outputs, database records, and service payloads into
a unified, canonical NormalizedEvent representation without altering the original events.
"""

import uuid
import logging
from typing import Dict, Any, Union
from datetime import datetime, timezone
from app.correlation.models import NormalizedEvent

logger = logging.getLogger("cipher.correlation.normalizer")


class EventNormalizer:
    """
    Normalizes heterogeneous detection subsystem outputs (Phishing, Network IDS,
    Heuristics, Live Sensor) into a single canonical NormalizedEvent schema.
    """

    @staticmethod
    def normalize(event_data: Union[Dict[str, Any], NormalizedEvent]) -> NormalizedEvent:
        """
        Takes raw event data dictionary or NormalizedEvent and returns a normalized event.
        Guarantees that the input object is never mutated.
        """
        if isinstance(event_data, NormalizedEvent):
            return event_data

        if not isinstance(event_data, dict):
            logger.warning(f"Unexpected event data type: {type(event_data)}. Creating minimal fallback.")
            event_data = {}

        # Safely copy to ensure immutability of input
        raw = dict(event_data)

        # 1. Event ID and Timestamp
        event_id = str(raw.get("event_id") or uuid.uuid4())
        timestamp = raw.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 2. Source and Subsystem Categorization
        raw_source = str(raw.get("source") or "").lower()
        raw_event_type = str(raw.get("event_type") or "").lower()
        
        is_phishing = (
            "phish" in raw_source 
            or "phish" in raw_event_type 
            or (raw.get("domain") and not raw.get("source_ip"))
        )

        source = "phishing" if is_phishing else (raw_source or "network")
        event_type = "phishing_detection" if is_phishing else (raw_event_type or "network_detection")

        # 3. Attack Category Mapping
        attack_category = "BENIGN"
        if is_phishing:
            classification = str(raw.get("classification") or "").upper()
            if classification == "PHISHING":
                attack_category = "PHISHING"
            elif classification in ("SUSPICIOUS", "UNKNOWN"):
                attack_category = "SUSPICIOUS"
            else:
                attack_category = "BENIGN"
        else:
            raw_attack = raw.get("attack_type") or raw.get("attack_category") or raw.get("classification") or ""
            attack_category = str(raw_attack).strip().upper().replace(" ", "_")
            if not attack_category or attack_category == "BENIGN":
                attack_category = "BENIGN"

        # 4. Scores and Confidences
        risk_score = raw.get("risk_score") or raw.get("threat_score") or 0
        try:
            risk_score = max(0, min(100, int(risk_score)))
        except (ValueError, TypeError):
            risk_score = 0

        confidence = raw.get("confidence") or raw.get("ml_confidence") or 0.0
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (ValueError, TypeError):
            confidence = 0.0

        severity = str(raw.get("severity") or "LOW").upper()
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            if risk_score >= 85:
                severity = "CRITICAL"
            elif risk_score >= 60:
                severity = "HIGH"
            elif risk_score >= 35:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # 5. Network Coordinates
        source_ip = raw.get("source_ip")
        if source_ip is not None:
            source_ip = str(source_ip).strip()
            if not source_ip:
                source_ip = None

        destination_ip = raw.get("destination_ip")
        if destination_ip is not None:
            destination_ip = str(destination_ip).strip()
            if not destination_ip:
                destination_ip = None

        source_port = raw.get("source_port")
        try:
            source_port = int(source_port) if source_port is not None else None
        except (ValueError, TypeError):
            source_port = None

        destination_port = raw.get("destination_port")
        try:
            destination_port = int(destination_port) if destination_port is not None else None
        except (ValueError, TypeError):
            destination_port = None

        protocol = raw.get("protocol")
        if protocol is not None:
            protocol = str(protocol).strip().upper()

        # 6. Domain / URL
        domain = raw.get("domain")
        if domain is not None:
            domain = str(domain).strip()
            if not domain:
                domain = None

        url = raw.get("url")
        if url is not None:
            url = str(url).strip()
            if not url:
                url = None

        # 7. Detection Details & Context
        description = raw.get("recommendation") or raw.get("explanation") or raw.get("description")
        detection_method = raw.get("detection_method") or "ML"
        
        ml_score = raw.get("ml_score") or raw.get("ml_attack_prob")
        try:
            model_probability = float(ml_score) if ml_score is not None else None
        except (ValueError, TypeError):
            model_probability = None

        rule_id = raw.get("rule_id")
        if not rule_id and isinstance(raw.get("metadata"), dict):
            rules = raw["metadata"].get("rules_triggered")
            if rules and isinstance(rules, list):
                rule_names = [
                    r.get("rule_id") or r.get("name") or "RULE" if isinstance(r, dict) else str(r)
                    for r in rules
                ]
                if rule_names:
                    rule_id = ",".join(rule_names)

        metadata = raw.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            attack_category=attack_category,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            domain=domain,
            url=url,
            description=description,
            detection_method=detection_method,
            model_probability=model_probability,
            rule_id=rule_id,
            metadata=metadata
        )
