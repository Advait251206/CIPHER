"""
CIPHER Correlation Service
Central coordinator for the Unified Detection and Security Event Correlation Layer.
Normalizes incoming events, tracks incident chains, calculates correlated threat assessments,
interfaces with PreventionEngine without duplicating logic, and coordinates SQLite persistence.
"""

import logging
from typing import Dict, Any, List, Optional, Union

from app.database.database import Database
from app.prevention.prevention_engine import PreventionEngine
from app.correlation.models import NormalizedEvent, IncidentItem
from app.correlation.normalizer import EventNormalizer
from app.correlation.correlator import EventCorrelator, CorrelatedChain
from app.correlation.incident import IncidentManager

logger = logging.getLogger("cipher.correlation.service")


class CorrelationService:
    """Coordinates event ingestion, multi-dimensional correlation, prevention, and persistence."""

    def __init__(
        self,
        correlator: Optional[EventCorrelator] = None,
        incident_mgr: Optional[IncidentManager] = None,
        prevention_engine: Optional[PreventionEngine] = None,
        db: Optional[Database] = None
    ):
        self.normalizer = EventNormalizer()
        self.correlator = correlator or EventCorrelator()
        self.db = db or Database()
        self.incident_mgr = incident_mgr or IncidentManager(self.db)
        self.prevention_engine = prevention_engine or PreventionEngine()
        logger.info("Initialized CIPHER Unified Correlation Service")

    def process_event(self, raw_event: Union[Dict[str, Any], NormalizedEvent]) -> Dict[str, Any]:
        """
        Ingests a raw detector output, normalizes it, evaluates heuristic and signature rules,
        correlates against active chains, evaluates prevention response, and persists to database.
        
        Returns the incident dictionary.
        """
        # 1. Normalize without altering original event
        norm_event = self.normalizer.normalize(raw_event)

        # 2. Deterministic Heuristic + Signature Rule Evaluation (Phase 7)
        try:
            from app.rules.engine import get_rule_engine
            rule_matches = get_rule_engine().evaluate(raw_event)
            if rule_matches:
                matched_ids = [m.rule_id for m in rule_matches]
                if not isinstance(norm_event.metadata, dict):
                    norm_event.metadata = {}
                norm_event.metadata["rule_matches"] = [m.model_dump() for m in rule_matches]
                if not norm_event.rule_id:
                    norm_event.rule_id = ",".join(matched_ids)
                else:
                    norm_event.rule_id += "," + ",".join(matched_ids)

                # If event was unclassified or benign but deterministic rules matched with high weight,
                # reflect the dominant rule category
                if norm_event.attack_category in ("BENIGN", "UNKNOWN"):
                    top_match = max(rule_matches, key=lambda m: m.weight)
                    if top_match.weight >= 45:
                        norm_event.attack_category = top_match.category
                        if norm_event.severity == "LOW" and top_match.severity in ("MEDIUM", "HIGH", "CRITICAL"):
                            norm_event.severity = top_match.severity
                        if norm_event.risk_score < top_match.weight:
                            norm_event.risk_score = top_match.weight
        except Exception as rule_err:
            logger.warning(f"Deterministic rule engine evaluation skipped: {rule_err}")

        # 3. Threat Intelligence IOC Matching (Phase 8)
        try:
            from app.threat_intel.service import get_threat_intel_service
            ti_matches = get_threat_intel_service().match_event(norm_event)
            if ti_matches:
                if not isinstance(norm_event.metadata, dict):
                    norm_event.metadata = {}
                norm_event.metadata["threat_intel_matches"] = [m.model_dump() for m in ti_matches]

                # Synthesize threat intelligence evidence through ThreatScorer
                from app.detection.threat_scorer import ThreatScorer
                scorer = ThreatScorer()
                new_risk, new_sev, new_class = scorer.apply_threat_intel(
                    current_risk=norm_event.risk_score,
                    current_severity=norm_event.severity,
                    current_classification=norm_event.attack_category,
                    ti_matches=ti_matches
                )
                norm_event.risk_score = new_risk
                norm_event.severity = new_sev
                norm_event.attack_category = new_class
        except Exception as ti_err:
            logger.warning(f"Threat intelligence matching skipped or failed: {ti_err}")

        # Do not correlate strictly BENIGN events into incidents
        if norm_event.attack_category in ("BENIGN", "UNKNOWN") and norm_event.severity == "LOW":
            return None

        # 4. Correlate with sliding window and safe identities
        chain, is_new = self.correlator.process_event(norm_event)

        # 3. Prevention Integration: delegate to existing PreventionEngine
        try:
            prev_res = self.prevention_engine.evaluate_response(
                threat_score=chain.correlation_score,
                attack_type=norm_event.attack_category,
                ml_confidence=chain.confidence,
                source_ip=chain.source_ip,
                event_id=chain.incident_id,
                is_heuristic_hit=chain.escalation_detected
            )
            rec_act = prev_res.get("recommended_action")
            chain.recommended_action = rec_act.value if hasattr(rec_act, "value") else str(rec_act or "ALERT")
            chain.applied_action = str(prev_res.get("applied_action") or "LOG_ONLY")
        except Exception as e:
            logger.warning(f"Error evaluating prevention response for incident {chain.incident_id}: {e}")
            chain.recommended_action = "ALERT"
            chain.applied_action = "LOG_ONLY"

        # 4. Synchronize incident and junction table in SQLite
        incident_id = self.incident_mgr.persist_chain(chain, is_new=is_new)

        # 5. Fetch updated incident representation
        incident_dict = self.incident_mgr.get_incident(incident_id)
        if not incident_dict:
            # Fallback if DB write encountered an issue
            incident_dict = {
                "incident_id": chain.incident_id,
                "status": chain.status,
                "correlation_score": chain.correlation_score,
                "severity": chain.severity,
                "event_count": len(chain.events),
                "escalation_detected": chain.escalation_detected,
                "summary": chain.summary,
                "event_ids": [e.event_id for e in chain.events]
            }

        return incident_dict

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.incident_mgr.get_incident(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.incident_mgr.list_incidents(
            limit=limit,
            offset=offset,
            status=status,
            severity=severity,
            source_ip=source_ip
        )

    def get_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        return self.incident_mgr.get_incident_events(incident_id)

    def resolve_incident(self, incident_id: str) -> bool:
        """Resolves both the in-memory active chain and the database record."""
        self.correlator.resolve_chain(incident_id)
        return self.incident_mgr.resolve_incident(incident_id)

    def get_correlation_stats(self) -> Dict[str, Any]:
        return self.incident_mgr.get_correlation_stats()


# Global singleton instance
_correlation_service_instance: Optional[CorrelationService] = None


def get_correlation_service() -> CorrelationService:
    global _correlation_service_instance
    if _correlation_service_instance is None:
        _correlation_service_instance = CorrelationService()
    return _correlation_service_instance
