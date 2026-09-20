"""
CIPHER Network IDPS Service Orchestrator
Coordinates flow analysis, ML inference, heuristic evaluation, threat scoring,
prevention response, and persistent event logging.
"""

import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

from app.network.model_loader import NetworkModelLoader
from app.network.predictor import NetworkPredictor
from app.detection.network_detector import NetworkDetector
from app.detection.threat_scorer import ThreatScorer
from app.prevention.prevention_engine import PreventionEngine
from app.database.database import Database
from app.network.schemas import NetworkFlowAnalyzeRequest, NetworkDetectionResponse

logger = logging.getLogger("cipher.network.service")


class NetworkService:
    """End-to-end coordinator for Network Intrusion Detection & Prevention."""

    def __init__(
        self,
        db: Optional[Database] = None,
        loader: Optional[NetworkModelLoader] = None,
        threat_scorer: Optional[ThreatScorer] = None,
        prevention_engine: Optional[PreventionEngine] = None
    ):
        self.db = db or Database()
        self.loader = loader or NetworkModelLoader()
        self.predictor = NetworkPredictor(self.loader) if self.loader.is_ready else None
        self.detector = NetworkDetector()
        self.threat_scorer = threat_scorer or ThreatScorer()
        self.prevention_engine = prevention_engine or PreventionEngine()

    def analyze_flow(self, request: NetworkFlowAnalyzeRequest) -> NetworkDetectionResponse:
        """
        Executes unified detection, scoring, response, and logging on an incoming network flow.
        """
        if not self.predictor:
            raise RuntimeError("Network IDS predictor is unavailable. Check model artifacts.")

        event_id = str(uuid.uuid4())
        timestamp = request.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Local ML Inference
        ml_result = self.predictor.predict_flow(request.features)
        ml_attack_prob = ml_result["attack_probability"]
        ml_predicted_category = ml_result["predicted_category"]
        ml_confidence = ml_result["model_confidence"]

        # 2. Deterministic Heuristic Analysis
        h_score, h_category, h_reasons, h_rules = self.detector.evaluate(
            features=request.features,
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            destination_port=request.destination_port,
            protocol=request.protocol
        )

        is_bcast_mcast = False
        is_trusted_traffic = False
        import ipaddress
        
        # Check source IP for trusted CDNs / Providers to avoid DDoS false positives
        if request.source_ip:
            try:
                sip = ipaddress.ip_address(request.source_ip)
                trusted_subnets = [
                    ipaddress.ip_network("140.82.0.0/16"),   # GitHub
                    ipaddress.ip_network("20.0.0.0/8"),      # Microsoft/Azure
                    ipaddress.ip_network("192.168.0.0/16"),  # Local Network
                    ipaddress.ip_network("10.0.0.0/8"),      # Local Network
                ]
                for subnet in trusted_subnets:
                    if sip in subnet:
                        is_trusted_traffic = True
                        break
            except ValueError:
                pass

        # If it's reply traffic from a web server (source port 80, 443, etc.), it's likely a download, not a DDoS.
        if request.source_port in [80, 443, 8080, 8443, 53]:
            is_trusted_traffic = True

        if request.destination_ip:
            try:
                ip = ipaddress.ip_address(request.destination_ip)
                if ip.is_multicast or (ip.version == 4 and (str(ip) == "255.255.255.255" or ip.exploded.endswith(".255"))):
                    is_bcast_mcast = True
            except ValueError:
                pass

        # 3. Determine Attack Type (Synergy between ML and Heuristics)
        if (is_bcast_mcast or is_trusted_traffic) and (h_category in ["DOS", "DDOS", "PORT_SCAN"] or ml_predicted_category in ["DOS", "DDOS", "PORT_SCAN"]):
            attack_type = "BENIGN"
            detection_method = "HEURISTIC"
            h_score = 0
            ml_attack_prob = 0.0
            h_reasons.append("Traffic targets broadcast/multicast or comes from known trusted provider (safelisted for DOS/DDOS)")
        elif h_score >= 50 and h_category:
            attack_type = h_category
            detection_method = "HEURISTIC" if ml_attack_prob < 0.50 else "HYBRID"
        elif ml_predicted_category != "BENIGN" and ml_attack_prob >= 0.50:
            attack_type = ml_predicted_category
            detection_method = "HYBRID" if h_score >= 35 else "ML"
        else:
            attack_type = "BENIGN"
            detection_method = "ML"

        # 4. Threat Scoring (0 - 100)
        risk_score, severity, classification, confidence = self.threat_scorer.calculate_network_risk(
            ml_attack_prob=ml_attack_prob,
            predicted_attack_type=attack_type,
            heuristic_score=h_score,
            flow_features=request.features
        )

        # 5. IPS Prevention Decision
        prevention_res = self.prevention_engine.evaluate_response(
            threat_score=risk_score,
            attack_type=attack_type,
            ml_confidence=ml_confidence,
            source_ip=request.source_ip,
            event_id=event_id,
            is_heuristic_hit=(h_score >= 35)
        )
        recommended_action = prevention_res["recommended_action"]
        applied_action = prevention_res["applied_action"]
        prevention_mode = prevention_res["mode"]

        # 6. Synthesize Explanations (Part 18 Requirements)
        explanation, reasons = self._build_explanation(
            attack_type=attack_type,
            severity=severity,
            ml_attack_prob=ml_attack_prob,
            features=request.features,
            heuristic_reasons=h_reasons,
            recommended_action=recommended_action
        )

        # 7. Persist to Unified Event Database
        event_record = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": "NETWORK",
            "attack_type": attack_type,
            "classification": classification,
            "risk_score": risk_score,
            "confidence": confidence,
            "severity": severity,
            "ml_score": ml_attack_prob,
            "heuristic_score": h_score,
            "domain": request.source_ip or "unknown",
            "source_ip": request.source_ip,
            "destination_ip": request.destination_ip,
            "source_port": request.source_port,
            "destination_port": request.destination_port,
            "protocol": request.protocol,
            "detection_method": detection_method,
            "reasons": reasons,
            "recommendation": explanation,
            "action": applied_action,
            "status": "BLOCKED" if "BLOCK" in applied_action else "NEW",
            "model_version": self.loader.model_version,
            "source": "api_flow",
            "metadata": {
                "class_probabilities": ml_result.get("class_probabilities", {}),
                "prevention_mode": prevention_mode,
                "applied_action": applied_action,
                "rules_triggered": h_rules
            }
        }
        self.db.save_event(event_record)

        # 8. Unified Security Event Correlation (Phase 6)
        try:
            from app.correlation.service import get_correlation_service
            get_correlation_service().process_event(event_record)
        except Exception as corr_err:
            logger.warning(f"Correlation processing deferred or failed for {event_id}: {corr_err}")

        return NetworkDetectionResponse(
            event_id=event_id,
            timestamp=timestamp,
            event_type="NETWORK",
            attack_type=attack_type,
            classification=classification,
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            source_port=request.source_port,
            destination_port=request.destination_port,
            protocol=request.protocol,
            ml_prediction=ml_predicted_category,
            ml_confidence=confidence,
            ml_attack_prob=ml_attack_prob,
            threat_score=risk_score,
            severity=severity,
            detection_method=detection_method,
            explanation=explanation,
            reasons=reasons,
            recommended_action=recommended_action,
            applied_action=applied_action,
            prevention_mode=prevention_mode,
            model_version=self.loader.model_version
        )

    def _build_explanation(
        self,
        attack_type: str,
        severity: str,
        ml_attack_prob: float,
        features: Dict[str, float],
        heuristic_reasons: List[str],
        recommended_action: str
    ) -> Tuple[str, List[str]]:
        """Generates evidence-based explanations complying with Part 18."""
        reasons = []

        # Collect genuine heuristic evidence
        for r in heuristic_reasons:
            if "conform to standard" not in r:
                reasons.append(r)

        # Collect observable ML flow feature evidence
        if ml_attack_prob >= 0.50:
            if features.get("Flow Packets/s", 0) > 1000:
                reasons.append(f"Elevated flow packet frequency ({features['Flow Packets/s']:,.0f} pkts/s)")
            if features.get("Total Length of Fwd Packets", 0) > 10000:
                reasons.append(f"Significant forward payload volume ({features['Total Length of Fwd Packets']:,} bytes)")
            if features.get("Fwd Packet Length Max", 0) > 1400:
                reasons.append(f"Maximum segment MTU utilization ({features['Fwd Packet Length Max']} bytes)")
            if features.get("SYN Flag Count", 0) > 0 and features.get("ACK Flag Count", 0) == 0:
                reasons.append("Unacknowledged SYN connection initiation without subsequent handshake completion")
            if features.get("Bwd Packet Length Std", 0) == 0 and features.get("Total Backward Packets", 0) > 0:
                reasons.append("Static backward response packet size typical of automated server rejection")

        if not reasons:
            reasons.append("Flow metrics and timing intervals align with typical benign network traffic")

        # Specific synthesized explanation
        if attack_type == "PORT_SCAN":
            explanation = (
                f"Probable Port Scan detected: Source host generated connection probes against destination port "
                f"{features.get('Destination Port', 'unknown')} with rapid probe intervals and half-open flags."
            )
        elif attack_type in ["DOS", "DDOS"]:
            explanation = (
                f"Network IDS classified the flow as probable {attack_type} based on abnormal flow rate, "
                f"packet rate statistics ({features.get('Flow Packets/s', 0):,.0f} pkts/s), and asymmetric traffic volume."
            )
        elif attack_type == "BRUTE_FORCE":
            explanation = (
                f"Probable Brute Force authentication attack: Repeated truncated connections targeting authentication "
                f"service on port {features.get('Destination Port', 'unknown')}."
            )
        elif attack_type == "BOTNET":
            explanation = (
                f"Probable Botnet communication identified based on periodic inter-arrival timing "
                f"and automated beaconing signatures."
            )
        elif attack_type == "WEB_ATTACK":
            explanation = (
                f"Anomalous web service flow detected directed at HTTP/HTTPS endpoint. "
                f"Note: Detailed SQLi/XSS payload validation requires application-layer HTTP inspection."
            )
        elif attack_type == "INFILTRATION":
            explanation = "Internal lateral movement flow detected exhibiting anomalous intra-host transfer characteristics."
        elif attack_type == "OTHER_ATTACK":
            explanation = "Severe protocol anomaly observed matching known vulnerability exploit flow characteristics."
        else:
            explanation = "Standard benign network flow verified. No intrusive activity detected."

        return explanation, reasons[:5]
