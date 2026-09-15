"""
CIPHER Threat Scorer
Combines local Machine Learning inference with independent Heuristic Engine assessments
into a unified, calibrated risk score (0-100) and severity classification.
Supports both Phishing URL analysis and Network Intrusion Detection (CIC-IDS2017).
"""

from typing import Dict, Any, Tuple, Optional, List


class ThreatScorer:
    """Configurable cybersecurity risk synthesis engine."""

    def __init__(self, ml_weight: float = 0.70, heuristic_weight: float = 0.30):
        assert abs((ml_weight + heuristic_weight) - 1.0) < 1e-4, "Weights must sum to 1.0"
        self.ml_weight = ml_weight
        self.heuristic_weight = heuristic_weight

    # =========================================================================
    # Phishing Threat Scoring (Preserved & Fully Backward Compatible)
    # =========================================================================

    def calculate_risk(
        self,
        ml_phishing_prob: float,
        heuristic_score: int
    ) -> Tuple[int, str, str, float]:
        """
        Combines ML probability (0.0 to 1.0) and heuristic score (0 to 100).

        Returns:
            risk_score (int): 0 - 100
            severity (str): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
            classification (str): 'LEGITIMATE' | 'SUSPICIOUS' | 'LIKELY_PHISHING'
            model_confidence (float): 0.0 - 1.0 (certainty of the ML prediction)
        """
        ml_contribution = ml_phishing_prob * 100.0
        raw_risk = (self.ml_weight * ml_contribution) + (self.heuristic_weight * float(heuristic_score))

        if heuristic_score >= 70:
            raw_risk = max(raw_risk, float(heuristic_score))

        risk_score = int(round(min(100.0, max(0.0, raw_risk))))

        if ml_phishing_prob >= 0.5:
            model_confidence = round(ml_phishing_prob, 4)
        else:
            model_confidence = round(1.0 - ml_phishing_prob, 4)

        if risk_score <= 24:
            severity = "LOW"
        elif risk_score <= 49:
            severity = "MEDIUM"
        elif risk_score <= 74:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        if risk_score >= 65 or ml_phishing_prob >= 0.75:
            classification = "LIKELY_PHISHING"
        elif risk_score >= 35 or ml_phishing_prob >= 0.40:
            classification = "SUSPICIOUS"
        else:
            classification = "LEGITIMATE"

        return risk_score, severity, classification, model_confidence

    @staticmethod
    def get_recommendation(severity: str, classification: str) -> str:
        """Produces clear, user-facing security guidance for URLs."""
        if severity == "CRITICAL" or classification == "LIKELY_PHISHING":
            return "DANGER: High probability of phishing attack. Do not enter credentials, credit cards, or personal data on this website."
        elif severity == "HIGH":
            return "WARNING: Suspicious characteristics detected. Verify the website's authenticity through trusted bookmarks or search before proceeding."
        elif severity == "MEDIUM" or classification == "SUSPICIOUS":
            return "CAUTION: Minor anomalies detected. Exercise caution when submitting any private information."
        else:
            return "SAFE: Website URL structure conforms to standard legitimate patterns. Proceed normally."

    # =========================================================================
    # Network Intrusion Threat Scoring (Part 17)
    # =========================================================================

    def calculate_network_risk(
        self,
        ml_attack_prob: float,
        predicted_attack_type: str,
        heuristic_score: int,
        flow_features: Optional[Dict[str, float]] = None,
        repetition_count: int = 1
    ) -> Tuple[int, str, str, float]:
        """
        Synthesizes Network ML probabilities, attack taxonomy, and deterministic flow
        heuristics into a calibrated 0-100 risk score and severity band.

        Does NOT blindly equate ML confidence with threat severity.
        E.g., high-confidence Port Scan is lower operational severity than DoS/Botnet.

        Returns:
            risk_score (int): 0 - 100
            severity (str): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
            classification (str): 'BENIGN' | 'SUSPICIOUS' | 'ATTACK'
            model_confidence (float): Certainty in the prediction
        """
        # 1. Base ML Risk Score
        if ml_attack_prob < 0.5:
            # Predicted benign
            base_ml_risk = ml_attack_prob * 40.0
            model_confidence = round(1.0 - ml_attack_prob, 4)
        else:
            # Predicted attack: baseline 50 to 80
            base_ml_risk = 50.0 + (ml_attack_prob - 0.5) * 60.0
            model_confidence = round(ml_attack_prob, 4)

        # 2. Attack Category Inherent Severity Multiplier
        # (Reconnaissance vs active breach vs service exhaustion)
        attack_weights = {
            "BENIGN": 0.0,
            "PORT_SCAN": 5.0,        # Pre-attack reconnaissance probe
            "WEB_ATTACK": 10.0,      # Exploitation attempt against web application
            "BRUTE_FORCE": 12.0,     # Active credential cracking on auth ports
            "DOS": 15.0,             # Single-source service exhaustion
            "DDOS": 18.0,            # Distributed high-impact availability assault
            "BOTNET": 20.0,          # Host infection / C2 active communication
            "INFILTRATION": 22.0,    # Host compromise and lateral propagation
            "OTHER_ATTACK": 20.0     # Critical vulnerability exploitation (e.g. Heartbleed)
        }
        category_boost = attack_weights.get(predicted_attack_type, 10.0) if ml_attack_prob >= 0.5 else 0.0

        # 3. Weighted Combination of ML and Deterministic Heuristics
        combined_risk = (self.ml_weight * (base_ml_risk + category_boost)) + (self.heuristic_weight * float(heuristic_score))

        # 4. Deterministic Heuristic Dominance
        # If deterministic rules found definitive signatures (e.g. SYN port scan, brute force, or flood)
        if heuristic_score >= 50:
            combined_risk = max(combined_risk, float(heuristic_score))

        # 5. Repetition & Traffic Intensity Factor
        if repetition_count >= 5 and ml_attack_prob >= 0.5:
            combined_risk += min(15.0, repetition_count * 2.0)

        # 6. Sanitize Bounds
        if predicted_attack_type == "BENIGN" and heuristic_score == 0 and ml_attack_prob < 0.40:
            risk_score = int(round(min(20.0, max(0.0, combined_risk))))
        else:
            risk_score = int(round(min(100.0, max(0.0, combined_risk))))

        # 7. Severity Bands
        if risk_score <= 24:
            severity = "LOW"
        elif risk_score <= 49:
            severity = "MEDIUM"
        elif risk_score <= 74:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # 8. Classification
        if risk_score >= 65 or (ml_attack_prob >= 0.70 and predicted_attack_type != "BENIGN"):
            classification = "ATTACK"
        elif risk_score >= 35 or ml_attack_prob >= 0.40:
            classification = "SUSPICIOUS"
        else:
            classification = "BENIGN"

        return risk_score, severity, classification, model_confidence

    @staticmethod
    def get_network_recommendation(severity: str, attack_type: str, action: str) -> str:
        """Produces clear, user-facing security response guidance for network events."""
        if attack_type == "BENIGN" or severity == "LOW":
            return "NORMAL: Flow metrics adhere to standard benign transport profiles. No defensive intervention required."

        action_prefix = f"Recommended Action: [{action}]. "

        guidance_map = {
            "PORT_SCAN": "Reconnaissance probe detected. Host attempted connection sweeps against varied destination ports. Recommend rate limiting or temporary source isolation.",
            "DOS": "Volumetric Denial of Service flow detected. Traffic displays asymmetric packet rates and rapid connection consumption. Recommend immediate ingress rate-limiting.",
            "DDOS": "Distributed Denial of Service pattern identified. High packet frequency with small variance targeting service endpoint. Ingress throttling and source containment recommended.",
            "BRUTE_FORCE": "Repeated short authentication connections detected on remote access service. Verify endpoint auth logs, enforce fail2ban / IP lock, and require multi-factor auth.",
            "BOTNET": "Suspicious periodic beaconing or C2 communication pattern observed. Isolate affected internal host and inspect active processes.",
            "WEB_ATTACK": "Abnormal flow pattern directed at web service endpoint. Correlate with application reverse-proxy logs (WAF inspection) for SQLi/XSS payload validation.",
            "INFILTRATION": "Potential internal lateral movement or privileged execution flow detected. Initiate threat hunting protocol on source and destination hosts.",
            "OTHER_ATTACK": "Severe protocol exploitation pattern detected (e.g. Heartbleed buffer over-read). Patch target cryptographic daemon immediately."
        }

        specific = guidance_map.get(
            attack_type,
            f"Anomalous network flow identified with {severity} threat profile. Inspect source traffic and verify destination endpoint integrity."
        )
        return action_prefix + specific

    # =========================================================================
    # Threat Intelligence Evidence Synthesis (Phase 8)
    # =========================================================================

    def apply_threat_intel(
        self,
        current_risk: int,
        current_severity: str,
        current_classification: str,
        ti_matches: List[Any]
    ) -> Tuple[int, str, str]:
        """
        Synthesizes Threat Intelligence IOC matches into existing calibrated threat scores.

        Principles:
        1. Non-additive: Evaluates the single dominant (strongest) IOC evidence; never sums matches.
        2. Floor-preserving: If existing risk > IOC floor, existing risk is preserved.
        3. Floor-elevating: If existing risk < IOC floor, the calibrated floor is applied.
        4. Classification integrity: Active IOC matches ensure benign/unknown classification
           is elevated to ATTACK or specific category (HIGH/CRITICAL) or SUSPICIOUS (MEDIUM/LOW).
        """
        if not ti_matches:
            return current_risk, current_severity, current_classification

        dominant_floor = 0
        dominant_match = None

        for match in ti_matches:
            sev = (getattr(match, "severity", None) or "LOW").upper()
            conf = float(getattr(match, "confidence", 0.85))
            conf = max(0.0, min(1.0, conf))

            # Calibrated severity band minimum floors
            if sev == "CRITICAL":
                floor = max(75, int(75 + 25 * conf))
            elif sev == "HIGH":
                floor = max(50, int(50 + 24 * conf))
            elif sev == "MEDIUM":
                floor = max(25, int(25 + 24 * conf))
            else:  # LOW
                floor = max(10, int(10 + 14 * conf))

            if floor > dominant_floor:
                dominant_floor = floor
                dominant_match = match

        # ThreatScorer authority: risk score is the maximum of current risk and the dominant floor
        risk_score = min(100, max(current_risk, dominant_floor))

        # Re-derive severity band based on standard CIPHER bands
        if risk_score <= 24:
            severity = "LOW"
        elif risk_score <= 49:
            severity = "MEDIUM"
        elif risk_score <= 74:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # Update classification: an active IOC match cannot remain BENIGN or UNKNOWN
        classification = current_classification
        if classification in ("BENIGN", "UNKNOWN", "LEGITIMATE"):
            if dominant_match and getattr(dominant_match, "category", None):
                classification = dominant_match.category
            else:
                classification = "ATTACK" if severity in ("HIGH", "CRITICAL") else "SUSPICIOUS"

        return risk_score, severity, classification

    # =========================================================================
    # Email Threat Scoring (Phase 12)
    # =========================================================================

    def calculate_email_risk(
        self,
        ml_phishing_prob: float,
        heuristic_score: int,
        url_risk_scores: Optional[List[int]] = None,
        ti_matches: Optional[List[Any]] = None
    ) -> Tuple[int, str, str, float]:
        """
        Synthesizes Email ML probability, behavioral email heuristics, embedded URL risk scores,
        and Threat Intelligence IOC matches into a calibrated 0-100 risk score and severity band.

        Returns:
            risk_score (int): 0 - 100
            severity (str): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
            classification (str): 'LEGITIMATE' | 'SUSPICIOUS' | 'MALICIOUS_EMAIL'
            model_confidence (float): 0.0 - 1.0
        """
        ml_contribution = ml_phishing_prob * 100.0
        raw_risk = (self.ml_weight * ml_contribution) + (self.heuristic_weight * float(heuristic_score))

        # Heuristic override if strong heuristic evidence
        if heuristic_score >= 70:
            raw_risk = max(raw_risk, float(heuristic_score))

        # Embedded URL risk synthesis
        if url_risk_scores:
            max_url_risk = max(url_risk_scores)
            if max_url_risk >= 70:
                # Embedded URL is confirmed or highly likely phishing
                raw_risk = max(raw_risk, float(max_url_risk))
            elif max_url_risk >= 40:
                # Embedded URL is suspicious - apply elevating pressure
                raw_risk = max(raw_risk, (raw_risk * 0.7) + (max_url_risk * 0.3))

        risk_score = int(round(min(100.0, max(0.0, raw_risk))))

        if ml_phishing_prob >= 0.5:
            model_confidence = round(ml_phishing_prob, 4)
        else:
            model_confidence = round(1.0 - ml_phishing_prob, 4)

        if risk_score <= 24:
            severity = "LOW"
        elif risk_score <= 49:
            severity = "MEDIUM"
        elif risk_score <= 74:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # Classification with heuristic/URL corroboration check to prevent false positives
        has_corroboration = (heuristic_score > 0) or bool(url_risk_scores and max(url_risk_scores) >= 50) or bool(ti_matches)

        if has_corroboration:
            if risk_score >= 60 or ml_phishing_prob >= 0.75:
                classification = "MALICIOUS_EMAIL"
            elif risk_score >= 35 or ml_phishing_prob >= 0.40:
                classification = "SUSPICIOUS"
            else:
                classification = "LEGITIMATE"
        else:
            # Uncorroborated purely statistical signal without any heuristic, URL, or IOC flags
            if risk_score >= 75 or ml_phishing_prob >= 0.85:
                classification = "MALICIOUS_EMAIL"
            elif risk_score >= 40 or ml_phishing_prob >= 0.60:
                classification = "SUSPICIOUS"
            else:
                classification = "LEGITIMATE"

        # Apply Threat Intelligence IOC matching if present
        if ti_matches:
            risk_score, severity, ti_class = self.apply_threat_intel(
                risk_score, severity, classification, ti_matches
            )
            if ti_class in ("ATTACK", "PHISHING"):
                classification = "MALICIOUS_EMAIL"
            elif ti_class == "SUSPICIOUS":
                classification = "SUSPICIOUS"

        return risk_score, severity, classification, model_confidence

    @staticmethod
    def get_email_recommendation(severity: str, classification: str, has_malicious_urls: bool = False) -> str:
        """Produces clear, user-facing security response guidance for email events."""
        if severity == "CRITICAL" or classification == "MALICIOUS_EMAIL":
            if has_malicious_urls:
                return "DANGER: High-confidence phishing email with weaponized embedded URLs. Do not click links, open attachments, or reply. Report to SOC and delete."
            return "DANGER: High probability of phishing or fraudulent solicitation. Do not provide credentials, wire funds, or reply. Flag as malicious."
        elif severity == "HIGH":
            return "WARNING: Suspicious characteristics detected (urgency, credential solicitation, or suspicious sender). Verify authenticity through trusted channels before responding."
        elif severity == "MEDIUM" or classification == "SUSPICIOUS":
            return "CAUTION: Minor anomalies or promotional urgency indicators detected. Verify sender identity before taking requested action."
        else:
            return "SAFE: Email language and link profile conform to legitimate communication patterns. Proceed normally."

