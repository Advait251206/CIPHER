"""
CIPHER Email Explanation Service
Synthesizes explainable, evidence-backed security explanations from extracted email features,
embedded URL analysis results, and threat intelligence matches.
Deterministic, human-auditable, and strictly tied to actual detection signals.
"""

from typing import Dict, Any, List, Optional


class EmailExplanationService:
    """Generates transparent security rationale for email analyses."""

    def generate_explanations(
        self,
        features: Dict[str, float],
        url_results: Optional[List[Dict[str, Any]]] = None,
        ti_matches: Optional[List[Any]] = None,
        ml_prob: float = 0.0,
        classification: str = "LEGITIMATE"
    ) -> List[str]:
        """
        Derives human-readable explanation bullets strictly corresponding
        to active feature triggers, URL inspection outcomes, and threat intelligence.
        """
        reasons = []

        # 1. Threat Intelligence Indicators
        if ti_matches:
            for match in ti_matches:
                indicator = getattr(match, "indicator", "Target indicator")
                category = getattr(match, "category", "THREAT")
                sev = getattr(match, "severity", "HIGH")
                reasons.append(f"Threat intelligence match: known malicious {category} indicator '{indicator}' ({sev} severity)")

        # 2. Weaponized or Suspicious Embedded URLs
        if url_results:
            phish_urls = [u for u in url_results if u.get("classification") == "LIKELY_PHISHING"]
            susp_urls = [u for u in url_results if u.get("classification") == "SUSPICIOUS"]
            
            for u in phish_urls:
                reasons.append(f"Weaponized URL identified: '{u.get('url')}' classified as LIKELY_PHISHING (Risk: {u.get('risk_score', 0)}/100)")
            for u in susp_urls:
                reasons.append(f"Suspicious embedded URL: '{u.get('url')}' flagged with risk score {u.get('risk_score', 0)}/100")

        # 3. Behavioral and Semantic Linguistic Triggers
        if features.get("urgency_term_count", 0) > 0:
            count = int(features["urgency_term_count"])
            reasons.append(f"Urgent/time-pressuring language detected ({count} indicator{'s' if count > 1 else ''})")

        if features.get("threat_term_count", 0) > 0:
            count = int(features["threat_term_count"])
            reasons.append(f"Coercive account-threat / penalty language identified ({count} indicator{'s' if count > 1 else ''})")

        if features.get("credential_term_count", 0) > 0:
            count = int(features["credential_term_count"])
            reasons.append(f"Credential solicitation / password authentication request detected ({count} indicator{'s' if count > 1 else ''})")

        if features.get("financial_term_count", 0) > 0:
            count = int(features["financial_term_count"])
            reasons.append(f"Financial transfer or invoice solicitation terminology detected ({count} indicator{'s' if count > 1 else ''})")

        if features.get("suspicious_cta_count", 0) > 0:
            count = int(features["suspicious_cta_count"])
            reasons.append(f"High-pressure call-to-action detected ({count} call{'s' if count > 1 else ''} to 'click here' / verify)")

        # 4. URL & Link Structure Anomalies
        if features.get("ip_url_count", 0) > 0:
            reasons.append("Embedded link uses a raw IP address instead of a trusted domain hostname")

        if features.get("at_symbol_url_count", 0) > 0:
            reasons.append("Embedded URL contains '@' symbol indicating potential URL authority redirection trick")

        if features.get("suspicious_tld_url_count", 0) > 0:
            reasons.append("Embedded link utilizes a high-risk or commonly abused top-level domain (TLD)")

        # 5. Sender Profile & Impersonation Anomalies
        if features.get("sender_display_name_mismatch", 0) > 0:
            reasons.append("Sender display-name mismatch: claims corporate or banking brand identity from an unverified domain")

        if features.get("has_ip_sender", 0) > 0:
            reasons.append("Sender address contains an unverified numerical IP address")

        # 6. HTML Concealment
        if features.get("hidden_text_indicators", 0) > 0:
            reasons.append("Concealed styling detected: email contains hidden elements (zero font-size or hidden visibility)")

        # 7. Fallbacks and Benign Rationale
        if not reasons:
            if classification == "LEGITIMATE":
                reasons.append("Email lexical patterns conform to standard benign communication")
                reasons.append("No credential harvesting, urgent coercion, or suspicious links detected")
                if features.get("has_urls", 0) > 0:
                    reasons.append("Embedded links verified benign with standard URL structures")
            elif classification == "SUSPICIOUS":
                reasons.append("Statistical feature distribution indicates mild elevation above benign baseline")
            else:
                reasons.append(f"Machine learning model flagged statistical email anomalies (Probability: {ml_prob*100:.1f}%)")

        return reasons
