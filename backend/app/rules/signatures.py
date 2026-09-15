"""
CIPHER Deterministic Signatures
Targeted, evidence-backed signatures for network flow profiles and phishing URL structures.
"""

import re
import urllib.parse
from typing import Dict, Any, Optional
from app.rules.models import BaseRule, RuleMatch
from app.rules.config import AUTH_PORTS, WEB_PORTS


class PortScanSignature(BaseRule):
    """Deterministic signature for automated port scan reconnaissance probes."""

    def __init__(self):
        super().__init__(
            rule_id="SIGN-PORTSCAN-001",
            name="Port Reconnaissance Probe Signature",
            description="Matches flow fingerprint of automated port reconnaissance probes.",
            category="PORT_SCAN",
            severity="MEDIUM",
            confidence=0.85,
            tags=["network", "signature", "portscan"],
            weight=50,
            recommendation="Log probe details and verify firewall ingress policy.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        syn = features.get("SYN Flag Count", 0)
        ack = features.get("ACK Flag Count", 0)
        bwd = features.get("Total Backward Packets", 0)
        duration = features.get("Flow Duration", 0)

        # Explicit signature: SYN set, ACK=0, Bwd=0, Duration < 5000µs
        if syn > 0 and ack == 0 and bwd == 0 and duration < 5000:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation="Signature match: Half-open SYN connection probe characteristic of automated port reconnaissance tools.",
                recommendation=self.recommendation
            )
        return None


class BruteForceSignature(BaseRule):
    """Deterministic signature for rapid authentication service connection churn."""

    def __init__(self):
        super().__init__(
            rule_id="SIGN-BRUTEFORCE-001",
            name="Auth Service Retry Signature",
            description="Matches high-frequency credential retry pattern on authentication service ports.",
            category="BRUTE_FORCE",
            severity="HIGH",
            confidence=0.85,
            tags=["network", "signature", "bruteforce"],
            weight=60,
            recommendation="Enforce IP lockout and require multi-factor authentication.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        dst_port = event.get("destination_port") or int(features.get("Destination Port", 0))

        if dst_port in AUTH_PORTS:
            duration = features.get("Flow Duration", 0)
            fwd_pkts = features.get("Total Fwd Packets", 0)
            rst = features.get("RST Flag Count", 0)

            if duration < 200000 and fwd_pkts <= 5 and rst > 0:
                return RuleMatch(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    weight=self.weight,
                    explanation=f"Signature match: Rapid truncated connection session on auth port {dst_port} with immediate reset.",
                    recommendation=self.recommendation
                )
        return None


class WebServiceSignature(BaseRule):
    """Deterministic signature for elevated web service request intensity."""

    def __init__(self):
        super().__init__(
            rule_id="SIGN-WEB-001",
            name="Web Service Anomaly Signature",
            description="Matches elevated request burst rate on standard web ports (80, 443, 8080, 8443).",
            category="WEB_ATTACK",
            severity="LOW",
            confidence=0.65,
            tags=["network", "signature", "web"],
            weight=30,
            recommendation="Correlate with application reverse-proxy WAF logs for detailed payload inspection.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        dst_port = event.get("destination_port") or int(features.get("Destination Port", 0))

        if dst_port in WEB_PORTS:
            flow_pkts = features.get("Flow Packets/s", 0)
            fwd_pkts = features.get("Total Fwd Packets", 0)

            if flow_pkts > 1000 or fwd_pkts > 100:
                return RuleMatch(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    weight=self.weight,
                    explanation=f"Signature match: Elevated transaction intensity directed at Web service port {dst_port}.",
                    recommendation=self.recommendation
                )
        return None


class PhishingIpHostSignature(BaseRule):
    """
    Deterministic signature for raw IPv4 address used in URL domain hostname.
    Evaluated strictly on PHISHING events; never forced onto network flow events.
    """

    def __init__(self):
        super().__init__(
            rule_id="SIGN-PHISH-001",
            name="Raw IPv4 Hostname Signature",
            description="Identifies raw IPv4 addresses used directly in URL hostname instead of domain names.",
            category="PHISHING",
            severity="HIGH",
            confidence=0.90,
            tags=["phishing", "signature", "ip-host"],
            weight=70,
            recommendation="Block URL access; legitimate web services rarely require users to browse directly to bare IP addresses.",
            target_event_type="PHISHING"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        domain = event.get("domain") or ""
        url = event.get("url") or ""

        target_host = ""
        if domain:
            target_host = domain.strip().lower()
        elif url:
            url_str = url.strip()
            if "://" not in url_str:
                url_str = f"http://{url_str}"
            try:
                parsed = urllib.parse.urlparse(url_str)
                target_host = (parsed.netloc or "").split(":")[0].lower()
            except Exception:
                target_host = ""

        if target_host:
            ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ipv4_pattern, target_host):
                return RuleMatch(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    weight=self.weight,
                    explanation=f"Signature match: Raw IPv4 address [{target_host}] used directly in URL hostname to bypass domain reputation checks.",
                    recommendation=self.recommendation
                )
        return None
