"""
CIPHER Deterministic Network Heuristic Rules
Conservative, evidence-based network heuristics for Port Scanning, Brute Force,
Denial of Service (DoS), Distributed Denial of Service (DDoS), and Suspicious Traffic Anomalies.
"""

from typing import Dict, Any, Optional
from app.rules.models import BaseRule, RuleMatch
from app.rules.config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DOS_PACKET_RATE_THRESHOLD,
    DOS_BYTE_RATE_THRESHOLD,
    DDOS_SOURCES_THRESHOLD,
    AUTH_PORTS,
    IRC_PORTS
)


# =============================================================================
# 1. Port Scan Heuristics
# =============================================================================

class PortScanSweepRule(BaseRule):
    """Detects a single source probing many distinct destination ports within a sliding window."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-PORTSCAN-001",
            name="Multi-Port Reconnaissance Sweep",
            description=f"Detects single source probing >= {PORT_SCAN_THRESHOLD} distinct destination ports within {int(PORT_SCAN_WINDOW_SECONDS)}s.",
            category="PORT_SCAN",
            severity="MEDIUM",
            confidence=0.85,
            tags=["network", "heuristic", "portscan", "reconnaissance"],
            weight=50,
            recommendation="Enforce temporary ingress connection rate-limiting on the probing source IP.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        ctx = context or {}
        distinct_ports = ctx.get("distinct_ports_count", 0)
        source_ip = event.get("source_ip") or "unknown"

        if distinct_ports >= PORT_SCAN_THRESHOLD:
            window = ctx.get("port_sweep_window", PORT_SCAN_WINDOW_SECONDS)
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Source {source_ip} probed {distinct_ports} distinct destination ports within {int(window)}s (threshold: {PORT_SCAN_THRESHOLD}).",
                recommendation=self.recommendation
            )
        return None


class PortScanSynRule(BaseRule):
    """Detects half-open SYN scan probes receiving zero backward response."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-PORTSCAN-002",
            name="Half-Open SYN Scan Probe",
            description="Identifies SYN flag without ACK or backward response on short flow duration.",
            category="PORT_SCAN",
            severity="MEDIUM",
            confidence=0.80,
            tags=["network", "heuristic", "portscan", "syn"],
            weight=45,
            recommendation="Monitor probing source IP for horizontal sweep progression.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        syn = features.get("SYN Flag Count", 0)
        ack = features.get("ACK Flag Count", 0)
        bwd = features.get("Total Backward Packets", 0)
        fwd = features.get("Total Fwd Packets", 0)
        duration = features.get("Flow Duration", 0)
        rst = features.get("RST Flag Count", 0)

        # SYN set without ACK on short duration with zero backward response
        if syn > 0 and ack == 0 and bwd == 0 and duration < 5000:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Half-open SYN probe detected: SYN set with zero ACK and zero backward response (Duration={int(duration)}µs).",
                recommendation=self.recommendation
            )

        # Unresponsive probe flow with RST/SYN
        if bwd == 0 and (rst > 0 or syn > 0) and duration < 10000 and fwd <= 3:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Unresponsive outbound probe flow receiving zero server response (Fwd={int(fwd)}, Duration={int(duration)}µs).",
                recommendation=self.recommendation
            )

        return None


# =============================================================================
# 2. Brute Force Heuristics
# =============================================================================

class BruteForceStormRule(BaseRule):
    """Detects repeated connection bursts against authentication services."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-BRUTEFORCE-001",
            name="Authentication Port Storm",
            description=f"Detects >= {BRUTE_FORCE_THRESHOLD} connection attempts against auth ports (21, 22, 23, 445, 3389) within {int(BRUTE_FORCE_WINDOW_SECONDS)}s.",
            category="BRUTE_FORCE",
            severity="HIGH",
            confidence=0.85,
            tags=["network", "heuristic", "bruteforce", "auth"],
            weight=60,
            recommendation="Verify endpoint authentication logs, enforce rate limiting, and verify MFA.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        dst_port = event.get("destination_port") or int(features.get("Destination Port", 0))

        if dst_port in AUTH_PORTS:
            ctx = context or {}
            attempts = ctx.get("auth_attempts_count", 0)
            if attempts >= BRUTE_FORCE_THRESHOLD:
                window = ctx.get("auth_window", BRUTE_FORCE_WINDOW_SECONDS)
                return RuleMatch(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    weight=self.weight,
                    explanation=f"Possible brute-force activity detected: {attempts} connection attempts targeting auth port {dst_port} within {int(window)}s (threshold: {BRUTE_FORCE_THRESHOLD}).",
                    recommendation=self.recommendation
                )
        return None


class BruteForceChurnRule(BaseRule):
    """Detects rapid short-lived connection retry churn on authentication services."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-BRUTEFORCE-002",
            name="Auth Service Session Churn",
            description="Identifies rapid, short-lived truncated sessions targeting authentication services.",
            category="BRUTE_FORCE",
            severity="MEDIUM",
            confidence=0.75,
            tags=["network", "heuristic", "bruteforce", "churn"],
            weight=50,
            recommendation="Inspect server authentication failure logs for repeated failed logins.",
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
            bwd_pkts = features.get("Total Backward Packets", 0)
            rst = features.get("RST Flag Count", 0)

            if duration < 500000 and fwd_pkts < 10 and (rst > 0 or bwd_pkts <= 2):
                return RuleMatch(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    weight=self.weight,
                    explanation=f"Abnormally truncated session targeting authentication port {dst_port}, characteristic of automated credential retry.",
                    recommendation=self.recommendation
                )
        return None


# =============================================================================
# 3. Denial of Service (DoS) Heuristics
# =============================================================================

class DosPacketRateRule(BaseRule):
    """Detects abnormal forward packet rate exceeding the configured threshold."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-DOS-001",
            name="Extreme Packet Flood Rate",
            description=f"Triggers when packet rate exceeds {int(DOS_PACKET_RATE_THRESHOLD):,} pkts/s.",
            category="DOS",
            severity="CRITICAL",
            confidence=0.90,
            tags=["network", "heuristic", "dos", "rate"],
            weight=70,
            recommendation="Apply immediate rate limiting or upstream ingress traffic filtering.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        flow_pkts = features.get("Flow Packets/s", 0)
        fwd_pkts_s = features.get("Fwd Packets/s", 0)
        max_rate = max(flow_pkts, fwd_pkts_s)
        
        fwd_pkts = features.get("Total Fwd Packets", 0)
        bwd_pkts = features.get("Total Backward Packets", 0)
        total_pkts = fwd_pkts + bwd_pkts

        if max_rate > DOS_PACKET_RATE_THRESHOLD and total_pkts > 50:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Abnormal forward packet rate ({max_rate:,.0f} pkts/s) exceeded the configured DoS threshold ({DOS_PACKET_RATE_THRESHOLD:,.0f} pkts/s).",
                recommendation=self.recommendation
            )
        return None


class DosByteRateRule(BaseRule):
    """Detects volumetric byte rate exceeding the configured threshold."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-DOS-002",
            name="Volumetric Bandwidth Flood",
            description=f"Flags flows exceeding {DOS_BYTE_RATE_THRESHOLD / 1e6:.1f} MB/s volumetric bandwidth.",
            category="DOS",
            severity="HIGH",
            confidence=0.85,
            tags=["network", "heuristic", "dos", "bandwidth"],
            weight=60,
            recommendation="Throttle high-bandwidth flows and inspect connection volume.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        flow_bytes = features.get("Flow Bytes/s", 0)
        
        fwd_pkts = features.get("Total Fwd Packets", 0)
        bwd_pkts = features.get("Total Backward Packets", 0)
        total_pkts = fwd_pkts + bwd_pkts

        if flow_bytes > DOS_BYTE_RATE_THRESHOLD and total_pkts > 50:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Excessive volumetric bandwidth rate ({flow_bytes / 1e6:.2f} MB/s) exceeded configured DoS threshold ({DOS_BYTE_RATE_THRESHOLD / 1e6:.1f} MB/s).",
                recommendation=self.recommendation
            )
        return None


class DosAsymmetricRule(BaseRule):
    """Detects rapid asymmetric request bursts without server response."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-DOS-003",
            name="Asymmetric Flood Burst",
            description="Detects rapid asymmetric request burst with low IAT and zero server reply.",
            category="DOS",
            severity="MEDIUM",
            confidence=0.75,
            tags=["network", "heuristic", "dos", "asymmetric"],
            weight=55,
            recommendation="Inspect server processing capacity and monitor request backlog.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        flow_iat_mean = features.get("Flow IAT Mean", 1e6)
        fwd_pkts = features.get("Total Fwd Packets", 0)
        down_up = features.get("Down/Up Ratio", 0)

        if flow_iat_mean < 50.0 and fwd_pkts > 50 and down_up == 0:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Asymmetric rapid request burst without server reply (Mean IAT={flow_iat_mean:.1f}µs, Fwd={int(fwd_pkts)}, Down/Up=0).",
                recommendation=self.recommendation
            )
        return None


# =============================================================================
# 4. Distributed Denial of Service (DDoS) Multi-Source Rule
# =============================================================================

class DdosMultiSourceRule(BaseRule):
    """Detects multiple distinct source IPs targeting the same destination with high volume."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-DDOS-001",
            name="Distributed Multi-Source Target Flood",
            description=f"Detects >= {DDOS_SOURCES_THRESHOLD} distinct sources targeting the same destination with aggregate high volume.",
            category="DDOS",
            severity="CRITICAL",
            confidence=0.90,
            tags=["network", "heuristic", "ddos", "multi-source"],
            weight=80,
            recommendation="Activate DDoS mitigation profile, inspect boundary routing, and rate-limit distributed ingress.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        ctx = context or {}
        distinct_sources = ctx.get("distinct_sources_targeting_dest_count", 1)
        dest_ip = event.get("destination_ip") or "unknown"
        
        # Ignore multicast and broadcast IPs (e.g. mDNS 224.0.0.251, SSDP 239.255.255.250, broadcast 255.255.255.255)
        # Multicast range is 224.0.0.0 to 239.255.255.255.
        if dest_ip.startswith("224.") or dest_ip.startswith("239.") or dest_ip.endswith(".255"):
            return None

        if distinct_sources >= DDOS_SOURCES_THRESHOLD:
            window = ctx.get("ddos_window", 60.0)
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Distributed flood pattern detected: {distinct_sources} distinct sources targeting destination {dest_ip} within {int(window)}s.",
                recommendation=self.recommendation
            )
        return None


# =============================================================================
# 5. Suspicious Traffic Anomalies
# =============================================================================

class SuspiciousFlagsRule(BaseRule):
    """Detects illegal TCP flag combinations characteristic of evasion scanning."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-SUSPICIOUS-001",
            name="Abnormal TCP Flags Anomaly",
            description="Identifies abnormal or illegal TCP flag combinations (e.g. SYN and FIN set simultaneously).",
            category="SUSPICIOUS",
            severity="LOW",
            confidence=0.70,
            tags=["network", "heuristic", "tcp", "flags"],
            weight=35,
            recommendation="Inspect client transport stack for non-standard packet crafting or scanner evasion tools.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        syn = features.get("SYN Flag Count", 0)
        fin = features.get("FIN Flag Count", 0)

        # SYN + FIN simultaneously set is standard evasion scan technique (RFC 793 violation)
        if syn > 0 and fin > 0:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation="Illegal TCP flag combination (SYN and FIN simultaneously set), characteristic of scanner evasion.",
                recommendation=self.recommendation
            )
        return None


class SuspiciousIrcRule(BaseRule):
    """Detects outbound connections to legacy IRC service ports."""

    def __init__(self):
        super().__init__(
            rule_id="HEUR-SUSPICIOUS-002",
            name="Suspicious Legacy IRC Communication",
            description="Identifies outbound communication targeting legacy IRC ports (6667, 6668, 6669, 7000).",
            category="SUSPICIOUS",
            severity="LOW",
            confidence=0.60,
            tags=["network", "heuristic", "irc", "suspicious"],
            weight=25,
            recommendation="Verify whether outbound legacy IRC traffic is authorized on the internal network.",
            target_event_type="NETWORK"
        )

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if not self.enabled:
            return None

        features = event.get("features") or {}
        dst_port = event.get("destination_port") or int(features.get("Destination Port", 0))

        if dst_port in IRC_PORTS:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                weight=self.weight,
                explanation=f"Outbound flow targeting legacy IRC port {dst_port}. Legacy IRC transport is deprecated and uncommon in standard workstations.",
                recommendation=self.recommendation
            )
        return None
