"""
CIPHER Heuristic + Signature Rule Engine
Provides stateful temporal tracking, thread-safe deterministic rule evaluation,
rule registry management, and bounded memory management.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Union

from app.rules.models import BaseRule, RuleMatch, RuleItem
from app.rules.config import (
    PORT_SCAN_WINDOW_SECONDS,
    BRUTE_FORCE_WINDOW_SECONDS,
    DDOS_WINDOW_SECONDS,
    MAX_STATE_ENTRIES
)
from app.rules.heuristics import (
    PortScanSweepRule,
    PortScanSynRule,
    BruteForceStormRule,
    BruteForceChurnRule,
    DosPacketRateRule,
    DosByteRateRule,
    DosAsymmetricRule,
    DdosMultiSourceRule,
    SuspiciousFlagsRule,
    SuspiciousIrcRule
)
from app.rules.signatures import (
    PortScanSignature,
    BruteForceSignature,
    WebServiceSignature,
    PhishingIpHostSignature
)

logger = logging.getLogger("cipher.rules.engine")


class RuleEngine:
    """
    Deterministic rule engine that matches events against registered heuristic
    and signature rules with temporal state tracking and bounded memory.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._rules: Dict[str, BaseRule] = {}

        # Stateful sliding-window trackers
        # 1. source_ip -> list of (timestamp_epoch, destination_port)
        self._source_ports: Dict[str, List[Tuple[float, int]]] = {}
        # 2. (source_ip, dest_ip, dest_port) -> list of timestamp_epoch
        self._auth_attempts: Dict[Tuple[str, str, int], List[float]] = {}
        # 3. dest_ip -> list of (timestamp_epoch, source_ip)
        self._dest_sources: Dict[str, List[Tuple[float, str]]] = {}

        # Register default conservative rules
        self._register_default_rules()
        logger.info(f"Initialized CIPHER Rule Engine with {len(self._rules)} default rules.")

    def _register_default_rules(self):
        default_rules: List[BaseRule] = [
            # Port Scan Heuristics
            PortScanSweepRule(),
            PortScanSynRule(),
            # Brute Force Heuristics
            BruteForceStormRule(),
            BruteForceChurnRule(),
            # DoS Heuristics
            DosPacketRateRule(),
            DosByteRateRule(),
            DosAsymmetricRule(),
            # DDoS Multi-Source Heuristic
            DdosMultiSourceRule(),
            # Suspicious Anomalies
            SuspiciousFlagsRule(),
            SuspiciousIrcRule(),
            # Signatures
            PortScanSignature(),
            BruteForceSignature(),
            WebServiceSignature(),
            PhishingIpHostSignature()
        ]
        for rule in default_rules:
            self.register_rule(rule)

    def register_rule(self, rule: BaseRule):
        """Registers a rule in the engine registry."""
        with self._lock:
            self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Retrieves a single rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[BaseRule]:
        """Lists all registered rules."""
        with self._lock:
            return list(self._rules.values())

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Enables or disables a specific rule."""
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule:
                rule.enabled = enabled
                logger.info(f"Rule {rule_id} enabled set to: {enabled}")
                return True
            return False

    def evaluate(self, event_input: Union[Dict[str, Any], Any]) -> List[RuleMatch]:
        """
        Evaluates enabled rules against an event.
        Guarantees that input event is never mutated.
        Returns a list of RuleMatch objects.
        """
        # Safely convert to dictionary if needed
        if hasattr(event_input, "model_dump"):
            raw_event = event_input.model_dump()
        elif hasattr(event_input, "dict"):
            raw_event = event_input.dict()
        elif isinstance(event_input, dict):
            raw_event = dict(event_input)
        else:
            raw_event = {}

        # Determine event type
        source = str(raw_event.get("source") or "").lower()
        ev_type = str(raw_event.get("event_type") or "").upper()
        if "phish" in source or "phish" in ev_type.lower() or (raw_event.get("domain") and not raw_event.get("source_ip")):
            target_type = "PHISHING"
        else:
            target_type = "NETWORK"

        # Sanitize features to dictionary
        features = raw_event.get("features")
        if not isinstance(features, dict):
            raw_event["features"] = {}

        now = time.time()
        context: Dict[str, Any] = {}

        with self._lock:
            # 1. Update stateful temporal trackers for network events
            if target_type == "NETWORK":
                context = self._update_and_build_context(raw_event, now)

            # 2. Evaluate active rules matching the event type
            matches: List[RuleMatch] = []
            for rule in self._rules.values():
                if not rule.enabled:
                    continue

                if rule.target_event_type not in (target_type, "ALL"):
                    continue

                try:
                    match = rule.evaluate(raw_event, context)
                    if match:
                        matches.append(match)
                except Exception as e:
                    logger.warning(f"Error evaluating rule {rule.rule_id}: {e}")

            return matches

    def _update_and_build_context(self, event: Dict[str, Any], now: float) -> Dict[str, Any]:
        """Updates internal sliding-window state and generates rule context dictionary."""
        source_ip = event.get("source_ip")
        dest_ip = event.get("destination_ip")
        features = event.get("features")
        if not isinstance(features, dict):
            features = {}
        dest_port_val = event.get("destination_port")
        if dest_port_val is not None:
            try:
                dest_port = int(dest_port_val)
            except (ValueError, TypeError):
                dest_port = 0
        else:
            try:
                dest_port = int(features.get("Destination Port", 0))
            except (ValueError, TypeError):
                dest_port = 0

        context: Dict[str, Any] = {
            "distinct_ports_count": 0,
            "auth_attempts_count": 0,
            "distinct_sources_targeting_dest_count": 0,
            "port_sweep_window": PORT_SCAN_WINDOW_SECONDS,
            "auth_window": BRUTE_FORCE_WINDOW_SECONDS,
            "ddos_window": DDOS_WINDOW_SECONDS
        }

        # 1. Update Port Sweep Tracker
        if source_ip and dest_port > 0:
            if source_ip not in self._source_ports:
                self._source_ports[source_ip] = []
            self._source_ports[source_ip].append((now, dest_port))

            # Prune expired entries
            cutoff = now - PORT_SCAN_WINDOW_SECONDS
            self._source_ports[source_ip] = [
                (t, p) for (t, p) in self._source_ports[source_ip] if t >= cutoff
            ]
            distinct_ports = {p for (_, p) in self._source_ports[source_ip]}
            context["distinct_ports_count"] = len(distinct_ports)

        # 2. Update Brute Force Auth Tracker
        if source_ip and dest_ip and dest_port > 0:
            auth_key = (source_ip, dest_ip, dest_port)
            if auth_key not in self._auth_attempts:
                self._auth_attempts[auth_key] = []
            self._auth_attempts[auth_key].append(now)

            cutoff_auth = now - BRUTE_FORCE_WINDOW_SECONDS
            self._auth_attempts[auth_key] = [
                t for t in self._auth_attempts[auth_key] if t >= cutoff_auth
            ]
            context["auth_attempts_count"] = len(self._auth_attempts[auth_key])

        # 3. Update Multi-Source DDoS Tracker
        if dest_ip and source_ip:
            if dest_ip not in self._dest_sources:
                self._dest_sources[dest_ip] = []
            self._dest_sources[dest_ip].append((now, source_ip))

            cutoff_ddos = now - DDOS_WINDOW_SECONDS
            self._dest_sources[dest_ip] = [
                (t, s) for (t, s) in self._dest_sources[dest_ip] if t >= cutoff_ddos
            ]
            distinct_sources = {s for (_, s) in self._dest_sources[dest_ip]}
            context["distinct_sources_targeting_dest_count"] = len(distinct_sources)

        # Memory Bounding
        self._bound_state_entries()

        return context

    def _bound_state_entries(self):
        """Enforces MAX_STATE_ENTRIES cap on internal tracking structures."""
        if len(self._source_ports) > MAX_STATE_ENTRIES:
            excess = len(self._source_ports) - MAX_STATE_ENTRIES
            for k in list(self._source_ports.keys())[:excess]:
                del self._source_ports[k]

        if len(self._auth_attempts) > MAX_STATE_ENTRIES:
            excess = len(self._auth_attempts) - MAX_STATE_ENTRIES
            for k in list(self._auth_attempts.keys())[:excess]:
                del self._auth_attempts[k]

        if len(self._dest_sources) > MAX_STATE_ENTRIES:
            excess = len(self._dest_sources) - MAX_STATE_ENTRIES
            for k in list(self._dest_sources.keys())[:excess]:
                del self._dest_sources[k]


# Singleton instance
_rule_engine_instance: Optional[RuleEngine] = None


def get_rule_engine() -> RuleEngine:
    global _rule_engine_instance
    if _rule_engine_instance is None:
        _rule_engine_instance = RuleEngine()
    return _rule_engine_instance
