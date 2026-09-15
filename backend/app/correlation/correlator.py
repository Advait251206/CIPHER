"""
CIPHER Event Correlation Engine
Implements safe, multi-dimensional security event correlation, sliding time windows,
attack diversity scoring, potential attack escalation detection, and bounded memory management.
"""

import os
import uuid
import logging
import threading
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timezone

from app.correlation.models import NormalizedEvent, IncidentItem

logger = logging.getLogger("cipher.correlation.correlator")

# Configurable correlation time window (default 300 seconds / 5 minutes)
DEFAULT_CORRELATION_WINDOW_SECONDS = int(os.getenv("CIPHER_CORRELATION_WINDOW", 300))
MAX_ACTIVE_CHAINS = int(os.getenv("CIPHER_MAX_ACTIVE_CHAINS", 10000))

# Escalation sequences (Stage transitions indicating potential attack progression)
# We treat these as potential escalation signals, avoiding definitive attribution claims.
ESCALATION_SEQUENCES: List[Tuple[str, str]] = [
    ("PORT_SCAN", "BRUTE_FORCE"),
    ("PORT_SCAN", "DOS"),
    ("PORT_SCAN", "DDOS"),
    ("PORT_SCAN", "WEB_ATTACK"),
    ("BRUTE_FORCE", "DOS"),
    ("BRUTE_FORCE", "DDOS"),
    ("BRUTE_FORCE", "INFILTRATION"),
    ("PHISHING", "INFILTRATION"),
    ("PHISHING", "BOTNET"),
]


class CorrelatedChain:
    """Internal working state for an active event correlation chain."""

    def __init__(self, incident_id: str, correlation_key: str, initial_event: NormalizedEvent):
        self.incident_id = incident_id
        self.correlation_key = correlation_key
        self.events: List[NormalizedEvent] = [initial_event]
        self.source_ip = initial_event.source_ip
        self.destination_ip = initial_event.destination_ip
        self.domain = initial_event.domain
        self.created_at = initial_event.timestamp
        self.first_seen = initial_event.timestamp
        self.last_seen = initial_event.timestamp
        self.status = "OPEN"
        self.escalation_detected = False
        self.correlation_score = initial_event.risk_score
        self.severity = initial_event.severity
        self.confidence = initial_event.confidence
        self.recommended_action: Optional[str] = None
        self.applied_action: Optional[str] = None
        self.summary: str = ""

    def add_event(self, event: NormalizedEvent):
        self.events.append(event)
        self.last_seen = event.timestamp


class EventCorrelator:
    """
    Stateful, thread-safe, bounded event correlator.
    Evaluates incoming normalized events against active correlation chains.
    Enforces strict identity rules (e.g. (source_ip, destination_ip)) to prevent
    unrelated incidents from merging solely due to a shared source IP.
    """

    def __init__(self, window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self._lock = threading.RLock()
        self._active_chains: Dict[str, CorrelatedChain] = {}
        # Secondary tracker: source_ip -> list of (timestamp_dt, destination_ip, attack_category)
        self._source_activity: Dict[str, List[Tuple[datetime, Optional[str], str]]] = {}

    def get_correlation_key(self, event: NormalizedEvent) -> str:
        """
        Determines the safe correlation identity for an event.
        
        Rules:
        - Network events prefer (source_ip, destination_ip).
        - Different destination systems create separate incident chains.
        - Phishing events prefer domain/url.
        - Do NOT correlate solely by source_ip alone.
        """
        if event.source_ip and event.destination_ip:
            # Primary network correlation identity: (source_ip, destination_ip)
            return f"net:{event.source_ip}->{event.destination_ip}"
        
        if event.source_ip and not event.destination_ip:
            # Fallback when destination is truly absent
            return f"net_src:{event.source_ip}"

        if event.domain:
            norm_domain = event.domain.strip().lower()
            if norm_domain.startswith("www."):
                norm_domain = norm_domain[4:]
            return f"phish:{norm_domain}"

        if event.url:
            return f"url:{event.url.strip().lower()}"

        # Generic fallback isolating specific events
        return f"generic:{event.source}:{event.event_id}"

    def process_event(self, event: NormalizedEvent) -> Tuple[CorrelatedChain, bool]:
        """
        Processes a single normalized event.
        Returns:
            (chain, is_new_incident)
        """
        with self._lock:
            self._prune_expired()

            corr_key = self.get_correlation_key(event)
            event_dt = self._parse_iso(event.timestamp)

            # Secondary source tracking for multi-target sweeps/reconnaissance
            if event.source_ip:
                if event.source_ip not in self._source_activity:
                    self._source_activity[event.source_ip] = []
                self._source_activity[event.source_ip].append(
                    (event_dt, event.destination_ip, event.attack_category)
                )

            chain = self._active_chains.get(corr_key)
            is_new = False

            if chain is not None:
                # Check if event is within the correlation window from chain.last_seen
                chain_last_dt = self._parse_iso(chain.last_seen)
                time_diff = (event_dt - chain_last_dt).total_seconds()

                if 0 <= time_diff <= self.window_seconds:
                    # Valid temporal correlation within window
                    chain.add_event(event)
                else:
                    # Outside time window - close previous chain and start new one
                    chain.status = "RESOLVED"
                    is_new = True
                    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
                    chain = CorrelatedChain(incident_id, corr_key, event)
                    self._active_chains[corr_key] = chain
            else:
                # First event for this correlation key
                is_new = True
                incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
                chain = CorrelatedChain(incident_id, corr_key, event)
                self._active_chains[corr_key] = chain

            # Recalculate correlation metrics for the chain
            self._evaluate_chain(chain, event_dt)

            return chain, is_new

    def get_active_chain(self, correlation_key: str) -> Optional[CorrelatedChain]:
        with self._lock:
            return self._active_chains.get(correlation_key)

    def resolve_chain(self, incident_id: str) -> bool:
        """Explicitly marks a chain as resolved."""
        with self._lock:
            for key, chain in list(self._active_chains.items()):
                if chain.incident_id == incident_id:
                    chain.status = "RESOLVED"
                    del self._active_chains[key]
                    return True
            return False

    def _evaluate_chain(self, chain: CorrelatedChain, current_dt: datetime):
        """
        Computes the bounded correlation score (0-100), detects escalation patterns,
        attack diversity, repetition, and synthesizes a concise security summary.
        """
        events = chain.events
        n_events = len(events)

        # 1. Base Score: Maximum of underlying event risk scores
        base_score = max((e.risk_score for e in events), default=0)

        # 2. Repetition Contribution:
        # Same attack repeated adds bounded points (+4 per repetition up to max +20)
        attack_counts: Dict[str, int] = {}
        for e in events:
            cat = e.attack_category
            attack_counts[cat] = attack_counts.get(cat, 0) + 1

        repetition_bonus = min(20, sum((count - 1) * 4 for count in attack_counts.values() if count > 1))

        # 3. Attack Diversity Contribution:
        # Multiple distinct attack categories from the same source to the same target
        distinct_categories = [cat for cat in attack_counts.keys() if cat not in ("BENIGN", "UNKNOWN")]
        diversity_bonus = 0
        if len(distinct_categories) == 2:
            diversity_bonus = 10
        elif len(distinct_categories) >= 3:
            diversity_bonus = 20

        # 4. Attack Escalation Detection:
        # Check chronological sequence of non-benign attack categories
        escalation_detected = False
        categories_in_order = [e.attack_category for e in events if e.attack_category not in ("BENIGN", "UNKNOWN")]
        
        for i in range(len(categories_in_order) - 1):
            pair = (categories_in_order[i], categories_in_order[i + 1])
            if pair in ESCALATION_SEQUENCES:
                escalation_detected = True
                break

        chain.escalation_detected = escalation_detected
        escalation_bonus = 15 if escalation_detected else 0

        # 5. Secondary Source Activity Signal (Sweep / Multi-target reconnaissance):
        # We do NOT merge incidents across different destination IPs, but we detect
        # if the same source IP is actively targeting multiple destinations in the correlation window.
        sweep_bonus = 0
        sweep_detected = False
        if chain.source_ip and chain.source_ip in self._source_activity:
            recent_acts = self._source_activity[chain.source_ip]
            destinations = {dest for _, dest, _ in recent_acts if dest is not None and dest != chain.destination_ip}
            if len(destinations) >= 1:
                # Source has targeted at least one other destination within the window
                sweep_bonus = 5
                sweep_detected = True

        # 6. Temporal Proximity Bonus:
        # Events occurring in rapid succession (e.g. <= 60 seconds between first and last)
        first_dt = self._parse_iso(chain.first_seen)
        last_dt = self._parse_iso(chain.last_seen)
        duration_secs = max(0.0, (last_dt - first_dt).total_seconds())
        temporal_bonus = 5 if (n_events > 1 and duration_secs <= 60) else 0

        # 7. Final Bounded Correlation Score [0 - 100]
        raw_score = base_score + repetition_bonus + diversity_bonus + escalation_bonus + sweep_bonus + temporal_bonus
        chain.correlation_score = max(0, min(100, int(raw_score)))

        # 8. Correlated Severity Mapping
        if chain.correlation_score >= 85:
            chain.severity = "CRITICAL"
        elif chain.correlation_score >= 60:
            chain.severity = "HIGH"
        elif chain.correlation_score >= 35:
            chain.severity = "MEDIUM"
        else:
            chain.severity = "LOW"

        # 9. Aggregate Confidence (Independent probability combination bounded to [0.0, 0.99])
        # P = 1 - product(1 - 0.85 * c_i)
        p_not = 1.0
        for e in events:
            eff_conf = max(0.0, min(0.95, e.confidence))
            p_not *= (1.0 - 0.85 * eff_conf)
        chain.confidence = round(max(0.0, min(0.99, 1.0 - p_not)), 3)

        # 10. Synthesize Structured Explanation / Summary
        cats_str = ", ".join(sorted(set(e.attack_category for e in events)))
        if escalation_detected:
            chain.summary = (
                f"Potential attack escalation detected: correlated activity progression "
                f"[{cats_str}] observed ({n_events} events, window {int(duration_secs)}s)."
            )
        elif diversity_bonus > 0:
            chain.summary = (
                f"Correlated multi-vector activity detected across categories [{cats_str}] "
                f"({n_events} events, window {int(duration_secs)}s)."
            )
        elif n_events > 1:
            chain.summary = (
                f"Repeated correlated suspicious activity detected for category [{cats_str}] "
                f"({n_events} events, window {int(duration_secs)}s)."
            )
        else:
            chain.summary = (
                f"Security event recorded for category [{cats_str}] "
                f"with severity {chain.severity}."
            )

        if sweep_detected:
            chain.summary += f" Source {chain.source_ip} also observed targeting other destinations."

    def _prune_expired(self):
        """Prunes chains older than the correlation window and maintains bounded capacity."""
        now = datetime.now(timezone.utc)
        expired_keys = []

        # 1. Window-based expiration
        for key, chain in self._active_chains.items():
            chain_last_dt = self._parse_iso(chain.last_seen)
            if (now - chain_last_dt).total_seconds() > (self.window_seconds * 1.5):
                expired_keys.append(key)

        for key in expired_keys:
            del self._active_chains[key]

        # 2. Secondary source tracker cleanup
        for src, act_list in list(self._source_activity.items()):
            fresh_acts = [
                (t, d, a) for (t, d, a) in act_list 
                if (now - t).total_seconds() <= (self.window_seconds * 1.5)
            ]
            if fresh_acts:
                self._source_activity[src] = fresh_acts
            else:
                del self._source_activity[src]

        # 3. Capacity bounding (LRU-like shedding if active chains exceed threshold)
        if len(self._active_chains) > MAX_ACTIVE_CHAINS:
            # Sort by last_seen ascending (oldest first)
            sorted_chains = sorted(
                self._active_chains.items(),
                key=lambda item: self._parse_iso(item[1].last_seen)
            )
            excess = len(self._active_chains) - MAX_ACTIVE_CHAINS
            for k, _ in sorted_chains[:excess]:
                del self._active_chains[k]

    @staticmethod
    def _parse_iso(ts_str: str) -> datetime:
        """Parses ISO 8601 string or returns current UTC time on error."""
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            # Handle standard ISO formats
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            return datetime.fromisoformat(ts_str)
        except Exception:
            return datetime.now(timezone.utc)
