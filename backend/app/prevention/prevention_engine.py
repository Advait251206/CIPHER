"""
CIPHER Intrusion Prevention Engine
Coordinates defensive responses based on threat score, attack taxonomy,
and operational mode (detect_only, simulate, enforce).

Safety model
- The default and fail-safe mode is `detect_only`. A missing or invalid
  CIPHER_PREVENTION_MODE never results in `enforce`.
- `simulate` records would-be blocks in SQLite only. It never touches the host.
- `enforce` is the only mode that creates host firewall rules, and never for
  protected addresses (see app.prevention.blocklist.validate_block_target).
- One engine instance is shared process-wide (get_prevention_engine), so the
  dashboard's mode switch applies to the API, the live sensor, the WAF and the
  correlation layer alike.
- RATE_LIMIT is advisory: it is recommended and logged, not enforced.
"""

import os
import logging
import threading
from typing import Dict, Any, Optional

from app.prevention.actions import PreventionAction, PreventionMode
from app.prevention.blocklist import IPBlocklistManager, ProtectedAddressError

logger = logging.getLogger("cipher.prevention")

VALID_MODES = {m.value for m in PreventionMode}


def resolve_mode(value: Optional[str]) -> str:
    """Normalizes a mode string; anything missing or invalid falls back to detect_only."""
    if value is None or not str(value).strip():
        return PreventionMode.DETECT_ONLY.value
    mode = str(value).strip().lower()
    if mode not in VALID_MODES:
        logger.error(
            f"Invalid prevention mode {value!r}; valid modes are {sorted(VALID_MODES)}. "
            f"Falling back to the safe default 'detect_only'."
        )
        return PreventionMode.DETECT_ONLY.value
    return mode


class PreventionEngine:
    """Decides and executes defensive IPS responses safely."""

    def __init__(
        self,
        blocklist_manager: Optional[IPBlocklistManager] = None,
        rate_limiter=None,
        mode: Optional[str] = None
    ):
        from app.prevention.rate_limiter import FlowRateLimiter

        self.blocklist = blocklist_manager or IPBlocklistManager()
        self.rate_limiter = rate_limiter or FlowRateLimiter()
        self._mode = resolve_mode(mode if mode is not None else os.getenv("CIPHER_PREVENTION_MODE"))
        self.default_block_minutes = int(os.getenv("DEFAULT_TEMP_BLOCK_MINUTES", "60"))
        self.auto_threat_intel = os.getenv("CIPHER_AUTO_THREAT_INTEL_FROM_BLOCKS", "false").lower() in ("1", "true", "yes")
        logger.info(f"Initialized CIPHER Prevention Engine in [{self._mode.upper()}] mode")

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str) -> None:
        new_mode = str(value).strip().lower()
        if new_mode not in VALID_MODES:
            raise ValueError(f"Invalid prevention mode '{value}'. Must be one of {sorted(VALID_MODES)}")
        if new_mode != self._mode:
            logger.warning(f"Prevention mode changed: {self._mode} -> {new_mode}")
        self._mode = new_mode

    # ------------------------------------------------------------------
    # Containment primitives (mode-aware)
    # ------------------------------------------------------------------

    def contain_ip(
        self,
        ip: Optional[str],
        reason: str,
        attack_type: str,
        threat_score: int,
        duration_minutes: Optional[int] = None,
        event_id: Optional[str] = None,
        is_permanent: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Automatic containment. detect_only: nothing. simulate: blocklist record only.
        enforce: blocklist record + host firewall rule. Protected/invalid IPs are skipped.
        """
        if not ip or self._mode == PreventionMode.DETECT_ONLY.value:
            return None
        simulate = self._mode == PreventionMode.SIMULATE.value
        try:
            return self.blocklist.block_ip(
                ip=ip,
                reason=f"[SIMULATION] {reason}" if simulate else reason,
                attack_type=attack_type,
                threat_score=threat_score,
                duration_minutes=None if is_permanent else (duration_minutes or self.default_block_minutes),
                source_event_id=event_id,
                is_permanent=is_permanent,
                apply_os_rule=(self._mode == PreventionMode.ENFORCE.value)
            )
        except ValueError as e:
            logger.warning(f"[IPS] Containment of {ip} skipped: {e}")
            return None

    def manual_block(self, ip: str, reason: str, duration_minutes: Optional[int] = None) -> Dict[str, Any]:
        """
        Analyst-initiated block. Always recorded in the blocklist; a host firewall rule is
        added only in enforce mode. Raises ValueError for invalid or protected addresses.
        """
        return self.blocklist.block_ip(
            ip=ip,
            reason=reason,
            attack_type="MANUAL_BLOCK",
            threat_score=100,
            duration_minutes=duration_minutes or self.default_block_minutes,
            apply_os_rule=(self._mode == PreventionMode.ENFORCE.value)
        )

    # ------------------------------------------------------------------
    # Decision logic
    # ------------------------------------------------------------------

    @staticmethod
    def recommend_action(threat_score: int, attack_type: str, rate_limit_exceeded: bool) -> PreventionAction:
        if threat_score >= 85:
            return PreventionAction.BLOCK if threat_score >= 95 else PreventionAction.TEMPORARY_BLOCK
        if threat_score >= 65:
            if rate_limit_exceeded or attack_type in ["PORT_SCAN", "DOS"]:
                return PreventionAction.TEMPORARY_BLOCK
            return PreventionAction.RATE_LIMIT
        if threat_score >= 35:
            return PreventionAction.RATE_LIMIT if rate_limit_exceeded else PreventionAction.ALERT
        return PreventionAction.LOG

    def evaluate_response(
        self,
        threat_score: int,
        attack_type: str,
        ml_confidence: float,
        source_ip: Optional[str] = None,
        event_id: Optional[str] = None,
        is_heuristic_hit: bool = False,
        count_flow: bool = True
    ) -> Dict[str, Any]:
        """
        Synthesizes threat indicators into a defensive response.

        count_flow=False lets a second stage (incident correlation) re-evaluate the same
        event at chain level without counting the flow twice in the rate limiter.
        """
        if count_flow:
            rate_limit_exceeded, flow_count = self.rate_limiter.record_flow(source_ip)
        else:
            flow_count = self.rate_limiter.get_flow_count(source_ip)
            rate_limit_exceeded = flow_count > self.rate_limiter.max_flows

        recommended_action = self.recommend_action(threat_score, attack_type, rate_limit_exceeded)
        wants_block = recommended_action in (PreventionAction.TEMPORARY_BLOCK, PreventionAction.BLOCK)
        is_perm = recommended_action == PreventionAction.BLOCK

        block_info = None
        mode = self._mode

        if mode == PreventionMode.DETECT_ONLY.value:
            applied_action = "MONITORED_ONLY"
            explanation = (
                f"Detection-only mode active: Recommended action [{recommended_action.value}] was logged. "
                f"Operating system firewall was NOT altered."
            )

        elif mode == PreventionMode.SIMULATE.value:
            applied_action = f"SIMULATED_{recommended_action.value}"
            if wants_block and source_ip:
                block_info = self.contain_ip(
                    source_ip,
                    reason=f"High risk {attack_type} detected (Threat Score: {threat_score})",
                    attack_type=attack_type,
                    threat_score=threat_score,
                    event_id=event_id,
                    is_permanent=is_perm
                )
            explanation = (
                f"IPS Simulation Mode: Simulated [{recommended_action.value}] for source {source_ip or 'unknown'}. "
                f"No changes made to Windows Defender or host firewall."
            )

        else:  # enforce
            applied_action = f"ENFORCED_{recommended_action.value}"
            explanation = f"Applied {recommended_action.value} containment action."
            if wants_block and source_ip:
                block_info = self.contain_ip(
                    source_ip,
                    reason=f"Enforced containment of {attack_type} (Threat Score: {threat_score})",
                    attack_type=attack_type,
                    threat_score=threat_score,
                    event_id=event_id,
                    is_permanent=is_perm
                )
                if block_info:
                    duration = "Permanent" if is_perm else f"{self.default_block_minutes}m"
                    fw = "host firewall rule added" if block_info.get("os_rule_applied") else "blocklist only (no host firewall rule)"
                    explanation = f"Host containment registered for source {source_ip} (Duration: {duration}; {fw})."
                    if self.auto_threat_intel:
                        self._add_to_threat_intel(source_ip, attack_type, threat_score, ml_confidence)
                else:
                    applied_action = f"RECOMMENDED_{recommended_action.value}"
                    explanation = f"Containment of {source_ip} skipped (protected or invalid address); recommendation logged."
            elif recommended_action == PreventionAction.RATE_LIMIT:
                explanation = "RATE_LIMIT recommended (advisory: CIPHER does not throttle traffic itself)."

        return {
            "recommended_action": recommended_action.value,
            "applied_action": applied_action,
            "mode": mode,
            "flow_count_recent": flow_count,
            "rate_limit_exceeded": rate_limit_exceeded,
            "block_info": block_info,
            "prevention_summary": explanation
        }

    @staticmethod
    def _add_to_threat_intel(ip: str, attack_type: str, threat_score: int, confidence: float) -> None:
        """Opt-in (CIPHER_AUTO_THREAT_INTEL_FROM_BLOCKS=true): one false positive would otherwise
        create a permanent high-severity IOC and a score floor for that address."""
        try:
            from app.threat_intel.service import get_threat_intel_service
            from app.threat_intel.models import IOCCreateRequest
            get_threat_intel_service().add_ioc(IOCCreateRequest(
                ioc_type="IP",
                indicator=ip,
                severity="CRITICAL" if threat_score >= 95 else "HIGH",
                category="AUTO_CONTAINED",
                description=f"Auto-added from active containment. Source: {attack_type}, Threat Score: {threat_score}",
                confidence=confidence
            ))
        except Exception as e:
            logger.warning(f"Failed to auto-add contained IP {ip} to Threat Intel: {e}")


# ----------------------------------------------------------------------
# Process-wide shared engine
# ----------------------------------------------------------------------

_engine: Optional[PreventionEngine] = None
_engine_lock = threading.Lock()


def get_prevention_engine() -> PreventionEngine:
    """Returns the single PreventionEngine shared by every subsystem."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = PreventionEngine()
        return _engine


def reset_prevention_engine() -> None:
    """Testing hook: discard the shared engine so the next call re-reads the environment."""
    global _engine
    with _engine_lock:
        _engine = None
