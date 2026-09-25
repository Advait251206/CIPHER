"""
CIPHER Intrusion Prevention Engine
Coordinates defensive responses based on threat score, attack taxonomy,
and operational mode (detect_only, simulate, enforce) with strict Windows safety guarantees.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple

from app.prevention.actions import PreventionAction, PreventionMode
from app.prevention.blocklist import IPBlocklistManager
from app.prevention.rate_limiter import FlowRateLimiter
from app.threat_intel.service import get_threat_intel_service
from app.threat_intel.models import IOCCreateRequest

logger = logging.getLogger("cipher.prevention")


class PreventionEngine:
    """Decides and executes defensive IPS responses safely."""

    def __init__(
        self,
        blocklist_manager: Optional[IPBlocklistManager] = None,
        rate_limiter: Optional[FlowRateLimiter] = None,
        mode: Optional[str] = None
    ):
        self.blocklist = blocklist_manager or IPBlocklistManager()
        self.rate_limiter = rate_limiter or FlowRateLimiter()

        # Operational mode: detect_only unless CIPHER_PREVENTION_MODE says
        # otherwise, and an unrecognised value falls back to detect_only too.
        # Prevention must fail safe: a typo in the environment must never turn
        # blocking on.
        env_mode = os.getenv("CIPHER_PREVENTION_MODE", PreventionMode.DETECT_ONLY.value).lower()
        self.mode = mode or env_mode
        if self.mode not in [m.value for m in PreventionMode]:
            logger.warning(f"Invalid CIPHER_PREVENTION_MODE '{self.mode}'. Falling back to 'detect_only'.")
            self.mode = PreventionMode.DETECT_ONLY.value

        logger.info(f"Initialized CIPHER Prevention Engine in [{self.mode.upper()}] mode")

    def evaluate_response(
        self,
        threat_score: int,
        attack_type: str,
        ml_confidence: float,
        source_ip: Optional[str] = None,
        event_id: Optional[str] = None,
        is_heuristic_hit: bool = False
    ) -> Dict[str, Any]:
        """
        Synthesizes threat indicators into a defensive response.

        Returns:
            Dict containing:
                - recommended_action: PreventionAction
                - applied_action: str
                - mode: str
                - block_info: Optional[Dict[str, Any]]
                - explanation: str
        """
        # 1. Check Rate Limiter
        rate_limit_exceeded, flow_count = self.rate_limiter.record_flow(source_ip)

        # 2. Determine Recommended Action based on threat thresholds
        if threat_score >= 85:
            # Critical threat (e.g. DoS flood, active exploit, confirmed Botnet)
            recommended_action = PreventionAction.BLOCK if threat_score >= 95 else PreventionAction.TEMPORARY_BLOCK
        elif threat_score >= 65:
            # High threat
            if rate_limit_exceeded or attack_type in ["PORT_SCAN", "DOS"]:
                recommended_action = PreventionAction.TEMPORARY_BLOCK
            else:
                recommended_action = PreventionAction.RATE_LIMIT
        elif threat_score >= 35:
            # Medium threat
            recommended_action = PreventionAction.RATE_LIMIT if rate_limit_exceeded else PreventionAction.ALERT
        else:
            # Low threat / Benign
            recommended_action = PreventionAction.LOG

        # 3. Apply Action Based on Mode (with strict Windows safety)
        applied_action = f"NONE_{self.mode.upper()}"
        block_info = None
        explanation = ""

        if self.mode == PreventionMode.DETECT_ONLY.value:
            # Passive monitoring: no OS changes, no active blocking
            applied_action = "MONITORED_ONLY"
            explanation = (
                f"Detection-only mode active: Recommended action [{recommended_action.value}] was logged. "
                f"Operating system firewall was NOT altered."
            )

        elif self.mode == PreventionMode.SIMULATE.value:
            # Simulation mode: records what IPS would do without altering host firewall
            applied_action = f"SIMULATED_{recommended_action.value}"
            if recommended_action in [PreventionAction.TEMPORARY_BLOCK, PreventionAction.BLOCK] and source_ip:
                is_perm = (recommended_action == PreventionAction.BLOCK)
                block_info = self.blocklist.block_ip(
                    ip=source_ip,
                    reason=f"[SIMULATION] High risk {attack_type} detected (Threat Score: {threat_score})",
                    attack_type=attack_type,
                    threat_score=threat_score,
                    duration_minutes=60 if not is_perm else None,
                    source_event_id=event_id,
                    is_permanent=is_perm
                )
            explanation = (
                f"IPS Simulation Mode: Simulated [{recommended_action.value}] for source {source_ip or 'unknown'}. "
                f"No changes made to Windows Defender or host firewall."
            )

        elif self.mode == PreventionMode.ENFORCE.value:
            # Active containment (Reserved mode)
            # Guarantee Windows Host Safety: Never disable Defender or add unrestricted firewall rules
            if recommended_action in [PreventionAction.TEMPORARY_BLOCK, PreventionAction.BLOCK] and source_ip:
                is_perm = (recommended_action == PreventionAction.BLOCK)
                block_info = self.blocklist.block_ip(
                    ip=source_ip,
                    reason=f"Enforced containment of {attack_type} (Threat Score: {threat_score})",
                    attack_type=attack_type,
                    threat_score=threat_score,
                    duration_minutes=60 if not is_perm else None,
                    source_event_id=event_id,
                    is_permanent=is_perm
                )
                
                # Automatically add to Threat Intel
                ti_service = get_threat_intel_service()
                try:
                    req = IOCCreateRequest(
                        ioc_type="IP",
                        indicator=source_ip,
                        severity="CRITICAL" if threat_score >= 95 else "HIGH",
                        category="AUTO_CONTAINED",
                        description=f"Auto-added from active containment. Source: {attack_type}, Threat Score: {threat_score}",
                        confidence=ml_confidence
                    )
                    ti_service.add_ioc(req)
                except Exception as e:
                    logger.warning(f"Failed to auto-add contained IP {source_ip} to Threat Intel: {e}")

                applied_action = f"ENFORCED_{recommended_action.value}"
                explanation = f"Host containment registered for source {source_ip} (Duration: {'Permanent' if is_perm else '60m'}). Added to Threat Intel."
            else:
                applied_action = f"ENFORCED_{recommended_action.value}"
                explanation = f"Applied {recommended_action.value} containment action."

        return {
            "recommended_action": recommended_action.value,
            "applied_action": applied_action,
            "mode": self.mode,
            "flow_count_recent": flow_count,
            "rate_limit_exceeded": rate_limit_exceeded,
            "block_info": block_info,
            "prevention_summary": explanation
        }
