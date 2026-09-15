"""
CIPHER Prevention Actions and Operational Modes
Defines standard IPS actions and configurable operating modes.
"""

from enum import Enum


class PreventionAction(str, Enum):
    """Supported mitigation actions."""
    ALERT = "ALERT"                      # Generate security alert for analyst review
    LOG = "LOG"                          # Passive telemetry logging
    RATE_LIMIT = "RATE_LIMIT"            # Recommend / simulate throttling of ingress traffic
    TEMPORARY_BLOCK = "TEMPORARY_BLOCK"  # Temporary source IP containment with TTL expiration
    BLOCK = "BLOCK"                      # Indefinite persistent source IP containment


class PreventionMode(str, Enum):
    """
    Defensive operational modes.
    Default must ALWAYS be DETECT_ONLY to guarantee zero unwanted OS changes.
    """
    DETECT_ONLY = "detect_only"          # Passive detection, metric collection, and logging
    SIMULATE = "simulate"                # Full IPS simulation: records actions without OS firewall calls
    ENFORCE = "enforce"                  # Live containment (reserved for controlled deployment)
