"""
CIPHER Phase 10 Validation Configuration & Safety Enforcement.
Strictly guarantees that all validation traffic remains inside localhost (127.0.0.1 / loopback)
with bounded connection counts, bounded execution durations, and zero host firewall modifications.
"""

import ipaddress
import logging
from typing import Set

logger = logging.getLogger("cipher.phase10.config")

# Strict localhost boundary
DEFAULT_TEST_TARGET: str = "127.0.0.1"
ALLOWED_HOSTS: Set[str] = {"127.0.0.1", "localhost", "::1"}

# Bounded execution parameters
MAX_ALLOWED_CONNECTIONS: int = 50
MAX_ALLOWED_DURATION_SECONDS: float = 15.0
DEFAULT_TIMEOUT_SECONDS: float = 2.0

# Dedicated unprivileged test port range
SAFE_PORT_RANGE_START: int = 18000
SAFE_PORT_RANGE_END: int = 18050
DEFAULT_BENIGN_PORT: int = 18080
DEFAULT_AUTH_TEST_PORT: int = 18022  # Synthetic local auth test service


def is_safe_local_target(target: str) -> bool:
    """
    Validates that a requested target is strictly a local loopback target.
    Rejects public, university, corporate, and remote IP addresses.
    """
    if not target or not isinstance(target, str):
        return False

    clean_target = target.strip().lower()
    if clean_target in ALLOWED_HOSTS:
        return True

    try:
        ip = ipaddress.ip_address(clean_target)
        return ip.is_loopback
    except ValueError:
        # Non-IP hostnames other than 'localhost' are rejected
        return False


def assert_safe_target(target: str) -> None:
    """
    Raises ValueError if target is not confirmed as safe local loopback.
    """
    if not is_safe_local_target(target):
        raise ValueError(
            f"SAFETY VIOLATION: Target '{target}' is not a permitted local loopback address. "
            f"CIPHER Phase 10 strictly forbids scanning non-local addresses."
        )


def validate_traffic_bounds(connections: int, duration_seconds: float) -> None:
    """
    Enforces strict ceilings on connections and runtime duration.
    """
    if connections <= 0:
        raise ValueError("Connection count must be a positive integer.")
    if connections > MAX_ALLOWED_CONNECTIONS:
        raise ValueError(
            f"SAFETY VIOLATION: Requested {connections} connections exceeds maximum "
            f"allowed ceiling of {MAX_ALLOWED_CONNECTIONS}."
        )

    if duration_seconds <= 0:
        raise ValueError("Duration must be positive.")
    if duration_seconds > MAX_ALLOWED_DURATION_SECONDS:
        raise ValueError(
            f"SAFETY VIOLATION: Requested duration {duration_seconds}s exceeds maximum "
            f"allowed ceiling of {MAX_ALLOWED_DURATION_SECONDS}s."
        )
