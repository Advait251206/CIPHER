"""
CIPHER Flow Rate Limiter
Tracks connection and packet frequencies per source IP using a sliding-window tracker.
Provides proactive rate-limit triggers for DoS and aggressive reconnaissance.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Tuple, Optional


class FlowRateLimiter:
    """In-memory sliding window rate tracker for network flows."""

    def __init__(self, window_seconds: int = 60, max_flows_per_window: int = 100):
        self.window_seconds = window_seconds
        self.max_flows = max_flows_per_window
        # Map: IP -> deque of timestamps
        self._history: Dict[str, deque] = defaultdict(deque)

    def record_flow(self, ip: Optional[str]) -> Tuple[bool, int]:
        """
        Records an inbound flow from an IP.

        Returns:
            should_rate_limit (bool): True if rate exceeds threshold
            current_count (int): Number of flows observed in the current window
        """
        if not ip:
            return False, 0

        now = time.time()
        q = self._history[ip]

        # Evict timestamps older than window
        while q and (now - q[0]) > self.window_seconds:
            q.popleft()

        # Add current timestamp
        q.append(now)
        count = len(q)

        return (count > self.max_flows), count

    def get_flow_count(self, ip: Optional[str]) -> int:
        """Returns the number of active flows recorded in the recent window."""
        if not ip or ip not in self._history:
            return 0
        now = time.time()
        q = self._history[ip]
        while q and (now - q[0]) > self.window_seconds:
            q.popleft()
        return len(q)

    def clear(self):
        """Resets all tracking histories."""
        self._history.clear()
