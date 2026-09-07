"""
AgentPrahari Sliding-Window Rate Limiter.
Protects AI endpoints and agent workflows from rapid flooding and DDoS attacks.
"""

from __future__ import annotations
import threading
import time
from collections import defaultdict
from typing import Dict, List
from agentprahari.core.exceptions import RateLimitExceededError


class RateLimiter:
    """
    Sliding window rate limiter per client_id or global session.
    """

    def __init__(self, max_requests_per_minute: int = 60):
        self.max_requests_per_minute = max_requests_per_minute
        self._lock = threading.Lock()
        self._request_timestamps: Dict[str, List[float]] = defaultdict(list)

    def check_and_record(self, client_id: str = "default") -> None:
        """Records a request or raises RateLimitExceededError if limit breached."""
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            # Clean timestamps older than 60s
            timestamps = [t for t in self._request_timestamps[client_id] if t > window_start]
            
            if len(timestamps) >= self.max_requests_per_minute:
                retry_after = round(timestamps[0] - window_start, 1)
                raise RateLimitExceededError(
                    f"Rate limit exceeded for client '{client_id}': maximum {self.max_requests_per_minute} "
                    f"requests per minute. Try again in {max(0.1, retry_after)} seconds."
                )

            timestamps.append(now)
            self._request_timestamps[client_id] = timestamps

    def reset(self) -> None:
        with self._lock:
            self._request_timestamps.clear()
