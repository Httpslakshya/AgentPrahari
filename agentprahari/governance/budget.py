"""
AgentPrahari Cost and Token Budget Governor.
Tracks cumulative token consumption and cost to halt runaway billing.
"""

from __future__ import annotations
import threading
from typing import Dict, Optional
from agentprahari.core.exceptions import BudgetExceededError


class BudgetGovernor:
    """
    Thread-safe tracker for token usage and cost caps.
    """

    def __init__(
        self,
        max_tokens: Optional[int] = None,
        max_cost_usd: Optional[float] = None,
        cost_per_1k_tokens: float = 0.002,
    ):
        self.max_tokens = max_tokens
        self.max_cost_usd = max_cost_usd
        self.cost_per_1k_tokens = cost_per_1k_tokens

        self._lock = threading.Lock()
        self.total_tokens_used: int = 0
        self.total_requests: int = 0

    @property
    def estimated_cost_usd(self) -> float:
        return (self.total_tokens_used / 1000.0) * self.cost_per_1k_tokens

    def record_usage(self, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """Records token usage and raises BudgetExceededError if limit breached."""
        tokens = prompt_tokens + completion_tokens
        with self._lock:
            self.total_requests += 1
            self.total_tokens_used += tokens

            if self.max_tokens and self.total_tokens_used > self.max_tokens:
                raise BudgetExceededError(
                    f"Token budget exceeded: used {self.total_tokens_used} tokens (Limit: {self.max_tokens})"
                )

            if self.max_cost_usd and self.estimated_cost_usd > self.max_cost_usd:
                raise BudgetExceededError(
                    f"Cost budget exceeded: ${self.estimated_cost_usd:.4f} USD (Limit: ${self.max_cost_usd:.2f} USD)"
                )

    def reset(self) -> None:
        with self._lock:
            self.total_tokens_used = 0
            self.total_requests = 0

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "total_tokens": self.total_tokens_used,
                "estimated_cost_usd": round(self.estimated_cost_usd, 6),
                "max_tokens_limit": self.max_tokens,
                "max_cost_limit": self.max_cost_usd,
            }
