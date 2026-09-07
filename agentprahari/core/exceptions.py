"""
AgentPrahari Custom Exceptions.
"""

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agentprahari.core.result import GuardResult


class GuardrailError(Exception):
    """Base exception for all AgentPrahari errors."""
    pass


class PrahariBlockedError(GuardrailError):
    """Raised when an input, tool call, or output is blocked by guardrails."""

    def __init__(self, message: str, result: Optional["GuardResult"] = None):
        super().__init__(message)
        self.message = message
        self.result = result

    def __str__(self) -> str:
        if self.result and self.result.violations:
            details = ", ".join(f"[{v.rule_id}: {v.message}]" for v in self.result.violations)
            return f"{self.message} -> Violations: {details}"
        return self.message


class BudgetExceededError(GuardrailError):
    """Raised when request cost or token budget limit is exceeded."""
    pass


class RateLimitExceededError(GuardrailError):
    """Raised when request rate limit is exceeded."""
    pass


class DangerousToolCallError(PrahariBlockedError):
    """Raised when an agent attempts a forbidden destructive tool call."""
    pass
