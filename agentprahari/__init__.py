"""
AgentPrahari: The Robust, Drop-in Security & Safety Guardrail Layer for AI Agents and LLMs.
"""

from agentprahari.core.config import PrahariConfig
from agentprahari.core.engine import AgentPrahari, PrahariBuilder
from agentprahari.core.exceptions import (
    BudgetExceededError,
    DangerousToolCallError,
    GuardrailError,
    RateLimitExceededError,
    PrahariBlockedError,
)
from agentprahari.core.result import (
    ActionDecision,
    GuardCategory,
    GuardResult,
    SanitizationDiff,
    Severity,
    TextModification,
    Violation,
)

# Backwards compatibility aliases
AgentShield = AgentPrahari
ShieldConfig = PrahariConfig
ShieldBlockedError = PrahariBlockedError

__all__ = [
    "AgentPrahari",
    "AgentShield",
    "PrahariBuilder",
    "PrahariConfig",
    "ShieldConfig",
    "GuardResult",
    "Violation",
    "SanitizationDiff",
    "TextModification",
    "Severity",
    "ActionDecision",
    "GuardCategory",
    "GuardrailError",
    "PrahariBlockedError",
    "ShieldBlockedError",
    "DangerousToolCallError",
    "BudgetExceededError",
    "RateLimitExceededError",
]

