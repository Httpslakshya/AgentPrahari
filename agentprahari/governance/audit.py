"""
AgentPrahari Structured Audit Logger and Telemetry Engine.
"""

from __future__ import annotations
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional
from agentprahari.core.result import ActionDecision, GuardResult, Violation

logger = logging.getLogger("agentprahari.audit")


class AuditLogger:
    """
    Structured logger that records security events, triggers webhooks/callbacks,
    and maintains an in-memory audit log for compliance.
    """

    def __init__(
        self,
        enabled: bool = True,
        on_violation: Optional[Callable[[Violation], None]] = None,
        max_history: int = 1000,
    ):
        self.enabled = enabled
        self.on_violation = on_violation
        self.max_history = max_history
        self.events: List[Dict[str, Any]] = []

    def log_event(
        self,
        event_type: str,
        result: GuardResult,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Logs a guardrail check result."""
        if not self.enabled:
            return

        entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "decision": result.decision.value,
            "is_valid": result.is_valid,
            "violations_count": len(result.violations),
            "highest_severity": result.highest_severity.value if result.highest_severity else None,
            "rejection_reason": result.rejection_reason,
            "has_diff": result.diff.has_changes if result.diff else False,
            "metadata": {**(result.metadata or {}), **(extra_metadata or {})},
        }

        self.events.append(entry)
        if len(self.events) > self.max_history:
            self.events.pop(0)

        # Trigger user callback if configured
        if self.on_violation and result.has_violations:
            for v in result.violations:
                try:
                    self.on_violation(v)
                except Exception as ex:
                    logger.warning("Error executing on_violation callback: %s", ex)

        # Standard Python logging
        if result.decision == ActionDecision.BLOCK:
            logger.warning("[AgentPrahari BLOCK] %s - %s", event_type, result.rejection_reason)
        elif result.decision == ActionDecision.SANITIZE:
            logger.info("[AgentPrahari SANITIZE] %s - Modifications applied", event_type)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.events[-limit:]

    def clear(self) -> None:
        self.events.clear()
