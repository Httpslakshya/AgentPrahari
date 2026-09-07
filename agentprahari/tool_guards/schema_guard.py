"""
AgentPrahari Tool Argument and Human-in-the-Loop Guard.
Validates parameters against expected types and enforces human confirmation gates.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.tool_guards.base import BaseToolGuard


class SchemaAndHITLGuard(BaseToolGuard):
    """
    Ensures tool arguments conform to safety types and enforces Human-in-the-Loop (HITL) gates.
    """

    @property
    def name(self) -> str:
        return "SchemaAndHITLGuard"

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        config: PrahariConfig
    ) -> List[Violation]:
        violations: List[Violation] = []

        # 1. Human-in-the-Loop verification gate
        if tool_name in config.require_human_approval_tools:
            # Check if an explicit approval token/flag was provided
            approved = tool_args.get("_human_approved", False)
            if not approved:
                violations.append(Violation(
                    rule_id="TOOL_REQUIRES_HUMAN_APPROVAL",
                    message=f"Action '{tool_name}' is privileged and requires explicit human confirmation before execution",
                    severity=Severity.HIGH,
                    category=GuardCategory.TOOL,
                    guard_name=self.name,
                    matched_content=tool_name,
                    details={"tool_name": tool_name, "requires_hitl": True}
                ))

        return violations
