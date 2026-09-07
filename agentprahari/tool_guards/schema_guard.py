"""
AgentPrahari Tool Argument and Human-in-the-Loop Guard.
Validates parameters against expected schemas, detects argument hijacking,
and enforces strict Human-in-the-Loop (HITL) confirmation gates on privileged tools.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.tool_guards.base import BaseToolGuard

# Common high-privilege tool patterns that must require explicit authorization
PRIVILEGED_TOOL_KEYWORDS = (
    "privileged", "admin", "transfer_funds", "delete_database",
    "modify_iam", "grant_role", "revoke_role", "drop_db",
    "execute_arbitrary", "sudo"
)


class SchemaAndHITLGuard(BaseToolGuard):
    """
    Ensures tool arguments conform to safety schemas, validates approvals against executed arguments,
    and enforces Human-in-the-Loop (HITL) gates.
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
        name_lower = tool_name.lower()

        is_privileged = (
            tool_name in config.require_human_approval_tools
            or any(kw in name_lower for kw in PRIVILEGED_TOOL_KEYWORDS)
        )

        # Check for explicit authorization failure or revocation flags
        if any(tool_args.get(flag) for flag in ("_auth_expired", "_denied", "_timeout", "_duplicate")):
            violations.append(Violation(
                rule_id="TOOL_AUTHORIZATION_FAILED",
                message=f"Tool call '{tool_name}' blocked due to expired, denied, duplicate, or timed-out authorization",
                severity=Severity.CRITICAL,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=tool_name,
                details={"tool_args": tool_args}
            ))

        # Check for Approval Argument Tampering / Bait-and-Switch:
        # Check specific _approved_<param> tags
        for k, v in list(tool_args.items()):
            if k.startswith("_approved_"):
                param_name = k[len("_approved_"):]
                if param_name in tool_args and tool_args[param_name] != v:
                    violations.append(Violation(
                        rule_id="TOOL_APPROVAL_BAIT_AND_SWITCH",
                        message=f"Approval granted for {param_name}='{v}' but executed with '{tool_args[param_name]}' in tool '{tool_name}'",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.TOOL,
                        guard_name=self.name,
                        matched_content=f"{param_name}: {tool_args[param_name]} != {v}",
                        details={"executed": tool_args[param_name], "approved": v}
                    ))

        # 1. Human-in-the-Loop verification gate for privileged tools
        if is_privileged:
            approved = tool_args.get("_human_approved", False) or tool_args.get("_approved", False)
            if not approved:
                violations.append(Violation(
                    rule_id="TOOL_REQUIRES_HUMAN_APPROVAL",
                    message=f"Action '{tool_name}' is privileged and requires explicit human confirmation before execution",
                    severity=Severity.CRITICAL if any(kw in name_lower for kw in ("delete", "admin", "transfer")) else Severity.HIGH,
                    category=GuardCategory.TOOL,
                    guard_name=self.name,
                    matched_content=tool_name,
                    details={"tool_name": tool_name, "requires_hitl": True}
                ))
            else:
                # 2. Check for Approval Argument Tampering in _approved_args dict
                approved_args = tool_args.get("_approved_args")
                if approved_args is not None and isinstance(approved_args, dict):
                    clean_actual = {k: v for k, v in tool_args.items() if not k.startswith("_")}
                    clean_approved = {k: v for k, v in approved_args.items() if not k.startswith("_")}
                    if clean_actual != clean_approved:
                        violations.append(Violation(
                            rule_id="TOOL_APPROVAL_ARGUMENT_MISMATCH",
                            message=f"Approval granted for different arguments than executed in privileged tool '{tool_name}'",
                            severity=Severity.CRITICAL,
                            category=GuardCategory.TOOL,
                            guard_name=self.name,
                            matched_content=str(clean_actual),
                            details={"executed": clean_actual, "approved": clean_approved}
                        ))

        # 3. Check for Malformed / Ambiguous Argument structures
        if not isinstance(tool_args, dict):
            violations.append(Violation(
                rule_id="TOOL_MALFORMED_ARGUMENTS",
                message=f"Malformed tool arguments provided to tool '{tool_name}' (expected dictionary)",
                severity=Severity.HIGH,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=str(type(tool_args)),
                details={"tool_name": tool_name}
            ))

        return violations
