"""
AgentPrahari Command and Tool Execution Safety Guard.
Intercepts destructive shell commands, disk formatting, fork bombs, and dangerous SQL statements.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.tool_guards.base import BaseToolGuard


class CommandGuard(BaseToolGuard):
    """
    Prevents execution of destructive commands, SQL injection data wipe,
    and irreversible administrative actions invoked via tools.
    """

    def __init__(self):
        self.dangerous_patterns = [
            (
                re.compile(r"\b(?:rm\s+-(?:rf|fr|r\s+-f)|del\s+/[fF]\s+/[sS]|rmdir\s+/[sS])\b", re.IGNORECASE),
                "TOOL_CMD_DESTRUCTIVE_DELETE",
                "Destructive recursive file deletion command detected"
            ),
            (
                re.compile(r"\b(?:mkfs|format\s+[a-zA-Z]:|dd\s+if=/dev/(?:zero|urandom|null))\b", re.IGNORECASE),
                "TOOL_CMD_DISK_FORMAT",
                "Disk formatting or block-device wipe command detected"
            ),
            (
                re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
                "TOOL_CMD_FORK_BOMB",
                "Bash fork-bomb detected"
            ),
            (
                re.compile(r"\b(?:curl|wget)\s+[^|]+\|\s*(?:ba)?sh\b", re.IGNORECASE),
                "TOOL_CMD_PIPE_TO_SHELL",
                "Unsafe pipe-to-shell execution (curl/wget | bash) detected"
            ),
            (
                re.compile(r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*(?:;|\s*$))\b", re.IGNORECASE),
                "TOOL_SQL_DESTRUCTIVE_DDL",
                "Destructive database operation (DROP/TRUNCATE/unconditional DELETE) detected"
            ),
            (
                re.compile(r"\bpowershell(?:\.exe)?\s+(?:-e|-enc|-encodedcommand)\b", re.IGNORECASE),
                "TOOL_CMD_ENCODED_POWERSHELL",
                "Obfuscated encoded PowerShell invocation detected"
            ),
            (
                re.compile(r"\b(?:shutdown\s+-[sShHrR]|reboot|init\s+0)\b", re.IGNORECASE),
                "TOOL_CMD_SYSTEM_SHUTDOWN",
                "System shutdown or reboot command detected"
            ),
        ]

    @property
    def name(self) -> str:
        return "CommandGuard"

    def _extract_string_values(self, data: Any) -> List[str]:
        """Recursively extracts all string values from tool arguments."""
        strings = []
        if isinstance(data, str):
            strings.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                strings.extend(self._extract_string_values(v))
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                strings.extend(self._extract_string_values(item))
        return strings

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        config: PrahariConfig
    ) -> List[Violation]:
        if not config.check_dangerous_commands:
            return []

        violations: List[Violation] = []
        string_args = self._extract_string_values(tool_args)

        for arg_str in string_args:
            # 1. Built-in dangerous patterns
            for pattern, rule_id, message in self.dangerous_patterns:
                match = pattern.search(arg_str)
                if match:
                    violations.append(Violation(
                        rule_id=rule_id,
                        message=f"{message} in tool '{tool_name}'",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.TOOL,
                        guard_name=self.name,
                        matched_content=match.group(0),
                        details={"tool_name": tool_name, "raw_arg": arg_str}
                    ))

            # 2. Configured blocked shell commands
            for blocked_cmd in config.blocked_shell_commands:
                if re.search(blocked_cmd, arg_str, re.IGNORECASE):
                    violations.append(Violation(
                        rule_id="TOOL_CUSTOM_BLOCKED_COMMAND",
                        message=f"Command matches blocked pattern '{blocked_cmd}' in tool '{tool_name}'",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.TOOL,
                        guard_name=self.name,
                        matched_content=blocked_cmd,
                        details={"tool_name": tool_name, "blocked_pattern": blocked_cmd}
                    ))

        return violations
