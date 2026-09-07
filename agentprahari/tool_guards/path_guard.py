"""
AgentPrahari Path Traversal and Sensitive File Access Guard.
Prevents agents from reading or modifying confidential files and navigating out of bounds.
"""

from __future__ import annotations
import os
import re
from typing import Any, Dict, List
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.tool_guards.base import BaseToolGuard


class PathGuard(BaseToolGuard):
    """
    Detects directory traversal attacks and unauthorized access to sensitive system files.
    """

    def __init__(self):
        self.traversal_pattern = re.compile(
            r"(?:\.\.[\\/]|%2e%2e|%252e%252e|\.\.$|^\.\.)",
            re.IGNORECASE
        )

    @property
    def name(self) -> str:
        return "PathGuard"

    def _extract_string_values(self, data: Any) -> List[str]:
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
        if not config.check_path_traversal:
            return []

        violations: List[Violation] = []
        arg_strings = self._extract_string_values(tool_args)

        for arg in arg_strings:
            # Recursively unquote percent encoding to detect double encoded traversal (e.g. %252e%252e%252f)
            decoded_arg = arg
            for _ in range(3):
                try:
                    next_dec = urllib.parse.unquote(decoded_arg)
                    if next_dec == decoded_arg:
                        break
                    decoded_arg = next_dec
                except Exception:
                    break

            # 1. Path traversal checks (e.g. ../../../etc/passwd or %252e%252e)
            if self.traversal_pattern.search(arg) or self.traversal_pattern.search(decoded_arg):
                violations.append(Violation(
                    rule_id="TOOL_PATH_TRAVERSAL",
                    message=f"Path traversal sequence detected in tool '{tool_name}' argument",
                    severity=Severity.HIGH,
                    category=GuardCategory.TOOL,
                    guard_name=self.name,
                    matched_content=arg,
                    details={"tool_name": tool_name, "path": arg}
                ))

            # 2. Blocked confidential files & directories
            normalized_arg = arg.replace("\\", "/").lower()
            for blocked in config.blocked_paths:
                blocked_norm = blocked.replace("\\", "/").lower()
                if blocked_norm in normalized_arg:
                    violations.append(Violation(
                        rule_id="TOOL_BLOCKED_FILE_ACCESS",
                        message=f"Access to sensitive target '{blocked}' blocked in tool '{tool_name}'",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.TOOL,
                        guard_name=self.name,
                        matched_content=blocked,
                        details={"tool_name": tool_name, "blocked_target": blocked, "path": arg}
                    ))

        return violations
