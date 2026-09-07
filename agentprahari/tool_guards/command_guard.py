"""
AgentPrahari Command and Tool Execution Safety Guard.
Intercepts destructive shell commands, disk formatting, fork bombs, and dangerous SQL statements,
while cleanly separating command execution from benign inspections and safe queries.
"""

from __future__ import annotations
import re
import shlex
from typing import Any, Dict, List, Tuple
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.tool_guards.base import BaseToolGuard


def strip_sql_comments(sql: str) -> str:
    """
    Strips SQL line (-- ...) and block (/* ... */) comments
    without corrupting text inside single or double-quoted string literals.
    """
    result = []
    i = 0
    n = len(sql)
    in_quote = False
    quote_char = ''

    while i < n:
        c = sql[i]
        if in_quote:
            result.append(c)
            if c == quote_char:
                # Check for escaped quotes like ''
                if i + 1 < n and sql[i + 1] == quote_char:
                    result.append(sql[i + 1])
                    i += 2
                    continue
                in_quote = False
            i += 1
        elif c in ("'", '"', '`'):
            in_quote = True
            quote_char = c
            result.append(c)
            i += 1
        elif c == '-' and i + 1 < n and sql[i + 1] == '-':
            # Single-line comment: skip until newline
            while i < n and sql[i] != '\n':
                i += 1
        elif c == '/' and i + 1 < n and sql[i + 1] == '*':
            # Block comment: skip until closing */
            i += 2
            while i + 1 < n and not (sql[i] == '*' and sql[i + 1] == '/'):
                i += 1
            i += 2
            result.append(' ')
        else:
            result.append(c)
            i += 1

    return ''.join(result)


class CommandGuard(BaseToolGuard):
    """
    Prevents execution of destructive commands, SQL injection data wipe,
    and irreversible administrative actions invoked via tools.
    """

    def __init__(self):
        # Shell destruction patterns
        self.shell_destructive_patterns = [
            (
                re.compile(r"\b(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*|del\s+/[fF]\s+/[sS]|rmdir\s+/[sS]|chmod\s+[0-7]{3,}\s+/(?:etc|bin|usr|var|root|boot))\b", re.IGNORECASE),
                "TOOL_CMD_DESTRUCTIVE_DELETE",
                "Destructive recursive file deletion or system permissions command detected"
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
                re.compile(r"\bpowershell(?:\.exe)?\s+(?:-e|-enc|-encodedcommand)\b", re.IGNORECASE),
                "TOOL_CMD_ENCODED_POWERSHELL",
                "Obfuscated encoded PowerShell invocation detected"
            ),
            (
                re.compile(r"\b(?:shutdown\s+-[sShHrR]|reboot|init\s+0)\b", re.IGNORECASE),
                "TOOL_CMD_SYSTEM_SHUTDOWN",
                "System shutdown or reboot command detected"
            ),
            # Subshell wrapper and command substitution (e.g. bash -c "rm -rf...", sh -c "...")
            (
                re.compile(r"\b(?:bash|sh|zsh)\s+-c\s+['\"][^'\"]*rm\s+-[a-zA-Z]*r", re.IGNORECASE),
                "TOOL_CMD_SUBSHELL_DESTRUCTIVE",
                "Subshell-wrapped destructive command execution detected"
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

    def _is_safe_inspection_command(self, cmd: str) -> bool:
        """Identifies benign inspection commands (echo, grep, ls, pwd, cat, man) without execution pipes."""
        s = cmd.strip()
        # If piped to shell or dangerous interpreter, NOT safe
        if re.search(r"\|\s*(?:bash|sh|zsh|python|eval)\b", s, re.IGNORECASE):
            return False
        # If wrapped in command substitution $(...) or backticks `...`, NOT safe
        if re.search(r"(?:\$\(|\`|\beval\b)", s):
            return False
        # If it is a benign query/display command
        if re.match(r"^(?:echo|printf|grep|man|cat|head|tail|less|more|pwd|ls|dir)\b", s, re.IGNORECASE):
            return True
        return False

    def _evaluate_sql(self, sql_raw: str, tool_name: str) -> List[Violation]:
        """Semantic evaluation of SQL statements distinguishing safe queries from destructive operations."""
        violations = []
        clean_sql = strip_sql_comments(sql_raw).strip()
        if not clean_sql:
            return []

        # 1. Check for DDL Destruction: DROP TABLE / DATABASE / SCHEMA, TRUNCATE, or dynamic EXEC
        if re.search(r"\b(?:drop\s+(?:table|database|schema)|truncate\s+(?:table)?|exec(?:ute)?\s+(?:sp_msforeachtable|immediate))\b", clean_sql, re.IGNORECASE):
            violations.append(Violation(
                rule_id="TOOL_SQL_DESTRUCTIVE_DDL",
                message=f"Destructive database DDL operation (DROP/TRUNCATE) detected in tool '{tool_name}'",
                severity=Severity.CRITICAL,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=clean_sql[:40] + "...",
                details={"sql": clean_sql}
            ))
            return violations

        # 2. Check for unconditional DELETE or DELETE WHERE 1=1 / true / 'a'='a'
        if re.search(r"\bdelete\s+from\s+\w+(?:\s*(?:;|$)|(?:\s+where\s+(?:1\s*=\s*1|true|'1'\s*=\s*'1'|'a'\s*=\s*'a'|1)))", clean_sql, re.IGNORECASE):
            violations.append(Violation(
                rule_id="TOOL_SQL_UNCONDITIONAL_DELETE",
                message=f"Unconditional or always-true DELETE operation detected in tool '{tool_name}'",
                severity=Severity.CRITICAL,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=clean_sql[:40] + "...",
                details={"sql": clean_sql}
            ))
            return violations

        # 3. Check for dangerous UPDATE (unconditional password override)
        if re.search(r"\bupdate\s+\w+\s+set\s+(?:password|passwd)\s*=", clean_sql, re.IGNORECASE):
            violations.append(Violation(
                rule_id="TOOL_SQL_PASSWORD_OVERWRITE",
                message=f"Mass password overwrite operation detected in tool '{tool_name}'",
                severity=Severity.CRITICAL,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=clean_sql[:40] + "...",
                details={"sql": clean_sql}
            ))
            return violations

        # 4. Dangerous ALTER: ALTER TABLE ... DROP (COLUMN/PARTITION) or ALTER DATABASE
        if re.search(r"\balter\s+table\s+\w+\s+(?:drop\s+(?:column|partition)?|rename\s+to)\b", clean_sql, re.IGNORECASE):
            violations.append(Violation(
                rule_id="TOOL_SQL_DANGEROUS_ALTER",
                message=f"Destructive ALTER TABLE DROP operation detected in tool '{tool_name}'",
                severity=Severity.CRITICAL,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=clean_sql[:40] + "...",
                details={"sql": clean_sql}
            ))

        return violations

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

        is_sql_tool = any(kw in tool_name.lower() for kw in ("sql", "query", "db", "database", "postgres", "mysql"))

        for arg_str in string_args:
            # Evaluate SQL specifically if tool is SQL-oriented or argument contains SQL keywords
            if is_sql_tool or re.search(r"\b(?:SELECT|DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT|EXPLAIN|DESCRIBE)\b", arg_str, re.IGNORECASE):
                sql_violations = self._evaluate_sql(arg_str, tool_name)
                if sql_violations:
                    violations.extend(sql_violations)
                    continue

            # Skip benign shell inspection commands (e.g. echo "rm -rf", grep "rm -rf", ls -la, pwd)
            if self._is_safe_inspection_command(arg_str):
                continue

            # Check built-in dangerous shell patterns
            for pattern, rule_id, message in self.shell_destructive_patterns:
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

            # Check configured blocked shell commands
            for blocked_cmd in config.blocked_shell_commands:
                if re.search(blocked_cmd, arg_str, re.IGNORECASE):
                    # Again verify not a safe inspection
                    if not self._is_safe_inspection_command(arg_str):
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
