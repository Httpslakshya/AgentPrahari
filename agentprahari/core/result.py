"""
AgentPrahari Core Result and Diff Tracking Models.
"""

from __future__ import annotations
import difflib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionDecision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    REQUIRE_HITL = "REQUIRE_HITL"


class GuardCategory(str, Enum):
    INPUT = "INPUT"
    TOOL = "TOOL"
    OUTPUT = "OUTPUT"
    GOVERNANCE = "GOVERNANCE"


@dataclass
class TextModification:
    """Represents a discrete text change, removal, or redaction."""
    start: int
    end: int
    original: str
    replacement: str
    reason: str
    rule_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "original": self.original,
            "replacement": self.replacement,
            "reason": self.reason,
            "rule_id": self.rule_id,
        }


@dataclass
class SanitizationDiff:
    """Tracks exact differences between original input and sanitized input."""
    original_text: str
    sanitized_text: str
    modifications: List[TextModification] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return self.original_text != self.sanitized_text or len(self.modifications) > 0

    def get_summary(self) -> str:
        """Returns a concise text summary of what was removed and what replaced it."""
        if not self.has_changes:
            return "No modifications made (input is pristine)."

        lines = [f"Total modifications: {len(self.modifications)}"]
        for idx, mod in enumerate(self.modifications, 1):
            if not mod.replacement:
                lines.append(f"  {idx}. [REMOVED] '{mod.original}' (Rule: {mod.rule_id} - {mod.reason})")
            elif not mod.original:
                lines.append(f"  {idx}. [INSERTED] '{mod.replacement}' (Rule: {mod.rule_id} - {mod.reason})")
            else:
                lines.append(
                    f"  {idx}. [REPLACED] '{mod.original}' -> '{mod.replacement}' "
                    f"(Rule: {mod.rule_id} - {mod.reason})"
                )
        return "\n".join(lines)

    def show_diff(self, style: str = "cli") -> str:
        """
        Renders a visual diff showing what was removed and what's the new input.
        
        Args:
            style: 'cli' (ANSI colored), 'markdown' (GitHub style), or 'inline' (bracketed text)
        """
        if not self.has_changes:
            return self.sanitized_text

        if style == "markdown":
            # Word-level or line-level diff
            output_lines = [
                "### [AgentPrahari] Input Sanitization Diff",
                "```diff",
            ]
            s = difflib.ndiff(self.original_text.splitlines(keepends=True),
                              self.sanitized_text.splitlines(keepends=True))
            output_lines.extend("".join(s).splitlines())
            output_lines.append("```")
            output_lines.append("\n**Detailed Modifications:**")
            for mod in self.modifications:
                output_lines.append(f"- **[- Removed: `{mod.original}`]** -> **{{+ New: `{mod.replacement}` +}}** *({mod.reason})*")
            return "\n".join(output_lines)

        elif style == "cli":
            # ANSI color codes: Red for removal, Green for addition, Reset
            RED = "\033[91m"
            GREEN = "\033[92m"
            RESET = "\033[0m"
            BOLD = "\033[1m"
            DIM = "\033[2m"

            diff_blocks = []
            for mod in self.modifications:
                orig_disp = f"{RED}[- REMOVED: {mod.original} -]{RESET}"
                new_disp = f"{GREEN}{{+ NEW: {mod.replacement} +}}{RESET}"
                diff_blocks.append(f"{orig_disp} -> {new_disp} {DIM}({mod.reason}){RESET}")

            header = f"{BOLD}=== AgentPrahari Sanitization Diff ==={RESET}"
            body = "\n".join(diff_blocks)
            sanitized_view = f"\n{BOLD}Sanitized Input Passed to Agent:{RESET}\n{self.sanitized_text}"
            return f"{header}\n{body}\n{sanitized_view}"

        else:
            # Inline bracketed mode (useful for plain logs)
            diff_blocks = []
            for mod in self.modifications:
                diff_blocks.append(f"[- REMOVED: '{mod.original}' -] {{+ NEW: '{mod.replacement}' +}} ({mod.reason})")
            return "\n".join(diff_blocks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_text": self.original_text,
            "sanitized_text": self.sanitized_text,
            "has_changes": self.has_changes,
            "modifications": [m.to_dict() for m in self.modifications],
        }


@dataclass
class Violation:
    """Represents a guardrail violation."""
    rule_id: str
    message: str
    severity: Severity
    category: GuardCategory
    guard_name: str
    matched_content: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "guard_name": self.guard_name,
            "matched_content": self.matched_content,
            "details": self.details,
        }


@dataclass
class GuardResult:
    """The outcome of running guardrails on an input, tool call, or output."""
    is_valid: bool
    decision: ActionDecision
    original_content: Any
    sanitized_content: Any
    violations: List[Violation] = field(default_factory=list)
    diff: Optional[SanitizationDiff] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    rejection_reason: Optional[str] = None

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.violations:
            return None
        priority = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
        return max(self.violations, key=lambda v: priority.get(v.severity, 0)).severity

    def raise_if_blocked(self) -> None:
        """Raises PrahariBlockedError if this result resulted in a BLOCK decision."""
        if self.decision == ActionDecision.BLOCK:
            from agentprahari.core.exceptions import PrahariBlockedError
            reason = self.rejection_reason or "Request blocked by safety guardrails."
            raise PrahariBlockedError(message=reason, result=self)

    def show_diff(self, style: str = "cli") -> str:
        """Helper to print or retrieve what removed and what is new."""
        if self.diff:
            return self.diff.show_diff(style=style)
        return "No text diff available for this result."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "decision": self.decision.value,
            "original_content": self.original_content,
            "sanitized_content": self.sanitized_content,
            "rejection_reason": self.rejection_reason,
            "violations": [v.to_dict() for v in self.violations],
            "diff": self.diff.to_dict() if self.diff else None,
            "metadata": self.metadata,
        }
