"""
AgentPrahari Loop and Runaway Execution Guard.
Detects infinite tool call loops, identical repeated invocations, and runaway agent recursion.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.tool_guards.base import BaseToolGuard


class LoopGuard(BaseToolGuard):
    """
    Prevents infinite agent loops by monitoring tool call sequences and halting runaway agents.
    """

    def __init__(self):
        self.call_history: List[Dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "LoopGuard"

    def reset(self) -> None:
        """Clears history for a new agent run."""
        self.call_history.clear()

    def record_call(self, tool_name: str, tool_args: Dict[str, Any]) -> None:
        """Records a tool invocation for loop analysis."""
        self.call_history.append({
            "tool": tool_name,
            "args": tool_args,
        })

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        config: PrahariConfig
    ) -> List[Violation]:
        violations: List[Violation] = []

        # 1. Total step limit check
        if len(self.call_history) >= config.max_tool_loop_iterations:
            violations.append(Violation(
                rule_id="TOOL_LOOP_MAX_STEPS_EXCEEDED",
                message=f"Agent exceeded maximum tool call limit of {config.max_tool_loop_iterations} steps",
                severity=Severity.CRITICAL,
                category=GuardCategory.TOOL,
                guard_name=self.name,
                matched_content=tool_name,
                details={"step_count": len(self.call_history), "max": config.max_tool_loop_iterations}
            ))
            return violations

        # 2. Identical consecutive call check (3 consecutive identical calls = stuck agent)
        if len(self.call_history) >= 2:
            try:
                curr_serialized = json.dumps({"t": tool_name, "a": tool_args}, sort_keys=True, default=str)
                prev_1 = json.dumps({"t": self.call_history[-1]["tool"], "a": self.call_history[-1]["args"]}, sort_keys=True, default=str)
                prev_2 = json.dumps({"t": self.call_history[-2]["tool"], "a": self.call_history[-2]["args"]}, sort_keys=True, default=str)
                if curr_serialized == prev_1 == prev_2:
                    violations.append(Violation(
                        rule_id="TOOL_LOOP_IDENTICAL_REPEATS",
                        message=f"Agent is stuck in an identical loop calling tool '{tool_name}' 3 consecutive times with the same arguments",
                        severity=Severity.HIGH,
                        category=GuardCategory.TOOL,
                        guard_name=self.name,
                        matched_content=tool_name,
                        details={"tool_name": tool_name}
                    ))
            except Exception:
                pass

        # 3. Ping-pong cycle check (A -> B -> A -> B -> A -> B)
        if len(self.call_history) >= 4:
            history_tools = [h["tool"] for h in self.call_history[-4:]] + [tool_name]
            if len(history_tools) == 5:
                # check pattern A, B, A, B, A
                if history_tools[0] == history_tools[2] == history_tools[4] and history_tools[1] == history_tools[3]:
                    violations.append(Violation(
                        rule_id="TOOL_LOOP_PING_PONG",
                        message=f"Agent is stuck alternating back-and-forth between '{history_tools[0]}' and '{history_tools[1]}'",
                        severity=Severity.HIGH,
                        category=GuardCategory.TOOL,
                        guard_name=self.name,
                        matched_content=f"{history_tools[0]} <-> {history_tools[1]}",
                        details={"tools": history_tools}
                    ))

        return violations
