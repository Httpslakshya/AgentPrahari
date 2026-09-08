"""
CrewAI Native Integration for AgentPrahari.

Provides a drop-in tool decorator/wrapper for CrewAI tools.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from agentprahari import AgentPrahari
from agentprahari.core.exceptions import DangerousToolCallError
from agentprahari.core.result import ActionDecision


class PrahariCrewAITool:
    """
    Wraps a CrewAI tool instance or custom BaseTool to ensure safe execution.

    Usage:
        from crewai.tools import tool
        from agentprahari.integrations import PrahariCrewAITool

        @tool("Execute bash command")
        def execute_bash(command: str) -> str:
            return "executed"

        safe_tool = PrahariCrewAITool(execute_bash, preset="strict")
    """

    def __init__(
        self,
        tool_instance: Any,
        shield: Optional[AgentPrahari] = None,
        preset: str = "strict",
        tool_name: Optional[str] = None,
    ) -> None:
        self.tool_instance = tool_instance
        self.shield = shield or AgentPrahari.from_preset(preset)
        self.tool_name = tool_name or getattr(tool_instance, "name", str(tool_instance))

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        # Convert args and kwargs into a dict for validation
        tool_args: Dict[str, Any] = dict(kwargs)
        if args:
            tool_args["_args"] = list(args)
            if len(args) == 1 and isinstance(args[0], (str, dict)):
                tool_args["input"] = args[0]

        res = self.shield.validate_tool_call(self.tool_name, tool_args)
        if res.decision == ActionDecision.BLOCK:
            raise DangerousToolCallError(
                f"CrewAI tool '{self.tool_name}' blocked by AgentPrahari: {res.rejection_reason}",
                result=res,
            )

        if hasattr(self.tool_instance, "run"):
            return self.tool_instance.run(*args, **kwargs)
        elif callable(self.tool_instance):
            return self.tool_instance(*args, **kwargs)
        raise TypeError(f"Object {self.tool_instance} is not callable and has no run() method.")

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)
