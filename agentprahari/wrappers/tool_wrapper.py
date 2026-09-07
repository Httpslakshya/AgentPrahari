"""
AgentPrahari Tool and Action Execution Wrapper.
"""

from __future__ import annotations
import functools
import inspect
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING
from agentprahari.core.exceptions import DangerousToolCallError

if TYPE_CHECKING:
    from agentprahari.core.engine import AgentPrahari


def wrap_tool_function(
    tool_func: Callable,
    shield: "AgentPrahari",
    tool_name: Optional[str] = None,
) -> Callable:
    """
    Wraps a tool or function to prevent destructive shell commands,
    SQL wipes, directory traversal, or unauthorized HITL actions.
    """
    name = tool_name or getattr(tool_func, "__name__", "unnamed_tool")
    sig = inspect.signature(tool_func)

    if inspect.iscoroutinefunction(tool_func):
        @functools.wraps(tool_func)
        async def async_guarded_tool(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            args_dict = dict(bound.arguments)

            result = shield.validate_tool_call(tool_name=name, tool_args=args_dict)
            if not result.is_valid:
                reason = result.rejection_reason or f"Tool call to '{name}' blocked by AgentPrahari"
                raise DangerousToolCallError(reason, result=result)

            return await tool_func(*args, **kwargs)

        return async_guarded_tool
    else:
        @functools.wraps(tool_func)
        def sync_guarded_tool(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            args_dict = dict(bound.arguments)

            result = shield.validate_tool_call(tool_name=name, tool_args=args_dict)
            if not result.is_valid:
                reason = result.rejection_reason or f"Tool call to '{name}' blocked by AgentPrahari"
                raise DangerousToolCallError(reason, result=result)

            return tool_func(*args, **kwargs)

        return sync_guarded_tool
