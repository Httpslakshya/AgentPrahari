"""
AgentPrahari Function & Agent Decorator.
"""

from __future__ import annotations
import functools
import inspect
from typing import Any, Callable, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from agentprahari.core.engine import AgentPrahari


def create_shield_decorator(
    shield: "AgentPrahari",
    input_param_names: Optional[List[str]] = None,
    check_output: bool = True,
    auto_sanitize: bool = True,
    show_diff_on_sanitize: bool = False,
) -> Callable:
    """
    Creates a decorator that automatically runs AgentPrahari guardrails
    on function arguments and returned output.
    """

    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())

        # Target parameter names to guard
        target_names = input_param_names or (param_names[:1] if param_names else [])

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()

                # 1. Guard input parameters
                for p_name in target_names:
                    if p_name in bound.arguments and isinstance(bound.arguments[p_name], str):
                        raw_text = bound.arguments[p_name]
                        result = shield.validate_input(raw_text)
                        result.raise_if_blocked()

                        if result.diff and result.diff.has_changes:
                            if show_diff_on_sanitize:
                                print(result.show_diff(style="cli"))
                            if auto_sanitize:
                                bound.arguments[p_name] = result.sanitized_content

                # 2. Execute agent function
                output = await func(*bound.args, **bound.kwargs)

                # 3. Guard output
                if check_output and isinstance(output, str):
                    out_res = shield.validate_output(output)
                    out_res.raise_if_blocked()
                    return out_res.sanitized_content

                return output

            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()

                # 1. Guard input parameters
                for p_name in target_names:
                    if p_name in bound.arguments and isinstance(bound.arguments[p_name], str):
                        raw_text = bound.arguments[p_name]
                        result = shield.validate_input(raw_text)
                        result.raise_if_blocked()

                        if result.diff and result.diff.has_changes:
                            if show_diff_on_sanitize:
                                print(result.show_diff(style="cli"))
                            if auto_sanitize:
                                bound.arguments[p_name] = result.sanitized_content

                # 2. Execute agent function
                output = func(*bound.args, **bound.kwargs)

                # 3. Guard output
                if check_output and isinstance(output, str):
                    out_res = shield.validate_output(output)
                    out_res.raise_if_blocked()
                    return out_res.sanitized_content

                return output

            return sync_wrapper

    return decorator
