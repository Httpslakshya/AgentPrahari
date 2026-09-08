"""
LangChain Native Integration for AgentPrahari.

Provides a drop-in CallbackHandler that transparently secures all LangChain
LLM calls, chains, and agent tool executions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from agentprahari import AgentPrahari
from agentprahari.core.exceptions import DangerousToolCallError, PrahariBlockedError
from agentprahari.core.result import ActionDecision

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    # Graceful fallback if langchain_core is not installed
    class BaseCallbackHandler:  # type: ignore
        """Dummy base class matching LangChain callback signatures."""
        pass


class PrahariCallbackHandler(BaseCallbackHandler):
    """
    Native LangChain Callback Handler.

    Attaching this handler to any LangChain LLM, ChatModel, Chain, or AgentExecutor
    automatically:
    1. Validates all input prompts before they reach the model.
    2. Validates all tool actions (SQL, bash, filesystem) before execution.
    3. Validates and sanitizes model outputs (blocking secret leaks).

    Usage:
        from langchain_openai import ChatOpenAI
        from agentprahari.integrations import PrahariCallbackHandler

        handler = PrahariCallbackHandler(preset="strict")
        llm = ChatOpenAI(model="gpt-4o", callbacks=[handler])
    """

    def __init__(
        self,
        shield: Optional[AgentPrahari] = None,
        preset: str = "strict",
        block_on_violation: bool = True,
        auto_sanitize_output: bool = True,
    ) -> None:
        super().__init__()
        self.shield = shield or AgentPrahari.from_preset(preset)
        self.block_on_violation = block_on_violation
        self.auto_sanitize_output = auto_sanitize_output

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Inspects incoming prompts before sending to LLM."""
        for prompt in prompts:
            res = self.shield.validate_input(prompt)
            if res.decision == ActionDecision.BLOCK and self.block_on_violation:
                raise PrahariBlockedError(
                    f"LangChain prompt blocked by AgentPrahari: {res.rejection_reason}",
                    result=res,
                )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Inspects impending tool calls before execution."""
        tool_name = serialized.get("name") or kwargs.get("name") or "agent_tool"
        res = self.shield.validate_tool_call(tool_name, {"command": input_str, "input": input_str})
        if res.decision == ActionDecision.BLOCK and self.block_on_violation:
            raise DangerousToolCallError(
                f"LangChain tool execution '{tool_name}' blocked by AgentPrahari: {res.rejection_reason}",
                result=res,
            )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Inspects LLM outputs for secret leaks and prompt leakage."""
        generations = getattr(response, "generations", [])
        for gen_list in generations:
            for gen in gen_list:
                text = getattr(gen, "text", "")
                if text:
                    res = self.shield.validate_output(text)
                    if res.decision == ActionDecision.BLOCK and self.block_on_violation:
                        raise PrahariBlockedError(
                            f"LangChain output blocked by AgentPrahari: {res.rejection_reason}",
                            result=res,
                        )
                    elif res.decision == ActionDecision.SANITIZE and self.auto_sanitize_output:
                        if hasattr(gen, "text"):
                            gen.text = res.sanitized_content
