"""
AgentPrahari Drop-in Client Wrapper for OpenAI and LLM SDKs.
"""

from __future__ import annotations
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from agentprahari.core.engine import AgentPrahari


class ShieldedCompletions:
    def __init__(self, raw_completions: Any, shield: "AgentPrahari"):
        self._raw_completions = raw_completions
        self._shield = shield

    def create(self, *args: Any, **kwargs: Any) -> Any:
        # Guard messages if provided
        messages = kwargs.get("messages")
        if messages and isinstance(messages, list):
            guarded_messages = []
            for msg in messages:
                if isinstance(msg, dict) and "content" in msg and isinstance(msg["content"], str):
                    res = self._shield.validate_input(msg["content"])
                    res.raise_if_blocked()
                    # Use sanitized text
                    guarded_msg = dict(msg)
                    guarded_msg["content"] = res.sanitized_content
                    guarded_messages.append(guarded_msg)
                else:
                    guarded_messages.append(msg)
            kwargs["messages"] = guarded_messages

        # Call underlying LLM client
        response = self._raw_completions.create(*args, **kwargs)

        # Inspect and guard response choices
        if hasattr(response, "choices") and response.choices:
            for choice in response.choices:
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    raw_out = choice.message.content
                    if raw_out:
                        out_res = self._shield.validate_output(raw_out)
                        out_res.raise_if_blocked()
                        choice.message.content = out_res.sanitized_content

        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw_completions, name)


class ShieldedChat:
    def __init__(self, raw_chat: Any, shield: "AgentPrahari"):
        self._raw_chat = raw_chat
        self._shield = shield
        self.completions = ShieldedCompletions(raw_chat.completions, shield)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw_chat, name)


class ShieldedClientProxy:
    """
    Transparent proxy wrapping OpenAI / Anthropic clients with AgentPrahari protection.
    """

    def __init__(self, client: Any, shield: "AgentPrahari"):
        self._client = client
        self._shield = shield
        if hasattr(client, "chat"):
            self.chat = ShieldedChat(client.chat, shield)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def wrap_client(client: Any, shield: "AgentPrahari") -> ShieldedClientProxy:
    """Wraps an LLM client instance with automated AgentPrahari protection."""
    return ShieldedClientProxy(client, shield)
