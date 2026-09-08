"""
FastAPI / Starlette ASGI Middleware for AgentPrahari.

Provides zero-code, transparent request guardrails for FastAPI, Starlette,
and any standard ASGI application.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

from agentprahari import AgentPrahari, PrahariConfig
from agentprahari.core.result import ActionDecision


class PrahariMiddleware:
    """
    ASGI Middleware that intercepts incoming requests, validates prompt contents
    against AgentPrahari security guardrails, and blocks hostile requests before
    they reach your FastAPI/Starlette route handlers.

    Example:
        from fastapi import FastAPI
        from agentprahari.middleware import PrahariMiddleware

        app = FastAPI()
        app.add_middleware(PrahariMiddleware, preset="strict")

        @app.post("/chat")
        async def chat(data: dict):
            return {"reply": "Safe!"}
    """

    def __init__(
        self,
        app: Any,
        shield: Optional[AgentPrahari] = None,
        preset: str = "strict",
        input_keys: Sequence[str] = ("prompt", "message", "query", "text", "input", "content"),
        excluded_paths: Optional[Sequence[str]] = None,
        block_status_code: int = 400,
        auto_sanitize: bool = True,
        on_violation: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.app = app
        self.shield = shield or AgentPrahari.from_preset(preset)
        self.input_keys = tuple(input_keys)
        self.excluded_paths: Set[str] = set(excluded_paths or ["/docs", "/openapi.json", "/redoc", "/health", "/metrics"])
        self.block_status_code = block_status_code
        self.auto_sanitize = auto_sanitize
        self.on_violation = on_violation

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        if method not in ("POST", "PUT", "PATCH") or path in self.excluded_paths:
            await self.app(scope, receive, send)
            return

        # Buffer request body
        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        raw_body = b"".join(body_chunks)
        if not raw_body:
            async def empty_receive():
                return {"type": "http.request", "body": b"", "more_body": False}
            await self.app(scope, empty_receive, send)
            return

        # Attempt to parse JSON body
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            # Not JSON or decode error; pass through
            async def passthrough_receive():
                return {"type": "http.request", "body": raw_body, "more_body": False}
            await self.app(scope, passthrough_receive, send)
            return

        # Scan for candidate prompt strings in JSON payload
        client_id = scope.get("client", ("127.0.0.1", 0))[0] if scope.get("client") else "default"
        is_blocked = False
        rejection_response: Optional[Dict[str, Any]] = None
        modified = False

        def scan_and_protect(obj: Any) -> Any:
            nonlocal is_blocked, rejection_response, modified
            if is_blocked:
                return obj

            if isinstance(obj, dict):
                new_dict = {}
                for k, v in obj.items():
                    if is_blocked:
                        return obj
                    # Check OpenAI messages array style
                    if k == "messages" and isinstance(v, list):
                        new_dict[k] = [scan_and_protect(item) for item in v]
                    elif k in self.input_keys and isinstance(v, str):
                        res = self.shield.validate_input(v, client_id=client_id)
                        if res.decision == ActionDecision.BLOCK:
                            is_blocked = True
                            rejection_response = {
                                "error": "Security violation detected by AgentPrahari",
                                "decision": res.decision.value,
                                "rejection_reason": res.rejection_reason,
                                "violations": [
                                    {"rule_id": vi.rule_id, "message": vi.message, "severity": vi.severity.value}
                                    for vi in res.violations
                                ],
                            }
                            if self.on_violation:
                                self.on_violation(rejection_response)
                            return obj
                        elif res.decision == ActionDecision.SANITIZE and self.auto_sanitize:
                            new_dict[k] = res.sanitized_content
                            modified = True
                        else:
                            new_dict[k] = v
                    else:
                        new_dict[k] = scan_and_protect(v)
                return new_dict
            elif isinstance(obj, list):
                return [scan_and_protect(elem) for elem in obj]
            return obj

        sanitized_payload = scan_and_protect(payload)

        # If blocked, return HTTP 400/403 directly
        if is_blocked and rejection_response:
            resp_body = json.dumps(rejection_response).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": self.block_status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(resp_body)).encode("ascii")),
                    (b"x-agentprahari-status", b"blocked"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": resp_body,
            })
            return

        # Re-encode body if sanitized
        if modified:
            new_body = json.dumps(sanitized_payload).encode("utf-8")
        else:
            new_body = raw_body

        async def sanitized_receive():
            return {"type": "http.request", "body": new_body, "more_body": False}

        await self.app(scope, sanitized_receive, send)
