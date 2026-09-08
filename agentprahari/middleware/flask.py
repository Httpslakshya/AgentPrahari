"""
Flask Extension / Hook for AgentPrahari.

Provides request guardrails for Flask applications.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Sequence

from agentprahari import AgentPrahari
from agentprahari.core.result import ActionDecision


class PrahariFlask:
    """
    Flask extension that hooks into before_request to validate incoming payloads.

    Example:
        from flask import Flask, request, jsonify
        from agentprahari.middleware import PrahariFlask

        app = Flask(__name__)
        prahari = PrahariFlask(app, preset="strict")

        @app.route("/chat", methods=["POST"])
        def chat():
            return jsonify({"reply": "Safe!"})
    """

    def __init__(
        self,
        app: Optional[Any] = None,
        shield: Optional[AgentPrahari] = None,
        preset: str = "strict",
        input_keys: Sequence[str] = ("prompt", "message", "query", "text", "input", "content"),
        block_status_code: int = 400,
        auto_sanitize: bool = True,
    ) -> None:
        self.shield = shield or AgentPrahari.from_preset(preset)
        self.input_keys = tuple(input_keys)
        self.block_status_code = block_status_code
        self.auto_sanitize = auto_sanitize

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        """Registers the before_request hook on the Flask app."""
        app.before_request(self._before_request)

    def _before_request(self) -> Any:
        try:
            from flask import request, jsonify
        except ImportError:
            return None

        if request.method not in ("POST", "PUT", "PATCH"):
            return None

        if not request.is_json:
            return None

        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return None

        client_id = request.remote_addr or "default"

        # Check top-level keys and messages
        for key in self.input_keys:
            val = data.get(key)
            if isinstance(val, str):
                res = self.shield.validate_input(val, client_id=client_id)
                if res.decision == ActionDecision.BLOCK:
                    return jsonify({
                        "error": "Security violation detected by AgentPrahari",
                        "decision": res.decision.value,
                        "rejection_reason": res.rejection_reason,
                        "violations": [
                            {"rule_id": v.rule_id, "message": v.message, "severity": v.severity.value}
                            for v in res.violations
                        ],
                    }), self.block_status_code
                elif res.decision == ActionDecision.SANITIZE and self.auto_sanitize:
                    data[key] = res.sanitized_content

        return None
