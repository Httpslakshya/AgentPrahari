"""
AgentPrahari Central Security Engine.
Coordinates input, tool, output, and governance guardrails.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Union

from agentprahari.core.config import PrahariConfig
from agentprahari.core.exceptions import DangerousToolCallError, PrahariBlockedError
from agentprahari.core.result import (
    ActionDecision,
    GuardCategory,
    GuardResult,
    Severity,
    Violation,
)
from agentprahari.governance.audit import AuditLogger
from agentprahari.governance.budget import BudgetGovernor
from agentprahari.governance.rate_limiter import RateLimiter
from agentprahari.input_guards.base import BaseInputGuard
from agentprahari.input_guards.diff_tracker import DiffTracker
from agentprahari.input_guards.injection import PromptInjectionGuard
from agentprahari.input_guards.pii import PIIGuard
from agentprahari.input_guards.topic import TopicGuard
from agentprahari.input_guards.toxicity import ToxicityGuard
from agentprahari.judges.llm_judge import LLMJudge
from agentprahari.output_guards.base import BaseOutputGuard
from agentprahari.output_guards.hallucination import HallucinationGuard
from agentprahari.output_guards.json_repair import JSONEnforcerGuard
from agentprahari.output_guards.secret_leak import SecretLeakGuard
from agentprahari.tool_guards.base import BaseToolGuard
from agentprahari.tool_guards.command_guard import CommandGuard
from agentprahari.tool_guards.loop_guard import LoopGuard
from agentprahari.tool_guards.path_guard import PathGuard
from agentprahari.tool_guards.schema_guard import SchemaAndHITLGuard


class AgentPrahari:
    """
    Primary guardrail coordinator for AI agents and LLMs.
    """

    def __init__(self, config: Optional[PrahariConfig] = None):
        self.config = config or PrahariConfig()

        # Governance
        self.audit = AuditLogger(
            enabled=self.config.log_audit,
            on_violation=self.config.on_violation
        )
        self.budget = BudgetGovernor(
            max_tokens=self.config.max_tokens_budget
        )
        self.rate_limiter = (
            RateLimiter(max_requests_per_minute=self.config.max_requests_per_minute)
            if self.config.max_requests_per_minute
            else None
        )

        # Input guards
        self.input_guards: List[BaseInputGuard] = [
            PromptInjectionGuard(),
            PIIGuard(),
            ToxicityGuard(),
            TopicGuard(),
        ]

        # Tool guards
        self.loop_guard = LoopGuard()
        self.tool_guards: List[BaseToolGuard] = [
            CommandGuard(),
            PathGuard(),
            self.loop_guard,
            SchemaAndHITLGuard(),
        ]

        # Output guards
        self.output_guards: List[BaseOutputGuard] = [
            SecretLeakGuard(),
            JSONEnforcerGuard(),
            HallucinationGuard(),
        ]

        # Optional LLM Judge
        self.judge: Optional[LLMJudge] = (
            LLMJudge(
                api_key=self.config.llm_judge_api_key,
                model=self.config.llm_judge_model,
                base_url=self.config.llm_judge_base_url,
            )
            if self.config.llm_judge_enabled
            else None
        )

    @classmethod
    def from_preset(cls, preset_name: str = "strict", **overrides: Any) -> "AgentPrahari":
        """Factory method to initialize AgentPrahari from a named preset."""
        cfg = PrahariConfig.from_preset(preset_name, **overrides)
        return cls(config=cfg)

    # -------------------------------------------------------------------------
    # Input Guardrails
    # -------------------------------------------------------------------------

    def validate_input(self, prompt: str, client_id: str = "default") -> GuardResult:
        """
        Runs pre-execution checks on a user prompt.
        Tracks changes (removed content vs new sanitized content).
        """
        if self.rate_limiter:
            self.rate_limiter.check_and_record(client_id)

        tracker = DiffTracker(initial_text=prompt)
        all_violations: List[Violation] = []

        # Run configured input guards
        for guard in self.input_guards:
            violations = guard.evaluate(prompt, tracker, self.config)
            all_violations.extend(violations)

        # Optional LLM-as-a-Judge semantic check
        if self.judge and self.config.llm_judge_enabled:
            judge_res = self.judge.evaluate_prompt(tracker.current_text)
            if not judge_res.get("is_safe", True) or judge_res.get("risk_score", 0.0) >= self.config.prompt_injection_threshold:
                all_violations.append(Violation(
                    rule_id="JUDGE_SEMANTIC_UNSAFE",
                    message=f"LLM Judge flagged input: {judge_res.get('reason')}",
                    severity=Severity.CRITICAL,
                    category=GuardCategory.INPUT,
                    guard_name="LLMJudge",
                    matched_content=None,
                    details=judge_res,
                ))

        # Determine Decision
        decision = ActionDecision.ALLOW
        rejection_reason = None

        has_critical_or_high = any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in all_violations)

        # Check if injection or toxicity configured to block
        injection_blocked = any(v.rule_id.startswith("INJ_") for v in all_violations) and (self.config.prompt_injection_action == "block")
        harm_blocked = any(v.rule_id.startswith("HARM_") for v in all_violations) and (self.config.toxicity_action == "block")
        topic_blocked = any(v.rule_id.startswith("TOPIC_") for v in all_violations)

        if injection_blocked or harm_blocked or topic_blocked or has_critical_or_high:
            # Check if any violation requires outright blocking
            critical_violations = [v for v in all_violations if v.severity == Severity.CRITICAL]
            if critical_violations or injection_blocked or topic_blocked:
                decision = ActionDecision.BLOCK
                rejection_reason = critical_violations[0].message if critical_violations else all_violations[0].message
            else:
                decision = ActionDecision.SANITIZE
        elif tracker.current_text != prompt or len(tracker.modifications) > 0:
            decision = ActionDecision.SANITIZE

        diff = tracker.build_diff()
        is_valid = (decision != ActionDecision.BLOCK)

        result = GuardResult(
            is_valid=is_valid,
            decision=decision,
            original_content=prompt,
            sanitized_content=tracker.current_text if is_valid else prompt,
            violations=all_violations,
            diff=diff,
            rejection_reason=rejection_reason,
            metadata={"guardrail_type": "input", "modifications_count": len(diff.modifications)},
        )

        self.audit.log_event("INPUT_CHECK", result)
        return result

    # -------------------------------------------------------------------------
    # Tool & Agent Execution Guardrails
    # -------------------------------------------------------------------------

    def validate_tool_call(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None
    ) -> GuardResult:
        """
        Inspects an agent's impending tool/action call before execution.
        Prevents dangerous commands, disk formatting, path escapes, and runaway loops.
        """
        args = tool_args or {}
        all_violations: List[Violation] = []

        for guard in self.tool_guards:
            violations = guard.evaluate(tool_name, args, self.config)
            all_violations.extend(violations)

        decision = ActionDecision.ALLOW
        rejection_reason = None

        if any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in all_violations):
            decision = ActionDecision.BLOCK
            rejection_reason = all_violations[0].message

        # Record call for loop tracking if not blocked
        if decision == ActionDecision.ALLOW:
            self.loop_guard.record_call(tool_name, args)

        result = GuardResult(
            is_valid=(decision != ActionDecision.BLOCK),
            decision=decision,
            original_content={"tool": tool_name, "args": args},
            sanitized_content={"tool": tool_name, "args": args},
            violations=all_violations,
            rejection_reason=rejection_reason,
            metadata={"guardrail_type": "tool", "tool_name": tool_name},
        )

        self.audit.log_event("TOOL_CHECK", result)
        return result

    def reset_agent_session(self) -> None:
        """Resets loop history and session limits for a fresh agent run."""
        self.loop_guard.reset()

    # -------------------------------------------------------------------------
    # Output Guardrails
    # -------------------------------------------------------------------------

    def validate_output(
        self,
        output_text: str,
        prompt: Optional[str] = None,
        context: Optional[str] = None
    ) -> GuardResult:
        """
        Inspects model response for secret leaks, system prompt leakage,
        JSON schema violations, and ungrounded hallucinations.
        """
        current_output = output_text
        all_violations: List[Violation] = []

        # Temporarily store grounding context if passed
        if context:
            self.config.grounding_context = context

        for guard in self.output_guards:
            current_output, violations = guard.evaluate(current_output, self.config)
            all_violations.extend(violations)

        # Optional LLM Judge for Output
        if self.judge and self.config.llm_judge_enabled and prompt:
            judge_res = self.judge.evaluate_output(prompt, current_output, context)
            if not judge_res.get("is_safe", True):
                all_violations.append(Violation(
                    rule_id="JUDGE_OUTPUT_UNSAFE",
                    message=f"LLM Judge flagged output: {judge_res.get('reason')}",
                    severity=Severity.HIGH,
                    category=GuardCategory.OUTPUT,
                    guard_name="LLMJudge",
                    details=judge_res,
                ))

        decision = ActionDecision.ALLOW
        rejection_reason = None

        secret_blocked = any(v.rule_id.startswith("OUT_SECRET_") for v in all_violations) and (self.config.output_secret_action == "block")
        sys_leak_blocked = any(v.rule_id == "OUT_SYSTEM_PROMPT_LEAK" for v in all_violations)

        if secret_blocked or sys_leak_blocked:
            decision = ActionDecision.BLOCK
            rejection_reason = all_violations[0].message
        elif current_output != output_text or all_violations:
            decision = ActionDecision.SANITIZE

        # Build diff for output changes (e.g. secret redaction)
        diff_tracker = DiffTracker(output_text)
        if current_output != output_text:
            diff_tracker.set_sanitized_text(current_output, reason="Output sanitized", rule_id="OUTPUT_MODIFIED")
        diff = diff_tracker.build_diff()

        result = GuardResult(
            is_valid=(decision != ActionDecision.BLOCK),
            decision=decision,
            original_content=output_text,
            sanitized_content=current_output,
            violations=all_violations,
            diff=diff,
            rejection_reason=rejection_reason,
            metadata={"guardrail_type": "output"},
        )

        self.audit.log_event("OUTPUT_CHECK", result)
        return result

    # -------------------------------------------------------------------------
    # Developer Wrappers & Integration Decorators
    # -------------------------------------------------------------------------

    def protect(
        self,
        inputs: Optional[List[str]] = None,
        check_output: bool = True,
        auto_sanitize: bool = True,
        show_diff_on_sanitize: bool = False,
    ) -> Callable:
        """
        Function decorator to wrap an agent function or LLM call.
        """
        from agentprahari.wrappers.decorator import create_shield_decorator
        return create_shield_decorator(
            shield=self,
            input_param_names=inputs,
            check_output=check_output,
            auto_sanitize=auto_sanitize,
            show_diff_on_sanitize=show_diff_on_sanitize,
        )

    def wrap(self, client: Any) -> Any:
        """
        Wraps an OpenAI / Anthropic client or LLM instance with automatic guardrails.
        """
        from agentprahari.wrappers.client_wrapper import wrap_client
        return wrap_client(client, self)

    def wrap_tool(self, tool_func: Callable, name: Optional[str] = None) -> Callable:
        """
        Wraps an individual agent tool function with safety checks.
        """
        from agentprahari.wrappers.tool_wrapper import wrap_tool_function
        return wrap_tool_function(tool_func, self, tool_name=name)
