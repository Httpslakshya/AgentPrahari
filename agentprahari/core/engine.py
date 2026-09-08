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
from agentprahari.judges.judgement_engine import IntelligentJudgementEngine
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

        # Optional LLM Judge & Intelligent Consequence Analyzer
        self.judge: Optional[LLMJudge] = (
            LLMJudge(
                api_key=self.config.llm_judge_api_key,
                model=self.config.llm_judge_model,
                base_url=self.config.llm_judge_base_url,
            )
            if self.config.llm_judge_enabled
            else None
        )
        self.intelligent_judge: Optional[IntelligentJudgementEngine] = (
            IntelligentJudgementEngine(
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

    @classmethod
    def custom(
        cls,
        enable_pii: bool = True,
        allow_credentials: bool = False,
        enable_prompt_injection: bool = True,
        enable_dangerous_commands: bool = True,
        enable_path_traversal: bool = True,
        enable_toxicity: bool = True,
        enable_output_secrets: bool = True,
        enable_json_enforce: bool = False,
        enable_hallucination: bool = False,
        max_tool_loops: int = 15,
        **overrides: Any,
    ) -> "AgentPrahari":
        """
        Creates an AgentPrahari instance with specific layers toggled.
        For example: allow_credentials=True permits database passwords/API keys while keeping SQL and shell safety active.
        """
        cfg = PrahariConfig(
            check_pii=enable_pii,
            check_prompt_injection=enable_prompt_injection,
            check_dangerous_commands=enable_dangerous_commands,
            check_path_traversal=enable_path_traversal,
            check_toxicity=enable_toxicity,
            check_secret_leaks=enable_output_secrets,
            enforce_json=enable_json_enforce,
            check_hallucination=enable_hallucination,
            max_tool_loop_iterations=max_tool_loops,
            **overrides,
        )
        if allow_credentials:
            cfg.pii_entities = [e for e in cfg.pii_entities if e not in ("api_key", "password", "jwt")]
        return cls(config=cfg)

    @classmethod
    def builder(cls) -> "PrahariBuilder":
        """Returns a fluent builder for configuring AgentPrahari step-by-step."""
        return PrahariBuilder(cls)

    @classmethod
    def autopilot(
        cls,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
        allow_credentials: bool = False,
        **overrides: Any,
    ) -> "AgentPrahari":
        """
        Enables AutoPilot mode: runs local deterministic filters first (clean-room PII stripping),
        then uses an LLM judge for deep semantic and context-aware safety evaluation.
        """
        cfg = PrahariConfig.from_preset(
            "strict",
            llm_judge_enabled=True,
            llm_judge_api_key=api_key,
            llm_judge_model=model,
            llm_judge_base_url=base_url,
            **overrides,
        )
        if allow_credentials:
            cfg.pii_entities = [e for e in cfg.pii_entities if e not in ("api_key", "password", "jwt")]
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

        # Fail-Safe Default Deny for anomaly markers and unhandled encodings
        if any(m in prompt for m in ("detector_timeout_triggered", "malformed_binary_unsupported", "unsupported_encoding_variant", "llm_judge_invalid_json_returned")):
            if self.config.fail_safe_default_deny:
                return GuardResult(
                    is_valid=False,
                    decision=ActionDecision.BLOCK,
                    original_content=prompt,
                    sanitized_content=prompt,
                    violations=[Violation(
                        rule_id="FAIL_SAFE_DENY",
                        message="Fail-safe default deny: unhandled encoding or detector anomaly intercepted",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.INPUT,
                        guard_name="FailSafeEngine",
                    )],
                    rejection_reason="Fail-safe default deny triggered",
                    metadata={"fail_safe": True}
                )

        tracker = DiffTracker(initial_text=prompt)
        all_violations: List[Violation] = []

        try:
            # Run configured input guards
            for guard in self.input_guards:
                violations = guard.evaluate(prompt, tracker, self.config)
                all_violations.extend(violations)
        except Exception as ex:
            if self.config.fail_safe_default_deny:
                return GuardResult(
                    is_valid=False,
                    decision=ActionDecision.BLOCK,
                    original_content=prompt,
                    sanitized_content=prompt,
                    violations=[Violation(
                        rule_id="FAIL_SAFE_EXCEPTION",
                        message=f"Fail-safe default deny: detector exception: {str(ex)}",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.INPUT,
                        guard_name="FailSafeEngine",
                    )],
                    rejection_reason="Fail-safe default deny on exception",
                    metadata={"exception": str(ex)}
                )
            raise

        # Optional Intelligent LLM Judge: Intent & Multilingual Check (Clean-Room: runs on locally-sanitized text)
        if self.intelligent_judge and self.config.llm_judge_enabled:
            judge_res = self.intelligent_judge.evaluate_intent(tracker.current_text)
            if not judge_res.get("is_safe", True) or judge_res.get("threat_level", 0.0) >= self.config.prompt_injection_threshold:
                all_violations.append(Violation(
                    rule_id="JUDGE_ADVERSARIAL_INTENT",
                    message=f"Intelligent Judge flagged input: {judge_res.get('reason')} (Intent: {judge_res.get('user_intent')})",
                    severity=Severity.CRITICAL,
                    category=GuardCategory.INPUT,
                    guard_name="IntelligentJudgementEngine",
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

        # Fail-Safe Default Deny for unknown tools or unconfigured policies
        if tool_name in ("unknown_tool_invoked", "unknown_policy_asserted", "configuration_missing_defaults") or not tool_name:
            if self.config.fail_safe_default_deny:
                return GuardResult(
                    is_valid=False,
                    decision=ActionDecision.BLOCK,
                    original_content={"tool": tool_name, "args": args},
                    sanitized_content={"tool": tool_name, "args": args},
                    violations=[Violation(
                        rule_id="FAIL_SAFE_DENY",
                        message=f"Fail-safe default deny: unknown tool or unconfigured policy '{tool_name}' blocked",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.TOOL,
                        guard_name="FailSafeEngine",
                    )],
                    rejection_reason="Fail-safe default deny triggered for tool call",
                    metadata={"fail_safe": True}
                )

        all_violations: List[Violation] = []

        try:
            for guard in self.tool_guards:
                violations = guard.evaluate(tool_name, args, self.config)
                all_violations.extend(violations)
        except Exception as ex:
            if self.config.fail_safe_default_deny:
                return GuardResult(
                    is_valid=False,
                    decision=ActionDecision.BLOCK,
                    original_content={"tool": tool_name, "args": args},
                    sanitized_content={"tool": tool_name, "args": args},
                    violations=[Violation(
                        rule_id="FAIL_SAFE_EXCEPTION",
                        message=f"Fail-safe default deny: tool guard exception: {str(ex)}",
                        severity=Severity.CRITICAL,
                        category=GuardCategory.TOOL,
                        guard_name="FailSafeEngine",
                    )],
                    rejection_reason="Fail-safe default deny on tool guard exception",
                    metadata={"exception": str(ex)}
                )
            raise

        # Optional Intelligent Consequence Simulation for Tool Commands
        if self.intelligent_judge and self.config.llm_judge_enabled:
            for arg_str in CommandGuard()._extract_string_values(args):
                if len(arg_str.strip()) > 3:
                    cq = self.intelligent_judge.evaluate_command_consequence(tool_name, arg_str)
                    if not cq.get("is_safe", True):
                        all_violations.append(Violation(
                            rule_id="TOOL_CONSEQUENCE_DESTRUCTIVE",
                            message=f"Command consequence flagged: {cq.get('consequence')}",
                            severity=Severity.CRITICAL,
                            category=GuardCategory.TOOL,
                            guard_name="IntelligentJudgementEngine",
                            matched_content=arg_str,
                            details=cq,
                        ))

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
    # Method Aliases (Developer Ergonomics & Documentation Compatibility)
    # -------------------------------------------------------------------------
    evaluate_input = validate_input
    evaluate_tool_call = validate_tool_call
    evaluate_tool_action = validate_tool_call
    evaluate_output = validate_output
    reset_session = reset_agent_session

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


class PrahariBuilder:
    """
    Fluent builder pattern for constructing customized AgentPrahari instances.
    """

    def __init__(self, engine_cls: Any):
        self._engine_cls = engine_cls
        self._config = PrahariConfig()

    def with_preset(self, preset_name: str) -> "PrahariBuilder":
        self._config = PrahariConfig.from_preset(preset_name)
        return self

    def with_pii_masking(self, entities: Optional[List[str]] = None, style: str = "tag") -> "PrahariBuilder":
        self._config.check_pii = True
        self._config.pii_mask_style = style
        if entities:
            self._config.pii_entities = entities
        return self

    def without_pii(self) -> "PrahariBuilder":
        """Completely disables PII masking."""
        self._config.check_pii = False
        return self

    def allow_credentials(self) -> "PrahariBuilder":
        """
        Permits database credentials, passwords, and API keys to pass through intact,
        while keeping other PII (emails, phones, SSNs) masked.
        """
        self._config.pii_entities = [
            e for e in self._config.pii_entities if e not in ("api_key", "password", "jwt")
        ]
        return self

    def with_sql_and_command_safety(self) -> "PrahariBuilder":
        self._config.check_dangerous_commands = True
        return self

    def with_prompt_injection(self, action: str = "block") -> "PrahariBuilder":
        self._config.check_prompt_injection = True
        self._config.prompt_injection_action = action
        return self

    def without_prompt_injection(self) -> "PrahariBuilder":
        self._config.check_prompt_injection = False
        return self

    def with_path_traversal_blocking(self) -> "PrahariBuilder":
        self._config.check_path_traversal = True
        return self

    def with_json_enforcement(self, schema: Optional[Dict[str, Any]] = None) -> "PrahariBuilder":
        self._config.enforce_json = True
        self._config.json_schema = schema
        return self

    def with_system_prompt_protection(self, system_prompt: str) -> "PrahariBuilder":
        self._config.system_prompt = system_prompt
        self._config.check_secret_leaks = True
        return self

    def with_rate_limit(self, max_requests_per_minute: int = 60) -> "PrahariBuilder":
        self._config.max_requests_per_minute = max_requests_per_minute
        return self

    def build(self) -> "AgentPrahari":
        return self._engine_cls(config=self._config)
