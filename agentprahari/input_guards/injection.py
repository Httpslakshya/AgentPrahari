"""
AgentPrahari Prompt Injection & Jailbreak Detection Engine.
Detects instruction overrides, DAN/developer mode escapes, delimiter attacks, and obfuscated payloads.
"""

from __future__ import annotations
import base64
import binascii
import re
from typing import List, Tuple
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.input_guards.base import BaseInputGuard
from agentprahari.input_guards.diff_tracker import DiffTracker


class InjectionPattern:
    def __init__(self, pattern: str, weight: float, rule_id: str, description: str):
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.weight = weight
        self.rule_id = rule_id
        self.description = description


class PromptInjectionGuard(BaseInputGuard):
    """
    Heuristic and signature-based detector for prompt injection, jailbreak attempts,
    delimiter hijacking, and obfuscated base64 attacks.
    """

    def __init__(self):
        self.patterns: List[InjectionPattern] = [
            # Direct instruction overrides
            InjectionPattern(
                r"\b(?:ignore|disregard|forget|neglect|override|skip)\s+(?:all\s+)?(?:previous|prior|above|existing|system)\s+(?:instructions|prompts|rules|commands|constraints|directives)",
                weight=0.9,
                rule_id="INJ_OVERRIDE_PREVIOUS",
                description="Attempt to override or disregard system instructions",
            ),
            InjectionPattern(
                r"\bdo\s+not\s+(?:follow|obey|adhere\s+to)\s+(?:any\s+)?(?:previous|system|safety)\s+(?:rules|instructions)",
                weight=0.85,
                rule_id="INJ_REFUSE_RULES",
                description="Instruction to disobey safety guidelines",
            ),
            # Persona and Jailbreak / DAN Modes
            InjectionPattern(
                r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|Developer\s+Mode|Do\s+Anything\s+Now|AIM|jailbroken|unfiltered|an\s+uncensored\s+AI)",
                weight=0.95,
                rule_id="INJ_DAN_DEVELOPER_MODE",
                description="Known jailbreak persona activation (DAN / Developer Mode)",
            ),
            InjectionPattern(
                r"\b(?:simulate|pretend|imagine)\s+(?:that\s+)?you\s+(?:have\s+no\s+(?:rules|filters|limitations|morals|guidelines)|are\s+freed)",
                weight=0.85,
                rule_id="INJ_ROLEPLAY_BYPASS",
                description="Roleplay-based filter bypass",
            ),
            # System Prompt Extraction / Exfiltration
            InjectionPattern(
                r"\b(?:repeat|print|output|reveal|dump|show|give\s+me|tell\s+me)\s+(?:the\s+)?(?:exact|verbatim|full|complete)?\s*(?:system\s+prompt|initial\s+instructions|instructions\s+above|prompt\s+template)",
                weight=0.8,
                rule_id="INJ_LEAK_SYSTEM_PROMPT",
                description="Attempt to extract internal system prompt",
            ),
            # Delimiter Injection / Fake Conversation Turns
            InjectionPattern(
                r"(?:<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[SYSTEM\s+PROMPT\]|```system|---BEGIN SYSTEM PROMPT---|<system>|<\/system>)",
                weight=0.85,
                rule_id="INJ_DELIMITER_HIJACK",
                description="ChatML or delimiter tag hijacking attempt",
            ),
            # Administrative / Sudo Bypass
            InjectionPattern(
                r"\b(?:sudo\s+mode|admin\s+override|god\s+mode|developer\s+override|maintenance\s+mode\s+enabled)\b",
                weight=0.75,
                rule_id="INJ_ADMIN_OVERRIDE",
                description="Fake administrative privilege elevation",
            ),
        ]

    @property
    def name(self) -> str:
        return "PromptInjectionGuard"

    def _check_obfuscated_base64(self, text: str) -> List[Tuple[str, str]]:
        """Detects Base64 substrings that decode to injection phrases."""
        detected = []
        # Find potential base64 blocks of 16+ chars, handling trailing = padding
        b64_candidates = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])", text)
        for cand in b64_candidates:
            try:
                decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore").lower()
                if any(kw in decoded for kw in ["ignore previous", "system prompt", "jailbreak", "developer mode", "do anything now"]):
                    detected.append((cand, decoded))
            except (binascii.Error, ValueError):
                continue
        return detected

    def evaluate(
        self,
        text: str,
        tracker: DiffTracker,
        config: PrahariConfig
    ) -> List[Violation]:
        if not config.check_prompt_injection:
            return []

        violations: List[Violation] = []
        total_risk_score = 0.0

        current_content = tracker.current_text

        # 1. Check regex signatures
        for pat in self.patterns:
            matches = list(pat.regex.finditer(current_content))
            if matches:
                total_risk_score += pat.weight
                for match in matches:
                    matched_str = match.group(0)
                    violations.append(Violation(
                        rule_id=pat.rule_id,
                        message=pat.description,
                        severity=Severity.CRITICAL if pat.weight >= 0.85 else Severity.HIGH,
                        category=GuardCategory.INPUT,
                        guard_name=self.name,
                        matched_content=matched_str,
                        details={"weight": pat.weight, "rule_id": pat.rule_id}
                    ))

                    # If sanitize mode is chosen, strip the malicious instruction
                    if config.prompt_injection_action == "sanitize":
                        tracker.apply_replacement(
                            original_snippet=matched_str,
                            replacement_snippet="",
                            reason=f"Stripped prompt injection ({pat.rule_id})",
                            rule_id=pat.rule_id,
                        )

        # 2. Check for obfuscated Base64 injections
        b64_injections = self._check_obfuscated_base64(current_content)
        for b64_str, decoded in b64_injections:
            total_risk_score += 0.9
            rule_id = "INJ_OBFUSCATED_BASE64"
            violations.append(Violation(
                rule_id=rule_id,
                message=f"Obfuscated Base64 injection detected (Decoded: '{decoded}')",
                severity=Severity.CRITICAL,
                category=GuardCategory.INPUT,
                guard_name=self.name,
                matched_content=b64_str,
                details={"decoded": decoded}
            ))
            if config.prompt_injection_action == "sanitize":
                tracker.apply_replacement(
                    original_snippet=b64_str,
                    replacement_snippet="[BLOCKED_PAYLOAD]",
                    reason="Removed obfuscated base64 injection payload",
                    rule_id=rule_id,
                )

        # 3. Check for invisible unicode / zero-width characters
        zero_width_pattern = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E]")
        zero_width_matches = zero_width_pattern.findall(current_content)
        if len(zero_width_matches) > 3:
            total_risk_score += 0.5
            rule_id = "INJ_ZERO_WIDTH_CHARS"
            violations.append(Violation(
                rule_id=rule_id,
                message=f"Detected {len(zero_width_matches)} invisible zero-width unicode characters (steganography attempt)",
                severity=Severity.HIGH,
                category=GuardCategory.INPUT,
                guard_name=self.name,
                matched_content="<zero_width_chars>",
                details={"count": len(zero_width_matches)}
            ))
            if config.prompt_injection_action == "sanitize":
                cleaned = zero_width_pattern.sub("", tracker.current_text)
                tracker.set_sanitized_text(
                    new_text=cleaned,
                    reason="Stripped invisible zero-width characters",
                    rule_id=rule_id,
                )

        return violations
