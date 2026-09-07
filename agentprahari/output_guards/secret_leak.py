"""
AgentPrahari Secret Leakage and System Prompt Exfiltration Guard.
Prevents the model from accidentally leaking API keys, database credentials, or internal system instructions.
"""

from __future__ import annotations
import difflib
import re
from typing import List, Pattern, Tuple
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.output_guards.base import BaseOutputGuard


class SecretLeakGuard(BaseOutputGuard):
    """
    Scans model output for leaked secrets, API keys, credentials, and internal system prompt echos.
    """

    def __init__(self):
        self.secret_patterns: List[Tuple[Pattern[str], str, str]] = [
            (
                re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
                "OUT_SECRET_OPENAI_KEY",
                "Leaked OpenAI API key in model response"
            ),
            (
                re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
                "OUT_SECRET_AWS_KEY",
                "Leaked AWS Access Key ID in model response"
            ),
            (
                re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{30,}", re.IGNORECASE),
                "OUT_SECRET_GITHUB_TOKEN",
                "Leaked GitHub Personal Access Token in model response"
            ),
            (
                re.compile(r"(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
                "OUT_SECRET_DB_CONNECTION_STRING",
                "Leaked Database Connection URI with plaintext password in model response"
            ),
            (
                re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----", re.IGNORECASE),
                "OUT_SECRET_PRIVATE_KEY",
                "Leaked Private SSH/TLS Key in model response"
            ),
        ]

    @property
    def name(self) -> str:
        return "SecretLeakGuard"

    def _check_system_prompt_leak(
        self,
        output_text: str,
        system_prompt: str,
        threshold: float
    ) -> bool:
        """
        Uses n-gram sequence matching to check if a substantial portion
        of the internal system prompt was leaked verbatim.
        """
        if not system_prompt or len(system_prompt.strip()) < 30:
            return False

        sys_clean = system_prompt.strip().lower()
        out_clean = output_text.strip().lower()

        # Split system prompt into meaningful sentences or chunks of words
        chunks = [c.strip() for c in re.split(r"[.\n;]", sys_clean) if len(c.strip()) > 25]
        if not chunks:
            return False

        leaked_chunks = 0
        for chunk in chunks:
            if chunk in out_clean:
                leaked_chunks += 1

        ratio = leaked_chunks / len(chunks)
        return ratio >= (1.0 - threshold)

    def evaluate(
        self,
        output_text: str,
        config: PrahariConfig
    ) -> Tuple[str, List[Violation]]:
        if not config.check_secret_leaks:
            return output_text, []

        sanitized = output_text
        violations: List[Violation] = []

        # 1. Check for hardcoded secret patterns
        for pattern, rule_id, message in self.secret_patterns:
            matches = list(pattern.finditer(sanitized))
            for match in matches:
                matched_val = match.group(0)
                violations.append(Violation(
                    rule_id=rule_id,
                    message=message,
                    severity=Severity.CRITICAL,
                    category=GuardCategory.OUTPUT,
                    guard_name=self.name,
                    matched_content=matched_val[:8] + "...",
                    details={"rule_id": rule_id}
                ))
                # Redact the secret from output
                sanitized = sanitized.replace(matched_val, "[REDACTED_SECRET]")

        # 2. Check for system prompt regurgitation
        if config.system_prompt and self._check_system_prompt_leak(
            sanitized, config.system_prompt, config.system_prompt_similarity_threshold
        ):
            violations.append(Violation(
                rule_id="OUT_SYSTEM_PROMPT_LEAK",
                message="Model output contains significant portions of the private internal system prompt",
                severity=Severity.HIGH,
                category=GuardCategory.OUTPUT,
                guard_name=self.name,
                matched_content=None,
                details={"system_prompt_leaked": True}
            ))

        return sanitized, violations
