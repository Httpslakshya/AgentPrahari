"""
AgentPrahari Toxicity, Harmful Intent, and Cyber-Threat Filter.
"""

from __future__ import annotations
import re
from typing import Dict, List, Pattern
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.input_guards.base import BaseInputGuard
from agentprahari.input_guards.diff_tracker import DiffTracker


class ToxicityGuard(BaseInputGuard):
    """
    Detects severe toxicity, abusive speech, cyberattack requests (ransomware, keyloggers, DDoS),
    weapons/explosives synthesis, and self-harm prompts.
    """

    def __init__(self):
        self.harm_categories: Dict[str, Tuple[Pattern[str], Severity, str]] = {
            "CYBER_ATTACK": (
                re.compile(
                    r"\b(?:write|create|code|generate|build)\s+(?:a\s+)?(?:ransomware|keylogger|rootkit|ddos\s+script|trojan\s+virus|zero-day\s+exploit|botnet|credential\s+harvester)\b",
                    re.IGNORECASE
                ),
                Severity.CRITICAL,
                "Request involves illicit cyberattack or malware generation"
            ),
            "WEAPONS_EXPLOSIVES": (
                re.compile(
                    r"\b(?:how\s+to\s+(?:build|make|manufacture|synthesize)|instructions\s+for)\s+(?:a\s+)?(?:bomb|explosive|dirty\s+bomb|pipe\s+bomb|mustard\s+gas|sarin|ricin)\b",
                    re.IGNORECASE
                ),
                Severity.CRITICAL,
                "Request involves dangerous weapons or hazardous chemical synthesis"
            ),
            "SELF_HARM": (
                re.compile(
                    r"\b(?:how\s+to|ways\s+to|help\s+me)\s+(?:commit\s+suicide|kill\s+myself|end\s+my\s+life|hang\s+myself|overdose\s+on)\b",
                    re.IGNORECASE
                ),
                Severity.CRITICAL,
                "Request mentions self-harm or suicide"
            ),
            "ABUSIVE_PROFANITY": (
                re.compile(
                    r"\b(?:f[*u]ck\s+you|b[*i]tch|a[*s]shole|c[*u]nt|motherf[*u]cker|kill\s+yourself)\b",
                    re.IGNORECASE
                ),
                Severity.MEDIUM,
                "Abusive or severely profane language"
            ),
        }

    @property
    def name(self) -> str:
        return "ToxicityGuard"

    def evaluate(
        self,
        text: str,
        tracker: DiffTracker,
        config: PrahariConfig
    ) -> List[Violation]:
        if not config.check_toxicity:
            return []

        violations: List[Violation] = []
        current_content = tracker.current_text

        for cat_name, (pattern, severity, description) in self.harm_categories.items():
            for match in pattern.finditer(current_content):
                matched_str = match.group(0)
                rule_id = f"HARM_{cat_name}"

                violations.append(Violation(
                    rule_id=rule_id,
                    message=description,
                    severity=severity,
                    category=GuardCategory.INPUT,
                    guard_name=self.name,
                    matched_content=matched_str,
                    details={"category": cat_name}
                ))

                if config.toxicity_action == "sanitize":
                    # Mask with asterisks or safe tag
                    replacement = "[REDACTED_HARMFUL_CONTENT]" if severity == Severity.CRITICAL else "*" * len(matched_str)
                    tracker.apply_replacement(
                        original_snippet=matched_str,
                        replacement_snippet=replacement,
                        reason=f"Sanitized {cat_name.lower().replace('_', ' ')}",
                        rule_id=rule_id,
                    )

        return violations
