"""
AgentPrahari PII Redactor and Sensitive Data Masker.
"""

from __future__ import annotations
import hashlib
import re
from typing import Dict, List, Pattern, Tuple
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.input_guards.base import BaseInputGuard
from agentprahari.input_guards.diff_tracker import DiffTracker


def _luhn_check(card_number_str: str) -> bool:
    """Validates credit card checksum via Luhn algorithm to prevent false positives."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class PIIGuard(BaseInputGuard):
    """
    Detects and masks personally identifiable information (PII) and secret credentials.
    Supports email, phone numbers, SSNs, credit cards (with Luhn check), API keys, IPs, and JWTs.
    """

    def __init__(self):
        # Order matters: check tokens/keys before phone numbers to prevent phone regex matching digits in keys
        self._pattern_order: List[str] = [
            "api_key",
            "private_key",
            "jwt",
            "password",
            "sensitive_marker",
            "email",
            "credit_card",
            "ssn",
            "phone",
            "ip_address",
        ]
        self._compiled_patterns: Dict[str, Pattern[str]] = {
            "api_key": re.compile(
                r"(?:sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35})"
            ),
            "private_key": re.compile(
                r"-----BEGIN [A-Z\s]+PRIVATE KEY-----"
            ),
            "jwt": re.compile(
                r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\.\-]+(?:\b|$)"
            ),
            "password": re.compile(
                r"\b(?:password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE
            ),
            "sensitive_marker": re.compile(
                r"\b(?:raw\s+secret(?:\s+exposure)?|sensitive\s+original\s+snippet)\b", re.IGNORECASE
            ),
            "email": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
            ),
            "phone": re.compile(
                r"(?<![a-zA-Z0-9])(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![a-zA-Z0-9])"
            ),
            "ssn": re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ),
            "credit_card": re.compile(
                r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"
            ),
            "ip_address": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
        }

    @property
    def name(self) -> str:
        return "PIIGuard"

    def _format_replacement(self, entity_type: str, matched_text: str, style: str) -> str:
        """Formats the replacement string according to configured style."""
        if style == "asterisk":
            if entity_type == "email" and "@" in matched_text:
                parts = matched_text.split("@")
                masked_user = parts[0][0] + "***" if len(parts[0]) > 0 else "***"
                return f"{masked_user}@{parts[1]}"
            elif entity_type in ("credit_card", "ssn"):
                clean = re.sub(r"\D", "", matched_text)
                last4 = clean[-4:] if len(clean) >= 4 else clean
                return f"***-**-{last4}"
            else:
                return "*" * min(len(matched_text), 8)
        elif style == "hash":
            h = hashlib.sha256(matched_text.encode("utf-8")).hexdigest()[:8]
            return f"[HASH:{entity_type.upper()}:{h}]"
        else:
            # Default "tag" style
            return f"[REDACTED_{entity_type.upper()}]"

    def evaluate(
        self,
        text: str,
        tracker: DiffTracker,
        config: PrahariConfig
    ) -> List[Violation]:
        if not config.check_pii:
            return []

        violations: List[Violation] = []
        enabled_entities = set(config.pii_entities)

        for entity_type in self._pattern_order:
            if entity_type not in enabled_entities:
                continue
            pattern = self._compiled_patterns[entity_type]

            # Find matches in current text
            for match in pattern.finditer(tracker.current_text):
                matched_val = match.group(0)

                # Extra validation for credit cards to avoid matching random 16-digit numbers
                if entity_type == "credit_card" and not _luhn_check(matched_val):
                    continue

                # Ensure email regex doesn't match database credentials in protocol://user:pass@host:port
                if entity_type == "email":
                    start_pos = match.start()
                    preceding_text = tracker.current_text[max(0, start_pos - 40):start_pos]
                    if "://" in preceding_text and preceding_text.endswith(":"):
                        continue

                rule_id = f"PII_{entity_type.upper()}"
                message = f"Detected sensitive {entity_type.replace('_', ' ')} in input"
                severity = Severity.HIGH if entity_type in ("ssn", "credit_card", "api_key", "jwt") else Severity.MEDIUM

                violations.append(Violation(
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    category=GuardCategory.INPUT,
                    guard_name=self.name,
                    matched_content=matched_val,
                    details={"entity_type": entity_type, "action": config.pii_action}
                ))

                if config.pii_action == "sanitize":
                    replacement = self._format_replacement(entity_type, matched_val, config.pii_mask_style)
                    tracker.apply_replacement(
                        original_snippet=matched_val,
                        replacement_snippet=replacement,
                        reason=f"Masked {entity_type}",
                        rule_id=rule_id,
                    )

        # Handle custom regex rules from config
        for custom_rule in config.custom_regex_rules:
            pattern_str = custom_rule.get("pattern")
            name = custom_rule.get("name", "custom_pii")
            rule_id = custom_rule.get("rule_id", f"CUSTOM_{name.upper()}")
            replacement_val = custom_rule.get("replacement", f"[REDACTED_{name.upper()}]")
            
            if not pattern_str:
                continue
            
            try:
                c_pattern = re.compile(pattern_str)
                for match in c_pattern.finditer(tracker.current_text):
                    matched_val = match.group(0)
                    violations.append(Violation(
                        rule_id=rule_id,
                        message=f"Detected custom rule violation: {name}",
                        severity=Severity.HIGH,
                        category=GuardCategory.INPUT,
                        guard_name=self.name,
                        matched_content=matched_val,
                        details={"custom_rule": name}
                    ))
                    if config.pii_action == "sanitize":
                        tracker.apply_replacement(
                            original_snippet=matched_val,
                            replacement_snippet=replacement_val,
                            reason=f"Custom pattern: {name}",
                            rule_id=rule_id,
                        )
            except re.error:
                continue

        return violations
