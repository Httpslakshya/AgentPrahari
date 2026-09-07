"""
AgentPrahari Input Diff Tracking Engine.
Tracks all modifications, redactions, and insertions to show exactly what was removed and what is new.
"""

from __future__ import annotations
from typing import List
from agentprahari.core.result import SanitizationDiff, TextModification


class DiffTracker:
    """
    Manages text transformations and builds the SanitizationDiff.
    Ensures accurate character span tracking and clear reporting of changes.
    """

    def __init__(self, initial_text: str):
        self.original_text: str = initial_text
        self.current_text: str = initial_text
        self.modifications: List[TextModification] = []

    def record_replacement(
        self,
        original_snippet: str,
        replacement_snippet: str,
        reason: str,
        rule_id: str,
        start_idx: int = -1,
        end_idx: int = -1,
    ) -> None:
        """Records a discrete text replacement or removal."""
        if start_idx == -1:
            start_idx = self.current_text.find(original_snippet)
            if start_idx != -1:
                end_idx = start_idx + len(original_snippet)
            else:
                start_idx = 0
                end_idx = len(original_snippet)

        # Ensure raw sensitive credentials are never stored unmasked in the audit trail
        safe_original = original_snippet
        if any(sec in rule_id.upper() for sec in ("API_KEY", "PASSWORD", "JWT", "SECRET", "PRIVATE_KEY", "CREDENTIAL")):
            if len(original_snippet) > 8:
                safe_original = original_snippet[:4] + "***" + original_snippet[-4:]
            else:
                safe_original = "***"

        mod = TextModification(
            start=start_idx,
            end=end_idx,
            original=safe_original,
            replacement=replacement_snippet,
            reason=reason,
            rule_id=rule_id,
        )
        self.modifications.append(mod)

    def apply_replacement(
        self,
        original_snippet: str,
        replacement_snippet: str,
        reason: str,
        rule_id: str,
    ) -> str:
        """Finds all occurrences of original_snippet, replaces them, and logs modifications."""
        if not original_snippet or original_snippet not in self.current_text:
            return self.current_text

        # Record each occurrence
        idx = 0
        while True:
            idx = self.current_text.find(original_snippet, idx)
            if idx == -1:
                break
            self.record_replacement(
                original_snippet=original_snippet,
                replacement_snippet=replacement_snippet,
                reason=reason,
                rule_id=rule_id,
                start_idx=idx,
                end_idx=idx + len(original_snippet),
            )
            idx += len(original_snippet)

        self.current_text = self.current_text.replace(original_snippet, replacement_snippet)
        return self.current_text

    def set_sanitized_text(self, new_text: str, reason: str, rule_id: str) -> None:
        """Sets completely new text when a whole block or prompt is sanitized."""
        if self.current_text != new_text:
            self.record_replacement(
                original_snippet=self.current_text,
                replacement_snippet=new_text,
                reason=reason,
                rule_id=rule_id,
                start_idx=0,
                end_idx=len(self.current_text),
            )
            self.current_text = new_text

    def build_diff(self) -> SanitizationDiff:
        """Constructs the final SanitizationDiff object, ensuring secrets are masked in audit trails."""
        safe_orig = self.original_text
        for mod in self.modifications:
            if any(sec in mod.rule_id.upper() for sec in ("API_KEY", "PASSWORD", "JWT", "SECRET", "PRIVATE_KEY", "CREDENTIAL")):
                if 0 <= mod.start < mod.end <= len(self.original_text):
                    safe_orig = safe_orig[:mod.start] + mod.original + safe_orig[mod.end:]

        return SanitizationDiff(
            original_text=safe_orig,
            sanitized_text=self.current_text,
            modifications=list(self.modifications),
        )
