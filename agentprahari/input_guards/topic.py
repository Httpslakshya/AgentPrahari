"""
AgentPrahari Topic and Domain Scope Enforcer.
"""

from __future__ import annotations
import re
from typing import List
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import GuardCategory, Severity, Violation
from agentprahari.input_guards.base import BaseInputGuard
from agentprahari.input_guards.diff_tracker import DiffTracker


class TopicGuard(BaseInputGuard):
    """
    Enforces conversational boundary by validating against allowed topics or rejecting blocked topics.
    """

    @property
    def name(self) -> str:
        return "TopicGuard"

    def evaluate(
        self,
        text: str,
        tracker: DiffTracker,
        config: PrahariConfig
    ) -> List[Violation]:
        violations: List[Violation] = []
        current_content = tracker.current_text.lower()

        # Check blocked topics
        for topic in config.blocked_topics:
            # Match word boundary
            pattern = re.compile(rf"\b{re.escape(topic.lower())}\b", re.IGNORECASE)
            if pattern.search(current_content):
                violations.append(Violation(
                    rule_id="TOPIC_BLOCKED_DOMAIN",
                    message=f"Prompt discusses prohibited topic: '{topic}'",
                    severity=Severity.HIGH,
                    category=GuardCategory.INPUT,
                    guard_name=self.name,
                    matched_content=topic,
                    details={"blocked_topic": topic}
                ))

        # Check allowed topics (if specified, input must match at least one allowed domain)
        if config.allowed_topics:
            matched_any = False
            for allowed in config.allowed_topics:
                pattern = re.compile(rf"\b{re.escape(allowed.lower())}\b", re.IGNORECASE)
                if pattern.search(current_content):
                    matched_any = True
                    break
            if not matched_any:
                violations.append(Violation(
                    rule_id="TOPIC_OFF_LIMITS",
                    message=f"Input does not relate to any allowed topics: {config.allowed_topics}",
                    severity=Severity.MEDIUM,
                    category=GuardCategory.INPUT,
                    guard_name=self.name,
                    matched_content=None,
                    details={"allowed_topics": config.allowed_topics}
                ))

        return violations
