"""
Base Interface for Input Guardrails.
"""

from abc import ABC, abstractmethod
from typing import List
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import Violation
from agentprahari.input_guards.diff_tracker import DiffTracker


class BaseInputGuard(ABC):
    """Abstract Base Class for all Pre-execution Input Guardrails."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The identifier of this guard."""
        pass

    @abstractmethod
    def evaluate(
        self,
        text: str,
        tracker: DiffTracker,
        config: PrahariConfig
    ) -> List[Violation]:
        """
        Evaluates the input text.
        Can mutate tracker (apply replacements/removals) and returns any violations discovered.
        """
        pass
