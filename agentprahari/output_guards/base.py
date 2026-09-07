"""
Base Interface for Output Guardrails.
"""

from abc import ABC, abstractmethod
from typing import List, Tuple
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import Violation


class BaseOutputGuard(ABC):
    """Abstract Base Class for Post-Execution Output Guardrails."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def evaluate(
        self,
        output_text: str,
        config: PrahariConfig
    ) -> Tuple[str, List[Violation]]:
        """
        Evaluates and optionally cleans the model's generated output.
        Returns (sanitized_output_text, list_of_violations).
        """
        pass
