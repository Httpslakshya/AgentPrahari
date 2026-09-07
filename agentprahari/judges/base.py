"""
Base Interface for AI Safety Judges.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional


class BaseJudge(ABC):
    """Abstract interface for external model evaluators and judges."""

    @abstractmethod
    def evaluate_prompt(self, prompt: str) -> Dict[str, any]:
        """Evaluates whether an input prompt is malicious, jailbreak, or unsafe."""
        pass

    @abstractmethod
    def evaluate_output(self, prompt: str, output: str, context: Optional[str] = None) -> Dict[str, any]:
        """Evaluates model response for toxicity, hallucination, or safety."""
        pass
