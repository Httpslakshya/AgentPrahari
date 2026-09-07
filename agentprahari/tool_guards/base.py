"""
Base Interface for Tool & Agent Execution Guardrails.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from agentprahari.core.config import PrahariConfig
from agentprahari.core.result import Violation


class BaseToolGuard(ABC):
    """Abstract Base Class for Tool Call Safety Guards."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        config: PrahariConfig
    ) -> List[Violation]:
        """
        Inspects an impending tool/function call before execution.
        Returns any violations detected.
        """
        pass
