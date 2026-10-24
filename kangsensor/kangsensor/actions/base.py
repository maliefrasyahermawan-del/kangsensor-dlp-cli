"""Abstract base class for action plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kangsensor.core.engine import Finding


class ActionBase(ABC):
    """All action plugins must implement this interface."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this action (e.g. 'log', 'alert')."""

    @abstractmethod
    def execute(self, finding: Finding) -> None:
        """React to a single finding. Must not raise; log errors instead."""
