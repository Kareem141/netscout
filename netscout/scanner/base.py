"""Abstract base class for scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Scanner(ABC):
    """Base class for all network scanners."""

    def __init__(self, timeout: float = 2.0) -> None:
        self.timeout = timeout

    @abstractmethod
    def scan(self, target: str, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Execute the scan and return results."""
        ...
