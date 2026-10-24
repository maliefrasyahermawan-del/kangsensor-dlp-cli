"""Abstract base class for all KangSensor sensor plugins."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod


class SensorBase(ABC):
    """Common interface for sensor plugins (file, clipboard, network, …)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the sensor in a background daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name=f"sensor-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the sensor to stop and wait for its thread to join."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ------------------------------------------------------------------
    # Override in subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    def _run(self) -> None:
        """Main sensor loop — executed in the background thread."""
