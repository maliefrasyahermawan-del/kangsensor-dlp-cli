"""Clipboard sensor — poll pyperclip every N ms and scan for PII."""

from __future__ import annotations

import hashlib
import logging
import time
from typing import TYPE_CHECKING, Callable

from kangsensor.sensors.base import SensorBase

if TYPE_CHECKING:
    from kangsensor.core.engine import Finding, RuleEngine

logger = logging.getLogger(__name__)


class ClipboardSensor(SensorBase):
    """Poll the system clipboard and alert when sensitive data is detected."""

    def __init__(
        self,
        engine: RuleEngine,
        on_finding: Callable[[list[Finding]], None],
        poll_ms: int = 500,
    ) -> None:
        super().__init__("clipboard")
        self._engine = engine
        self._on_finding = on_finding
        self._poll_interval = poll_ms / 1000.0
        self._prev_hash: str | None = None

    def _run(self) -> None:
        try:
            import pyperclip
        except ImportError:
            logger.error("pyperclip is not installed — clipboard sensor disabled.")
            return

        logger.info("ClipboardSensor started (poll=%dms)", int(self._poll_interval * 1000))
        while not self._stop_event.is_set():
            try:
                content = pyperclip.paste()
            except Exception:
                time.sleep(self._poll_interval)
                continue

            if not content:
                time.sleep(self._poll_interval)
                continue

            content_hash = hashlib.sha256(content.encode()).hexdigest()
            if content_hash == self._prev_hash:
                time.sleep(self._poll_interval)
                continue

            self._prev_hash = content_hash
            findings = self._engine.evaluate(content, file_path="<clipboard>", source="clipboard")
            if findings:
                self._on_finding(findings)

            time.sleep(self._poll_interval)
