"""Alert action — desktop notification via plyer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from kangsensor.actions.base import ActionBase

if TYPE_CHECKING:
    from kangsensor.core.engine import Finding

logger = logging.getLogger(__name__)

_PLYER_AVAILABLE: bool | None = None


def _can_notify() -> bool:
    global _PLYER_AVAILABLE
    if _PLYER_AVAILABLE is None:
        try:
            from plyer import notification  # noqa: F401
            _PLYER_AVAILABLE = True
        except Exception:
            _PLYER_AVAILABLE = False
    return _PLYER_AVAILABLE


class AlertAction(ActionBase):
    """Send a desktop notification for each finding."""

    @property
    def name(self) -> str:
        return "alert"

    def execute(self, finding: Finding) -> None:
        if not _can_notify():
            logger.info("AlertAction: plyer not available, skipping desktop notification.")
            return

        from plyer import notification

        title = f"KangSensor [{finding.severity}] — {finding.rule_id}"
        message = (
            f"Rule: {finding.rule_name}\n"
            f"File: {finding.file_path}\n"
            f"Line: {finding.line_no}  Confidence: {finding.confidence}%"
        )
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="KangSensor",
                timeout=8,
            )
        except Exception:
            logger.exception("AlertAction: notification failed")
