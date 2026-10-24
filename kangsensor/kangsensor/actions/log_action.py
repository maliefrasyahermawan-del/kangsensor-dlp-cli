"""Log action — write finding to audit log and Python logger."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from kangsensor.actions.base import ActionBase

if TYPE_CHECKING:
    from kangsensor.core.audit import AuditLog
    from kangsensor.core.engine import Finding

logger = logging.getLogger(__name__)


class LogAction(ActionBase):
    """Append a finding to the tamper-evident audit log and stderr."""

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    @property
    def name(self) -> str:
        return "log"

    def execute(self, finding: Finding) -> None:
        logger.warning(
            "[%s] %s — %s (confidence=%d%%) @ %s line %d",
            finding.severity,
            finding.rule_id,
            finding.rule_name,
            finding.confidence,
            finding.file_path,
            finding.line_no,
        )
        try:
            self._audit.append(
                event_type="FINDING",
                rule_id=finding.rule_id,
                severity=finding.severity,
                file_path=finding.file_path,
                action_taken="log",
                extra={
                    "rule_name": finding.rule_name,
                    "line_no": finding.line_no,
                    "confidence": finding.confidence,
                    "snippet": finding.snippet,
                    "source": finding.source,
                },
            )
        except Exception:
            logger.exception("LogAction: failed to write audit entry")
