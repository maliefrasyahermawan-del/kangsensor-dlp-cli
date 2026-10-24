"""Quarantine action — move offending file to an isolated staging area."""

from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from kangsensor.actions.base import ActionBase

if TYPE_CHECKING:
    from kangsensor.core.audit import AuditLog
    from kangsensor.core.engine import Finding

logger = logging.getLogger(__name__)

QUARANTINE_DIR = Path.home() / ".kangsensor" / "quarantine"


def _file_sha256_prefix(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            h.update(fh.read(65536))
    except OSError:
        pass
    return h.hexdigest()[:16]


class QuarantineAction(ActionBase):
    """Move the file that triggered a finding into the quarantine directory."""

    def __init__(self, audit: AuditLog, quarantine_dir: Path | None = None) -> None:
        self._audit = audit
        self._qdir = quarantine_dir or QUARANTINE_DIR

    @property
    def name(self) -> str:
        return "quarantine"

    def execute(self, finding: Finding) -> None:
        if finding.source != "file":
            logger.debug("QuarantineAction: skipping non-file finding (%s)", finding.source)
            return

        src = Path(finding.file_path)
        if not src.is_file():
            logger.warning("QuarantineAction: source file not found: %s", src)
            return

        self._qdir.mkdir(parents=True, exist_ok=True)
        prefix = _file_sha256_prefix(src)
        dest_name = f"{src.name}.{prefix}.quarantined"
        dest = self._qdir / dest_name

        try:
            shutil.move(str(src), str(dest))
            logger.warning("QUARANTINED %s → %s", src, dest)
            self._audit.append(
                event_type="QUARANTINE",
                rule_id=finding.rule_id,
                severity=finding.severity,
                file_path=str(src),
                action_taken="quarantine",
                extra={"destination": str(dest), "trigger_rule": finding.rule_id},
            )
        except (OSError, shutil.Error) as exc:
            logger.error("QuarantineAction failed to move %s: %s", src, exc)
