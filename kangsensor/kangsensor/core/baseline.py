"""File integrity baseline — create SHA-256 snapshot and verify later."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CHUNK = 65536  # 64 KB read chunks


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(CHUNK):
                h.update(chunk)
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot hash %s: %s", path, exc)
        return "ERROR"
    return h.hexdigest()


class Baseline:
    """Manage a JSON-backed integrity snapshot of a directory tree."""

    def __init__(self, baseline_path: str | Path) -> None:
        self._bpath = Path(baseline_path).expanduser()

    def create(self, target: str | Path, extensions: Optional[list[str]] = None) -> dict:
        """Walk *target*, hash every file, save baseline JSON, return summary."""
        target = Path(target).expanduser().resolve()
        exts = {e.lower() for e in (extensions or [])}
        snapshot: dict[str, str] = {}

        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if exts and p.suffix.lower() not in exts:
                continue
            rel = str(p.relative_to(target))
            snapshot[rel] = _sha256(p)

        data = {
            "root": str(target),
            "created_at": __import__("datetime").datetime.utcnow().isoformat(),
            "files": snapshot,
        }
        self._bpath.parent.mkdir(parents=True, exist_ok=True)
        self._bpath.write_text(json.dumps(data, indent=2))
        return {"root": str(target), "file_count": len(snapshot), "path": str(self._bpath)}

    def verify(self, target: str | Path) -> dict:
        """Compare current state of *target* against saved baseline."""
        if not self._bpath.exists():
            return {"error": f"No baseline found at {self._bpath}"}

        data = json.loads(self._bpath.read_text())
        root = Path(data["root"])
        snapshot: dict[str, str] = data["files"]

        current: dict[str, str] = {}
        for p in root.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(root))
                current[rel] = _sha256(p)

        added = sorted(set(current) - set(snapshot))
        removed = sorted(set(snapshot) - set(current))
        modified = sorted(
            k for k in set(snapshot) & set(current) if snapshot[k] != current[k]
        )

        return {
            "baseline_date": data.get("created_at"),
            "added": added,
            "removed": removed,
            "modified": modified,
            "clean": not (added or removed or modified),
        }
