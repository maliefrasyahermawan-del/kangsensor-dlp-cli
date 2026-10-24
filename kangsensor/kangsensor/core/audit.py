"""Append-only, hash-chained audit log backed by SQLite."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    rule_id      TEXT,
    severity     TEXT,
    file_path    TEXT,
    action_taken TEXT,
    extra        TEXT,
    prev_hash    TEXT    NOT NULL,
    current_hash TEXT    NOT NULL
);
"""


def _row_hash(prev_hash: str, row_data: dict) -> str:
    """SHA-256 of previous hash concatenated with canonical JSON of row_data."""
    raw = prev_hash + json.dumps(row_data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class AuditLog:
    """Thread-safe, append-only audit log with tamper-evident hash chain."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(DDL)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self,
        event_type: str,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        file_path: Optional[str] = None,
        action_taken: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """Insert one tamper-evident row."""
        prev_hash = self._last_hash()
        ts = datetime.now(timezone.utc).isoformat()
        row_data = {
            "timestamp": ts,
            "event_type": event_type,
            "rule_id": rule_id,
            "severity": severity,
            "file_path": file_path,
            "action_taken": action_taken,
            "extra": extra,
        }
        cur_hash = _row_hash(prev_hash, row_data)
        self._conn.execute(
            """INSERT INTO audit_log
               (timestamp, event_type, rule_id, severity, file_path,
                action_taken, extra, prev_hash, current_hash)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                ts,
                event_type,
                rule_id,
                severity,
                file_path,
                action_taken,
                json.dumps(extra) if extra else None,
                prev_hash,
                cur_hash,
            ),
        )
        self._conn.commit()

    def verify_chain(self) -> tuple[bool, str]:
        """Walk every row and re-derive hashes. Returns (ok, message)."""
        rows = self._conn.execute(
            "SELECT id, timestamp, event_type, rule_id, severity, file_path, "
            "action_taken, extra, prev_hash, current_hash FROM audit_log ORDER BY id"
        ).fetchall()

        if not rows:
            return True, "Audit log is empty — chain valid."

        prev_hash = "GENESIS"
        for row in rows:
            (rid, ts, et, rule_id, sev, fp, act, extra_str, stored_prev, stored_cur) = row
            if stored_prev != prev_hash:
                return False, f"Chain break at row id={rid}: expected prev={prev_hash!r}"
            extra = json.loads(extra_str) if extra_str else None
            row_data = {
                "timestamp": ts, "event_type": et, "rule_id": rule_id,
                "severity": sev, "file_path": fp, "action_taken": act, "extra": extra,
            }
            expected = _row_hash(prev_hash, row_data)
            if expected != stored_cur:
                return False, f"Hash mismatch at row id={rid}"
            prev_hash = stored_cur

        return True, f"Chain intact — {len(rows)} entries verified."

    def query(
        self,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return recent audit entries as dicts, newest first."""
        if since:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE timestamp >= ? ORDER BY id DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

        cols = [d[0] for d in self._conn.execute("SELECT * FROM audit_log LIMIT 0").description]
        return [dict(zip(cols, r)) for r in rows]

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "GENESIS"
