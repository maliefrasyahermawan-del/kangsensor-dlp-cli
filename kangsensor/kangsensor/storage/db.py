"""SQLite manager — thin wrapper used by audit and baseline."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


class Database:
    """Thread-safe SQLite connection wrapper with WAL mode enabled."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def executemany(self, sql: str, params_seq: list) -> None:
        with self._lock:
            self._conn.executemany(sql, params_seq)

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
