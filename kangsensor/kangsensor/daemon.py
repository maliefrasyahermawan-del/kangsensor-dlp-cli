"""Daemon controller — manage background sensor processes via a PID file."""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

PID_FILE = Path.home() / ".kangsensor" / "kangsensor.pid"


def _write_pid(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()))


def _read_pid(path: Path) -> Optional[int]:
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def start_daemon(config: dict) -> None:
    """Fork into background (Unix) or run inline (Windows) and start all sensors."""
    if sys.platform == "win32":
        _run_sensors(config)
        return

    # Double-fork on Unix
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        sys.exit(0)

    sys.stdin = open(os.devnull)
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")

    _run_sensors(config)


def _run_sensors(config: dict) -> None:
    from kangsensor.core.audit import AuditLog
    from kangsensor.core.engine import RuleEngine
    from kangsensor.rules.library import RuleLibrary
    from kangsensor.sensors.clipboard_sensor import ClipboardSensor
    from kangsensor.sensors.file_sensor import FileSensor
    from kangsensor.actions.log_action import LogAction
    from kangsensor.actions.alert_action import AlertAction
    from kangsensor.actions.quarantine_action import QuarantineAction

    _write_pid(PID_FILE)

    audit = AuditLog(config.get("audit", {}).get("db_path", "~/.kangsensor/audit.db"))

    lib = RuleLibrary()
    lib.load_builtin()

    engine = RuleEngine(lib.rules)

    log_action = LogAction(audit)
    alert_action = AlertAction()
    quarantine_action = QuarantineAction(audit)

    policies: dict = config.get("policies", {}).get("default", {})

    def dispatch(findings: list) -> None:
        for f in findings:
            action_name = policies.get(f.rule_id, "log")
            if action_name == "quarantine":
                quarantine_action.execute(f)
                log_action.execute(f)
            elif action_name == "alert":
                alert_action.execute(f)
                log_action.execute(f)
            elif action_name == "log":
                log_action.execute(f)

    sensors = []
    sensor_cfg = config.get("sensors", {})

    if sensor_cfg.get("file", {}).get("enabled", True):
        paths = sensor_cfg["file"].get("paths", ["~/Documents"])
        sensors.append(FileSensor(paths, engine, dispatch))

    if sensor_cfg.get("clipboard", {}).get("enabled", True):
        poll_ms = sensor_cfg.get("clipboard", {}).get("poll_ms", 500)
        sensors.append(ClipboardSensor(engine, dispatch, poll_ms=poll_ms))

    for s in sensors:
        s.start()
        logger.info("Started sensor: %s", s.name)

    audit.append(event_type="DAEMON_START", action_taken="start")

    try:
        while True:
            time.sleep(5)
    except (KeyboardInterrupt, SystemExit):
        for s in sensors:
            s.stop()
        audit.append(event_type="DAEMON_STOP", action_taken="stop")
        PID_FILE.unlink(missing_ok=True)


def stop_daemon() -> str:
    pid = _read_pid(PID_FILE)
    if pid is None:
        return "No daemon is running (no PID file found)."
    if not _is_running(pid):
        PID_FILE.unlink(missing_ok=True)
        return f"Stale PID file removed (process {pid} not running)."
    try:
        os.kill(pid, signal.SIGTERM)
        return f"Sent SIGTERM to daemon (PID {pid})."
    except PermissionError:
        return f"Permission denied to kill PID {pid}."


def daemon_status() -> str:
    pid = _read_pid(PID_FILE)
    if pid is None:
        return "Daemon is NOT running."
    if _is_running(pid):
        return f"Daemon is RUNNING (PID {pid})."
    return f"Daemon is NOT running (stale PID {pid})."
