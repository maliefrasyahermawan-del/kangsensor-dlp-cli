"""KangSensor CLI — entry point for all subcommands."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich import box

# Force UTF-8 output on Windows to avoid cp1252 encoding errors in Rich
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()

# ── Config helpers ────────────────────────────────────────────────────────────

DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "default.yaml"
USER_CONFIG = Path.home() / ".kangsensor" / "config.yaml"


def _load_config(config_path: Optional[str]) -> dict:
    path = Path(config_path) if config_path else (USER_CONFIG if USER_CONFIG.exists() else DEFAULT_CONFIG)
    try:
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _severity_color(sev: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }.get(sev.upper(), "white")


# ── Root group ────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="kangsensor")
def main() -> None:
    """KangSensor — Data Leakage Prevention CLI for Indonesian compliance (UU PDP)."""


# ── scan ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--rules", "ruleset", default="all", show_default=True,
              help="Comma-separated rule files (e.g. id_indonesia,credentials) or 'all'.")
@click.option("--output", "-o", default=None, help="Write JSON report to file.")
@click.option("--config", "-c", default=None, help="Path to config YAML.")
@click.option("--min-confidence", default=50, show_default=True,
              help="Ignore findings below this confidence threshold (0-100).")
@click.option("--verbose", "-v", is_flag=True, help="Show INFO log output.")
def scan(path: str, ruleset: str, output: Optional[str], config: Optional[str],
         min_confidence: int, verbose: bool) -> None:
    """One-shot scan of a file or directory for sensitive data."""
    _setup_logging("DEBUG" if verbose else "WARNING")

    from kangsensor.core.engine import RuleEngine
    from kangsensor.rules.library import RuleLibrary
    from kangsensor.sensors.file_sensor import FileSensor

    lib = RuleLibrary()
    if ruleset == "all":
        total = lib.load_builtin()
    else:
        subset = [r.strip() for r in ruleset.split(",")]
        total = lib.load_builtin(subset=subset)

    console.print(f"[dim]Loaded {total} rules.[/dim]")

    engine = RuleEngine(lib.rules)

    # Use FileSensor.scan_now so text-extraction logic is shared
    sensor = FileSensor([], engine, lambda _: None)

    with console.status(f"[bold green]Scanning {path}…"):
        findings = sensor.scan_now(path)

    findings = [f for f in findings if f.confidence >= min_confidence]

    if not findings:
        console.print("[bold green]No sensitive data detected.[/bold green]")
        return

    # ── Rich table ───────────────────────────────────────────────────────
    table = Table(title=f"Findings — {path}", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule ID", width=22)
    table.add_column("File", width=40)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Snippet", width=50)

    for f in sorted(findings, key=lambda x: (x.severity, -x.confidence)):
        color = _severity_color(f.severity)
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.rule_id,
            os.path.basename(f.file_path),
            str(f.line_no),
            f"{f.confidence}%",
            f.snippet[:80],
        )

    console.print(table)
    console.print(f"\n[bold]{len(findings)} finding(s) in {_count_files(findings)} file(s).[/bold]")

    if output:
        report = [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_no": f.line_no,
                "confidence": f.confidence,
                "snippet": f.snippet,
                "timestamp": f.timestamp.isoformat(),
            }
            for f in findings
        ]
        Path(output).write_text(json.dumps(report, indent=2))
        console.print(f"[dim]Report saved to {output}[/dim]")

    # Exit code 1 if any HIGH/CRITICAL found
    if any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)


def _count_files(findings: list) -> int:
    return len({f.file_path for f in findings})


# ── watch ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--policy", default="default", show_default=True,
              help="Policy name from config (maps rule → action).")
@click.option("--config", "-c", default=None, help="Path to config YAML.")
@click.option("--verbose", "-v", is_flag=True)
def watch(path: str, policy: str, config: Optional[str], verbose: bool) -> None:
    """Continuously watch a directory. Press Ctrl-C to stop."""
    _setup_logging("DEBUG" if verbose else "INFO")

    cfg = _load_config(config)

    from kangsensor.core.audit import AuditLog
    from kangsensor.core.engine import RuleEngine
    from kangsensor.rules.library import RuleLibrary
    from kangsensor.sensors.file_sensor import FileSensor
    from kangsensor.actions.log_action import LogAction
    from kangsensor.actions.alert_action import AlertAction
    from kangsensor.actions.quarantine_action import QuarantineAction

    lib = RuleLibrary()
    lib.load_builtin()
    engine = RuleEngine(lib.rules)

    audit = AuditLog(cfg.get("audit", {}).get("db_path", "~/.kangsensor/audit.db"))
    log_action = LogAction(audit)
    alert_action = AlertAction()
    quarantine_action = QuarantineAction(audit)

    policies: dict = cfg.get("policies", {}).get(policy, {})

    def dispatch(findings: list) -> None:
        for f in findings:
            action_name = policies.get(f.rule_id, "log")
            color = _severity_color(f.severity)
            console.print(
                f"[{color}][{f.severity}][/{color}] {f.rule_id} in "
                f"[bold]{f.file_path}[/bold] (line {f.line_no}, {f.confidence}%)"
            )
            if action_name == "quarantine":
                quarantine_action.execute(f)
                log_action.execute(f)
            elif action_name == "alert":
                alert_action.execute(f)
                log_action.execute(f)
            else:
                log_action.execute(f)

    sensor = FileSensor([path], engine, dispatch)
    sensor.start()
    console.print(f"[bold green]Watching:[/bold green] {path}  (Ctrl-C to stop)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sensor.stop()
        console.print("\n[dim]Watch stopped.[/dim]")


# ── daemon ────────────────────────────────────────────────────────────────────

@main.group()
def daemon() -> None:
    """Manage the KangSensor background daemon."""


@daemon.command("start")
@click.option("--config", "-c", default=None)
def daemon_start(config: Optional[str]) -> None:
    """Start the daemon (all sensors active)."""
    from kangsensor.daemon import start_daemon
    cfg = _load_config(config)
    console.print("[bold green]Starting daemon…[/bold green]")
    start_daemon(cfg)


@daemon.command("stop")
def daemon_stop() -> None:
    """Stop the running daemon."""
    from kangsensor.daemon import stop_daemon
    msg = stop_daemon()
    console.print(msg)


@daemon.command("status")
def daemon_status_cmd() -> None:
    """Show daemon status."""
    from kangsensor.daemon import daemon_status
    console.print(daemon_status())


# ── rules ─────────────────────────────────────────────────────────────────────

@main.group()
def rules() -> None:
    """Manage detection rules."""


@rules.command("list")
@click.option("--severity", default=None, help="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO).")
def rules_list(severity: Optional[str]) -> None:
    """List all loaded rules."""
    from kangsensor.rules.library import RuleLibrary
    lib = RuleLibrary()
    lib.load_builtin()

    table = Table(title="KangSensor Rule Library", box=box.ROUNDED)
    table.add_column("Rule ID", width=26)
    table.add_column("Name", width=38)
    table.add_column("Severity", width=10)
    table.add_column("Confidence Base", justify="right", width=16)

    for r in lib.summary():
        sev = r["severity"]
        if severity and sev != severity.upper():
            continue
        color = _severity_color(sev)
        table.add_row(r["id"], r["name"], f"[{color}]{sev}[/{color}]", str(r["confidence_base"]))

    console.print(table)
    console.print(f"[dim]Total: {len(lib.rules)} rules across 4 built-in categories[/dim]")


@rules.command("test")
@click.argument("text")
def rules_test(text: str) -> None:
    """Test TEXT against all rules and show matching rules."""
    from kangsensor.core.engine import RuleEngine
    from kangsensor.rules.library import RuleLibrary

    lib = RuleLibrary()
    lib.load_builtin()
    engine = RuleEngine(lib.rules)
    findings = engine.evaluate(text, file_path="<stdin>")

    if not findings:
        console.print("[green]No matches.[/green]")
        return

    for f in findings:
        color = _severity_color(f.severity)
        console.print(
            f"  [{color}]{f.severity}[/{color}]  {f.rule_id} ({f.rule_name})  "
            f"confidence={f.confidence}%  snippet={f.snippet!r}"
        )


# ── audit ─────────────────────────────────────────────────────────────────────

@main.group()
def audit() -> None:
    """View and verify the tamper-evident audit log."""


@audit.command("show")
@click.option("--since", default=None, help="ISO date e.g. 2024-01-01")
@click.option("--limit", default=50, show_default=True)
@click.option("--config", "-c", default=None)
def audit_show(since: Optional[str], limit: int, config: Optional[str]) -> None:
    """Display recent audit log entries."""
    from kangsensor.core.audit import AuditLog
    cfg = _load_config(config)
    db_path = cfg.get("audit", {}).get("db_path", "~/.kangsensor/audit.db")

    log = AuditLog(db_path)
    rows = log.query(since=since, limit=limit)

    if not rows:
        console.print("[dim]No audit entries found.[/dim]")
        return

    table = Table(title="Audit Log", box=box.SIMPLE_HEAVY)
    table.add_column("ID", width=6)
    table.add_column("Timestamp", width=22)
    table.add_column("Event", width=14)
    table.add_column("Rule", width=22)
    table.add_column("Severity", width=10)
    table.add_column("Action", width=12)
    table.add_column("File", width=30)

    for row in rows:
        sev = row.get("severity") or ""
        color = _severity_color(sev) if sev else "dim"
        table.add_row(
            str(row["id"]),
            row["timestamp"][:19],
            row["event_type"],
            row.get("rule_id") or "",
            f"[{color}]{sev}[/{color}]",
            row.get("action_taken") or "",
            (row.get("file_path") or "")[-30:],
        )

    console.print(table)


@audit.command("verify")
@click.option("--config", "-c", default=None)
def audit_verify(config: Optional[str]) -> None:
    """Verify the hash chain integrity of the audit log."""
    from kangsensor.core.audit import AuditLog
    cfg = _load_config(config)
    db_path = cfg.get("audit", {}).get("db_path", "~/.kangsensor/audit.db")

    log = AuditLog(db_path)
    ok, msg = log.verify_chain()
    if ok:
        console.print(f"[bold green]PASS[/bold green] {msg}")
    else:
        console.print(f"[bold red]FAIL[/bold red] {msg}")
        sys.exit(1)


# ── baseline ──────────────────────────────────────────────────────────────────

@main.group()
def baseline() -> None:
    """File integrity baseline management."""


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True))
@click.option("--config", "-c", default=None)
def baseline_create(path: str, config: Optional[str]) -> None:
    """Create a SHA-256 integrity baseline for PATH."""
    from kangsensor.core.baseline import Baseline
    cfg = _load_config(config)
    bpath = cfg.get("baseline", {}).get("db_path", "~/.kangsensor/baseline.json")

    b = Baseline(bpath)
    result = b.create(path)
    console.print(
        f"[bold green]Baseline created[/bold green]: {result['file_count']} files "
        f"under {result['root']}\n  saved to: {result['path']}"
    )


@baseline.command("verify")
@click.argument("path", type=click.Path(exists=True))
@click.option("--config", "-c", default=None)
def baseline_verify(path: str, config: Optional[str]) -> None:
    """Compare PATH against saved baseline and show diff."""
    from kangsensor.core.baseline import Baseline
    cfg = _load_config(config)
    bpath = cfg.get("baseline", {}).get("db_path", "~/.kangsensor/baseline.json")

    b = Baseline(bpath)
    result = b.verify(path)

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        sys.exit(1)

    if result["clean"]:
        console.print("[bold green]Baseline CLEAN — no changes detected.[/bold green]")
        return

    if result["modified"]:
        console.print(f"[bold red]MODIFIED ({len(result['modified'])}):[/bold red]")
        for f in result["modified"]:
            console.print(f"  [red]~ {f}[/red]")

    if result["added"]:
        console.print(f"[bold yellow]ADDED ({len(result['added'])}):[/bold yellow]")
        for f in result["added"]:
            console.print(f"  [yellow]+ {f}[/yellow]")

    if result["removed"]:
        console.print(f"[bold cyan]REMOVED ({len(result['removed'])}):[/bold cyan]")
        for f in result["removed"]:
            console.print(f"  [cyan]- {f}[/cyan]")

    sys.exit(1)
