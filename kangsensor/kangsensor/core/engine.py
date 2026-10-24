"""Rule evaluation engine — the brain of KangSensor."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kangsensor.rules.library import CompiledRule

BINARY_SAMPLE_BYTES = 8192
BINARY_NULL_THRESHOLD = 0.30


@dataclass
class Finding:
    """A single PII/sensitive-data hit produced by the rule engine."""

    rule_id: str
    rule_name: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    file_path: str
    line_no: int
    offset: int
    snippet: str           # ≤100 chars, redacted centre
    confidence: int        # 0–100
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "file"   # file | clipboard | network


def _is_binary(data: bytes) -> bool:
    """Return True when the byte sample looks like binary content."""
    if len(data) == 0:
        return False
    null_ratio = data.count(b"\x00") / len(data)
    return null_ratio > BINARY_NULL_THRESHOLD


def _redact_snippet(text: str, max_len: int = 100) -> str:
    """Keep first/last 20 chars, replace middle with ellipsis."""
    if len(text) <= max_len:
        return text
    half = (max_len - 3) // 2
    return text[:half] + "..." + text[-(max_len - half - 3):]


class RuleEngine:
    """Evaluate a text payload against a list of compiled rules."""

    def __init__(self, rules: list[CompiledRule]) -> None:
        self._rules = rules

    def evaluate(self, payload: str, file_path: str = "", source: str = "file") -> list[Finding]:
        """Apply all rules to *payload* and return a list of findings."""
        findings: list[Finding] = []
        lines = payload.splitlines(keepends=True)

        for rule in self._rules:
            hits = list(rule.pattern.finditer(payload))
            if not hits:
                continue

            for m in hits:
                confidence = rule.confidence_base
                confidence = rule.run_validators(m, payload, confidence)
                if confidence < rule.min_confidence:
                    continue

                # Map match offset to line number
                line_no = payload.count("\n", 0, m.start()) + 1
                raw_snippet = payload[max(0, m.start() - 20): m.end() + 20]
                snippet = _redact_snippet(raw_snippet.replace("\n", " "))

                findings.append(Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    file_path=file_path,
                    line_no=line_no,
                    offset=m.start(),
                    snippet=snippet,
                    confidence=min(confidence, 100),
                    source=source,
                ))

        return findings

    def evaluate_file(self, path: str) -> list[Finding]:
        """Read *path*, skip binaries, and run all rules."""
        try:
            with open(path, "rb") as fh:
                header = fh.read(BINARY_SAMPLE_BYTES)
                if _is_binary(header):
                    return []
                fh.seek(0)
                content = fh.read().decode("utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        return self.evaluate(content, file_path=path)
