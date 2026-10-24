"""Rule library: load YAML rule files, compile patterns, build validator chains."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

logger = logging.getLogger(__name__)

# Valid Indonesian province codes (first 2 digits of NIK)
_VALID_PROVINCE_CODES = {
    "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "21",
    "31", "32", "33", "34", "35", "36",
    "51", "52", "53",
    "61", "62", "63", "64", "65",
    "71", "72", "73", "74", "75", "76",
    "81", "82",
    "91", "92", "94",
}

BUILTIN_DIR = Path(__file__).parent / "builtin"


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _validate_province_code(match: re.Match, payload: str, confidence: int) -> int:
    province = match.group(0)[:2]
    return confidence + 20 if province in _VALID_PROVINCE_CODES else confidence - 40


def _make_context_keyword_validator(keywords: list[str], window: int) -> Callable:
    kw_lower = [k.lower() for k in keywords]

    def _validate(match: re.Match, payload: str, confidence: int) -> int:
        start = max(0, match.start() - window)
        end = min(len(payload), match.end() + window)
        context = payload[start:end].lower()
        if any(kw in context for kw in kw_lower):
            return confidence + 25
        return confidence - 15

    return _validate


def _validate_luhn(match: re.Match, payload: str, confidence: int) -> int:
    digits = re.sub(r"\D", "", match.group(0))
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return confidence + 15 if total % 10 == 0 else confidence - 30


def _make_not_placeholder_validator(placeholders: list[str]) -> Callable:
    lower_ph = [p.lower() for p in placeholders]

    def _validate(match: re.Match, payload: str, confidence: int) -> int:
        snippet = match.group(0).lower()
        if any(ph in snippet for ph in lower_ph):
            return confidence - 50
        return confidence

    return _validate


def _build_validator(spec: dict[str, Any]) -> Callable | None:
    vtype = spec.get("type")
    if vtype == "province_code":
        return _validate_province_code
    if vtype == "context_keyword":
        return _make_context_keyword_validator(spec.get("keywords", []), spec.get("window", 50))
    if vtype == "luhn_check":
        return _validate_luhn
    if vtype == "not_placeholder":
        return _make_not_placeholder_validator(spec.get("placeholders", []))
    logger.warning("Unknown validator type: %s", vtype)
    return None


# ---------------------------------------------------------------------------
# CompiledRule
# ---------------------------------------------------------------------------

@dataclass
class CompiledRule:
    rule_id: str
    name: str
    severity: str
    pattern: re.Pattern
    validators: list[Callable] = field(default_factory=list)
    confidence_base: int = 70
    min_confidence: int = 50
    description: str = ""

    def run_validators(self, match: re.Match, payload: str, confidence: int) -> int:
        for v in self.validators:
            confidence = v(match, payload, confidence)
        return confidence


# ---------------------------------------------------------------------------
# RuleLibrary
# ---------------------------------------------------------------------------

class RuleLibrary:
    """Load, store and retrieve compiled rules."""

    def __init__(self) -> None:
        self._rules: list[CompiledRule] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_file(self, path: str | Path) -> int:
        """Parse one YAML file and add its rules. Returns number added."""
        path = Path(path)
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception as exc:
            logger.error("Failed to load rule file %s: %s", path, exc)
            return 0

        count = 0
        for spec in data.get("rules", []):
            rule = self._compile(spec)
            if rule:
                self._rules.append(rule)
                count += 1
        return count

    def load_builtin(self, subset: Optional[list[str]] = None) -> int:
        """Load all (or a named subset of) builtin YAML rule files."""
        total = 0
        for yaml_file in sorted(BUILTIN_DIR.glob("*.yaml")):
            if subset and yaml_file.stem not in subset:
                continue
            total += self.load_file(yaml_file)
        return total

    def load_directory(self, directory: str | Path) -> int:
        """Load every YAML file in a directory (for custom rules)."""
        total = 0
        for yaml_file in Path(directory).glob("*.yaml"):
            total += self.load_file(yaml_file)
        return total

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def rules(self) -> list[CompiledRule]:
        return list(self._rules)

    def get(self, rule_id: str) -> Optional[CompiledRule]:
        return next((r for r in self._rules if r.rule_id == rule_id), None)

    def summary(self) -> list[dict]:
        return [
            {
                "id": r.rule_id,
                "name": r.name,
                "severity": r.severity,
                "confidence_base": r.confidence_base,
            }
            for r in self._rules
        ]

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _compile(self, spec: dict) -> Optional[CompiledRule]:
        try:
            rule_id = spec["id"]
            pattern = re.compile(spec["pattern"])
            validators = [
                v for v in (_build_validator(vs) for vs in spec.get("validators", []))
                if v is not None
            ]
            return CompiledRule(
                rule_id=rule_id,
                name=spec.get("name", rule_id),
                severity=spec.get("severity", "MEDIUM").upper(),
                pattern=pattern,
                validators=validators,
                confidence_base=int(spec.get("confidence_base", 70)),
                min_confidence=int(spec.get("min_confidence", 50)),
                description=spec.get("description", ""),
            )
        except Exception as exc:
            logger.error("Error compiling rule %s: %s", spec.get("id", "?"), exc)
            return None
